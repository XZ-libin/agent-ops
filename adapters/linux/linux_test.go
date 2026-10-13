package linux

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	contractv1 "github.com/XZ-libin/agent-ops/contract/gen/go/agent_ops/contract/v1"

	"github.com/XZ-libin/agent-ops/internal/exec"
	"github.com/XZ-libin/agent-ops/internal/policy"
	"github.com/XZ-libin/agent-ops/internal/validation"
)

// fakeRunner 本地模拟 Runner：记录调用、返回预设输出；不执行任何真实命令。
type fakeRunner struct {
	mu       sync.Mutex
	outputs  map[string]exec.Result
	errs     map[string]error
	calls    [][]string
	blockCtx bool // 为 true 时阻塞直到 ctx 取消
}

func newFakeRunner() *fakeRunner {
	return &fakeRunner{outputs: map[string]exec.Result{}, errs: map[string]error{}}
}

func (f *fakeRunner) setOutput(argv []string, stdout string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.outputs[joinKey(argv)] = exec.Result{Stdout: []byte(stdout), ExitCode: 0}
}

func (f *fakeRunner) Run(ctx context.Context, argv []string, _ exec.RunOptions) (exec.Result, error) {
	f.mu.Lock()
	f.calls = append(f.calls, append([]string{}, argv...))
	block := f.blockCtx
	err := f.errs[joinKey(argv)]
	res := f.outputs[joinKey(argv)]
	f.mu.Unlock()

	if block {
		<-ctx.Done()
		return exec.Result{}, ctx.Err()
	}
	if err != nil {
		return exec.Result{}, err
	}
	return res, nil
}

func (f *fakeRunner) snapshotCalls() [][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([][]string, len(f.calls))
	for i, c := range f.calls {
		out[i] = append([]string{}, c...)
	}
	return out
}

func joinKey(argv []string) string { return strings.Join(argv, "\x00") }

func testAdapter(t *testing.T, r *fakeRunner, opts ...Option) *Adapter {
	t.Helper()
	a, err := New(r, opts...)
	if err != nil {
		t.Fatalf("构建适配器失败：%v", err)
	}
	return a
}

// TestDiscover 返回内核版本与发行版。
func TestDiscover(t *testing.T) {
	r := newFakeRunner()
	r.setOutput([]string{"uname", "-r"}, "6.1.0-25-amd64\n")
	r.setOutput([]string{"cat", "/etc/os-release"}, "NAME=\"Debian GNU/Linux\"\nVERSION_ID=\"12\"\n")

	a := testAdapter(t, r)
	insts, err := a.Discover(context.Background(), &contractv1.AssetTarget{AssetId: "ast_01HX"})
	if err != nil {
		t.Fatal(err)
	}
	if len(insts) != 1 {
		t.Fatalf("应返回 1 个实例，got %d", len(insts))
	}
	i := insts[0]
	if i.Version != "6.1.0-25-amd64" {
		t.Fatalf("内核版本不符：%q", i.Version)
	}
	if i.Id != "ast_01HX/linux" {
		t.Fatalf("实例 ID 不符：%q", i.Id)
	}
	found := false
	for _, kv := range i.Extra {
		if kv.Key == "distro" && kv.Value == "Debian GNU/Linux" {
			found = true
		}
	}
	if !found {
		t.Fatalf("发行版未解析：%v", i.Extra)
	}
}

// TestHealthStatuses 覆盖 healthy/degraded/unhealthy/unknown 四个状态。
func TestHealthStatuses(t *testing.T) {
	cases := []struct {
		name       string
		df         string
		loadavg    string
		cores      int
		wantStatus string
	}{
		{"healthy", "Filesystem 1K-blocks Used Available Capacity Mounted on\n/dev/sda1 100000 51000 49000 51% /\n", "1.00 1.20 1.30 3/456 12345", 4, "healthy"},
		{"disk-degraded-91", "/dev/sda1 100000 91000 9000 91% /", "0.50 1.20 1.30 3/456 12345", 4, "degraded"},
		{"disk-unhealthy-96", "/dev/sda1 100000 96000 4000 96% /", "0.50 1.20 1.30 3/456 12345", 4, "unhealthy"},
		{"load-degraded", "/dev/sda1 100000 50000 50000 50% /", "9.50 8.00 7.00 3/456 12345", 4, "degraded"},
		{"unknown", "garbage output", "", 4, "unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newFakeRunner()
			r.setOutput([]string{"df", "-P"}, tc.df)
			r.setOutput([]string{"cat", "/proc/loadavg"}, tc.loadavg)
			a := testAdapter(t, r, WithCores(tc.cores))

			rep, err := a.Health(context.Background(), &contractv1.Instance{Id: "i1"})
			if err != nil {
				t.Fatal(err)
			}
			if rep.Status != tc.wantStatus {
				t.Fatalf("状态 = %q，期望 %q（metrics=%v）", rep.Status, tc.wantStatus, rep.Metrics)
			}
		})
	}
}

// TestDiagnoseEachQuestion 覆盖四个预定义问题。
func TestDiagnoseEachQuestion(t *testing.T) {
	r := newFakeRunner()
	r.setOutput([]string{"df", "-P"}, "/dev/sda1 100000 91000 9000 91% /")
	r.setOutput([]string{"free", "-m"}, "Mem: 16000 8000 7999 1 100 7900")
	r.setOutput([]string{"cat", "/proc/loadavg"}, "2.50 2.00 1.90 3/456 12345")
	r.setOutput([]string{"systemctl", "is-active", "nginx@main.service"}, "active\n")

	cases := []struct {
		question string
		wantSub  string
	}{
		{QuestionDiskUsage, "根分区使用率"},
		{QuestionMemoryPressure, "内存"},
		{QuestionLoadAverage, "1 分钟负载"},
		{"service_state:nginx@main.service", "active"},
	}
	for _, tc := range cases {
		t.Run(tc.question, func(t *testing.T) {
			a := testAdapter(t, r)
			rep, err := a.Diagnose(context.Background(), &contractv1.Instance{Id: "i1"}, tc.question)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(rep.Conclusion, tc.wantSub) {
				t.Fatalf("结论 %q 应包含 %q", rep.Conclusion, tc.wantSub)
			}
			if len(rep.Findings) == 0 || len(rep.Findings[0].EvidenceRefs) == 0 {
				t.Fatal("诊断结论必须附证据引用")
			}
		})
	}
}

// TestDiagnoseFreeTextRejected 自由文本诊断问题一律拒绝。
func TestDiagnoseFreeTextRejected(t *testing.T) {
	a := testAdapter(t, newFakeRunner())
	_, err := a.Diagnose(context.Background(), &contractv1.Instance{Id: "i1"}, "why is this host slow")
	if !errors.Is(err, errQuestionReject) {
		t.Fatalf("自由文本应被拒绝（errQuestionReject），got %v", err)
	}
}

// TestDiagnoseInvalidUnitRejected 非法 unit 名被拒且不调用任何命令。
func TestDiagnoseInvalidUnitRejected(t *testing.T) {
	r := newFakeRunner()
	a := testAdapter(t, r)

	_, err := a.Diagnose(context.Background(), &contractv1.Instance{Id: "i1"}, "service_state:foo;bar")
	if !errors.Is(err, errBadUnit) {
		t.Fatalf("非法 unit 应返回 errBadUnit，got %v", err)
	}
	for _, call := range r.snapshotCalls() {
		if call[0] == "systemctl" {
			t.Fatalf("非法 unit 不应触发 systemctl 调用：%v", call)
		}
	}
}

// TestExecuteRejectsWrite 写能力被 Execute 拒绝，且错误信息固定。
func TestExecuteRejectsWrite(t *testing.T) {
	a := testAdapter(t, newFakeRunner())
	_, err := a.Execute(context.Background(),
		&contractv1.Action{Capability: "restart.service"},
		&contractv1.AuthZ{AuthorizationId: "a1"})
	if err == nil || !strings.Contains(err.Error(), "只读适配器不执行写操作") {
		t.Fatalf("写能力应被拒绝且信息固定，got %v", err)
	}
}

// TestExecuteRejectsUndeclared 未声明能力被拒绝。
func TestExecuteRejectsUndeclared(t *testing.T) {
	a := testAdapter(t, newFakeRunner())
	_, err := a.Execute(context.Background(),
		&contractv1.Action{Capability: "diagnose.nothing"},
		&contractv1.AuthZ{AuthorizationId: "a1"})
	if err == nil || !strings.Contains(err.Error(), "未在清单声明") {
		t.Fatalf("未声明能力应被拒绝并注明原因，got %v", err)
	}
}

// TestPlanRollbackEmpty 只读能力回滚计划恒为空并附理由。
func TestPlanRollbackEmpty(t *testing.T) {
	a := testAdapter(t, newFakeRunner())
	plan, err := a.PlanRollback(context.Background(), &contractv1.ActionRecord{OutputRef: "r1"})
	if !errors.Is(err, ErrNoRollbackNeeded) {
		t.Fatalf("应返回 ErrNoRollbackNeeded 理由，got %v", err)
	}
	if plan == nil || len(plan) != 0 {
		t.Fatalf("回滚计划应为空，got %v", plan)
	}
}

// TestManifestDeclared 清单中的四个能力均通过名称校验且等级为 read_only。
func TestManifestDeclared(t *testing.T) {
	a := testAdapter(t, newFakeRunner())
	if len(a.declared) != 4 {
		t.Fatalf("清单应声明 4 个能力，got %d", len(a.declared))
	}
	for name, tier := range a.declared {
		if tier != contractv1.RiskTier_RISK_TIER_READ_ONLY {
			t.Fatalf("能力 %s 等级应为 read_only，got %v", name, tier)
		}
		if !validation.ValidCapabilityName(name) {
			t.Fatalf("能力名 %s 未通过名称校验", name)
		}
	}
}

// TestReadOnlyRollbackableFalse 第九轮 R2：只读能力没有真实 PlanRollback 实现，
// 清单中 Rollbackable 必须为 false（策略对只读能力不受影响，仍为 auto）。
func TestReadOnlyRollbackableFalse(t *testing.T) {
	a := testAdapter(t, newFakeRunner())
	m := a.Manifest()
	if m == nil || len(m.Capabilities) == 0 {
		t.Fatal("清单为空")
	}
	for _, c := range m.Capabilities {
		if c.Rollbackable {
			t.Fatalf("只读能力 %s 的 Rollbackable 必须为 false（R2）", c.Name)
		}
		if c.Destructive {
			t.Fatalf("只读能力 %s 不得标 destructive", c.Name)
		}
	}
	// 交叉验证：策略对 read_only + rollbackable=false 仍判 auto。
	got := policy.Evaluate(policy.DefaultConfig(), policy.Request{
		Capability:  m.Capabilities[0],
		Environment: contractv1.Environment_ENVIRONMENT_PROD,
		FreezeWindow: true,
	})
	if got.Decision != contractv1.Decision_DECISION_AUTO {
		t.Fatalf("只读能力不应被回滚性/环境因素影响，got %v（%v）", got.Decision, got.Reasons)
	}
}
