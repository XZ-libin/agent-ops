package linuxwire

import (
	"context"
	"strings"
	"sync"
	"testing"

	"google.golang.org/protobuf/types/known/structpb"

	contractv1 "github.com/ORG/agent-ops/contract/gen/go/agent_ops/contract/v1"

	"github.com/ORG/agent-ops/adapters/linux"
	"github.com/ORG/agent-ops/gateway/internal/gateway"
	"github.com/ORG/agent-ops/internal/exec"
)

// fakeRunner 本地模拟 Runner（与 adapters/linux 测试同款，此处为最小实现）。
type fakeRunner struct {
	mu      sync.Mutex
	outputs map[string]exec.Result
	calls   [][]string
}

func newFakeRunner() *fakeRunner {
	return &fakeRunner{outputs: map[string]exec.Result{}}
}

func (f *fakeRunner) setOutput(argv []string, stdout string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.outputs[strings.Join(argv, "\x00")] = exec.Result{Stdout: []byte(stdout), ExitCode: 0}
}

func (f *fakeRunner) Run(_ context.Context, argv []string, _ exec.RunOptions) (exec.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, append([]string{}, argv...))
	return f.outputs[strings.Join(argv, "\x00")], nil
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

// testAdapter 构建带固定输出集的适配器。
func testAdapter(t *testing.T) (*linux.Adapter, *fakeRunner) {
	t.Helper()
	r := newFakeRunner()
	r.setOutput([]string{"uname", "-r"}, "6.1.0-test\n")
	r.setOutput([]string{"cat", "/etc/os-release"}, "NAME=\"Test OS\"\n")
	r.setOutput([]string{"df", "-P"}, "/dev/sda1 100000 50000 50000 50% /")
	r.setOutput([]string{"free", "-m"}, "Mem: 16000 8000 7999 1 100 7900")
	r.setOutput([]string{"cat", "/proc/loadavg"}, "1.00 1.20 1.30 3/456 12345")
	r.setOutput([]string{"systemctl", "is-active", "nginx"}, "active\n")
	a, err := linux.New(r)
	if err != nil {
		t.Fatalf("构建适配器失败：%v", err)
	}
	return a, r
}

// testRequest 构造网关请求。
func testRequest(capability string, params map[string]any) gateway.Request {
	var st *structpb.Struct
	if len(params) > 0 {
		st, _ = structpb.NewStruct(params)
	}
	return gateway.Request{
		Actor:          "ops-lead",
		IdempotencyKey: "k-1",
		Action: &contractv1.Action{
			Capability: capability,
			Params:     st,
			Target:     &contractv1.AssetTarget{AssetId: "ast_01HX", Access: contractv1.AccessKind_ACCESS_SSH},
		},
		Environment: contractv1.Environment_ENVIRONMENT_TEST,
	}
}

// TestRegisterAllManifestCapabilities 清单中 4 个能力全部注册成功且可路由。
func TestRegisterAllManifestCapabilities(t *testing.T) {
	a, _ := testAdapter(t)
	reg := gateway.NewRegistry()
	if err := Register(reg, a); err != nil {
		t.Fatalf("注册失败：%v", err)
	}
	for _, name := range []string{
		"diagnose.disk_usage", "diagnose.memory_pressure",
		"diagnose.load_average", "diagnose.service_state",
	} {
		if _, ok := reg.Lookup(name); !ok {
			t.Fatalf("能力 %s 未注册", name)
		}
	}
}

// TestDiagnoseHandlerExecutes 诊断能力经 Handler 走适配器 → 命令 argv 白名单。
func TestDiagnoseHandlerExecutes(t *testing.T) {
	a, r := testAdapter(t)
	reg := gateway.NewRegistry()
	if err := Register(reg, a); err != nil {
		t.Fatal(err)
	}
	entry, _ := reg.Lookup("diagnose.disk_usage")

	result, err := entry.Handler(context.Background(), testRequest("diagnose.disk_usage", nil))
	if err != nil {
		t.Fatalf("执行失败：%v", err)
	}
	if !result.Success {
		t.Fatalf("诊断应成功：%+v", result)
	}
	joined := ""
	for _, c := range r.snapshotCalls() {
		joined += strings.Join(c, " ") + ";"
	}
	if !strings.Contains(joined, "df -P") || !strings.Contains(joined, "uname -r") {
		t.Fatalf("应经 Discover + Diagnose 执行 df/uname：%q", joined)
	}
	ok := false
	for _, o := range result.Outputs {
		if o.Content != "" && strings.Contains(o.Content, "根分区使用率") {
			ok = true
		}
	}
	if !ok {
		t.Fatalf("输出应包含诊断结论：%+v", result.Outputs)
	}
}

// TestServiceStateUnitValidated service_state 的 unit 必须通过名称校验（fail-closed），
// 非法 unit 不触发 systemctl 调用。
func TestServiceStateUnitValidated(t *testing.T) {
	a, r := testAdapter(t)
	reg := gateway.NewRegistry()
	if err := Register(reg, a); err != nil {
		t.Fatal(err)
	}
	entry, _ := reg.Lookup("diagnose.service_state")

	if _, err := entry.Handler(context.Background(), testRequest("diagnose.service_state", map[string]any{"unit": "nginx"})); err != nil {
		t.Fatalf("合法 unit 应成功：%v", err)
	}
	before := len(r.snapshotCalls())

	if _, err := entry.Handler(context.Background(), testRequest("diagnose.service_state", map[string]any{"unit": "foo;bar"})); err == nil {
		t.Fatal("非法 unit 应被拒绝")
	}
	if got := len(r.snapshotCalls()) - before; got != 0 {
		t.Fatalf("非法 unit 不得触发任何命令：新增调用 %d", got)
	}
}

// TestUnroutableCapability 无路由能力返回错误（fail-closed，不部分注册）。
func TestUnroutableCapability(t *testing.T) {
	a, _ := testAdapter(t)
	if _, err := handlerFor("diagnose.unknown_question", a); err == nil {
		t.Fatal("未定义路由的诊断问题应报错")
	}
	if _, err := handlerFor("restart.service", a); err == nil {
		t.Fatal("写能力不应有路由（本轮不实现写操作适配器）")
	}
}
