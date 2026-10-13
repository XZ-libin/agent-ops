// P5 集成链路（第十七轮）：告警入站 → outbox → 消费者 → 待诊断请求 →
// 规划器 → **只读诊断执行器** → 结果表。
//
// 与 chain_test.go 的区别：本文件把链路走到"执行 + 结果"，并使用**真实**适配器
// 接线（linux 经 sshd 测试容器、docker 经本地 Docker 守护进程与测试标签容器），
// 不使用任何替身（fake）。每一步断言行数，结束时断言 run schema 已删除。
package chain

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/XZ-libin/agent-ops/adapters/docker"
	"github.com/XZ-libin/agent-ops/adapters/linux"
	"github.com/XZ-libin/agent-ops/alerts/internal/executor"
	"github.com/XZ-libin/agent-ops/alerts/internal/planner"
	contractv1 "github.com/XZ-libin/agent-ops/contract/gen/go/agent_ops/contract/v1"
	"github.com/XZ-libin/agent-ops/internal/audit"
	"github.com/XZ-libin/agent-ops/internal/exec/ssh"
	"github.com/XZ-libin/agent-ops/internal/exec/ssh/sshdtest"
	"github.com/XZ-libin/agent-ops/internal/policy"
	"github.com/XZ-libin/agent-ops/internal/testdb"
)

// —— 审计接线（把 internal/audit.Store 适配为执行器需要的 AuditSink）——

type chainAudit struct {
	mu  sync.Mutex
	st  *audit.Store
	seq int
}

func (a *chainAudit) Append(ctx context.Context, ev executor.AuditEvent) (string, error) {
	a.mu.Lock()
	a.seq++
	id := ev.ID
	if id == "" {
		id = fmt.Sprintf("evt-chain-diag-%d", a.seq)
	}
	a.mu.Unlock()
	return a.st.Append(ctx, audit.Event{
		ID: id, Actor: ev.Actor, Action: ev.Action, Target: ev.Target, Payload: ev.Payload,
	})
}

// —— 真实适配器接线 ——

// chainReadOnlyDecl 只读能力声明（仅测试使用）。
func chainReadOnlyDecl(name string) *contractv1.Capability {
	return &contractv1.Capability{
		Name: name, RiskTier: contractv1.RiskTier_RISK_TIER_READ_ONLY,
		Idempotent: true, Rollbackable: false, Destructive: false,
	}
}

// chainLinuxCaps 经真实 sshd 测试容器接线 linux 只读能力。
func chainLinuxCaps(t *testing.T) map[string]executor.CapEntry {
	t.Helper()
	sshd := sshdtest.StartLocalSSHD(t)
	runner, err := ssh.New(ssh.Options{Addr: sshd.Addr, User: sshd.User, Signer: sshd.Signer, HostKey: sshd.HostKey})
	if err != nil {
		t.Fatalf("构建 SSH Runner 失败：%v", err)
	}
	t.Cleanup(func() { _ = runner.Close() })
	adapter, err := linux.New(runner)
	if err != nil {
		t.Fatal(err)
	}
	questions := map[string]string{
		"diagnose.disk_usage":      linux.QuestionDiskUsage,
		"diagnose.memory_pressure": linux.QuestionMemoryPressure,
		"diagnose.load_average":    linux.QuestionLoadAverage,
	}
	out := map[string]executor.CapEntry{}
	for name, q := range questions {
		name, q := name, q
		out[name] = executor.CapEntry{Decl: chainReadOnlyDecl(name),
			Run: func(ctx context.Context, _ executor.Request) (executor.Report, error) {
				insts, derr := adapter.Discover(ctx, &contractv1.AssetTarget{AssetId: "ast_chain_exec"})
				if derr != nil {
					return executor.Report{}, derr
				}
				diag, derr := adapter.Diagnose(ctx, insts[0], q)
				if derr != nil {
					return executor.Report{}, derr
				}
				return executor.Report{Conclusion: diag.Conclusion, Success: true}, nil
			}}
	}
	return out
}

// chainDockerCaps 经本地 Docker 守护进程 + 测试标签容器接线 docker 只读能力。
func chainDockerCaps(t *testing.T) (map[string]executor.CapEntry, func()) {
	t.Helper()
	endpoint := chainDockerEndpoint(t)
	dockerBin := chainToolPath(t, "docker")
	image := "busybox:1.36"
	name := fmt.Sprintf("agent-ops-chaindiag-%d", time.Now().UnixNano())
	if out, err := exec.Command(dockerBin, "run", "-d", "--name", name,
		"--label", docker.TestLabel+"=true", image, "sleep", "300").CombinedOutput(); err != nil {
		t.Skipf("Docker 集成测试 skip：无法启动测试容器（%v，输出 %q）。", err, strings.TrimSpace(string(out)))
		return nil, nil
	}
	cleanup := func() { _ = exec.Command(dockerBin, "rm", "-f", name).Run() }
	adapter, err := docker.New(docker.Config{Endpoint: endpoint, Mode: docker.ModeTest})
	if err != nil {
		cleanup()
		t.Fatalf("构建 docker 适配器失败：%v", err)
	}
	questions := map[string]string{
		"docker.version":        docker.QuestionVersion,
		"docker.info":           docker.QuestionInfo,
		"docker.container.list": docker.QuestionContainerList,
	}
	out := map[string]executor.CapEntry{}
	for name, q := range questions {
		name, q := name, q
		out[name] = executor.CapEntry{Decl: chainReadOnlyDecl(name),
			Run: func(ctx context.Context, _ executor.Request) (executor.Report, error) {
				diag, derr := adapter.Diagnose(ctx, nil, q)
				if derr != nil {
					return executor.Report{}, derr
				}
				return executor.Report{Conclusion: diag.Conclusion, Success: true}, nil
			}}
	}
	return out, cleanup
}

// chainDockerEndpoint 定位本地 Docker 守护进程（unix socket）。
func chainDockerEndpoint(t *testing.T) string {
	t.Helper()
	if host := strings.TrimSpace(os.Getenv("DOCKER_HOST")); host != "" {
		return host
	}
	home, _ := os.UserHomeDir()
	for _, sock := range []string{"/var/run/docker.sock", filepath.Join(home, ".docker/run/docker.sock")} {
		if _, err := os.Stat(sock); err == nil {
			return "unix://" + sock
		}
	}
	t.Skip("Docker 集成测试 skip：未找到 Docker socket。")
	return ""
}

// chainToolPath 定位命令行工具（PATH → ~/go/bin）。
func chainToolPath(t *testing.T, name string) string {
	t.Helper()
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	home, _ := os.UserHomeDir()
	cand := filepath.Join(home, "go", "bin", name)
	if _, err := os.Stat(cand); err == nil {
		return cand
	}
	t.Skipf("未找到 %s（Docker 集成测试 skip）。", name)
	return ""
}

// newChainEnvWithExecutor 在完整链路基础上接线只读诊断执行器（P5）。
func newChainEnvWithExecutor(t *testing.T) (*chainEnv, *executor.Executor, *chainAudit) {
	t.Helper()
	env := newChainEnv(t)
	if env == nil {
		return nil, nil, nil
	}
	ctx := context.Background()

	caps := chainLinuxCaps(t)
	dc, cleanup := chainDockerCaps(t)
	if dc == nil {
		return nil, nil, nil
	}
	for k, v := range dc {
		caps[k] = v
	}
	t.Cleanup(cleanup)

	ex, err := executor.New(executor.Config{
		Pool: env.pool, Caps: caps, Policy: policy.DefaultConfig(),
		Environment: contractv1.Environment_ENVIRONMENT_TEST, Now: env.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ex.EnsureSchema(ctx); err != nil {
		t.Fatalf("执行器建结果表失败：%v", err)
	}
	ast := audit.NewTestStore(env.pool, "test_audit_events_chain_diag")
	if err := ast.EnsureSchema(ctx); err != nil {
		t.Fatalf("审计建表失败：%v", err)
	}
	return env, ex, &chainAudit{st: ast}
}

// TestFullChainAlertToDiagnosisResult（P5）完整链路：
// 告警入站 → outbox → 消费者 → 待诊断请求 → 规划器 → 执行器 → 结果表。
//
// 三个源：
//   - prometheus/critical    → R-001（3 个 linux 只读能力，真实 sshd 容器）
//   - docker-src/critical    → R-005（3 个 docker 只读能力，真实本地 Docker）
//   - test-source-a/warning  → 无匹配规则 → no_rule（执行器不得执行）
//
// 逐步断言行数；结束时断言 run schema 已删除。
func TestFullChainAlertToDiagnosisResult(t *testing.T) {
	// 先注册（后执行）schema 删除断言：testdb 的清理在本断言之前运行。
	var schemaName string
	t.Cleanup(func() {
		if schemaName == "" || t.Failed() {
			return
		}
		base, err := testdb.Resolve()
		if err != nil {
			t.Errorf("解析测试库 DSN 失败：%v", err)
			return
		}
		pool, err := pgxpool.New(context.Background(), base)
		if err != nil {
			t.Errorf("连接测试库失败：%v", err)
			return
		}
		defer pool.Close()
		var n int
		if err := pool.QueryRow(context.Background(),
			`SELECT count(*) FROM pg_namespace WHERE nspname = $1`, schemaName).Scan(&n); err != nil {
			t.Errorf("检查 schema 是否存在失败：%v", err)
			return
		}
		if n != 0 {
			t.Errorf("run schema 未删除：%s", schemaName)
			return
		}
		t.Logf("[P5] run schema 已删除：%s", schemaName)
	})

	env, ex, aud := newChainEnvWithExecutor(t)
	if env == nil || ex == nil {
		return
	}
	schemaName = env.schema.Name()
	ctx := context.Background()
	base := time.Unix(1791825000, 0)

	// 0) 初始：全链路为空。
	if got := env.snapshot(t); got != (counts{}) {
		t.Fatalf("初始应为空：%+v", got)
	}
	if n, err := ex.ResultCount(ctx); err != nil || n != 0 {
		t.Fatalf("初始结果表应为空：n=%d err=%v", n, err)
	}

	// 1) 入站：三条告警 → alerts=3、outbox=3。
	for i, a := range []struct{ source, sev, fp, key string }{
		{"prometheus", "critical", "fp-exec-1", testKeyPrometheus},
		{"docker-src", "critical", "fp-exec-2", testKeyDocker},
		{"test-source-a", "warning", "fp-exec-3", testKeySourceA},
	} {
		code, body := env.postAlert(t, a.source, a.sev, a.fp, a.key, base.Add(time.Duration(i)*time.Minute))
		if code != 202 {
			t.Fatalf("第 %d 条入站应 202，实际 %d（%s）", i+1, code, body)
		}
	}
	got := env.snapshot(t)
	if got.alerts != 3 || got.outbox != 3 {
		t.Fatalf("入站后应 alerts=3 outbox=3，实际 %+v", got)
	}
	t.Logf("[P5] ① 入站：alerts=%d outbox=%d", got.alerts, got.outbox)

	// 2) 消费者：outbox → 待诊断请求。
	if n, err := env.consumer.RunOnce(ctx); err != nil || n != 3 {
		t.Fatalf("消费者应处理 3 条：n=%d err=%v", n, err)
	}
	got = env.snapshot(t)
	if got.requests != 3 || got.outbox != 3 {
		t.Fatalf("消费者后应有 3 条请求：%+v", got)
	}
	if pending, _ := env.consumer.PendingCount(ctx); pending != 0 {
		t.Fatalf("outbox 应已全部消费：pending=%d", pending)
	}
	t.Logf("[P5] ② 消费者：requests=%d（outbox 全部 consumed）", got.requests)

	// 3) 规划器：请求 → 计划（2 条 planned + 1 条 no_rule）。
	if n, err := env.planner.RunOnce(ctx); err != nil || n != 3 {
		t.Fatalf("规划器应生成 3 条计划：n=%d err=%v", n, err)
	}
	plans, err := env.planner.Plans(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var plannedCount, noRuleCount int
	for _, p := range plans {
		switch p.Status {
		case planner.StatusPlanned:
			plannedCount++
		case planner.StatusNoRule:
			noRuleCount++
		}
	}
	if plannedCount != 2 || noRuleCount != 1 {
		t.Fatalf("应有 2 条 planned + 1 条 no_rule，实际 %d + %d：%+v", plannedCount, noRuleCount, plans)
	}
	t.Logf("[P5] ③ 规划器：plans=%d（planned=%d no_rule=%d）", len(plans), plannedCount, noRuleCount)

	// 4) 执行器：只执行 planned 计划（no_rule 不执行）→ 6 条结果，2 条计划 done。
	executed, err := ex.RunOnce(ctx, aud)
	if err != nil {
		t.Fatal(err)
	}
	if executed != 2 {
		t.Fatalf("执行器应执行 2 个计划（no_rule 不执行），实际 %d", executed)
	}
	if n, err := ex.ResultCount(ctx); err != nil || n != 6 {
		t.Fatalf("应有 6 条结果（2×3），实际 %d（err=%v）", n, err)
	}
	t.Logf("[P5] ④ 执行器：executed=%d results=6", executed)

	// 5) 结果逐条核对：按画像分组，全部 ok，摘要非空，无凭据泄漏。
	type row struct{ profile, capability, status, summary, reason string }
	rows, err := env.pool.Query(ctx, `SELECT p.profile, r.capability, r.status, r.output_summary, r.reason
FROM test_diagnosis_results r JOIN test_diagnosis_plans p ON p.id = r.plan_id
ORDER BY p.profile, r.capability`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	byProfile := map[string]int{}
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.profile, &r.capability, &r.status, &r.summary, &r.reason); err != nil {
			t.Fatal(err)
		}
		if r.status != executor.StatusOK {
			t.Fatalf("只读能力应执行成功：%+v", r)
		}
		if strings.TrimSpace(r.summary) == "" {
			t.Fatalf("结果摘要不应为空：%+v", r)
		}
		for _, bad := range []string{testKeyPrometheus, testKeyDocker, testKeySourceA, "AGENT_OPS_ALERT_KEY"} {
			if strings.Contains(r.summary, bad) {
				t.Fatalf("结果不得含凭据：%+v", r)
			}
		}
		byProfile[r.profile]++
	}
	if byProfile["prometheus"] != 3 || byProfile["docker-monitor"] != 3 {
		t.Fatalf("结果应按画像分组为 prometheus=3 docker-monitor=3，实际 %+v", byProfile)
	}
	t.Logf("[P5] ⑤ 结果核对：%+v（全部 ok）", byProfile)

	// 6) 计划终态：2 条 done、1 条 no_rule（no_rule 计划未被触碰）。
	statusCount := map[string]int{}
	srows, err := env.pool.Query(ctx, `SELECT status FROM test_diagnosis_plans ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer srows.Close()
	for srows.Next() {
		var st string
		if err := srows.Scan(&st); err != nil {
			t.Fatal(err)
		}
		statusCount[st]++
	}
	if statusCount[executor.PlanDone] != 2 || statusCount[planner.StatusNoRule] != 1 || len(statusCount) != 2 {
		t.Fatalf("计划终态应为 done×2 + no_rule×1，实际 %+v", statusCount)
	}
	t.Log("[P5] ⑥ 计划终态：planned→done ×2，no_rule 未被触碰 ×1")

	// 7) 幂等复跑：执行器、消费者、规划器均不新增任何行。
	before := env.snapshot(t)
	for i := 0; i < 2; i++ {
		if n, _ := ex.RunOnce(ctx, aud); n != 0 {
			t.Fatalf("复跑执行器不应执行：%d", n)
		}
		if n, _ := env.consumer.RunOnce(ctx); n != 0 {
			t.Fatalf("复跑消费者不应处理：%d", n)
		}
		if n, _ := env.planner.RunOnce(ctx); n != 0 {
			t.Fatalf("复跑规划器不应新增：%d", n)
		}
	}
	if after := env.snapshot(t); after != before {
		t.Fatalf("复跑不得改变行数：%+v → %+v", before, after)
	}
	if n, _ := ex.ResultCount(ctx); n != 6 {
		t.Fatalf("复跑不得新增结果：%d", n)
	}
	t.Logf("[P5] ⑦ 幂等复跑：行数不变（%+v），结果仍为 6 条", before)

	// 8) 审计：6 条 executed（每次执行一条），seq 连续从 1 开始。
	var seqs []int64
	arows, err := env.pool.Query(ctx, `SELECT seq FROM test_audit_events_chain_diag ORDER BY seq`)
	if err != nil {
		t.Fatal(err)
	}
	defer arows.Close()
	for arows.Next() {
		var s int64
		if err := arows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		seqs = append(seqs, s)
	}
	if len(seqs) != 6 {
		t.Fatalf("应有 6 条审计事件，实际 %d（%v）", len(seqs), seqs)
	}
	for i, s := range seqs {
		if s != int64(i+1) {
			t.Fatalf("审计 seq 必须连续：%v", seqs)
		}
	}
	t.Logf("[P5] ⑧ 审计：seq 连续 %v", seqs)
}
