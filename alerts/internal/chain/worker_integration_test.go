// W2 集成测试（第十八轮）：真实 HTTP + 真实 PG + 真实 kind 集群 + 真实 sshd 容器 +
// 真实本地 Docker + 测试模式 worker。
//
// 链路：HTTP 入站告警 → outbox → 消费者 → 待诊断请求 → 规划器 → 执行器 → 结果表，
// 由 worker 驱动（有界迭代，测试钩子控制轮数），覆盖三类画像：
//
//	prometheus（Linux）/ docker-monitor（Docker）/ alertmanager（Kubernetes）。
//
// 结束后残留检查：test_run_* schema 为 0、kind 集群为 0、测试容器为 0。
package chain

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/XZ-libin/agent-ops/adapters/docker"
	"github.com/XZ-libin/agent-ops/alerts/internal/diagcaps"
	"github.com/XZ-libin/agent-ops/alerts/internal/executor"
	"github.com/XZ-libin/agent-ops/alerts/internal/worker"
	contractv1 "github.com/XZ-libin/agent-ops/contract/gen/go/agent_ops/contract/v1"
	"github.com/XZ-libin/agent-ops/internal/audit"
	"github.com/XZ-libin/agent-ops/internal/exec/ssh"
	"github.com/XZ-libin/agent-ops/internal/exec/ssh/sshdtest"
	"github.com/XZ-libin/agent-ops/internal/k8stest"
	"github.com/XZ-libin/agent-ops/internal/policy"
	"github.com/XZ-libin/agent-ops/internal/testdb"
)

// chainWorkerEnv W2 的完整环境（含 worker 所需组件）。
type chainWorkerEnv struct {
	*chainEnv
	ex     *executor.Executor
	sink   executor.AuditSink
	auditT string
	// ownedCluster 本用例自建（需删除）的 kind 集群名；空表示复用外部集群。
	ownedCluster string
	// containerName 本用例自建的测试容器名（需删除）。
	containerName string
}

// newWorker 构建一个 worker（有界迭代；Sleep 为测试钩子，不真实等待）。
func (e *chainWorkerEnv) newWorker(t *testing.T, maxIter int) *worker.Worker {
	t.Helper()
	wk, err := worker.New(worker.Config{
		Pool: e.pool, Consumer: e.consumer, Planner: e.planner, Executor: e.ex,
		AuditSink: e.sink, MaxIterations: maxIter,
		Sleep: func(context.Context, time.Duration) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	return wk
}

// dockerSocketEndpoint 定位本地 Docker 守护进程（unix socket）。
func dockerSocketEndpoint(t *testing.T) string {
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

// dockerToolPath 定位 docker CLI（argv 调用）。
func dockerToolPath(t *testing.T) string {
	t.Helper()
	if p, err := exec.LookPath("docker"); err == nil {
		return p
	}
	home, _ := os.UserHomeDir()
	cand := filepath.Join(home, "go", "bin", "docker")
	if _, err := os.Stat(cand); err == nil {
		return cand
	}
	t.Skip("Docker 集成测试 skip：未找到 docker CLI。")
	return ""
}

// startLabelledContainer 启动一个带测试标签的容器（真实 Docker 路径）。
func startLabelledContainer(t *testing.T) string {
	t.Helper()
	bin := dockerToolPath(t)
	name := fmt.Sprintf("agent-ops-chainw2-%d", time.Now().UnixNano())
	if out, err := exec.Command(bin, "run", "-d", "--name", name,
		"--label", docker.TestLabel+"=true", "busybox:1.36", "sleep", "300").CombinedOutput(); err != nil {
		t.Skipf("Docker 集成测试 skip：无法启动测试容器（%v，输出 %q）。", err, strings.TrimSpace(string(out)))
	}
	t.Cleanup(func() { _ = exec.Command(bin, "rm", "-f", name).Run() })
	t.Logf("[W2] 已启动测试容器：%s（label=%s=true）", name, docker.TestLabel)
	return name
}

// newChainWorkerEnv 建立 W2 环境：真实 HTTP + PG（独立 run schema）+ kind + sshd + Docker。
func newChainWorkerEnv(t *testing.T) *chainWorkerEnv {
	t.Helper()
	env := newChainEnv(t)
	if env == nil {
		return nil
	}
	ctx := context.Background()

	// —— 真实 sshd 容器（Linux 画像）——
	sshd := sshdtest.StartLocalSSHD(t)
	runner, err := ssh.New(ssh.Options{Addr: sshd.Addr, User: sshd.User, Signer: sshd.Signer, HostKey: sshd.HostKey})
	if err != nil {
		t.Fatalf("构建 SSH Runner 失败：%v", err)
	}
	t.Cleanup(func() { _ = runner.Close() })

	// —— 真实本地 Docker（docker-monitor 画像）——
	dockerEndpoint := dockerSocketEndpoint(t)
	containerName := startLabelledContainer(t)

	// —— 真实 kind 集群（alertmanager 画像）——
	cluster := k8stest.Start(t)
	if cluster == nil {
		return nil
	}
	ownedCluster := ""
	if cluster.Owned {
		ownedCluster = cluster.Name
	}
	ns := fmt.Sprintf("%s%d", k8stest.NamespacePrefix, time.Now().UnixNano())
	cluster.CreatePodFixture(t, ns, "itest-pod")
	cluster.WaitPodRunning(t, ns, "itest-pod")

	caps, err := diagcaps.Build(diagcaps.Config{
		AssetID: "ast_chain_w2", SSHRunner: runner,
		DockerEndpoint: dockerEndpoint, KubeconfigPath: cluster.KubeconfigPath, K8sNamespace: ns,
	})
	if err != nil {
		t.Fatalf("只读能力接线失败：%v", err)
	}
	if caps.Close != nil {
		t.Cleanup(caps.Close)
	}

	ex, err := executor.New(executor.Config{
		Pool: env.pool, Caps: caps.Caps, Policy: policy.DefaultConfig(),
		Environment: contractv1.Environment_ENVIRONMENT_TEST, Now: env.now,
		ClusterConfigured: caps.ClusterConfigured,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ex.EnsureSchema(ctx); err != nil {
		t.Fatalf("结果表建表失败：%v", err)
	}
	ast := audit.NewTestStore(env.pool, "test_audit_events_chain_w2")
	if err := ast.EnsureSchema(ctx); err != nil {
		t.Fatalf("审计表建表失败：%v", err)
	}
	return &chainWorkerEnv{chainEnv: env, ex: ex,
		sink: worker.NewAuditAdapter(ast), auditT: "test_audit_events_chain_w2",
		ownedCluster: ownedCluster, containerName: containerName}
}

// TestW2FullChainWithWorkerAcrossThreeProfiles（W2）三类画像的端到端链路：
// HTTP 入站 → outbox → 消费者 → 请求 → 规划器 → 执行器 → 结果表，由 worker 驱动。
func TestW2FullChainWithWorkerAcrossThreeProfiles(t *testing.T) {
	// 先登记本用例自有资源的清理核对（LIFO：在 k8stest / 容器 / testdb 的清理
	// 之后执行）。只核对自己创建的资源；**全局**残留检查由
	// internal/k8stest 的 TestNoLeftoversAfterSuite 在整套测试结束后单独执行
	// （`go test ./...` 的并行包会让全局断言误报）。
	var schemaName, ownedCluster, containerName string
	t.Cleanup(func() {
		if t.Failed() {
			return
		}
		if schemaName != "" {
			assertSchemaDeleted(t, schemaName)
		}
		if ownedCluster != "" {
			k8stest.AssertClusterDeleted(t, ownedCluster)
		}
		if containerName != "" {
			assertContainerDeleted(t, containerName)
		}
	})

	env := newChainWorkerEnv(t)
	if env == nil {
		return
	}
	schemaName = env.schema.Name()
	ownedCluster = env.ownedCluster
	containerName = env.containerName
	ctx := context.Background()
	base := time.Unix(1791825000, 0)

	// 1) HTTP 入站三条告警（三类画像各一），走真实 HMAC 签名。
	posts := []struct{ source, fp, key string }{
		{"prometheus", "fp-w2-1", testKeyPrometheus},
		{"docker-src", "fp-w2-2", testKeyDocker},
		{"k8s-src", "fp-w2-3", testKeyK8s},
	}
	for i, p := range posts {
		code, body := env.postAlert(t, p.source, "critical", p.fp, p.key, base.Add(time.Duration(i)*time.Minute))
		if code != 202 {
			t.Fatalf("第 %d 条入站应 202，实际 %d（%s）", i+1, code, body)
		}
	}
	got := env.snapshot(t)
	if got.alerts != 3 || got.outbox != 3 {
		t.Fatalf("入站后应 alerts=3 outbox=3，实际 %+v", got)
	}
	t.Logf("[W2] ① 入站：alerts=%d outbox=%d（prometheus / docker-src / k8s-src）", got.alerts, got.outbox)

	// 2) worker 一轮推进：consumer → planner → executor。
	wk := env.newWorker(t, 1)
	if err := wk.Run(ctx); err != nil {
		t.Fatalf("worker 运行失败：%v", err)
	}
	stats := wk.Stats()
	if len(stats) != 1 {
		t.Fatalf("应有 1 轮统计，实际 %d", len(stats))
	}
	if stats[0].Consumer != 3 || stats[0].Planner != 3 || stats[0].Executor != 3 {
		t.Fatalf("一轮内三个阶段应各推进 3 条：%+v", stats[0])
	}
	t.Logf("[W2] ② worker 一轮：consumer=%d planner=%d executor=%d",
		stats[0].Consumer, stats[0].Planner, stats[0].Executor)

	// 3) 各表行数。
	got = env.snapshot(t)
	if got.requests != 3 || got.plans != 3 {
		t.Fatalf("应有 requests=3 plans=3，实际 %+v", got)
	}
	results, err := env.ex.Results(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 9 {
		t.Fatalf("应有 9 条结果（3 计划 × 3 能力），实际 %d：%+v", len(results), results)
	}
	t.Logf("[W2] ③ 行数：alerts=%d outbox=%d requests=%d plans=%d results=%d",
		got.alerts, got.outbox, got.requests, got.plans, len(results))

	// 4) 结果按画像分组核对（三类画像各 3 条，全部 ok，无凭据/敏感值）。
	byProfile := map[string]int{}
	rows, err := env.pool.Query(ctx, `SELECT p.profile, r.capability, r.status, r.output_summary, r.reason
FROM test_diagnosis_results r JOIN test_diagnosis_plans p ON p.id = r.plan_id
ORDER BY p.profile, r.capability`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var profile, capability, status, summary, reason string
		if err := rows.Scan(&profile, &capability, &status, &summary, &reason); err != nil {
			t.Fatal(err)
		}
		if status != executor.StatusOK {
			t.Fatalf("只读能力应执行成功：profile=%s capability=%s status=%s reason=%s",
				profile, capability, status, reason)
		}
		if strings.TrimSpace(summary) == "" {
			t.Fatalf("结果摘要不应为空：profile=%s capability=%s", profile, capability)
		}
		for _, bad := range []string{testKeyPrometheus, testKeyDocker, testKeySourceA, testKeyK8s,
			"must-not-leak", "must-not-leak-annotation", "AGENT_OPS_ALERT_KEY"} {
			if strings.Contains(summary, bad) {
				t.Fatalf("结果不得含凭据/敏感值 %q：profile=%s capability=%s summary=%s",
					bad, profile, capability, summary)
			}
		}
		byProfile[profile]++
	}
	want := map[string]int{"prometheus": 3, "docker-monitor": 3, "alertmanager": 3}
	for p, n := range want {
		if byProfile[p] != n {
			t.Fatalf("画像 %s 应有 %d 条结果，实际 %d（全部 %+v）", p, n, byProfile[p], byProfile)
		}
	}
	t.Logf("[W2] ④ 结果按画像分组：%+v（全部 ok）", byProfile)

	// 5) 计划终态全部 done。
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
	if statusCount[executor.PlanDone] != 3 || len(statusCount) != 1 {
		t.Fatalf("3 个计划应全部 done，实际 %+v", statusCount)
	}
	t.Log("[W2] ⑤ 计划终态：done ×3")

	// 6) 审计 seq 连续（9 次能力执行 → 9 条）。
	seqs := auditSeqsOf(t, env.pool, env.auditT)
	if len(seqs) != 9 {
		t.Fatalf("应有 9 条审计事件，实际 %d（%v）", len(seqs), seqs)
	}
	for i, s := range seqs {
		if s != int64(i+1) {
			t.Fatalf("审计 seq 必须连续从 1 开始：%v", seqs)
		}
	}
	t.Logf("[W2] ⑥ 审计 seq 连续：%v", seqs)

	// 7) 幂等复跑：不新增任何行；无 running 残留。
	before := env.snapshot(t)
	for i := 0; i < 2; i++ {
		if err := env.newWorker(t, 1).Run(ctx); err != nil {
			t.Fatalf("复跑 worker 失败：%v", err)
		}
	}
	if after := env.snapshot(t); after != before {
		t.Fatalf("复跑不得改变行数：%+v → %+v", before, after)
	}
	if n, _ := env.ex.ResultCount(ctx); n != 9 {
		t.Fatalf("复跑不得新增结果：%d", n)
	}
	if n, _ := env.ex.StaleRunning(ctx); n != 0 {
		t.Fatalf("停止后不得残留 running 计划：%d", n)
	}
	t.Logf("[W2] ⑦ 幂等复跑：行数不变（%+v），无 running 残留", before)
}

// assertSchemaDeleted 断言 run schema 已被删除（用独立连接查询 pg_namespace）。
func assertSchemaDeleted(t *testing.T, name string) {
	t.Helper()
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
		`SELECT count(*) FROM pg_namespace WHERE nspname = $1`, name).Scan(&n); err != nil {
		t.Errorf("检查 schema 是否存在失败：%v", err)
		return
	}
	if n != 0 {
		t.Errorf("run schema 未删除：%s", name)
		return
	}
	t.Logf("[W2] ① run schema 已删除：%s", name)
}

// auditSeqsOf 返回审计表 seq（升序）。
func auditSeqsOf(t *testing.T, pool *pgxpool.Pool, table string) []int64 {
	t.Helper()
	rows, err := pool.Query(context.Background(), fmt.Sprintf(`SELECT seq FROM %s ORDER BY seq`, table))
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var s int64
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	return out
}

// assertContainerDeleted 断言本用例自建的测试容器已被删除。
func assertContainerDeleted(t *testing.T, name string) {
	t.Helper()
	bin := dockerToolPath(t)
	out, err := exec.Command(bin, "ps", "-a", "--filter", "name=^"+name+"$",
		"--format", "{{.Names}}").CombinedOutput()
	if err != nil {
		t.Errorf("检查测试容器失败：%v（输出 %q）", err, strings.TrimSpace(string(out)))
		return
	}
	if names := strings.TrimSpace(string(out)); names != "" {
		t.Errorf("自建测试容器未被删除：%q", names)
		return
	}
	t.Logf("[W2] ③ 自建测试容器已删除：%s", name)
}
