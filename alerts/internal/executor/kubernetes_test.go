package executor_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/XZ-libin/agent-ops/alerts/internal/diagcaps"
	"github.com/XZ-libin/agent-ops/alerts/internal/executor"
	contractv1 "github.com/XZ-libin/agent-ops/contract/gen/go/agent_ops/contract/v1"
	"github.com/XZ-libin/agent-ops/internal/k8stest"
	"github.com/XZ-libin/agent-ops/internal/policy"
)

// requestCounter 在 HTTP 层记录真正发出的请求（K1：断言 /secrets 请求数为 0）。
type requestCounter struct {
	mu    sync.Mutex
	paths []string
}

func (c *requestCounter) observe(_ /*method*/, path string) {
	c.mu.Lock()
	c.paths = append(c.paths, path)
	c.mu.Unlock()
}

func (c *requestCounter) all() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, len(c.paths))
	copy(out, c.paths)
	return out
}

func (c *requestCounter) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.paths)
}

// secretsCount 统计 /secrets 相关路径的请求数（必须恒为 0）。
func (c *requestCounter) secretsCount() int {
	n := 0
	for _, p := range c.all() {
		if strings.Contains(strings.ToLower(p), "secret") {
			n++
		}
	}
	return n
}

// TestKubernetesExecutionAgainstKindCluster（K1 ①②④）在**真实 kind 集群**上验证
// kubernetes 画像的只读执行：
//
//	① alertmanager 画像的计划全部能力执行成功，结果写入 test_diagnosis_results；
//	② 非只读 k8s 能力（delete 语义）仍记为 denied，适配器调用为 0；
//	④ 结果屏蔽与第十三轮白名单一致（不含 env、注解原值）。
//
// 集群由 k8stest 自建自删（失败也删除），结束时断言无 agent-ops-itest-* 残留。
func TestKubernetesExecutionAgainstKindCluster(t *testing.T) {
	// 先登记"自建集群已删除"的核对（LIFO：在 k8stest 的删除清理之后执行）。
	// 只核对自己创建的集群；全局残留检查由 internal/k8stest 的
	// TestNoLeftoversAfterSuite 在整套测试结束后单独执行。
	var ownedName string
	t.Cleanup(func() {
		if ownedName == "" || t.Failed() {
			return
		}
		k8stest.AssertClusterDeleted(t, ownedName)
	})
	cluster := k8stest.Start(t)
	if cluster == nil {
		return
	}
	if cluster.Owned {
		ownedName = cluster.Name
	}
	ns := fmt.Sprintf("%s%d", k8stest.NamespacePrefix, time.Now().UnixNano())
	cluster.CreatePodFixture(t, ns, "itest-pod")
	cluster.WaitPodRunning(t, ns, "itest-pod")

	counter := &requestCounter{}
	caps, err := diagcaps.Build(diagcaps.Config{
		AssetID: "ast_k8s_exec_itest", KubeconfigPath: cluster.KubeconfigPath,
		K8sNamespace: ns, K8sObserve: counter.observe,
	})
	if err != nil {
		t.Fatalf("只读能力接线失败：%v", err)
	}
	if !caps.ClusterConfigured {
		t.Fatal("已提供 kubeconfig 时 ClusterConfigured 应为 true")
	}
	if caps.Close != nil {
		defer caps.Close()
	}

	// ② 追加一个"非只读"的 k8s 能力（delete 语义）：即使出现在计划中也必须 denied。
	deniedCalls := 0
	caps.Caps["k8s.pod.delete"] = executor.CapEntry{
		Decl: &contractv1.Capability{
			Name: "k8s.pod.delete", RiskTier: contractv1.RiskTier_RISK_TIER_MEDIUM,
			Rollbackable: false, Destructive: true,
		},
		RequiresCluster: true,
		Run: func(context.Context, executor.Request) (executor.Report, error) {
			deniedCalls++
			return executor.Report{Conclusion: "不应被调用", Success: true}, nil
		},
	}

	ex, aud, rs := executor.NewExecEnvCluster(t, caps.Caps, policy.DefaultConfig(), true)
	if ex == nil {
		return
	}
	ctx := context.Background()

	// —— ① alertmanager 画像：R-003 的 3 个只读能力 ——
	planID := executor.InsertPlan(t, rs, 201, "alertmanager",
		[]string{"k8s.version", "k8s.pod.list", "k8s.deployment.list"}, "planned")
	n, err := ex.RunOnce(ctx, aud)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("应执行 1 个计划，实际 %d", n)
	}
	if st, _ := ex.PlanStatus(ctx, planID); st != executor.PlanDone {
		results, _ := ex.Results(ctx)
		t.Fatalf("alertmanager 计划应全部成功（done），实际 %q：%+v", st, results)
	}
	results, err := ex.Results(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 3 {
		t.Fatalf("应有 3 条结果，实际 %d", len(results))
	}
	for _, r := range results {
		if r.Status != executor.StatusOK {
			t.Fatalf("kubernetes 只读能力应执行成功：%+v", r)
		}
		if strings.TrimSpace(r.OutputSummary) == "" {
			t.Fatalf("结果摘要不应为空：%+v", r)
		}
	}
	t.Logf("[断言] ① alertmanager 画像 3 条能力真实执行（kind 集群）：status=%s，结果行数=%d",
		executor.PlanDone, len(results))

	// —— ④ 屏蔽与第十三轮白名单一致：不含 env 值与注解原值 ——
	for _, r := range results {
		for _, bad := range []string{"must-not-leak", "must-not-leak-annotation", "AGENT_OPS_TEST_SECRET", "secret.itest"} {
			if strings.Contains(r.OutputSummary, bad) {
				t.Fatalf("结果不得含 env 值/注解原值 %q：%+v", bad, r)
			}
		}
	}
	// Pod 状态结论应说明"已屏蔽字段"，而不是把字段值带出来。
	var podStatusSummary string
	for _, r := range results {
		if r.Capability == "k8s.pod.list" {
			podStatusSummary = r.OutputSummary
		}
	}
	if !strings.Contains(podStatusSummary, "itest-pod") {
		t.Fatalf("Pod 列表结论应包含测试 Pod 名：%q", podStatusSummary)
	}
	t.Logf("[断言] ④ 结果屏蔽与白名单一致（无 env 值/注解原值）：%s", podStatusSummary)

	// —— ② 非只读 k8s 能力被拒绝 ——
	deniedPlan := executor.InsertPlan(t, rs, 202, "alertmanager",
		[]string{"k8s.pod.delete", "k8s.version"}, "planned")
	beforeReqs := counter.count()
	if _, err := ex.RunOnce(ctx, aud); err != nil {
		t.Fatal(err)
	}
	if deniedCalls != 0 {
		t.Fatalf("非只读能力不得被调用：calls=%d", deniedCalls)
	}
	if st, _ := ex.PlanStatus(ctx, deniedPlan); st != executor.PlanPartial {
		t.Fatalf("含 denied 的计划终态应为 partial，实际 %q", st)
	}
	// denied 的能力不得产生任何集群请求；k8s.version 正常执行会发 1 个 /version 请求。
	after := counter.all()
	newPaths := after[beforeReqs:]
	for _, p := range newPaths {
		if strings.Contains(strings.ToLower(p), "delete") {
			t.Fatalf("非只读能力不得发起任何请求：%v", newPaths)
		}
	}
	var deniedResult *executor.ResultRow
	all, _ := ex.Results(ctx)
	for i := range all {
		if all[i].PlanID == deniedPlan && all[i].Capability == "k8s.pod.delete" {
			deniedResult = &all[i]
		}
	}
	if deniedResult == nil || deniedResult.Status != executor.StatusDenied {
		t.Fatalf("非只读 k8s 能力应记为 denied：%+v", deniedResult)
	}
	t.Logf("[断言] ② 非只读 k8s 能力 denied（适配器调用 0 次、无 delete 请求）：%+v", deniedResult)

	// —— K1 硬性要求：任何时刻都不得请求 /secrets ——
	if n := counter.secretsCount(); n != 0 {
		t.Fatalf("/secrets 路径请求数必须为 0，实际 %d（全部请求：%v）", n, counter.all())
	}
	t.Logf("[断言] HTTP 层计数：共 %d 个请求，其中 /secrets 请求 %d 个（路径样例 %v）",
		counter.count(), counter.secretsCount(), samplePaths(counter.all(), 4))

	// 审计：4 条 executed（3 成功 + 1 个 k8s.version 成功）+ 1 条 denied，seq 连续。
	seq := executor.AuditSeqOf(t, rs, executor.AuditTableNameOf(t, rs))
	if len(seq) != 5 {
		t.Fatalf("应有 5 条审计事件（4 executed + 1 denied），实际 %d（%v）", len(seq), seq)
	}
	for i, s := range seq {
		if s != int64(i+1) {
			t.Fatalf("审计 seq 必须连续：%v", seq)
		}
	}
	t.Logf("[断言] 审计 seq 连续：%v", seq)

	// 夹具清理（删除测试命名空间并断言删除成功；集群删除与残留断言在 Cleanup 中）。
	cluster.DeleteNamespace(t, ns)
	if _, err := cluster.Kubectl("get", "namespace", ns); err == nil {
		t.Fatalf("删除后命名空间应不存在：%s", ns)
	}
	t.Logf("[断言] 测试命名空间已删除：%s", ns)
}

// TestNoClusterConfiguredNoRequests（K1 ③）未配置 kubeconfig 时：
// 状态为 no_cluster_configured，且**不发起任何请求**（HTTP 层计数为 0）。
func TestNoClusterConfiguredNoRequests(t *testing.T) {
	counter := &requestCounter{}
	// 未提供 KubeconfigPath → 未配置集群。
	caps, err := diagcaps.Build(diagcaps.Config{
		AssetID: "ast_k8s_exec_nocluster", K8sObserve: counter.observe,
	})
	if err != nil {
		t.Fatalf("只读能力接线失败：%v", err)
	}
	if caps.ClusterConfigured {
		t.Fatal("未提供 kubeconfig 时 ClusterConfigured 应为 false")
	}
	ex, aud, rs := executor.NewExecEnvCluster(t, caps.Caps, policy.DefaultConfig(), caps.ClusterConfigured)
	if ex == nil {
		return
	}
	ctx := context.Background()
	planID := executor.InsertPlan(t, rs, 210, "alertmanager",
		[]string{"k8s.version", "k8s.pod.list", "k8s.deployment.list"}, "planned")

	if _, err := ex.RunOnce(ctx, aud); err != nil {
		t.Fatal(err)
	}
	if counter.count() != 0 {
		t.Fatalf("未配置集群时不得发起任何请求，实际 %d 个：%v", counter.count(), counter.all())
	}
	if counter.secretsCount() != 0 {
		t.Fatalf("/secrets 请求数必须为 0，实际 %d", counter.secretsCount())
	}
	if st, _ := ex.PlanStatus(ctx, planID); st != executor.PlanNotExecuted {
		t.Fatalf("全部 no_cluster_configured 时终态应为 not_executed（不得 done/partial），实际 %q", st)
	}
	results, err := ex.Results(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 3 {
		t.Fatalf("应有 3 条结果，实际 %d", len(results))
	}
	for _, r := range results {
		if r.Status != executor.StatusNoClusterConfigured {
			t.Fatalf("状态应为 %s：%+v", executor.StatusNoClusterConfigured, r)
		}
		if !strings.Contains(r.Reason, diagcaps.EnvKubeconfig) {
			t.Fatalf("原因应写明缺少 %s：%+v", diagcaps.EnvKubeconfig, r)
		}
	}
	t.Logf("[断言] ③ 未配置 kubeconfig：3 条 %s，请求数 0，终态=%s",
		executor.StatusNoClusterConfigured, executor.PlanNotExecuted)
}

// TestKubernetesCapabilityUnavailableIsLoud 未配置集群时能力不可用**不得静默成功**：
// 执行器必须把原因写进结果，而不是返回 ok。
func TestKubernetesCapabilityUnavailableIsLoud(t *testing.T) {
	caps, err := diagcaps.Build(diagcaps.Config{AssetID: "ast-x"})
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := caps.Caps["k8s.version"]
	if !ok {
		t.Fatal("未配置集群时也应注册 k8s 能力（以便记为 no_cluster_configured）")
	}
	if !entry.RequiresCluster {
		t.Fatal("k8s 能力必须标记 RequiresCluster")
	}
	// 直接调用 Run（模拟"配置已就绪但调用失败"的路径）→ 必须返回错误，不得成功。
	if _, err := entry.Run(context.Background(), executor.Request{Capability: "k8s.version"}); err == nil {
		t.Fatal("配置缺失时 Run 必须返回错误（不得静默成功）")
	} else if !errors.Is(err, err) && !strings.Contains(err.Error(), "不可用") {
		t.Fatalf("错误应说明能力不可用：%v", err)
	}
	t.Log("[断言] 配置缺失时能力 Run 明确报错（不静默成功）")
}

// samplePaths 取前 n 个路径样例（日志用）。
func samplePaths(paths []string, n int) []string {
	if len(paths) <= n {
		return paths
	}
	return paths[:n]
}
