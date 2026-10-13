package executor

import (
	"context"
	"strings"
	"testing"

	contractv1 "github.com/ORG/agent-ops/contract/gen/go/agent_ops/contract/v1"
	"github.com/ORG/agent-ops/internal/policy"
	"github.com/ORG/agent-ops/internal/testdb"
)

// TestExecuteLinuxPlanRealPath（P4 ①）linux 画像的计划通过 **sshd 测试容器**
// 真实执行，结果写入 test_diagnosis_results，计划终态 done。
func TestExecuteLinuxPlanRealPath(t *testing.T) {
	caps := linuxCaps(t)
	ex, aud, rs := newExecEnv(t, caps, policy.DefaultConfig())
	if ex == nil {
		return
	}
	ctx := context.Background()
	planID := planRow(t, rs, 101, "node-exporter",
		[]string{"diagnose.disk_usage", "diagnose.memory_pressure", "diagnose.load_average"}, "planned")

	n, err := ex.RunOnce(ctx, aud)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("应执行 1 个计划，实际 %d", n)
	}
	if st, _ := ex.PlanStatus(ctx, planID); st != PlanDone {
		t.Fatalf("全部成功应为 done，实际 %q", st)
	}
	results, err := ex.Results(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 3 {
		t.Fatalf("应有 3 条结果，实际 %d", len(results))
	}
	for _, r := range results {
		if r.Status != StatusOK {
			t.Fatalf("linux 只读能力应执行成功：%+v", r)
		}
		if r.OutputSummary == "" {
			t.Fatalf("结果摘要不应为空：%+v", r)
		}
	}
	t.Logf("[断言] linux 画像 3 条能力真实执行（sshd 容器）：status=%s，结果行数=%d",
		PlanDone, len(results))
	// 审计：3 条 executed（seq 连续，见专门用例）。
	seq := auditSeq(t, rs, auditTableName(t, rs))
	if len(seq) != 3 {
		t.Fatalf("应有 3 条审计事件，实际 %d（seq=%v）", len(seq), seq)
	}
}

// TestExecuteDockerPlanRealPath（P4 ②）docker-monitor 画像的计划通过
// **本地 Docker 测试容器**真实执行。
func TestExecuteDockerPlanRealPath(t *testing.T) {
	caps, cleanup := dockerCaps(t)
	if caps == nil {
		return
	}
	defer cleanup()
	ex, aud, rs := newExecEnv(t, caps, policy.DefaultConfig())
	if ex == nil {
		return
	}
	ctx := context.Background()
	planID := planRow(t, rs, 102, "docker-monitor",
		[]string{"docker.version", "docker.info", "docker.container.list"}, "planned")

	n, err := ex.RunOnce(ctx, aud)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("应执行 1 个计划，实际 %d", n)
	}
	if st, _ := ex.PlanStatus(ctx, planID); st != PlanDone {
		t.Fatalf("全部成功应为 done，实际 %q", st)
	}
	results, err := ex.Results(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 3 {
		t.Fatalf("应有 3 条结果，实际 %d", len(results))
	}
	// 容器列表结论应包含测试标签容器（真实 Docker 路径）。
	// 注：其他包（如 adapters/docker）可能并行运行并创建同类标签容器，
	// 因此只断言"至少 1 个"，不要求恰好 1 个。
	found := false
	for _, r := range results {
		if r.Status != StatusOK {
			t.Fatalf("docker 只读能力应执行成功：%+v", r)
		}
		if strings.Contains(r.Capability, "container.list") &&
			strings.Contains(r.OutputSummary, "测试标签容器") &&
			!strings.Contains(r.OutputSummary, "测试标签容器 0 个") {
			found = true
		}
	}
	if !found {
		t.Fatalf("容器列表结论应显示至少 1 个测试标签容器：%+v", results)
	}
	t.Logf("[断言] docker-monitor 画像 3 条能力真实执行（本地 Docker）：status=%s", PlanDone)
}

// TestKubernetesCapabilityDeferred 已废弃：第十八轮 K1 起 kubernetes 能力不再
// 记为 deferred，改为与 Linux/Docker 相同的真实执行路径
// （见 kubernetes_test.go 的 TestExecuteKubernetesPlanRealCluster 等用例）。
//
// 本用例保留为**回归断言**：k8s 能力在"已配置集群"时不得再落到 deferred。
func TestKubernetesCapabilityNoLongerDeferred(t *testing.T) {
	calls := 0
	caps := map[string]CapEntry{
		"k8s.version": {Decl: readOnlyDecl("k8s.version"), RequiresCluster: true,
			Run: func(context.Context, Request) (Report, error) {
				calls++
				return Report{Conclusion: "集群版本 v1.test", Success: true}, nil
			}},
	}
	ex, aud, rs := newExecEnvCluster(t, caps, policy.DefaultConfig(), true)
	if ex == nil {
		return
	}
	ctx := context.Background()
	planID := planRow(t, rs, 103, "alertmanager", []string{"k8s.version"}, "planned")

	if _, err := ex.RunOnce(ctx, aud); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("已配置集群时 k8s 能力必须真实执行：calls=%d", calls)
	}
	if st, _ := ex.PlanStatus(ctx, planID); st != PlanDone {
		t.Fatalf("k8s 能力成功后计划终态应为 done（不得再是 deferred），实际 %q", st)
	}
	results, err := ex.Results(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Status != StatusOK {
		t.Fatalf("k8s 能力应写 ok 结果：%+v", results)
	}
	t.Logf("[断言] k8s 能力真实执行（calls=1），计划终态=%s（不再 deferred）", PlanDone)
}

// TestNoClusterConfiguredStatus（K1 ③）未配置集群时状态为 no_cluster_configured，
// 不执行、不发请求、不记为 done。
func TestNoClusterConfiguredStatus(t *testing.T) {
	calls := 0
	caps := map[string]CapEntry{
		"k8s.version": {Decl: readOnlyDecl("k8s.version"), RequiresCluster: true,
			Run: func(context.Context, Request) (Report, error) {
				calls++
				return Report{Conclusion: "不应被调用", Success: true}, nil
			}},
		"k8s.pod.list": {Decl: readOnlyDecl("k8s.pod.list"), RequiresCluster: true,
			Run: func(context.Context, Request) (Report, error) {
				calls++
				return Report{Conclusion: "不应被调用", Success: true}, nil
			}},
	}
	ex, aud, rs := newExecEnvCluster(t, caps, policy.DefaultConfig(), false /* 未配置集群 */)
	if ex == nil {
		return
	}
	ctx := context.Background()
	planID := planRow(t, rs, 110, "alertmanager", []string{"k8s.version", "k8s.pod.list"}, "planned")

	if _, err := ex.RunOnce(ctx, aud); err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatalf("未配置集群时不得调用适配器：calls=%d", calls)
	}
	if st, _ := ex.PlanStatus(ctx, planID); st != PlanNotExecuted {
		t.Fatalf("全部 no_cluster_configured 时计划终态应为 not_executed（不得 done/partial），实际 %q", st)
	}
	results, err := ex.Results(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("应有 2 条结果，实际 %d", len(results))
	}
	for _, r := range results {
		if r.Status != StatusNoClusterConfigured {
			t.Fatalf("状态应为 %s：%+v", StatusNoClusterConfigured, r)
		}
		if !strings.Contains(r.Reason, "未配置集群") {
			t.Fatalf("原因应写明未配置集群：%+v", r)
		}
	}
	// 审计：no_cluster_configured 事件，且计划原因写明不得 done。
	var reason string
	if err := rs.Pool().QueryRow(ctx, `SELECT reason FROM test_diagnosis_plans WHERE id=$1`, planID).Scan(&reason); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(reason, "no_cluster_configured") {
		t.Fatalf("计划原因应写明 no_cluster_configured：%q", reason)
	}
	seq := auditSeq(t, rs, auditTableName(t, rs))
	if len(seq) != 2 {
		t.Fatalf("应有 2 条审计事件，实际 %d", len(seq))
	}
	t.Logf("[断言] 未配置集群：2 条 %s，适配器调用 0 次，计划终态=%s",
		StatusNoClusterConfigured, PlanNotExecuted)
}

// TestReconcileRunningMarksStale（W1 ④ 的对账机制）running 且无终态结果的计划
// 必须能被对账标记为 failed（stale_running）。
func TestReconcileRunningMarksStale(t *testing.T) {
	caps := map[string]CapEntry{
		"diagnose.disk_usage": {Decl: readOnlyDecl("diagnose.disk_usage"),
			Run: func(context.Context, Request) (Report, error) {
				return Report{Conclusion: "ok", Success: true}, nil
			}},
	}
	ex, _, rs := newExecEnv(t, caps, policy.DefaultConfig())
	if ex == nil {
		return
	}
	ctx := context.Background()
	// 人为制造残留：计划处于 running（模拟被强杀），且没有任何结果行。
	planID := planRow(t, rs, 120, "prometheus", []string{"diagnose.disk_usage"}, "running")
	if n, err := ex.StaleRunning(ctx); err != nil || n != 1 {
		t.Fatalf("应识别出 1 条残留：n=%d err=%v", n, err)
	}
	n, err := ex.ReconcileRunning(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("对账应标记 1 条计划，实际 %d", n)
	}
	if st, _ := ex.PlanStatus(ctx, planID); st != PlanFailed {
		t.Fatalf("对账后计划终态应为 failed，实际 %q", st)
	}
	var reason string
	if err := rs.Pool().QueryRow(ctx, `SELECT reason FROM test_diagnosis_plans WHERE id=$1`, planID).Scan(&reason); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(reason, "stale_running") {
		t.Fatalf("对账原因应写明 stale_running：%q", reason)
	}
	if n, _ := ex.StaleRunning(ctx); n != 0 {
		t.Fatalf("对账后不应再有残留：%d", n)
	}
	t.Logf("[断言] 对账把 running 残留标记为 failed（reason=%q）", reason)
}

// TestNonReadOnlyCapabilityDenied（P4 ④）非只读能力即使出现在计划中也记为 denied，
// 且不执行（Run 不被调用）。
func TestNonReadOnlyCapabilityDenied(t *testing.T) {
	calls := 0
	run := func(context.Context, Request) (Report, error) {
		calls++
		return Report{Conclusion: "不应被调用", Success: true}, nil
	}
	caps := map[string]CapEntry{
		// 中风险（非 read_only）：必须 denied。
		"test.unit.write": {Decl: &contractv1.Capability{
			Name: "test.unit.write", RiskTier: contractv1.RiskTier_RISK_TIER_MEDIUM,
			Rollbackable: true, TestOnly: true,
		}, Run: run},
		// 破坏性：必须 denied。
		"test.destroy.disk": {Decl: &contractv1.Capability{
			Name: "test.destroy.disk", RiskTier: contractv1.RiskTier_RISK_TIER_READ_ONLY,
			Destructive: true, TestOnly: true,
		}, Run: run},
		// 未声明能力：fail-closed denied。
	}
	ex, aud, rs := newExecEnv(t, caps, policy.DefaultConfig())
	if ex == nil {
		return
	}
	ctx := context.Background()
	planID := planRow(t, rs, 104, "prometheus",
		[]string{"test.unit.write", "test.destroy.disk", "unknown.capability"}, "planned")

	if _, err := ex.RunOnce(ctx, aud); err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatalf("非只读能力不得被调用：calls=%d", calls)
	}
	if st, _ := ex.PlanStatus(ctx, planID); st != PlanNotExecuted {
		t.Fatalf("全部 denied 的计划终态应为 not_executed（F2：没有任何能力被执行），实际 %q", st)
	}
	results, err := ex.Results(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 3 {
		t.Fatalf("应有 3 条结果，实际 %d", len(results))
	}
	for _, r := range results {
		if r.Status != StatusDenied {
			t.Fatalf("非只读/未声明能力应记为 denied：%+v", r)
		}
	}
	t.Logf("[断言] 非只读与未声明能力均 denied（Run 调用 0 次），计划终态=%s", PlanNotExecuted)
}

// TestCASPreventsDuplicateExecution（P4 ⑤）同一计划重复执行不产生重复结果。
func TestCASPreventsDuplicateExecution(t *testing.T) {
	calls := 0
	caps := map[string]CapEntry{
		"diagnose.disk_usage": {Decl: readOnlyDecl("diagnose.disk_usage"), Run: func(context.Context, Request) (Report, error) {
			calls++
			return Report{Conclusion: "ok", Success: true}, nil
		}},
	}
	ex, aud, rs := newExecEnv(t, caps, policy.DefaultConfig())
	if ex == nil {
		return
	}
	ctx := context.Background()
	planID := planRow(t, rs, 105, "prometheus", []string{"diagnose.disk_usage"}, "planned")

	// 第一次：执行成功（done）。
	if n, err := ex.RunOnce(ctx, aud); err != nil || n != 1 {
		t.Fatalf("首次应执行 1 个计划：n=%d err=%v", n, err)
	}
	before, err := ex.ResultCount(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if before != 1 || calls != 1 {
		t.Fatalf("首次应产生 1 条结果、1 次调用：results=%d calls=%d", before, calls)
	}
	// 后续多次：计划已非 planned（CAS 拒绝）→ 不执行、不新增结果。
	for i := 0; i < 3; i++ {
		n, err := ex.RunOnce(ctx, aud)
		if err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Fatalf("重复执行不得抢占计划：n=%d", n)
		}
	}
	after, err := ex.ResultCount(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("重复执行不得新增结果：%d → %d", before, after)
	}
	if calls != 1 {
		t.Fatalf("重复执行不得再次调用适配器：calls=%d", calls)
	}
	if st, _ := ex.PlanStatus(ctx, planID); st != PlanDone {
		t.Fatalf("计划终态应为 done，实际 %q", st)
	}
	t.Log("[断言] CAS 保证同一计划只执行一次（结果 1 行、调用 1 次）")
}

// TestAuditSeqContiguous（P4 ⑥）每次执行都有对应审计事件，且 seq 连续。
func TestAuditSeqContiguous(t *testing.T) {
	calls := 0
	caps := map[string]CapEntry{
		"diagnose.disk_usage": {Decl: readOnlyDecl("diagnose.disk_usage"), Run: func(context.Context, Request) (Report, error) {
			calls++
			return Report{Conclusion: "ok", Success: true}, nil
		}},
		"test.unit.write": {Decl: &contractv1.Capability{
			Name: "test.unit.write", RiskTier: contractv1.RiskTier_RISK_TIER_MEDIUM, TestOnly: true,
		}, Run: func(context.Context, Request) (Report, error) {
			calls++
			return Report{Conclusion: "不应被调用", Success: true}, nil
		}},
	}
	ex, aud, rs := newExecEnv(t, caps, policy.DefaultConfig())
	if ex == nil {
		return
	}
	ctx := context.Background()
	// 两条计划：一条成功（1 executed）、一条全 denied（1 denied）。
	planRow(t, rs, 106, "prometheus", []string{"diagnose.disk_usage"}, "planned")
	planRow(t, rs, 107, "prometheus", []string{"test.unit.write"}, "planned")

	if _, err := ex.RunOnce(ctx, aud); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("只有只读能力应被调用：calls=%d", calls)
	}
	table := auditTableName(t, rs)
	seq := auditSeq(t, rs, table)
	if len(seq) != 2 {
		t.Fatalf("应有 2 条审计事件（executed + denied），实际 %d（seq=%v）", len(seq), seq)
	}
	for i, s := range seq {
		if s != int64(i+1) {
			t.Fatalf("审计 seq 必须连续从 1 开始：%v", seq)
		}
	}
	// 事件类型与目标。
	rows, err := rs.Pool().Query(ctx, "SELECT action, actor, target FROM "+table+" ORDER BY seq")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var actions []string
	for rows.Next() {
		var action, actor, target string
		if err := rows.Scan(&action, &actor, &target); err != nil {
			t.Fatal(err)
		}
		actions = append(actions, action)
		if actor != "diagnosis-executor" {
			t.Fatalf("审计 actor 应为 diagnosis-executor，实际 %q", actor)
		}
		if !strings.HasPrefix(target, "plan-") {
			t.Fatalf("审计 target 应为 plan-<id>，实际 %q", target)
		}
	}
	if len(actions) != 2 || actions[0] != ActionExecuted || actions[1] != ActionDenied {
		t.Fatalf("审计事件类型不符：%v", actions)
	}
	t.Logf("[断言] 审计 seq 连续（%v），事件类型 %v", seq, actions)

	// 审计 payload 不得含凭据类字段值。
	payloads, err := rs.Pool().Query(ctx, "SELECT payload::text FROM "+table)
	if err != nil {
		t.Fatal(err)
	}
	defer payloads.Close()
	for payloads.Next() {
		var p string
		if err := payloads.Scan(&p); err != nil {
			t.Fatal(err)
		}
		for _, bad := range []string{"test-only-key", "AGENT_OPS_ALERT_KEY", "password="} {
			if strings.Contains(p, bad) {
				t.Fatalf("审计 payload 不得含凭据：%s", p)
			}
		}
	}
}

// auditTableName 返回本次 run schema 中唯一的审计表名。
func auditTableName(t *testing.T, rs *testdb.RunSchema) string {
	t.Helper()
	var name string
	if err := rs.Pool().QueryRow(context.Background(),
		`SELECT tablename FROM pg_tables WHERE schemaname = current_schema() AND tablename LIKE 'test_audit_events_diag_%' LIMIT 1`).Scan(&name); err != nil {
		t.Fatal(err)
	}
	return name
}
