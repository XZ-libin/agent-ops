package executor

import (
	"context"
	"strings"
	"testing"

	contractv1 "github.com/XZ-libin/agent-ops/contract/gen/go/agent_ops/contract/v1"
	"github.com/XZ-libin/agent-ops/internal/policy"
)

// TestTerminalStateMapping（F2）计划终态的完整映射：
//
//	①全部 no_cluster_configured（集群未配置）        → not_executed
//	②一个能力成功、一个 denied                       → partial
//	③全部成功                                        → done
//	④全部 denied                                     → not_executed
//	⑤一个成功、一个失败                              → failed
//
// 用例通过真实执行器 + 真实 PG 驱动，断言计划终态与 reason 首要原因。
func TestTerminalStateMapping(t *testing.T) {
	cases := []struct {
		name        string
		caps        []string
		cluster     bool
		wantStatus  string
		wantReason  string
		wantCalls   int
		resultStats map[string]int // 结果状态 → 条数
	}{
		{
			name: "①集群未配置全部 no_cluster_configured", caps: []string{"k8s.version", "k8s.pod.list"},
			cluster: false, wantStatus: PlanNotExecuted, wantReason: "no_cluster_configured", wantCalls: 0,
			resultStats: map[string]int{StatusNoClusterConfigured: 2},
		},
		{
			name: "②一个成功一个 denied", caps: []string{"diagnose.disk_usage", "test.unit.write"},
			cluster: false, wantStatus: PlanPartial, wantReason: "部分完成", wantCalls: 1,
			resultStats: map[string]int{StatusOK: 1, StatusDenied: 1},
		},
		{
			name: "③全部成功", caps: []string{"diagnose.disk_usage", "diagnose.load_average"},
			cluster: false, wantStatus: PlanDone, wantReason: "", wantCalls: 2,
			resultStats: map[string]int{StatusOK: 2},
		},
		{
			name: "④全部 denied", caps: []string{"test.unit.write", "test.destroy.disk", "unknown.capability"},
			cluster: false, wantStatus: PlanNotExecuted, wantReason: "被拒绝", wantCalls: 0,
			resultStats: map[string]int{StatusDenied: 3},
		},
		{
			name: "⑤一个成功一个失败", caps: []string{"diagnose.disk_usage", "diagnose.boom"},
			cluster: false, wantStatus: PlanFailed, wantReason: "执行失败", wantCalls: 2,
			resultStats: map[string]int{StatusOK: 1, StatusFailed: 1},
		},
	}

	for i, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			caps := map[string]CapEntry{
				// 只读且可执行。
				"diagnose.disk_usage": {Decl: readOnlyDecl("diagnose.disk_usage"),
					Run: func(context.Context, Request) (Report, error) {
						calls++
						return Report{Conclusion: "ok", Success: true}, nil
					}},
				"diagnose.load_average": {Decl: readOnlyDecl("diagnose.load_average"),
					Run: func(context.Context, Request) (Report, error) {
						calls++
						return Report{Conclusion: "ok", Success: true}, nil
					}},
				// 只读但执行失败。
				"diagnose.boom": {Decl: readOnlyDecl("diagnose.boom"),
					Run: func(context.Context, Request) (Report, error) {
						calls++
						return Report{Conclusion: "", Success: false}, nil
					}},
				// 非只读（必须 denied）。
				"test.unit.write": {Decl: &contractv1.Capability{
					Name: "test.unit.write", RiskTier: contractv1.RiskTier_RISK_TIER_MEDIUM,
					TestOnly: true,
				}, Run: func(context.Context, Request) (Report, error) {
					calls++
					return Report{Conclusion: "不应被调用", Success: true}, nil
				}},
				"test.destroy.disk": {Decl: &contractv1.Capability{
					Name: "test.destroy.disk", RiskTier: contractv1.RiskTier_RISK_TIER_READ_ONLY,
					Destructive: true, TestOnly: true,
				}, Run: func(context.Context, Request) (Report, error) {
					calls++
					return Report{Conclusion: "不应被调用", Success: true}, nil
				}},
				// 需要集群（未配置 → no_cluster_configured）。
				"k8s.version": {Decl: readOnlyDecl("k8s.version"), RequiresCluster: true,
					Run: func(context.Context, Request) (Report, error) {
						calls++
						return Report{Conclusion: "ok", Success: true}, nil
					}},
				"k8s.pod.list": {Decl: readOnlyDecl("k8s.pod.list"), RequiresCluster: true,
					Run: func(context.Context, Request) (Report, error) {
						calls++
						return Report{Conclusion: "ok", Success: true}, nil
					}},
				// unknown.capability 故意不注册（fail-closed denied）。
			}
			ex, aud, rs := newExecEnvCluster(t, caps, policy.DefaultConfig(), tc.cluster)
			if ex == nil {
				return
			}
			ctx := context.Background()
			planID := planRow(t, rs, int64(300+i), "prometheus", tc.caps, "planned")

			if _, err := ex.RunOnce(ctx, aud); err != nil {
				t.Fatal(err)
			}
			if calls != tc.wantCalls {
				t.Fatalf("适配器调用次数应为 %d，实际 %d", tc.wantCalls, calls)
			}
			got, err := ex.PlanStatus(ctx, planID)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.wantStatus {
				t.Fatalf("计划终态应为 %q，实际 %q", tc.wantStatus, got)
			}
			var reason string
			if err := rs.Pool().QueryRow(ctx,
				`SELECT reason FROM test_diagnosis_plans WHERE id=$1`, planID).Scan(&reason); err != nil {
				t.Fatal(err)
			}
			if tc.wantReason != "" && !strings.Contains(reason, tc.wantReason) {
				t.Fatalf("reason 应包含 %q，实际 %q", tc.wantReason, reason)
			}
			if tc.wantReason == "" && reason != "" {
				t.Fatalf("done 的 reason 应为空，实际 %q", reason)
			}
			// 结果状态分布。
			stats := map[string]int{}
			results, err := ex.Results(ctx)
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range results {
				stats[r.Status]++
			}
			for k, v := range tc.resultStats {
				if stats[k] != v {
					t.Fatalf("结果状态 %s 应为 %d 条，实际 %d（全部 %v）", k, v, stats[k], stats)
				}
			}
			t.Logf("[断言] %s → 终态=%s（reason=%q，调用=%d，结果=%v）", tc.name, got, reason, calls, stats)
		})
	}
}

// TestNotExecutedNeverDoneOrPartial（F2）回归守卫：
// 一个能力都没执行时，终态**既不能是 done 也不能是 partial**。
func TestNotExecutedNeverDoneOrPartial(t *testing.T) {
	caps := map[string]CapEntry{
		"test.unit.write": {Decl: &contractv1.Capability{
			Name: "test.unit.write", RiskTier: contractv1.RiskTier_RISK_TIER_MEDIUM, TestOnly: true,
		}, Run: func(context.Context, Request) (Report, error) {
			return Report{Conclusion: "不应被调用", Success: true}, nil
		}},
		"k8s.version": {Decl: readOnlyDecl("k8s.version"), RequiresCluster: true,
			Run: func(context.Context, Request) (Report, error) {
				return Report{Conclusion: "不应被调用", Success: true}, nil
			}},
	}
	ex, aud, rs := newExecEnvCluster(t, caps, policy.DefaultConfig(), false)
	if ex == nil {
		return
	}
	ctx := context.Background()
	// 一条 denied + 一条 no_cluster_configured：没有任何能力被执行。
	planID := planRow(t, rs, 350, "prometheus", []string{"test.unit.write", "k8s.version"}, "planned")
	if _, err := ex.RunOnce(ctx, aud); err != nil {
		t.Fatal(err)
	}
	got, _ := ex.PlanStatus(ctx, planID)
	if got == PlanDone || got == PlanPartial {
		t.Fatalf("没有能力被执行时不得记为 done/partial，实际 %q", got)
	}
	if got != PlanNotExecuted {
		t.Fatalf("应为 %s，实际 %q", PlanNotExecuted, got)
	}
	var reason string
	if err := rs.Pool().QueryRow(ctx, `SELECT reason FROM test_diagnosis_plans WHERE id=$1`, planID).Scan(&reason); err != nil {
		t.Fatal(err)
	}
	// 首要原因优先级：集群未配置 > 被拒绝。
	if !strings.Contains(reason, "no_cluster_configured") {
		t.Fatalf("首要原因应为集群未配置：%q", reason)
	}
	t.Logf("[断言] denied + no_cluster_configured → %s（reason=%q）", got, reason)
}

// TestPlannerStatusCheckAcceptsNotExecuted（F2）计划表 CHECK 必须接受 not_executed。
func TestPlannerStatusCheckAcceptsNotExecuted(t *testing.T) {
	ex, _, rs := newExecEnv(t, map[string]CapEntry{}, policy.DefaultConfig())
	if ex == nil {
		return
	}
	ctx := context.Background()
	// 直接写入 not_executed（模拟执行器落终态）——CHECK 拒绝时这里会失败。
	id := planRow(t, rs, 360, "prometheus", []string{}, PlanNotExecuted)
	if st, _ := ex.PlanStatus(ctx, id); st != PlanNotExecuted {
		t.Fatalf("not_executed 应可写入计划表：%q", st)
	}
	// 非法状态仍必须被拒绝。
	if _, err := rs.Pool().Exec(ctx, `INSERT INTO test_diagnosis_plans
(event_id, fingerprint, source, severity, profile, status, rule_id, capabilities, reason, created_at, updated_at)
VALUES (361,'fp','s','critical','prometheus','bogus','R',ARRAY[]::text[],'',now(),now())`); err == nil {
		t.Fatal("非法状态必须被 CHECK 约束拒绝")
	}
	t.Log("[断言] 计划表 CHECK 接受 not_executed、拒绝非法状态")
}
