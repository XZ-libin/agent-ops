package contract

import (
	"context"
	"testing"

	contractv1 "github.com/XZ-libin/agent-ops/contract/gen/go/agent_ops/contract/v1"
)

// mockAdapter 是本地模拟，仅用于校验 Adapter 接口形状；
// 不实现任何真实适配器与业务逻辑，不接入真实资产（约束：测试只用本地模拟）。
type mockAdapter struct {
	instances []*contractv1.Instance
	executed  []*contractv1.Action
}

// 编译期断言：mockAdapter 完整实现 Adapter。
var _ Adapter = (*mockAdapter)(nil)

func (m *mockAdapter) Discover(_ context.Context, _ *contractv1.AssetTarget) ([]*contractv1.Instance, error) {
	return m.instances, nil
}

func (m *mockAdapter) Health(_ context.Context, _ *contractv1.Instance) (*contractv1.HealthReport, error) {
	return &contractv1.HealthReport{Status: "healthy"}, nil
}

func (m *mockAdapter) Diagnose(_ context.Context, _ *contractv1.Instance, question string) (*contractv1.DiagnosisReport, error) {
	return &contractv1.DiagnosisReport{
		Findings: []*contractv1.Finding{{Hypothesis: question, Verdict: "unknown"}},
	}, nil
}

func (m *mockAdapter) Execute(_ context.Context, action *contractv1.Action, _ *contractv1.AuthZ) (*contractv1.ActionResult, error) {
	m.executed = append(m.executed, action)
	return &contractv1.ActionResult{Success: true, RecordId: "r-local"}, nil
}

func (m *mockAdapter) PlanRollback(_ context.Context, _ *contractv1.ActionRecord) ([]*contractv1.Action, error) {
	// 回滚计划只是"已声明能力的动作"，不经风险策略判定与 Execute 不得直接执行。
	return []*contractv1.Action{{Capability: "restart.service"}}, nil
}

// TestAdapterContractShape 走查五个接口方法，校验统一接口契约可用。
func TestAdapterContractShape(t *testing.T) {
	a := &mockAdapter{
		instances: []*contractv1.Instance{{Id: "i1", Version: "5.7", AssetId: "ast_01HX"}},
	}

	instances, err := a.Discover(context.Background(), &contractv1.AssetTarget{AssetId: "ast_01HX"})
	if err != nil || len(instances) != 1 || instances[0].Id != "i1" {
		t.Fatalf("Discover: got %v, err %v", instances, err)
	}

	report, err := a.Health(context.Background(), instances[0])
	if err != nil || report.Status != "healthy" {
		t.Fatalf("Health: got %v, err %v", report, err)
	}

	diag, err := a.Diagnose(context.Background(), instances[0], "why is it slow")
	if err != nil || len(diag.Findings) != 1 || diag.Findings[0].Hypothesis != "why is it slow" {
		t.Fatalf("Diagnose: got %v, err %v", diag, err)
	}

	action := &contractv1.Action{Capability: "restart.service"}
	result, err := a.Execute(context.Background(), action, &contractv1.AuthZ{AuthorizationId: "a1"})
	if err != nil || !result.Success || len(a.executed) != 1 {
		t.Fatalf("Execute: got %v, err %v", result, err)
	}

	plan, err := a.PlanRollback(context.Background(), &contractv1.ActionRecord{OutputRef: "r1"})
	if err != nil || len(plan) != 1 || plan[0].Capability != "restart.service" {
		t.Fatalf("PlanRollback: got %v, err %v", plan, err)
	}
}
