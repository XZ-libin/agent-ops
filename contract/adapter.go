package contract

import (
	"context"

	contractv1 "github.com/ORG/agent-ops/contract/gen/go/agent_ops/contract/v1"
)

// Adapter 是每个组件适配器必须实现的统一接口（开发文档「适配器规范」）。
// 核心系统不包含任何组件专属逻辑；未在清单声明的能力不可调用；
// Execute 只接受风险策略放行的请求（AuthZ）；
// PlanRollback 只生成回滚计划，回滚动作须再次经过风险策略判定并由 Execute 执行，
// 不得直接执行（ADR-006 决策 8）。
type Adapter interface {
	// Discover 发现目标上该组件的实例与版本。
	Discover(ctx context.Context, target *contractv1.AssetTarget) ([]*contractv1.Instance, error)
	// Health 返回健康状态与关键指标，必须只读。
	Health(ctx context.Context, instance *contractv1.Instance) (*contractv1.HealthReport, error)
	// Diagnose 执行只读的排查步骤，返回证据与结论。
	Diagnose(ctx context.Context, instance *contractv1.Instance, question string) (*contractv1.DiagnosisReport, error)
	// Execute 执行已声明的能力，只接受带 AuthZ 的请求。
	Execute(ctx context.Context, action *contractv1.Action, authz *contractv1.AuthZ) (*contractv1.ActionResult, error)
	// PlanRollback 根据执行记录生成回滚计划；计划中的每个动作都是已声明的能力。
	// 不可回滚的操作必须在清单中声明。
	PlanRollback(ctx context.Context, record *contractv1.ActionRecord) ([]*contractv1.Action, error)
}
