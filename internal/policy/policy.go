// Package policy 实现风险策略引擎（ADR-006）：
//
//   - 输入：能力声明（名称、基础风险等级、可回滚性）、目标环境、影响范围、是否处于冻结窗口；
//   - 输出：Decision（auto / require_approval / deny）与判定理由；
//   - 等级只能被上下文因素升级，不能降级；
//   - 等级→决策的映射从策略配置读取，不写死在代码里；
//   - 未声明的能力必须返回 deny；硬拒绝规则命中时，即使能力被误声明也返回 deny；
//   - Evaluate 是纯函数：不读取时间或随机数（冻结窗口由调用方传入），
//     相同的 Config+Request 永远返回相同的 Result。
package policy

import (
	"fmt"
	"strings"

	contractv1 "github.com/XZ-libin/agent-ops/contract/gen/go/agent_ops/contract/v1"

	"github.com/XZ-libin/agent-ops/internal/validation"
)

// ImpactScope 影响范围（开发文档「分级因子」：单个 Pod 与整个 Deployment 不同）。
type ImpactScope int32

const (
	// ImpactScopeUnspecified 未指定，按单实例处理（默认）。
	ImpactScopeUnspecified ImpactScope = 0
	// ImpactScopeSingle 单实例/单副本。
	ImpactScopeSingle ImpactScope = 1
	// ImpactScopeMulti 多实例/整个组件。
	ImpactScopeMulti ImpactScope = 2
)

// HardDenyRule 硬拒绝名称规则（ADR-006 第二道防线）：
// 即使能力被误声明，命中即 deny。所有规则统一为前缀匹配（见 denyMatch，ADR-007 修订）。
type HardDenyRule struct {
	// Pattern 能力名前缀（比较前归一化：去掉末尾 "."）。
	Pattern string
	// Reason 拒绝理由，写入判定理由。
	Reason string
}

// Config 策略配置：等级→决策映射与各上下文因素的等级下限均由配置提供。
type Config struct {
	// DecisionForTier 等级→决策映射（配置驱动，不写死在代码里）。
	DecisionForTier map[contractv1.RiskTier]contractv1.Decision
	// EnvironmentMinTier 环境等级下限：命中环境的操作等级低于该值时升级。
	EnvironmentMinTier map[contractv1.Environment]contractv1.RiskTier
	// MultiImpactMinTier 多实例影响范围等级下限。
	MultiImpactMinTier contractv1.RiskTier
	// NotRollbackableMinTier 不可回滚操作等级下限。
	NotRollbackableMinTier contractv1.RiskTier
	// FreezeWindowMinTier 冻结窗口内写操作等级下限（只读能力不受影响）。
	FreezeWindowMinTier contractv1.RiskTier
	// HardDeny 硬拒绝规则列表。
	HardDeny []HardDenyRule
}

// Request 判定输入。全部由调用方提供；Evaluate 不读取时间或随机数。
type Request struct {
	// Capability 能力声明；nil 或名称为空表示未声明。
	Capability *contractv1.Capability
	// Environment 目标环境（FixedEnum prod/staging/test）。
	Environment contractv1.Environment
	// ImpactScope 影响范围。
	ImpactScope ImpactScope
	// FreezeWindow 是否处于变更冻结窗口内（由调用方判断并传入）。
	FreezeWindow bool
}

// Result 判定输出。
type Result struct {
	// Decision 最终决策：auto / require_approval / deny。
	Decision contractv1.Decision
	// Tier 上下文升级后的最终等级（只会 ≥ 声明等级）。
	Tier contractv1.RiskTier
	// Reasons 判定理由，按判定顺序记录。
	Reasons []string
}

// Evaluate 执行判定。纯函数：相同 Config+Request 永远返回相同 Result。
func Evaluate(cfg Config, req Request) Result {
	if req.Capability == nil || req.Capability.Name == "" {
		return Result{
			Decision: contractv1.Decision_DECISION_DENY,
			Tier:     contractv1.RiskTier_RISK_TIER_UNSPECIFIED,
			Reasons:  []string{"能力未声明，拒绝（deny）"},
		}
	}
	cap := req.Capability

	tier := cap.RiskTier
	if tier == contractv1.RiskTier_RISK_TIER_UNSPECIFIED {
		return denyResult(contractv1.RiskTier_RISK_TIER_UNSPECIFIED, "能力声明缺少基础风险等级，拒绝（deny）")
	}

	reasons := make([]string, 0, 6)

	// 0. 名称合法性（第五轮修正，fail-closed）：只允许小写字母/数字/下划线、
	// 以 "." 分段（规则唯一来源 internal/validation，见 ADR-008）；不合法即拒绝，
	// 不做大小写/空白自动修正。
	if !validation.ValidCapabilityName(cap.Name) {
		return denyResult(tier, "能力名称不合法，拒绝（deny）")
	}

	// 1. 硬拒绝第一道防线：destructive 标注（契约字段，破坏性能力一律 deny）。
	// 理由固定，检查顺序：未声明检查（含名称合法性）之后、名称规则之前。
	if cap.Destructive {
		return denyResult(tier, "能力标记为破坏性，硬拒绝")
	}
	// 1b. 硬拒绝第二道防线：名称规则（统一前缀匹配，见 denyMatch）。
	for _, rule := range cfg.HardDeny {
		if denyMatch(rule.Pattern, cap.Name) {
			reasons = append(reasons, rule.Reason)
			return denyResult(tier, rule.Pattern+"，拒绝（deny）", reasons...)
		}
	}

	// 2. 只读能力不受写操作上下文因素影响（环境/影响范围/可逆性/冻结窗口）。
	if tier == contractv1.RiskTier_RISK_TIER_READ_ONLY {
		return finish(cfg, tier, reasons)
	}

	// 3. 环境：生产环境比测试环境更严格。
	if floor, ok := cfg.EnvironmentMinTier[req.Environment]; ok && floor > tier {
		reasons = append(reasons,
			fmt.Sprintf("环境上下文升级：%s→%s", tier, floor))
		tier = floor
	}

	// 4. 影响范围：多实例影响范围升级。
	if req.ImpactScope == ImpactScopeMulti && cfg.MultiImpactMinTier > tier {
		reasons = append(reasons,
			fmt.Sprintf("影响范围升级：%s→%s", tier, cfg.MultiImpactMinTier))
		tier = cfg.MultiImpactMinTier
	}

	// 5. 可逆性：不可回滚的操作直接升级。
	if !cap.Rollbackable && cfg.NotRollbackableMinTier > tier {
		reasons = append(reasons,
			fmt.Sprintf("不可回滚升级：%s→%s", tier, cfg.NotRollbackableMinTier))
		tier = cfg.NotRollbackableMinTier
	}

	// 6. 冻结窗口：冻结期内所有写操作需审批。
	if req.FreezeWindow && cfg.FreezeWindowMinTier > tier {
		reasons = append(reasons,
			fmt.Sprintf("冻结窗口升级：%s→%s", tier, cfg.FreezeWindowMinTier))
		tier = cfg.FreezeWindowMinTier
	}

	return finish(cfg, tier, reasons)
}

// finish 依据配置的等级→决策映射输出最终结果。
func finish(cfg Config, tier contractv1.RiskTier, reasons []string) Result {
	decision, ok := cfg.DecisionForTier[tier]
	if !ok {
		return denyResult(tier,
			fmt.Sprintf("策略配置缺失等级 %s 的决策映射，拒绝（deny）", tier), reasons...)
	}
	reasons = append(reasons, fmt.Sprintf("最终等级 %s，决策 %s", tier, decision))
	return Result{Decision: decision, Tier: tier, Reasons: reasons}
}

// denyResult 构造 deny 结果。
func denyResult(tier contractv1.RiskTier, reason string, prev ...string) Result {
	reasons := append(append([]string{}, prev...), reason)
	return Result{Decision: contractv1.Decision_DECISION_DENY, Tier: tier, Reasons: reasons}
}

// denyMatch 硬拒绝名称规则匹配（ADR-007 修订，第二道防线）：
// 所有名称规则统一为前缀匹配；比较前对 Pattern 归一化（去掉末尾 "."），
// 不再区分 "." 结尾与否，也不再按名称后缀推断删除类——
// 删除/破坏性语义由能力声明的 destructive 标注（第一道防线）承担。
func denyMatch(pattern, name string) bool {
	p := strings.TrimRight(pattern, ".")
	return strings.HasPrefix(name, p)
}
