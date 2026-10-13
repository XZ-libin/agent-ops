package policy

import (
	"time"

	contractv1 "github.com/ORG/agent-ops/contract/gen/go/agent_ops/contract/v1"
)

// DefaultConfig 返回内置策略配置（等级→决策映射与各上下文等级下限）。
// 映射中的 low→auto 依赖低风险自动执行清单的最终确认（见 exampleAutoExecCandidates）。
func DefaultConfig() Config {
	return Config{
		DecisionForTier: map[contractv1.RiskTier]contractv1.Decision{
			contractv1.RiskTier_RISK_TIER_READ_ONLY: contractv1.Decision_DECISION_AUTO,
			contractv1.RiskTier_RISK_TIER_LOW:       contractv1.Decision_DECISION_AUTO,
			contractv1.RiskTier_RISK_TIER_MEDIUM:    contractv1.Decision_DECISION_REQUIRE_APPROVAL,
			contractv1.RiskTier_RISK_TIER_HIGH:      contractv1.Decision_DECISION_REQUIRE_APPROVAL,
		},
		// 生产环境比测试环境更严格（开发文档「分级因子」：生产重启升级为需审批）。
		EnvironmentMinTier: map[contractv1.Environment]contractv1.RiskTier{
			contractv1.Environment_ENVIRONMENT_PROD: contractv1.RiskTier_RISK_TIER_MEDIUM,
		},
		MultiImpactMinTier:     contractv1.RiskTier_RISK_TIER_MEDIUM,
		NotRollbackableMinTier: contractv1.RiskTier_RISK_TIER_HIGH,
		FreezeWindowMinTier:    contractv1.RiskTier_RISK_TIER_MEDIUM,
		HardDeny:               DefaultHardDenyRules(),
	}
}

// DefaultHardDenyRules 禁止类操作的硬拒绝名称规则（开发文档「范围与非目标」，
// 第二道防线；第一道防线为能力声明的 destructive 标注）。
// 匹配语义（ADR-007 修订）：所有规则统一为前缀匹配，比较前归一化（去掉末尾 "."）；
// 名称在规则中是否带 "." 结尾不再影响语义。
func DefaultHardDenyRules() []HardDenyRule {
	return []HardDenyRule{
		{Pattern: "volume.delete", Reason: "禁止删除数据卷"},
		{Pattern: "database.delete", Reason: "禁止删除数据库"},
		{Pattern: "firewall.", Reason: "禁止修改防火墙"},
		{Pattern: "security_group.", Reason: "禁止修改安全组"},
		{Pattern: "audit.disable", Reason: "禁止关闭审计"},
	}
}

// —— 以下为待决策占位常量：保持 TODO(待决策)，不自行决定 ——

// DefaultApprovalTimeout 审批超时占位（候选项：30 分钟）。
// TODO(待决策)：终值待运维负责人确认。
const DefaultApprovalTimeout = 30 * time.Minute

// HighRiskProductionApprovalTimeout 生产高风险变更审批放宽占位（候选项：2 小时）。
// TODO(待决策)：终值待运维负责人确认。
const HighRiskProductionApprovalTimeout = 2 * time.Hour

// DefaultReadOnlyCapabilityTimeout 只读诊断能力超时占位（候选项：60 秒）。
// TODO(待决策)：终值待确认，适配器清单可覆盖。
const DefaultReadOnlyCapabilityTimeout = 60 * time.Second

// DefaultExecuteCapabilityTimeout 执行类能力超时占位（候选项：300 秒）。
// TODO(待决策)：终值待确认，适配器清单可覆盖。
const DefaultExecuteCapabilityTimeout = 300 * time.Second

// PodRestartMaxRatio 无状态 Pod 重启单次影响副本数比例上限（管理后台原型 10%）。
// TODO(待决策)：待运维负责人确认。
const PodRestartMaxRatio = 0.10

// exampleAutoExecCandidates 低风险自动执行清单的示例条目。
// TODO(待决策)：完整清单待运维负责人逐条确认；
// 任何涉及数据、网络或权限的操作不得进入自动清单。
// 当前不参与判定：low 等级的决策完全由 Config.DecisionForTier 决定。
var exampleAutoExecCandidates = []string{
	"log.cleanup_expired",   // 清理超过保留期限、且在允许路径内的日志与临时文件
	"pod.restart_stateless", // 重启无状态 Pod（单次影响 ≤ PodRestartMaxRatio）
	"diagnose.collect",      // 只读诊断信息采集
}
