package registry

import "github.com/ORG/agent-ops/internal/validation"

// CapabilityNamePattern 能力名称规则（第五轮修正，安全相关）：
// 只允许小写 ASCII 字母、数字、下划线，以 "." 分段。
// 规则唯一来源为 internal/validation（第七轮遗留决策 D2 / ADR-008）：
// 本包只做别名，不得再维护第二份正则。
var CapabilityNamePattern = validation.CapabilityNamePattern

// ValidCapabilityName 校验能力名称（委托 internal/validation）。
// 注册处（适配器清单加载）与策略评估处（internal/policy）引用同一规则源，
// 两侧行为一致性由本文件测试与 validation 包测试共同保证。
func ValidCapabilityName(name string) bool {
	return validation.ValidCapabilityName(name)
}
