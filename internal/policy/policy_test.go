package policy

import (
	"reflect"
	"strings"
	"testing"

	contractv1 "github.com/ORG/agent-ops/contract/gen/go/agent_ops/contract/v1"
)

func cap(name string, tier contractv1.RiskTier, rollbackable bool) *contractv1.Capability {
	return &contractv1.Capability{Name: name, RiskTier: tier, Rollbackable: rollbackable}
}

// capD 构造带 destructive 标注的能力声明。
func capD(name string, tier contractv1.RiskTier, rollbackable, destructive bool) *contractv1.Capability {
	c := cap(name, tier, rollbackable)
	c.Destructive = destructive
	return c
}

func newRequest(c *contractv1.Capability, env contractv1.Environment, impact ImpactScope, freeze bool) Request {
	return Request{Capability: c, Environment: env, ImpactScope: impact, FreezeWindow: freeze}
}

func (r Result) reasonsContain(t *testing.T, want string) {
	t.Helper()
	if !strings.Contains(strings.Join(r.Reasons, "；"), want) {
		t.Fatalf("理由缺少 %q，实际理由：%v", want, r.Reasons)
	}
}

// TestReadOnlyNotUpgradedByContext 只读能力不受环境/冻结窗口等写操作因素影响。
func TestReadOnlyNotUpgradedByContext(t *testing.T) {
	got := Evaluate(DefaultConfig(), newRequest(
		cap("diagnose.slow_query", contractv1.RiskTier_RISK_TIER_READ_ONLY, false),
		contractv1.Environment_ENVIRONMENT_PROD, ImpactScopeMulti, true))
	if got.Decision != contractv1.Decision_DECISION_AUTO {
		t.Fatalf("read_only 应自动放行，got %v", got.Decision)
	}
	if got.Tier != contractv1.RiskTier_RISK_TIER_READ_ONLY {
		t.Fatalf("read_only 等级不应被升级，got %v", got.Tier)
	}
}

// TestLowAutoInTestEnv 低风险在测试环境、单实例、可回滚时自动执行。
func TestLowAutoInTestEnv(t *testing.T) {
	got := Evaluate(DefaultConfig(), newRequest(
		cap("restart.service", contractv1.RiskTier_RISK_TIER_LOW, true),
		contractv1.Environment_ENVIRONMENT_TEST, ImpactScopeSingle, false))
	if got.Decision != contractv1.Decision_DECISION_AUTO {
		t.Fatalf("低风险测试环境应 auto，got %v（%v）", got.Decision, got.Reasons)
	}
	if got.Tier != contractv1.RiskTier_RISK_TIER_LOW {
		t.Fatalf("等级不应变化，got %v", got.Tier)
	}
}

// TestEnvironmentUpgradesTier 生产环境把低风险升级为需审批。
func TestEnvironmentUpgradesTier(t *testing.T) {
	got := Evaluate(DefaultConfig(), newRequest(
		cap("restart.service", contractv1.RiskTier_RISK_TIER_LOW, true),
		contractv1.Environment_ENVIRONMENT_PROD, ImpactScopeSingle, false))
	if got.Decision != contractv1.Decision_DECISION_REQUIRE_APPROVAL {
		t.Fatalf("生产环境升级后应需审批，got %v", got.Decision)
	}
	if got.Tier != contractv1.RiskTier_RISK_TIER_MEDIUM {
		t.Fatalf("等级应升级为 medium，got %v", got.Tier)
	}
	got.reasonsContain(t, "环境上下文升级")
}

// TestMultiImpactUpgradesTier 多实例影响范围升级等级。
func TestMultiImpactUpgradesTier(t *testing.T) {
	got := Evaluate(DefaultConfig(), newRequest(
		cap("restart.deployment", contractv1.RiskTier_RISK_TIER_LOW, true),
		contractv1.Environment_ENVIRONMENT_STAGING, ImpactScopeMulti, false))
	if got.Decision != contractv1.Decision_DECISION_REQUIRE_APPROVAL {
		t.Fatalf("多实例影响应需审批，got %v", got.Decision)
	}
	if got.Tier != contractv1.RiskTier_RISK_TIER_MEDIUM {
		t.Fatalf("等级应升级为 medium，got %v", got.Tier)
	}
	got.reasonsContain(t, "影响范围升级")
}

// TestNotRollbackableUpgradesTier 不可回滚直接升级。
func TestNotRollbackableUpgradesTier(t *testing.T) {
	got := Evaluate(DefaultConfig(), newRequest(
		cap("restart.node", contractv1.RiskTier_RISK_TIER_LOW, false),
		contractv1.Environment_ENVIRONMENT_STAGING, ImpactScopeSingle, false))
	if got.Decision != contractv1.Decision_DECISION_REQUIRE_APPROVAL {
		t.Fatalf("不可回滚应需审批，got %v", got.Decision)
	}
	if got.Tier != contractv1.RiskTier_RISK_TIER_HIGH {
		t.Fatalf("等级应升级为 high，got %v", got.Tier)
	}
	got.reasonsContain(t, "不可回滚升级")
}

// TestFreezeWindowUpgradesWrite 冻结窗口内写操作需审批。
func TestFreezeWindowUpgradesWrite(t *testing.T) {
	got := Evaluate(DefaultConfig(), newRequest(
		cap("restart.service", contractv1.RiskTier_RISK_TIER_LOW, true),
		contractv1.Environment_ENVIRONMENT_STAGING, ImpactScopeSingle, true))
	if got.Decision != contractv1.Decision_DECISION_REQUIRE_APPROVAL {
		t.Fatalf("冻结窗口内写操作应需审批，got %v", got.Decision)
	}
	if got.Tier != contractv1.RiskTier_RISK_TIER_MEDIUM {
		t.Fatalf("等级应升级为 medium，got %v", got.Tier)
	}
	got.reasonsContain(t, "冻结窗口升级")
}

// TestFreezeWindowIgnoresReadOnly 冻结窗口不影响只读能力。
func TestFreezeWindowIgnoresReadOnly(t *testing.T) {
	got := Evaluate(DefaultConfig(), newRequest(
		cap("diagnose.collect", contractv1.RiskTier_RISK_TIER_READ_ONLY, false),
		contractv1.Environment_ENVIRONMENT_STAGING, ImpactScopeSingle, true))
	if got.Decision != contractv1.Decision_DECISION_AUTO || got.Tier != contractv1.RiskTier_RISK_TIER_READ_ONLY {
		t.Fatalf("只读能力不应受冻结窗口影响，got decision=%v tier=%v", got.Decision, got.Tier)
	}
}

// TestReadOnlyNoUpgradeProdFreezeMulti 只读操作不升级（ADR-007）：
// read_only 在生产环境、冻结窗口内、影响范围为 multi 时仍不升级并返回 auto。
func TestReadOnlyNoUpgradeProdFreezeMulti(t *testing.T) {
	got := Evaluate(DefaultConfig(), newRequest(
		cap("diagnose.collect", contractv1.RiskTier_RISK_TIER_READ_ONLY, false),
		contractv1.Environment_ENVIRONMENT_PROD, ImpactScopeMulti, true))
	if got.Tier != contractv1.RiskTier_RISK_TIER_READ_ONLY {
		t.Fatalf("只读操作不应被升级，got tier=%v", got.Tier)
	}
	if got.Decision != contractv1.Decision_DECISION_AUTO {
		t.Fatalf("只读操作应返回 auto，got decision=%v（%v）", got.Decision, got.Reasons)
	}
}

// TestUndeclaredCapabilityDenied 未声明能力必须 deny 并记录理由。
func TestUndeclaredCapabilityDenied(t *testing.T) {
	got := Evaluate(DefaultConfig(), newRequest(
		nil, contractv1.Environment_ENVIRONMENT_STAGING, ImpactScopeSingle, false))
	if got.Decision != contractv1.Decision_DECISION_DENY {
		t.Fatalf("未声明能力应 deny，got %v", got.Decision)
	}
	got.reasonsContain(t, "未声明")
}

// TestEmptyCapabilityNameDenied 能力名为空同样视为未声明。
func TestEmptyCapabilityNameDenied(t *testing.T) {
	got := Evaluate(DefaultConfig(), newRequest(
		cap("", contractv1.RiskTier_RISK_TIER_LOW, true),
		contractv1.Environment_ENVIRONMENT_STAGING, ImpactScopeSingle, false))
	if got.Decision != contractv1.Decision_DECISION_DENY {
		t.Fatalf("空名称能力应 deny，got %v", got.Decision)
	}
}

// TestUnspecifiedTierDenied 声明缺少基础风险等级时拒绝。
func TestUnspecifiedTierDenied(t *testing.T) {
	got := Evaluate(DefaultConfig(), newRequest(
		cap("something.do", contractv1.RiskTier_RISK_TIER_UNSPECIFIED, true),
		contractv1.Environment_ENVIRONMENT_STAGING, ImpactScopeSingle, false))
	if got.Decision != contractv1.Decision_DECISION_DENY {
		t.Fatalf("未声明等级的声明应 deny，got %v", got.Decision)
	}
	got.reasonsContain(t, "缺少基础风险等级")
}

// TestInvalidCapabilityNameDenied 能力名称校验（第五轮修正，fail-closed）：
// 大写、空白、空分段与 Unicode 名称一律 deny，且不做自动修正。
func TestInvalidCapabilityNameDenied(t *testing.T) {
	invalid := []string{
		"Volume.Delete",  // 大写开头（大小写绕过）
		"VOLUME.DELETE",  // 全大写
		" volume.delete", // 前导空格
		"volume.delete ", // 尾随空格
		"volume..delete", // 空分段
		"诊断.采集",          // Unicode
	}
	for _, name := range invalid {
		t.Run(name, func(t *testing.T) {
			got := Evaluate(DefaultConfig(), newRequest(
				cap(name, contractv1.RiskTier_RISK_TIER_LOW, true),
				contractv1.Environment_ENVIRONMENT_STAGING, ImpactScopeSingle, false))
			if got.Decision != contractv1.Decision_DECISION_DENY {
				t.Fatalf("非法名称 %q 应 deny，got %v", name, got.Decision)
			}
			got.reasonsContain(t, "能力名称不合法")
		})
	}
}

// TestDestructiveDenied destructive=true 一律 deny（第一道防线，理由固定）。
// 覆盖：a) 删除语义名称；b) 无删除关键词；c) 名称命中硬拒绝但 destructive=false。
func TestDestructiveDenied(t *testing.T) {
	// a) 名称为删除语义、destructive=true → deny。
	for _, name := range []string{"volume.remove", "volume.destroy", "volume.wipe"} {
		t.Run(name, func(t *testing.T) {
			got := Evaluate(DefaultConfig(), newRequest(
				capD(name, contractv1.RiskTier_RISK_TIER_LOW, true, true),
				contractv1.Environment_ENVIRONMENT_STAGING, ImpactScopeSingle, false))
			if got.Decision != contractv1.Decision_DECISION_DENY {
				t.Fatalf("destructive=true 的 %s 应 deny，got %v", name, got.Decision)
			}
			got.reasonsContain(t, "能力标记为破坏性，硬拒绝")
		})
	}

	// b) 名称不含任何删除关键词、但 destructive=true → deny。
	t.Run("neutral-name-destructive", func(t *testing.T) {
		got := Evaluate(DefaultConfig(), newRequest(
			capD("config.apply_batch", contractv1.RiskTier_RISK_TIER_LOW, true, true),
			contractv1.Environment_ENVIRONMENT_STAGING, ImpactScopeSingle, false))
		if got.Decision != contractv1.Decision_DECISION_DENY {
			t.Fatalf("destructive=true 应 deny，got %v", got.Decision)
		}
		got.reasonsContain(t, "能力标记为破坏性，硬拒绝")
	})

	// c) 名称命中硬拒绝前缀、但 destructive=false → 仍 deny（第二道防线独立生效）。
	t.Run("name-rule-destructive-false", func(t *testing.T) {
		got := Evaluate(DefaultConfig(), newRequest(
			cap("firewall.rule_add", contractv1.RiskTier_RISK_TIER_LOW, true),
			contractv1.Environment_ENVIRONMENT_STAGING, ImpactScopeSingle, false))
		if got.Decision != contractv1.Decision_DECISION_DENY {
			t.Fatalf("名称命中硬拒绝前缀应 deny，got %v", got.Decision)
		}
		got.reasonsContain(t, "禁止修改防火墙")
	})

	// d) 名称与 destructive 均不命中的普通能力 → 按分级正常判定。
	t.Run("normal-capability", func(t *testing.T) {
		got := Evaluate(DefaultConfig(), newRequest(
			cap("restart.service", contractv1.RiskTier_RISK_TIER_LOW, true),
			contractv1.Environment_ENVIRONMENT_TEST, ImpactScopeSingle, false))
		if got.Decision != contractv1.Decision_DECISION_AUTO {
			t.Fatalf("普通能力应按分级判定为 auto，got %v（%v）", got.Decision, got.Reasons)
		}
	})
}
func TestHardDenyExactMatch(t *testing.T) {
	got := Evaluate(DefaultConfig(), newRequest(
		cap("volume.delete", contractv1.RiskTier_RISK_TIER_LOW, true),
		contractv1.Environment_ENVIRONMENT_STAGING, ImpactScopeSingle, false))
	if got.Decision != contractv1.Decision_DECISION_DENY {
		t.Fatalf("volume.delete 应 deny，got %v", got.Decision)
	}
	got.reasonsContain(t, "禁止删除数据卷")
}

// TestHardDenyRenameBypass 硬拒绝改名绕过（ADR-007）：删除类与 "." 前缀规则
// 必须覆盖各种改名变体。注意：volume.delete_all、firewall.rule_add 等能力
// 仅存在于本测试，用于验证「能力被误声明」的场景。
func TestHardDenyRenameBypass(t *testing.T) {
	cases := []struct {
		name   string // 被（误）声明的能力名
		rule   string // 理由中应包含的命中规则
		reason string // 理由中应包含的规则说明
	}{
		{"volume.delete_all", "volume.delete", "禁止删除数据卷"},
		{"volume.delete.snapshot", "volume.delete", "禁止删除数据卷"},
		{"database.delete_drop", "database.delete", "禁止删除数据库"},
		{"firewall.rule_add", "firewall.", "禁止修改防火墙"},
		{"security_group.rule_add", "security_group.", "禁止修改安全组"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Evaluate(DefaultConfig(), newRequest(
				cap(tc.name, contractv1.RiskTier_RISK_TIER_LOW, true),
				contractv1.Environment_ENVIRONMENT_STAGING, ImpactScopeSingle, false))
			if got.Decision != contractv1.Decision_DECISION_DENY {
				t.Fatalf("改名变体 %s 应 deny，got %v", tc.name, got.Decision)
			}
			joined := strings.Join(got.Reasons, "；")
			if !strings.Contains(joined, tc.rule) {
				t.Fatalf("理由应包含命中规则 %q，实际：%v", tc.rule, got.Reasons)
			}
			if !strings.Contains(joined, tc.reason) {
				t.Fatalf("理由应包含 %q，实际：%v", tc.reason, got.Reasons)
			}
		})
	}
}

// TestHardDenyMisdeclared 硬拒绝覆盖「能力被误声明」的情形：
// firewall.modify 即使被误声明为低风险、可回滚，也必须 deny。
func TestHardDenyMisdeclared(t *testing.T) {
	// 故意误声明：低风险 + 可回滚（实际是禁止类操作）。
	got := Evaluate(DefaultConfig(), newRequest(
		cap("firewall.modify", contractv1.RiskTier_RISK_TIER_LOW, true),
		contractv1.Environment_ENVIRONMENT_TEST, ImpactScopeSingle, false))
	if got.Decision != contractv1.Decision_DECISION_DENY {
		t.Fatalf("被误声明的防火墙修改应 deny，got %v", got.Decision)
	}
	got.reasonsContain(t, "禁止修改防火墙")
	got.reasonsContain(t, "deny")
}

// TestHardDenyNotHit 不命中硬拒绝规则的正常能力不受影响。
func TestHardDenyNotHit(t *testing.T) {
	got := Evaluate(DefaultConfig(), newRequest(
		cap("restart.service", contractv1.RiskTier_RISK_TIER_LOW, true),
		contractv1.Environment_ENVIRONMENT_TEST, ImpactScopeSingle, false))
	if got.Decision == contractv1.Decision_DECISION_DENY {
		t.Fatalf("正常能力不应被硬拒绝规则误伤，got %v", got.Reasons)
	}
}

// TestDecisionFromConfig 等级→决策映射从配置读取：
// 自定义配置把 medium 映射为 auto，验证代码未写死映射。
func TestDecisionFromConfig(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DecisionForTier[contractv1.RiskTier_RISK_TIER_MEDIUM] = contractv1.Decision_DECISION_AUTO

	got := Evaluate(cfg, newRequest(
		cap("restart.service", contractv1.RiskTier_RISK_TIER_LOW, true),
		contractv1.Environment_ENVIRONMENT_PROD, ImpactScopeSingle, false))
	if got.Tier != contractv1.RiskTier_RISK_TIER_MEDIUM {
		t.Fatalf("生产环境应升级到 medium，got %v", got.Tier)
	}
	if got.Decision != contractv1.Decision_DECISION_AUTO {
		t.Fatalf("medium 决策应来自配置（auto），got %v", got.Decision)
	}
}

// TestTierNeverDowngraded 等级只能升级不能降级。
func TestTierNeverDowngraded(t *testing.T) {
	got := Evaluate(DefaultConfig(), newRequest(
		cap("restart.service", contractv1.RiskTier_RISK_TIER_HIGH, true),
		contractv1.Environment_ENVIRONMENT_TEST, ImpactScopeSingle, false))
	if got.Tier != contractv1.RiskTier_RISK_TIER_HIGH {
		t.Fatalf("high 等级不应被降级，got %v", got.Tier)
	}
	if got.Decision != contractv1.Decision_DECISION_REQUIRE_APPROVAL {
		t.Fatalf("high 应需审批，got %v", got.Decision)
	}
}

// TestMissingConfigMappingDenied 配置缺失等级映射时拒绝（fail-safe）。
func TestMissingConfigMappingDenied(t *testing.T) {
	cfg := DefaultConfig()
	delete(cfg.DecisionForTier, contractv1.RiskTier_RISK_TIER_MEDIUM)

	got := Evaluate(cfg, newRequest(
		cap("restart.service", contractv1.RiskTier_RISK_TIER_LOW, true),
		contractv1.Environment_ENVIRONMENT_PROD, ImpactScopeSingle, false))
	if got.Decision != contractv1.Decision_DECISION_DENY {
		t.Fatalf("配置缺失应 fail-safe deny，got %v", got.Decision)
	}
	got.reasonsContain(t, "缺失")
}

// TestEvaluateDeterministic 纯函数确定性：相同输入两次调用结果完全一致。
func TestEvaluateDeterministic(t *testing.T) {
	cfg := DefaultConfig()
	req := newRequest(
		cap("restart.service", contractv1.RiskTier_RISK_TIER_LOW, false),
		contractv1.Environment_ENVIRONMENT_PROD, ImpactScopeMulti, true)

	first := Evaluate(cfg, req)
	for i := 0; i < 10; i++ {
		again := Evaluate(cfg, req)
		if !reflect.DeepEqual(first, again) {
			t.Fatalf("第 %d 次调用结果不一致：%v vs %v", i, first, again)
		}
	}
}
