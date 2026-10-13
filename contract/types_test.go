package contract

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	contractv1 "github.com/ORG/agent-ops/contract/gen/go/agent_ops/contract/v1"
)

// TestRiskTierEnum 固定风险等级四档的枚举名（ADR-006：领域词汇 read_only/low/medium/high）。
// proto3 JSON 编码使用枚举值名；REST 侧的领域词汇由 api/openapi.yaml 独立承载。
func TestRiskTierEnum(t *testing.T) {
	want := map[contractv1.RiskTier]string{
		contractv1.RiskTier_RISK_TIER_READ_ONLY: "RISK_TIER_READ_ONLY",
		contractv1.RiskTier_RISK_TIER_LOW:       "RISK_TIER_LOW",
		contractv1.RiskTier_RISK_TIER_MEDIUM:    "RISK_TIER_MEDIUM",
		contractv1.RiskTier_RISK_TIER_HIGH:      "RISK_TIER_HIGH",
	}
	if got := contractv1.RiskTier_RISK_TIER_LOW.Descriptor().Values().Len(); got != len(want)+1 { // +1 为 UNSPECIFIED
		t.Fatalf("RiskTier 取值数: got %d, want %d", got, len(want)+1)
	}
	for tier, name := range want {
		if got := tier.String(); got != name {
			t.Errorf("RiskTier %v 枚举名: got %q, want %q", tier, got, name)
		}
	}
}

// TestDecisionEnum 固定策略决策三档的枚举名（领域词汇 auto/require_approval/deny）。
func TestDecisionEnum(t *testing.T) {
	want := map[contractv1.Decision]string{
		contractv1.Decision_DECISION_AUTO:             "DECISION_AUTO",
		contractv1.Decision_DECISION_REQUIRE_APPROVAL: "DECISION_REQUIRE_APPROVAL",
		contractv1.Decision_DECISION_DENY:             "DECISION_DENY",
	}
	if got := contractv1.Decision_DECISION_AUTO.Descriptor().Values().Len(); got != len(want)+1 {
		t.Fatalf("Decision 取值数: got %d, want %d", got, len(want)+1)
	}
	for d, name := range want {
		if got := d.String(); got != name {
			t.Errorf("Decision %v 枚举名: got %q, want %q", d, got, name)
		}
	}
}

// TestChangePlanRoundTrip 校验变更方案经 JSON 序列化往返一致，字段名保持 proto 命名。
func TestChangePlanRoundTrip(t *testing.T) {
	in := &contractv1.ChangePlan{
		Id:        "cp_01HX",
		CreatedBy: &contractv1.Actor{Kind: contractv1.Actor_KIND_AGENT, Id: "agent-7"},
		Target:    &contractv1.AssetTarget{AssetId: "ast_01HX", Access: contractv1.AccessKind_ACCESS_AGENT},
		Actions:   []*contractv1.Action{{Capability: "restart.service"}},
		RiskTier:  contractv1.RiskTier_RISK_TIER_MEDIUM,
		Decision:  contractv1.Decision_DECISION_REQUIRE_APPROVAL,
		Status:    contractv1.ChangePlanStatus_CHANGE_PLAN_STATUS_PENDING_APPROVAL,
	}

	mo := protojson.MarshalOptions{UseProtoNames: true}
	b, err := mo.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"risk_tier"`, `"decision"`, `"status"`, `"id"`} {
		if !strings.Contains(string(b), key) {
			t.Errorf("JSON 缺少字段 %s，实际：%s", key, b)
		}
	}

	out := new(contractv1.ChangePlan)
	if err := protojson.Unmarshal(b, out); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(in, out) {
		t.Errorf("往返不一致: in=%v, out=%v", in, out)
	}
}

// TestAuditEventRoundTrip 校验审计事件（只追加实体）经二进制序列化往返一致。
func TestAuditEventRoundTrip(t *testing.T) {
	in := &contractv1.AuditEvent{
		Id:       "ae_01HX",
		Actor:    &contractv1.Actor{Kind: contractv1.Actor_KIND_HUMAN, Id: "ops-lead"},
		Action:   "change.approved",
		Target:   "cp_01HX",
		RiskTier: contractv1.RiskTier_RISK_TIER_HIGH,
		Before:   `{"replicas":3}`,
		After:    `{"replicas":6}`,
		TraceId:  "tr-1",
		Ts:       timestamppb.Now(),
	}
	b, err := proto.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	out := new(contractv1.AuditEvent)
	if err := proto.Unmarshal(b, out); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(in, out) {
		t.Errorf("往返不一致: in=%v, out=%v", in, out)
	}
}
