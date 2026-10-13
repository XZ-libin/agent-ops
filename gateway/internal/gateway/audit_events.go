package gateway

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	contractv1 "github.com/XZ-libin/agent-ops/contract/gen/go/agent_ops/contract/v1"

	"github.com/XZ-libin/agent-ops/gateway/internal/approvals"
	"github.com/XZ-libin/agent-ops/internal/audit"
)

// —— 网关审计事件（第八轮约束 7 + 第九轮 R4）——
// 事件类型：
//
//	gateway.decision      —— allow / require_approval / deny（含网关级拒绝、
//	                          审批执行路径的重评拒绝）
//	approval.created      —— require_approval 分支的 pending 记录创建
//	approval.approved / approval.rejected / approval.expired —— 审批状态事件
//	gateway.executing     —— 执行开始前（R4：先于执行写入，崩溃对账依据）
//	gateway.executed      —— 执行成功（终态）
//	gateway.execution.failed —— 执行失败（终态；payload 只记 outcome）
//	gateway.execution.replayed —— 幂等重放（终态，用于闭合 executing 记录）
//	gateway.execution.skipped  —— 幂等 422/409 跳过（终态）
//	gateway.execution.abandoned —— 对账发现 executing 后无终态（进程崩溃）
//
// 终态集合（closure）：Reconcile 以 execution_id 匹配 executing 与终态事件。
var terminalActions = map[string]bool{
	"gateway.executed":            true,
	"gateway.execution.failed":    true,
	"gateway.execution.replayed":  true,
	"gateway.execution.skipped":   true,
	"gateway.execution.abandoned": true,
}

// decisionPayload 决策事件载荷。
type decisionPayload struct {
	Actor      string   `json:"actor"`
	Capability string   `json:"capability"`
	Decision   string   `json:"decision"` // allow / require_approval / deny
	Tier       string   `json:"tier"`
	Reasons    []string `json:"reasons"`
}

// executingPayload 执行开始事件载荷（R4）。
type executingPayload struct {
	Actor       string `json:"actor"`
	Capability  string `json:"capability"`
	ExecutionID string `json:"execution_id"`
	ApprovalID  string `json:"approval_id,omitempty"`
}

// executionPayload 执行结果事件载荷。
type executionPayload struct {
	Actor       string `json:"actor"`
	Capability  string `json:"capability"`
	Success     bool   `json:"success"`
	ExecutionID string `json:"execution_id,omitempty"`
	ApprovalID  string `json:"approval_id,omitempty"`
}

// skipPayload 幂等跳过事件载荷（408/409/重放之外的 422/409）。
type skipPayload struct {
	Actor       string `json:"actor"`
	Capability  string `json:"capability"`
	ExecutionID string `json:"execution_id"`
	ApprovalID  string `json:"approval_id,omitempty"`
	Reason      string `json:"reason"`
}

// replayedPayload 幂等重放事件载荷。
type replayedPayload struct {
	Actor       string `json:"actor"`
	Capability  string `json:"capability"`
	ExecutionID string `json:"execution_id"`
	ApprovalID  string `json:"approval_id,omitempty"`
}

// abandonedPayload 对账发现的中断执行（R4：abandoned 绝不自动重放）。
type abandonedPayload struct {
	ExecutionID string `json:"execution_id"`
	Reason      string `json:"reason"`
}

// approvalCreatedPayload 审批创建事件载荷。
type approvalCreatedPayload struct {
	Actor      string `json:"actor"`
	Capability string `json:"capability"`
	ApprovalID string `json:"approval_id"`
	Status     string `json:"status"`
}

// approvalStatePayload 审批状态事件载荷（approved/rejected/expired）。
type approvalStatePayload struct {
	ApprovalID string `json:"approval_id"`
	Actor      string `json:"actor"`
	Capability string `json:"capability"`
	Status     string `json:"status"`
	DecidedBy  string `json:"decided_by,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

// decisionLabel 决策到审计标签（allow / require_approval / deny）。
func decisionLabel(d contractv1.Decision) string {
	switch d {
	case contractv1.Decision_DECISION_AUTO:
		return "allow"
	case contractv1.Decision_DECISION_REQUIRE_APPROVAL:
		return "require_approval"
	case contractv1.Decision_DECISION_DENY:
		return "deny"
	}
	return "unspecified"
}

// DecisionLabel 决策到审计/契约标签（allow / require_approval / deny）。
// 供对外契约（gRPC 结局）复用同一套标签，避免两处各写一份映射。
func DecisionLabel(d contractv1.Decision) string { return decisionLabel(d) }

// decisionFromLabel 标签回映射（幂等重放用）。
func decisionFromLabel(label string) contractv1.Decision {
	switch label {
	case "allow":
		return contractv1.Decision_DECISION_AUTO
	case "require_approval":
		return contractv1.Decision_DECISION_REQUIRE_APPROVAL
	case "deny":
		return contractv1.Decision_DECISION_DENY
	}
	return contractv1.Decision_DECISION_UNSPECIFIED
}

// auditDecision 写入 gateway.decision（决策审计失败即返回错误 → fail-closed）。
func (s *Service) auditDecision(ctx context.Context, req Request, decision contractv1.Decision, tier contractv1.RiskTier, reasons []string) error {
	_, err := s.audit.Append(ctx, audit.Event{
		ID:     newGatewayEventID(),
		Actor:  req.Actor,
		Action: "gateway.decision",
		Target: req.Action.Capability,
		Payload: decisionPayload{
			Actor:      req.Actor,
			Capability: req.Action.Capability,
			Decision:   decisionLabel(decision),
			Tier:       tier.String(),
			Reasons:    reasons,
		},
	})
	return err
}

// auditExecution 写入 gateway.executed / gateway.execution.failed（终态）。
func (s *Service) auditExecution(ctx context.Context, req Request, success bool, executionID, approvalID string) error {
	action := "gateway.executed"
	if !success {
		action = "gateway.execution.failed"
	}
	_, err := s.audit.Append(ctx, audit.Event{
		ID:     newGatewayEventID(),
		Actor:  req.Actor,
		Action: action,
		Target: req.Action.Capability,
		Payload: executionPayload{
			Actor:       req.Actor,
			Capability:  req.Action.Capability,
			Success:     success,
			ExecutionID: executionID,
			ApprovalID:  approvalID,
		},
	})
	return err
}

// auditExecuting 写入 gateway.executing（R4：执行前、幂等前，崩溃对账依据）。
func (s *Service) auditExecuting(ctx context.Context, req Request, executionID, approvalID string) error {
	_, err := s.audit.Append(ctx, audit.Event{
		ID:     newGatewayEventID(),
		Actor:  req.Actor,
		Action: "gateway.executing",
		Target: req.Action.Capability,
		Payload: executingPayload{
			Actor:       req.Actor,
			Capability:  req.Action.Capability,
			ExecutionID: executionID,
			ApprovalID:  approvalID,
		},
	})
	return err
}

// auditSkipped 写入 gateway.execution.skipped（幂等 422/409 等未执行终态）。
func (s *Service) auditSkipped(ctx context.Context, req Request, executionID, approvalID, reason string) error {
	_, err := s.audit.Append(ctx, audit.Event{
		ID:     newGatewayEventID(),
		Actor:  req.Actor,
		Action: "gateway.execution.skipped",
		Target: req.Action.Capability,
		Payload: skipPayload{
			Actor:       req.Actor,
			Capability:  req.Action.Capability,
			ExecutionID: executionID,
			ApprovalID:  approvalID,
			Reason:      reason,
		},
	})
	return err
}

// auditReplayed 写入 gateway.execution.replayed（幂等重放终态，闭合 executing）。
func (s *Service) auditReplayed(ctx context.Context, req Request, executionID, approvalID string) error {
	_, err := s.audit.Append(ctx, audit.Event{
		ID:     newGatewayEventID(),
		Actor:  req.Actor,
		Action: "gateway.execution.replayed",
		Target: req.Action.Capability,
		Payload: replayedPayload{
			Actor:       req.Actor,
			Capability:  req.Action.Capability,
			ExecutionID: executionID,
			ApprovalID:  approvalID,
		},
	})
	return err
}

// appendAbandoned 写入 gateway.execution.abandoned（对账标记崩溃中断的执行）。
func (s *Service) appendAbandoned(ctx context.Context, executionID, reason string) error {
	_, err := s.audit.Append(ctx, audit.Event{
		ID:     newGatewayEventID(),
		Actor:  "system",
		Action: "gateway.execution.abandoned",
		Target: executionID,
		Payload: abandonedPayload{
			ExecutionID: executionID,
			Reason:      reason,
		},
	})
	return err
}

// auditApprovalState 写入 approval.approved / approval.rejected / approval.expired。
func (s *Service) auditApprovalState(ctx context.Context, rec approvals.Record, action string) error {
	_, err := s.audit.Append(ctx, audit.Event{
		ID:     newGatewayEventID(),
		Actor:  rec.Actor,
		Action: action,
		Target: rec.ID,
		Payload: approvalStatePayload{
			ApprovalID: rec.ID,
			Actor:      rec.Actor,
			Capability: rec.Capability,
			Status:     string(rec.Status),
			DecidedBy:  rec.DecidedBy,
			Reason:     rec.Reason,
		},
	})
	return err
}

// auditApprovalCreated 写入 approval.created。
func (s *Service) auditApprovalCreated(ctx context.Context, req Request, rec approvals.Record) error {
	_, err := s.audit.Append(ctx, audit.Event{
		ID:     newGatewayEventID(),
		Actor:  req.Actor,
		Action: "approval.created",
		Target: rec.ID,
		Payload: approvalCreatedPayload{
			Actor:      req.Actor,
			Capability: rec.Capability,
			ApprovalID: rec.ID,
			Status:     string(rec.Status),
		},
	})
	return err
}

// newGatewayEventID 生成本地事件 ID（随机 hex；与 audit 包形状一致，ULID
// 类 ID 规范随资产模块统一后替换）。
func newGatewayEventID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand 失败属于环境异常，直接暴露。
		panic(fmt.Sprintf("gateway event id: %v", err))
	}
	return "evt-" + hex.EncodeToString(b)
}

// newExecutionID 生成执行 ID（exec- 前缀随机 hex；对账以它匹配 executing 与终态）。
func newExecutionID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("gateway execution id: %v", err))
	}
	return "exec-" + hex.EncodeToString(b)
}
