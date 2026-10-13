package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/XZ-libin/agent-ops/gateway/internal/approvals"
)

// Reconcile 对账（R4 + 第十轮 F2 + 第十一轮 H1）：
//
//  1. 审计层：扫描 gateway.executing 事件，找出没有终态事件
//     （executed / execution.failed / execution.replayed / execution.skipped /
//     execution.abandoned）的执行，追加 gateway.execution.abandoned 标记；
//  2. 审批层（H1）：**只**把 status=executing 且 **lease_until 已过期**
//     （含无租约记录）的审批标记 abandoned——未过期的记录一律跳过，
//     因为它可能仍在执行中（租约即"仍在运行"的凭据）。
//
// 覆盖两个窗口：CAS 抢占成功但 executing 审计未写（无 executing 事件可扫），
// 以及 executing 已写但进程在终态前崩溃。
//
// 对账只写 abandoned 标记：abandoned 的写操作绝不自动重放——重试命中审批状态
// （executing/abandoned → FAILED_PRECONDITION）与幂等存储的 abandoned/409 语义。
//
// 前置条件（工程默认，待运维确认）：本进程必须是单实例（GuardSingleInstance），
// 否则并发实例的在飞行执行会被误判；多实例部署被禁止。
//
// 返回追加的 abandoned 审计事件数。
func (s *Service) Reconcile(ctx context.Context) (int, error) {
	executing, err := s.audit.ListByAction(ctx, "gateway.executing")
	if err != nil {
		return 0, fmt.Errorf("gateway：读取 executing 事件失败：%w", err)
	}
	terminated := make(map[string]bool)        // execution_id → 已有终态
	terminalApprovals := make(map[string]bool) // approval_id → 已有终态
	for _, action := range []string{
		"gateway.executed", "gateway.execution.failed", "gateway.execution.replayed",
		"gateway.execution.skipped", "gateway.execution.abandoned",
	} {
		events, err := s.audit.ListByAction(ctx, action)
		if err != nil {
			return 0, fmt.Errorf("gateway：读取终态事件 %s 失败：%w", action, err)
		}
		for _, ev := range events {
			if id := executionIDFromPayload(ev.Payload); id != "" {
				terminated[id] = true
			}
			if aid := approvalIDFromPayload(ev.Payload); aid != "" {
				terminalApprovals[aid] = true
			}
		}
	}

	count := 0
	for _, ev := range executing {
		id := executionIDFromPayload(ev.Payload)
		if id == "" || terminated[id] {
			continue
		}
		if err := s.appendAbandoned(ctx, id, "对账：executing 后无终态事件（疑似进程崩溃），不自动重放"); err != nil {
			return count, fmt.Errorf("gateway：写入 abandoned 事件失败：%w", err)
		}
		count++
	}

	// H1：审批层只处理租约已过期的 executing（未过期的一律跳过）。
	recs, err := s.approvals.ListExpiredExecuting(ctx, s.cfg.Now())
	if err != nil {
		return count, fmt.Errorf("gateway：读取过期 executing 审批失败：%w", err)
	}
	for _, rec := range recs {
		if terminalApprovals[rec.ID] {
			continue
		}
		marked, merr := s.approvals.MarkAbandoned(ctx, rec.ID)
		if merr != nil {
			if errors.Is(merr, approvals.ErrNotFound) {
				continue // 记录已被清理：跳过
			}
			return count, fmt.Errorf("gateway：审批 %s 标记 abandoned 失败：%w", rec.ID, merr)
		}
		_ = s.auditApprovalState(ctx, marked, "approval.abandoned")
	}
	return count, nil
}

// executionIDFromPayload 从事件 payload 提取 execution_id（旧格式/解析失败返回空）。
func executionIDFromPayload(payload json.RawMessage) string {
	var probe struct {
		ExecutionID string `json:"execution_id"`
	}
	if err := json.Unmarshal(payload, &probe); err != nil {
		return ""
	}
	return probe.ExecutionID
}

// approvalIDFromPayload 从事件 payload 提取 approval_id（无则空）。
func approvalIDFromPayload(payload json.RawMessage) string {
	var probe struct {
		ApprovalID string `json:"approval_id"`
	}
	if err := json.Unmarshal(payload, &probe); err != nil {
		return ""
	}
	return probe.ApprovalID
}
