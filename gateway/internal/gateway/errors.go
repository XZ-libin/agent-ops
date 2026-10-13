package gateway

import (
	"errors"
	"fmt"
)

// —— 机器可读错误分类（第十轮 G1：gRPC 错误码映射的唯一依据）——
//
// 业务性结局（拒绝/冲突/状态不允许）以 Response.Code 表达（err 为 nil）；
// 基础设施性失败（依赖不可用、审计写入失败等）以带 Code 的 error 表达。
// 两类统一经 CodeOf / Response.Code 映射到固定 gRPC 错误码：
//
//	CodePolicyDenied   → PERMISSION_DENIED（策略拒绝、destructive、能力未声明）
//	CodeIdemConflict   → ALREADY_EXISTS   （幂等/审批去重的内容冲突）
//	CodeApprovalState  → FAILED_PRECONDITION（审批状态不允许或审批与请求不匹配）
//	CodeAuditFailed    → INTERNAL         （审计写入失败，fail closed）
//	CodeUnauthenticated→ UNAUTHENTICATED  （身份缺失或不可信）
//	CodeInvalidArgument→ INVALID_ARGUMENT （请求边界校验失败）
//	CodeNotFound       → NOT_FOUND        （审批记录不存在）
//	CodeInternal       → INTERNAL         （其余基础设施失败）
type Code string

const (
	// CodeNone 无分类（成功或未分类）。
	CodeNone Code = ""
	// CodePolicyDenied 策略/网关拒绝（不可通过审批解除的条件）。
	CodePolicyDenied Code = "policy_denied"
	// CodeIdemConflict 幂等键或审批去重的内容冲突（HTTP 422 语义）。
	CodeIdemConflict Code = "idempotency_conflict"
	// CodeApprovalState 审批状态不允许（pending/expired/consumed/executing/abandoned）
	// 或审批与请求不匹配（内容/请求人/审批人）。
	CodeApprovalState Code = "approval_state"
	// CodeAuditFailed 审计写入失败（fail closed）。
	CodeAuditFailed Code = "audit_failed"
	// CodeUnauthenticated 身份缺失或不可信（gRPC 层认证）。
	CodeUnauthenticated Code = "unauthenticated"
	// CodeInvalidArgument 请求边界校验失败。
	CodeInvalidArgument Code = "invalid_argument"
	// CodeNotFound 目标记录不存在。
	CodeNotFound Code = "not_found"
	// CodeInternal 其余基础设施失败。
	CodeInternal Code = "internal"
)

// codedError 携带 Code 的错误（保留原始 error 链，便于 errors.Is/As 判定）。
type codedError struct {
	code Code
	err  error
}

func (e *codedError) Error() string { return e.err.Error() }
func (e *codedError) Unwrap() error { return e.err }
func (e *codedError) Code() Code    { return e.code }

// codeCarrier 由 CodeOf 识别的最小接口（避免依赖具体类型）。
type codeCarrier interface{ Code() Code }

// Errorf 构造带 Code 的错误（msg 经调用方传入，不携带凭据）。
func Errorf(code Code, format string, args ...any) error {
	return &codedError{code: code, err: fmt.Errorf(format, args...)}
}

// Wrap 为已有错误贴 Code（保留原错误链）。
func Wrap(code Code, err error) error {
	if err == nil {
		return nil
	}
	return &codedError{code: code, err: err}
}

// CodeOf 提取错误的 Code；未分类返回 CodeNone（调用方按 Internal 兜底）。
func CodeOf(err error) Code {
	if err == nil {
		return CodeNone
	}
	var c codeCarrier
	if errors.As(err, &c) {
		return c.Code()
	}
	return CodeNone
}
