package grpcwire

import (
	"context"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	contractv1 "github.com/ORG/agent-ops/contract/gen/go/agent_ops/contract/v1"

	"github.com/ORG/agent-ops/gateway/internal/approvals"
	"github.com/ORG/agent-ops/gateway/internal/gateway"
)

// Server 执行网关的 gRPC 服务实现（第十轮 G1）。
// 只做三件事：认证取 actor → 契约消息与内部 Request 互转 → 错误码映射；
// 所有策略/幂等/审批/审计语义都在 gateway.Service 内，本包不复制任何判定逻辑。
type Server struct {
	contractv1.UnimplementedGatewayServer
	svc  *gateway.Service
	auth Authenticator
}

// NewServer 构建 gRPC 服务；auth 为 nil 时所有请求以 UNAUTHENTICATED 拒绝
// （fail-closed）。
func NewServer(svc *gateway.Service, auth Authenticator) *Server {
	return &Server{svc: svc, auth: auth}
}

// Health 健康检查占位（与对外 REST 的 /healthz 对应）。
func (s *Server) Health(_ context.Context, _ *contractv1.HealthRequest) (*contractv1.HealthResponse, error) {
	return &contractv1.HealthResponse{Status: "ok"}, nil
}

// SubmitExecute 提交执行：策略 → 幂等 → 执行 → 审计；需审批时只创建 pending 记录。
func (s *Server) SubmitExecute(ctx context.Context, req *contractv1.SubmitExecuteRequest) (*contractv1.SubmitExecuteResponse, error) {
	actor, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}
	gReq, err := toRequest(actor, req.GetAction(), req.GetEnvironment(), req.GetIdempotencyKey(), req.GetFreezeWindow())
	if err != nil {
		return nil, err
	}
	if s.svc == nil {
		return nil, status.Error(codes.Internal, "gateway：服务未初始化")
	}
	resp, err := s.svc.Execute(ctx, gReq)
	if err != nil {
		return nil, errorStatus(err)
	}
	if err := outcomeStatus(resp); err != nil {
		return nil, err
	}
	return &contractv1.SubmitExecuteResponse{Outcome: toOutcome(resp)}, nil
}

// Approve 审批通过（四眼原则：审批人必须不同于请求人；审批人为认证身份）。
func (s *Server) Approve(ctx context.Context, req *contractv1.ApproveRequest) (*contractv1.ApproveResponse, error) {
	actor, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetApprovalId() == "" {
		return nil, status.Error(codes.InvalidArgument, "gateway：缺少 approval_id")
	}
	if s.svc == nil {
		return nil, status.Error(codes.Internal, "gateway：服务未初始化")
	}
	rec, err := s.svc.Approve(ctx, req.GetApprovalId(), actor, req.GetReason())
	if err != nil {
		return nil, errorStatus(err)
	}
	return &contractv1.ApproveResponse{Approval: toApprovalRecord(rec)}, nil
}

// Reject 审批拒绝（拒绝人为认证身份）。
func (s *Server) Reject(ctx context.Context, req *contractv1.RejectRequest) (*contractv1.RejectResponse, error) {
	actor, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetApprovalId() == "" {
		return nil, status.Error(codes.InvalidArgument, "gateway：缺少 approval_id")
	}
	if s.svc == nil {
		return nil, status.Error(codes.Internal, "gateway：服务未初始化")
	}
	rec, err := s.svc.Reject(ctx, req.GetApprovalId(), actor, req.GetReason())
	if err != nil {
		return nil, errorStatus(err)
	}
	return &contractv1.RejectResponse{Approval: toApprovalRecord(rec)}, nil
}

// ExecuteApproved 审批通过后的受控执行（先占后执行）。
func (s *Server) ExecuteApproved(ctx context.Context, req *contractv1.ExecuteApprovedRequest) (*contractv1.ExecuteApprovedResponse, error) {
	actor, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetApprovalId() == "" {
		return nil, status.Error(codes.InvalidArgument, "gateway：缺少 approval_id")
	}
	gReq, err := toRequest(actor, req.GetAction(), req.GetEnvironment(), req.GetIdempotencyKey(), req.GetFreezeWindow())
	if err != nil {
		return nil, err
	}
	if s.svc == nil {
		return nil, status.Error(codes.Internal, "gateway：服务未初始化")
	}
	resp, err := s.svc.ExecuteApproved(ctx, gReq, req.GetApprovalId())
	if err != nil {
		return nil, errorStatus(err)
	}
	if err := outcomeStatus(resp); err != nil {
		return nil, err
	}
	return &contractv1.ExecuteApprovedResponse{Outcome: toOutcome(resp)}, nil
}

// GetApproval 查询审批记录。
func (s *Server) GetApproval(ctx context.Context, req *contractv1.GetApprovalRequest) (*contractv1.GetApprovalResponse, error) {
	if _, err := s.authenticate(ctx); err != nil {
		return nil, err
	}
	if s.svc == nil {
		return nil, status.Error(codes.Internal, "gateway：服务未初始化")
	}
	rec, err := s.svc.GetApproval(ctx, req.GetApprovalId())
	if err != nil {
		return nil, errorStatus(err)
	}
	return &contractv1.GetApprovalResponse{Approval: toApprovalRecord(rec)}, nil
}

// —— 契约 ↔ 内部模型转换 ——

// toRequest 契约请求 → 网关 Request（actor 来自认证身份，不由请求体提供）。
func toRequest(actor string, action *contractv1.Action, env contractv1.Environment,
	key string, freeze bool) (gateway.Request, error) {
	if action == nil || action.GetCapability() == "" {
		return gateway.Request{}, status.Error(codes.InvalidArgument, "gateway：请求缺少执行动作/能力名")
	}
	if key == "" {
		return gateway.Request{}, status.Error(codes.InvalidArgument, "gateway：请求缺少幂等键 idempotency_key")
	}
	return gateway.Request{
		Actor:          actor,
		IdempotencyKey: key,
		Action:         action,
		Environment:    env,
		FreezeWindow:   freeze,
	}, nil
}

// toOutcome 网关响应 → 契约结局。
func toOutcome(resp *gateway.Response) *contractv1.ExecuteOutcome {
	if resp == nil {
		return nil
	}
	return &contractv1.ExecuteOutcome{
		Status:     string(resp.Status),
		Decision:   gateway.DecisionLabel(resp.Decision),
		Reasons:    resp.Reasons,
		ApprovalId: resp.ApprovalID,
		Result:     resp.Result,
		Message:    resp.Message,
		Replayed:   resp.Replayed,
	}
}

// toApprovalRecord 审批记录 → 契约投影。
func toApprovalRecord(rec approvals.Record) *contractv1.ApprovalRecord {
	out := &contractv1.ApprovalRecord{
		Id:         rec.ID,
		Actor:      rec.Actor,
		Capability: rec.Capability,
		Status:     string(rec.Status),
		CreatedAt:  timestampOrNil(rec.CreatedAt),
		ExpiresAt:  timestampOrNil(rec.ExpiresAt),
		DecidedBy:  rec.DecidedBy,
		Reason:     rec.Reason,
	}
	if rec.ApprovedAt != nil {
		out.ApprovedAt = timestamppb.New(*rec.ApprovedAt)
	}
	return out
}

// timestampOrNil 零值时间 → nil（proto3 可选语义）。
func timestampOrNil(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}

// —— 错误码映射 ——

// grpcCode 网关结局分类 → gRPC 错误码（固定映射表，见包注释）。
func grpcCode(code gateway.Code) codes.Code {
	switch code {
	case gateway.CodePolicyDenied:
		return codes.PermissionDenied
	case gateway.CodeIdemConflict:
		return codes.AlreadyExists
	case gateway.CodeApprovalState:
		return codes.FailedPrecondition
	case gateway.CodeAuditFailed:
		return codes.Internal
	case gateway.CodeUnauthenticated:
		return codes.Unauthenticated
	case gateway.CodeInvalidArgument:
		return codes.InvalidArgument
	case gateway.CodeNotFound:
		return codes.NotFound
	}
	return codes.Internal
}

// errorStatus 基础设施性失败 → gRPC 状态（含审计失败 → INTERNAL）。
func errorStatus(err error) error {
	if err == nil {
		return nil
	}
	if st, ok := status.FromError(err); ok && st.Code() != codes.Unknown {
		return err // 已是 gRPC 状态（如 InvalidArgument）
	}
	code := grpcCode(gateway.CodeOf(err))
	if code == codes.Internal && gateway.CodeOf(err) == gateway.CodeNone {
		return status.Error(codes.Internal, "gateway：内部错误")
	}
	// 错误信息经脱敏（含凭据形态字段掩码）：凭据不得经错误通道外泄（约束 8）。
	return status.Error(code, gateway.Sanitize(err.Error()))
}

// outcomeStatus 业务性结局 → gRPC 状态：success/pending 返回 nil（正常响应），
// 其余按固定映射返回错误，并把完整结局作为错误详情附带（客户端可用 status.Details 取回）。
func outcomeStatus(resp *gateway.Response) error {
	if resp == nil {
		return status.Error(codes.Internal, "gateway：内部错误")
	}
	switch resp.Status {
	case gateway.StatusSuccess, gateway.StatusPendingApproval:
		return nil
	}
	code := grpcCode(resp.Code)
	if resp.Code == gateway.CodeNone {
		// 未分类的非成功结局：failed → INTERNAL（工程默认，见假设清单）。
		code = codes.Internal
	}
	msg := gateway.Sanitize(resp.Message)
	if msg == "" {
		msg = string(resp.Status)
	}
	st := status.New(code, msg)
	if withDetails, derr := st.WithDetails(toOutcome(resp)); derr == nil {
		return withDetails.Err()
	}
	return st.Err()
}
