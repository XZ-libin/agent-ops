package grpcwire

import (
	"context"
	"errors"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	contractv1 "github.com/XZ-libin/agent-ops/contract/gen/go/agent_ops/contract/v1"

	"github.com/XZ-libin/agent-ops/gateway/internal/gateway"
)

// —— G1 错误码映射（固定，不随实现漂移） ——

// TestGRPCCodeMappingFixed 固定映射表：策略拒绝/幂等冲突/审批状态/审计失败
// 分别对应 PERMISSION_DENIED / ALREADY_EXISTS / FAILED_PRECONDITION / INTERNAL。
func TestGRPCCodeMappingFixed(t *testing.T) {
	cases := []struct {
		name string
		code gateway.Code
		want codes.Code
	}{
		{"策略拒绝", gateway.CodePolicyDenied, codes.PermissionDenied},
		{"幂等冲突", gateway.CodeIdemConflict, codes.AlreadyExists},
		{"审批状态不允许", gateway.CodeApprovalState, codes.FailedPrecondition},
		{"审计失败", gateway.CodeAuditFailed, codes.Internal},
		{"未认证", gateway.CodeUnauthenticated, codes.Unauthenticated},
		{"参数非法", gateway.CodeInvalidArgument, codes.InvalidArgument},
		{"记录不存在", gateway.CodeNotFound, codes.NotFound},
		{"未分类", gateway.CodeNone, codes.Internal},
		{"内部错误", gateway.CodeInternal, codes.Internal},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := grpcCode(tc.code); got != tc.want {
				t.Fatalf("映射不符：%s → %s，期望 %s", tc.code, got, tc.want)
			}
		})
	}
}

// TestErrorStatusMapsWrappedErrors 基础设施错误的 Code 透传（含审计失败 → INTERNAL）。
func TestErrorStatusMapsWrappedErrors(t *testing.T) {
	err := gateway.Wrap(gateway.CodeAuditFailed, errors.New("审计库不可用"))
	if got := status.Code(errorStatus(err)); got != codes.Internal {
		t.Fatalf("审计失败应映射 INTERNAL，实际 %s", got)
	}
	err = gateway.Wrap(gateway.CodeApprovalState, errors.New("审批已消费"))
	if got := status.Code(errorStatus(err)); got != codes.FailedPrecondition {
		t.Fatalf("审批状态不允许应映射 FAILED_PRECONDITION，实际 %s", got)
	}
	err = gateway.Wrap(gateway.CodePolicyDenied, errors.New("四眼原则"))
	if got := status.Code(errorStatus(err)); got != codes.PermissionDenied {
		t.Fatalf("策略拒绝应映射 PERMISSION_DENIED，实际 %s", got)
	}
}

// TestOutcomeStatus 业务性结局：success/pending 为正常响应；其余按 Code 映射为错误。
func TestOutcomeStatus(t *testing.T) {
	if err := outcomeStatus(&gateway.Response{Status: gateway.StatusSuccess}); err != nil {
		t.Fatalf("成功不应返回错误：%v", err)
	}
	if err := outcomeStatus(&gateway.Response{Status: gateway.StatusPendingApproval}); err != nil {
		t.Fatalf("pending 不应返回错误：%v", err)
	}
	denied := &gateway.Response{Status: gateway.StatusDenied, Code: gateway.CodePolicyDenied, Message: "破坏性"}
	if got := status.Code(outcomeStatus(denied)); got != codes.PermissionDenied {
		t.Fatalf("拒绝应映射 PERMISSION_DENIED，实际 %s", got)
	}
	conflict := &gateway.Response{Status: gateway.StatusConflict, Code: gateway.CodeIdemConflict}
	if got := status.Code(outcomeStatus(conflict)); got != codes.AlreadyExists {
		t.Fatalf("幂等冲突应映射 ALREADY_EXISTS，实际 %s", got)
	}
	pre := &gateway.Response{Status: gateway.StatusDenied, Code: gateway.CodeApprovalState}
	if got := status.Code(outcomeStatus(pre)); got != codes.FailedPrecondition {
		t.Fatalf("审批状态不允许应映射 FAILED_PRECONDITION，实际 %s", got)
	}
}

// —— 仅测试静态 token 认证 ——

// TestStaticTokenAuth 仅测试认证：缺失/未知/非 Bearer → 拒绝；命中 → 返回 actor。
func TestStaticTokenAuth(t *testing.T) {
	auth := NewStaticTokenAuth(map[string]string{
		testRequesterToken: "ops-lead",
		testApproverToken:  "ops-auditor",
	})
	withMD := func(kv ...string) context.Context {
		return metadata.NewIncomingContext(context.Background(), metadata.Pairs(kv...))
	}
	if _, err := auth.Authenticate(context.Background()); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("无 metadata 应拒绝：%v", err)
	}
	if _, err := auth.Authenticate(withMD(MetaAuthorization, "Bearer unknown-token")); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("未知 token 应拒绝：%v", err)
	}
	if _, err := auth.Authenticate(withMD(MetaAuthorization, testRequesterToken)); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("非 Bearer 形式应拒绝：%v", err)
	}
	actor, err := auth.Authenticate(withMD(MetaAuthorization, "Bearer "+testRequesterToken))
	if err != nil || actor != "ops-lead" {
		t.Fatalf("有效 token 应解析出 actor：actor=%q err=%v", actor, err)
	}
	// 未配置任何 token → 一律拒绝（fail-closed）。
	empty := NewStaticTokenAuth(nil)
	if _, err := empty.Authenticate(withMD(MetaAuthorization, "Bearer "+testRequesterToken)); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("未配置 token 时应拒绝：%v", err)
	}
}

// TestServerRejectsUnauthenticated 未携带可信身份的 RPC 一律 UNAUTHENTICATED
// （认证先于任何业务逻辑；本用例的服务依赖为 nil，能进一步证明未触达业务层）。
func TestServerRejectsUnauthenticated(t *testing.T) {
	srv := grpc.NewServer()
	contractv1.RegisterGatewayServer(srv, NewServer(nil,
		NewStaticTokenAuth(map[string]string{testRequesterToken: "ops-lead"})))
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	client := contractv1.NewGatewayClient(conn)
	ctx := context.Background()

	if _, err := client.SubmitExecute(ctx, &contractv1.SubmitExecuteRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("无身份提交应 UNAUTHENTICATED，实际 %v", err)
	}
	if _, err := client.Approve(ctx, &contractv1.ApproveRequest{ApprovalId: "apr-x"}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("无身份审批应 UNAUTHENTICATED，实际 %v", err)
	}
	if _, err := client.ExecuteApproved(ctx, &contractv1.ExecuteApprovedRequest{ApprovalId: "apr-x"}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("无身份执行应 UNAUTHENTICATED，实际 %v", err)
	}
	if _, err := client.GetApproval(ctx, &contractv1.GetApprovalRequest{ApprovalId: "apr-x"}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("无身份查询应 UNAUTHENTICATED，实际 %v", err)
	}

	// 携带有效身份但缺少必填字段 → INVALID_ARGUMENT（请求边界校验）。
	withToken := metadata.NewOutgoingContext(ctx,
		metadata.Pairs(MetaAuthorization, "Bearer "+testRequesterToken))
	if _, err := client.SubmitExecute(withToken, &contractv1.SubmitExecuteRequest{}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("缺动作/幂等键应 INVALID_ARGUMENT，实际 %v", err)
	}
}

// —— H3：运行模式与认证守卫 ——

// TestParseModeRequiresExplicitValue mode 必须显式指定（无默认值），
// 且只接受 test / prod。
func TestParseModeRequiresExplicitValue(t *testing.T) {
	for _, tc := range []struct {
		in, want string
		wantErr  bool
	}{
		{"test", "test", false},
		{"prod", "prod", false},
		{"", "", true},
		{"staging", "", true},
	} {
		got, err := ParseMode(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("mode=%q 应报错", tc.in)
			}
			continue
		}
		if err != nil || string(got) != tc.want {
			t.Fatalf("mode=%q → (%q, %v)", tc.in, got, err)
		}
	}
}

// TestGuardAuthRejectsStaticTokenInProduction mode=prod 时启用仅测试静态 token
// 一律拒绝（代码层面，不依赖文档）；mode=test 允许。
func TestGuardAuthRejectsStaticTokenInProduction(t *testing.T) {
	static := NewStaticTokenAuth(map[string]string{"t": "ops-lead"})
	if err := GuardAuth(ModeProd, static); !errors.Is(err, ErrTestAuthInProduction) {
		t.Fatalf("prod + 静态 token 应拒绝：%v", err)
	}
	if err := GuardAuth(ModeTest, static); err != nil {
		t.Fatalf("test + 静态 token 应允许：%v", err)
	}
	// 未配置任何 token 的生产实例同样拒绝：prod 不得引入仅测试认证对象（H3）。
	empty := NewStaticTokenAuth(nil)
	if err := GuardAuth(ModeProd, empty); !errors.Is(err, ErrTestAuthInProduction) {
		t.Fatalf("prod + 未配置 token 的静态认证应拒绝：%v", err)
	}
}
