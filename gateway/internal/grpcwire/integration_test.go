package grpcwire

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"

	contractv1 "github.com/ORG/agent-ops/contract/gen/go/agent_ops/contract/v1"

	"github.com/ORG/agent-ops/adapters/linux"
	"github.com/ORG/agent-ops/gateway/internal/approvals"
	"github.com/ORG/agent-ops/gateway/internal/gateway"
	"github.com/ORG/agent-ops/gateway/internal/testwrite"
	"github.com/ORG/agent-ops/internal/audit"
	"github.com/ORG/agent-ops/internal/exec"
	"github.com/ORG/agent-ops/internal/exec/ssh"
	"github.com/ORG/agent-ops/internal/exec/ssh/sshdtest"
	"github.com/ORG/agent-ops/internal/idempotency"
	"github.com/ORG/agent-ops/internal/testdb"
)

// 仅测试的静态 token（第十轮 G1：认证方式为仅测试静态 token；
// 这些字符串是测试常量，不是任何真实凭据）。
const (
	testRequesterToken = "itest-token-requester" // 仅测试
	testApproverToken  = "itest-token-approver"  // 仅测试
)

// TestGRPCIntegrationReadonlyAndApprovedWrite 第十轮 G3 端到端集成（D3）：
// Docker 可用则真跑本地 sshd 测试容器（临时密钥、127.0.0.1 随机端口）；
// PostgreSQL（55432）不可用则 skip 并输出原因。
//
// 通过**真实 gRPC 客户端**调用真实服务，覆盖：
//  1. 只读能力（diagnose.disk_usage）SubmitExecute → 真实 SSH 执行；
//  2. 写能力（test.write.marker）SubmitExecute → pending → 四眼拒绝（同人）
//     → 审批人批准 → 批准前执行 FailedPrecondition → 批准后执行成功
//     → 标记文件落盘 → GetApproval 为 consumed；
//  3. destructive 能力经 gRPC 提交 → PERMISSION_DENIED 且未到达 SSH 层。
func TestGRPCIntegrationReadonlyAndApprovedWrite(t *testing.T) {
	sshd := sshdtest.StartLocalSSHD(t)
	pool := integrationPool(t)
	ctx := context.Background()

	// 真实审计表与审批表（test_ 前缀）。
	auditTable := fmt.Sprintf("test_audit_events_grpc_%d", time.Now().UnixNano())
	aud := audit.NewTestStore(pool, auditTable)
	if err := aud.EnsureSchema(ctx); err != nil {
		t.Fatalf("审计建表失败（非 skip）：%v", err)
	}
	// 审批表按运行唯一命名（第十二轮修复：固定表名会被并行运行的其它包清空）。
	approvalTable := fmt.Sprintf("test_approvals_grpc_%d", time.Now().UnixNano())
	apStore := approvals.NewTestPostgresStore(pool, approvalTable)
	if err := apStore.EnsureSchema(ctx); err != nil {
		t.Fatalf("审批建表失败（非 skip）：%v", err)
	}

	inner, err := ssh.New(ssh.Options{Addr: sshd.Addr, User: sshd.User, Signer: sshd.Signer, HostKey: sshd.HostKey})
	if err != nil {
		t.Fatalf("构建 SSH Runner 失败：%v", err)
	}
	t.Cleanup(func() { _ = inner.Close() })
	counter := &countingRunner{inner: inner}
	t.Cleanup(func() {
		// 清理本用例写入的标记文件（仅测试容器内的 /tmp/agent-ops-test）。
		_, _ = inner.Run(context.Background(),
			[]string{"rm", "-f", testwrite.MarkerPath("grpc10a")}, exec.RunOptions{})
	})

	// 注册表（仅测试）：Linux 只读诊断 + 测试写能力 + 破坏性能力。
	reg := gateway.NewTestRegistry() // 仅测试
	lin, err := linux.New(counter)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Register(&contractv1.Capability{
		Name: "diagnose.disk_usage", RiskTier: contractv1.RiskTier_RISK_TIER_READ_ONLY,
		Timeout: durationpb.New(60 * time.Second),
	}, diagnoseHandler(lin)); err != nil {
		t.Fatal(err)
	}
	if err := testwrite.Register(reg, counter); err != nil {
		t.Fatal(err)
	}
	if err := reg.Register(&contractv1.Capability{
		Name: "test.destroy.disk", RiskTier: contractv1.RiskTier_RISK_TIER_LOW,
		Rollbackable: true, Destructive: true, TestOnly: true, // 仅测试
		Timeout: durationpb.New(60 * time.Second),
	}, diagnoseHandler(lin)); err != nil {
		t.Fatal(err)
	}
	svc, err := gateway.New(gateway.DefaultConfig(), idempotency.NewMemoryStore(), aud, apStore, reg)
	if err != nil {
		t.Fatal(err)
	}

	// 真实 gRPC 服务端（127.0.0.1 随机端口）+ 仅测试静态 token 认证。
	auth := NewStaticTokenAuth(map[string]string{
		testRequesterToken: "ops-lead",    // 仅测试
		testApproverToken:  "ops-auditor", // 仅测试
	})
	srv := grpc.NewServer()
	contractv1.RegisterGatewayServer(srv, NewServer(svc, auth))
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败：%v", err)
	}
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("建立 gRPC 连接失败：%v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	client := contractv1.NewGatewayClient(conn)

	requesterCtx := metadata.NewOutgoingContext(ctx,
		metadata.Pairs(MetaAuthorization, "Bearer "+testRequesterToken))
	approverCtx := metadata.NewOutgoingContext(ctx,
		metadata.Pairs(MetaAuthorization, "Bearer "+testApproverToken))

	// 1) 只读能力：真实 SSH 执行。
	roReq := &contractv1.SubmitExecuteRequest{
		Action: &contractv1.Action{
			Capability: "diagnose.disk_usage",
			Target:     &contractv1.AssetTarget{AssetId: "ast_grpc", Access: contractv1.AccessKind_ACCESS_SSH},
		},
		Environment:    contractv1.Environment_ENVIRONMENT_TEST,
		IdempotencyKey: "grpc-ro-1",
	}
	callsBefore := counter.Count()
	roResp, err := client.SubmitExecute(requesterCtx, roReq)
	if err != nil {
		t.Fatalf("只读执行失败：%v", err)
	}
	if roResp.GetOutcome().GetStatus() != string(gateway.StatusSuccess) {
		t.Fatalf("只读能力应执行成功：%+v", roResp.GetOutcome())
	}
	if roResp.GetOutcome().GetDecision() != "allow" {
		t.Fatalf("决策标签应为 allow：%+v", roResp.GetOutcome())
	}
	if counter.Count() <= callsBefore {
		t.Fatal("只读执行未到达 SSH 层")
	}
	out := ""
	for _, o := range roResp.GetOutcome().GetResult().GetOutputs() {
		out += o.GetContent()
	}
	if !strings.Contains(out, "根分区使用率") {
		t.Fatalf("诊断结论缺失：%q", out)
	}
	// 身份来自 gRPC metadata（不接受请求体自报）：审计事件的 actor 必须为 token 绑定的身份。
	decisions, err := aud.ListByAction(ctx, "gateway.decision")
	if err != nil {
		t.Fatal(err)
	}
	if len(decisions) == 0 {
		t.Fatal("决策审计缺失")
	}
	for _, ev := range decisions {
		if ev.Actor != "ops-lead" {
			t.Fatalf("审计 actor 应取自认证身份（ops-lead），实际 %q", ev.Actor)
		}
	}
	// 1b) 同键不同内容 → ALREADY_EXISTS（幂等冲突）。
	conflictReq := &contractv1.SubmitExecuteRequest{
		Action: &contractv1.Action{
			Capability: "diagnose.disk_usage",
			Target:     &contractv1.AssetTarget{AssetId: "ast_other", Access: contractv1.AccessKind_ACCESS_SSH},
		},
		Environment:    contractv1.Environment_ENVIRONMENT_TEST,
		IdempotencyKey: "grpc-ro-1", // 同键、不同目标
	}
	callsBefore = counter.Count()
	if _, err := client.SubmitExecute(requesterCtx, conflictReq); err == nil {
		t.Fatal("同键不同内容应返回错误")
	} else {
		wantCode(t, err, codes.AlreadyExists, "幂等冲突")
	}
	if counter.Count() != callsBefore {
		t.Fatal("幂等冲突不得触达 SSH 层")
	}

	// 2) 写能力：提交 → pending → 四眼拒绝 → 批准 → 执行。
	marker := "grpc10a"
	writeReq := &contractv1.SubmitExecuteRequest{
		Action: &contractv1.Action{
			Capability: testwrite.CapWriteMarker,
			Params:     markerParams(marker),
			Target:     &contractv1.AssetTarget{AssetId: "ast_grpc", Access: contractv1.AccessKind_ACCESS_SSH},
		},
		Environment:    contractv1.Environment_ENVIRONMENT_TEST,
		IdempotencyKey: "grpc-write-1",
	}
	submitted, err := client.SubmitExecute(requesterCtx, writeReq)
	if err != nil {
		t.Fatalf("提交写请求失败：%v", err)
	}
	if submitted.GetOutcome().GetStatus() != string(gateway.StatusPendingApproval) {
		t.Fatalf("写请求应转审批：%+v", submitted.GetOutcome())
	}
	approvalID := submitted.GetOutcome().GetApprovalId()
	if approvalID == "" {
		t.Fatal("应返回审批记录 ID")
	}

	// 2a) 批准前执行 → FAILED_PRECONDITION。
	if _, err := client.ExecuteApproved(requesterCtx, &contractv1.ExecuteApprovedRequest{
		ApprovalId: approvalID, Action: writeReq.GetAction(),
		Environment:    writeReq.GetEnvironment(),
		IdempotencyKey: "grpc-write-1",
	}); err == nil {
		t.Fatal("批准前执行应被拒绝")
	} else {
		wantCode(t, err, codes.FailedPrecondition, "批准前执行")
	}

	// 2b) 四眼原则：请求人本人审批 → PERMISSION_DENIED。
	if _, err := client.Approve(requesterCtx, &contractv1.ApproveRequest{
		ApprovalId: approvalID, Reason: "自批",
	}); err == nil {
		t.Fatal("同人审批应被拒绝")
	} else {
		wantCode(t, err, codes.PermissionDenied, "同人审批")
	}

	// 2c) 审批人批准。
	approved, err := client.Approve(approverCtx, &contractv1.ApproveRequest{
		ApprovalId: approvalID, Reason: "同意执行",
	})
	if err != nil {
		t.Fatalf("审批人批准失败：%v", err)
	}
	if approved.GetApproval().GetStatus() != string(approvals.StatusApproved) {
		t.Fatalf("批准状态不符：%+v", approved.GetApproval())
	}

	// 2d) 批准后执行：真实 SSH 写入标记文件。
	callsBefore = counter.Count()
	done, err := client.ExecuteApproved(requesterCtx, &contractv1.ExecuteApprovedRequest{
		ApprovalId: approvalID, Action: writeReq.GetAction(),
		Environment:    writeReq.GetEnvironment(),
		IdempotencyKey: "grpc-write-1",
	})
	if err != nil {
		t.Fatalf("批准后执行失败：%v", err)
	}
	if done.GetOutcome().GetStatus() != string(gateway.StatusSuccess) {
		t.Fatalf("批准后执行应成功：%+v", done.GetOutcome())
	}
	if counter.Count() <= callsBefore {
		t.Fatal("批准后执行未到达 SSH 层")
	}
	if exists, err := fileExists(inner, marker); err != nil {
		t.Fatal(err)
	} else if !exists {
		t.Fatal("标记文件应已写入")
	}

	// 2e) 审批已消费（consumed）。
	got, err := client.GetApproval(requesterCtx, &contractv1.GetApprovalRequest{ApprovalId: approvalID})
	if err != nil {
		t.Fatalf("查询审批失败：%v", err)
	}
	if got.GetApproval().GetStatus() != string(approvals.StatusConsumed) {
		t.Fatalf("执行后审批应为 consumed：%+v", got.GetApproval())
	}

	// 3) destructive 经 gRPC 提交 → PERMISSION_DENIED 且未到达 SSH 层。
	callsBefore = counter.Count()
	if _, err := client.SubmitExecute(requesterCtx, &contractv1.SubmitExecuteRequest{
		Action: &contractv1.Action{
			Capability: "test.destroy.disk",
			Target:     &contractv1.AssetTarget{AssetId: "ast_grpc", Access: contractv1.AccessKind_ACCESS_SSH},
		},
		Environment:    contractv1.Environment_ENVIRONMENT_TEST,
		IdempotencyKey: "grpc-destroy-1",
	}); err == nil {
		t.Fatal("destructive 提交应被拒绝")
	} else {
		wantCode(t, err, codes.PermissionDenied, "destructive 提交")
	}
	if counter.Count() != callsBefore {
		t.Fatalf("destructive 请求到达了 SSH 层：before=%d after=%d", callsBefore, counter.Count())
	}
}

// wantCode 断言 gRPC 错误码（失败即终止用例）。
func wantCode(t *testing.T, err error, want codes.Code, what string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s 应返回 %s，实际成功", what, want)
	}
	if got := status.Code(err); got != want {
		t.Fatalf("%s 应返回 %s，实际 %s（%v）", what, want, got, err)
	}
}

// —— 辅助 ——

// integrationPool 建立 PG 连接池；不可用时 skip 并输出原因（不静默通过）。
func integrationPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	// 第十四轮 H5：集成测试使用独立 schema（test_run_<时间戳>），
	// 断言通过后自动删除；public 不再增长。
	rs := testdb.NewRunSchema(t)
	if rs == nil {
		return nil // 已 skip
	}
	return rs.Pool()
}

// countingRunner 包装 exec.Runner 统计 Run 调用次数。
type countingRunner struct {
	mu    sync.Mutex
	inner exec.Runner
	n     int
}

func (c *countingRunner) Run(ctx context.Context, argv []string, opts exec.RunOptions) (exec.Result, error) {
	c.mu.Lock()
	c.n++
	c.mu.Unlock()
	return c.inner.Run(ctx, argv, opts)
}

func (c *countingRunner) Count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

// diagnoseHandler Linux 诊断能力的最小接线（等价 linuxwire 的 disk_usage 路由）。
func diagnoseHandler(a *linux.Adapter) gateway.Handler {
	return func(ctx context.Context, req gateway.Request) (*contractv1.ActionResult, error) {
		insts, err := a.Discover(ctx, req.Action.Target)
		if err != nil {
			return nil, err
		}
		diag, err := a.Diagnose(ctx, insts[0], linux.QuestionDiskUsage)
		if err != nil {
			return nil, err
		}
		return &contractv1.ActionResult{Success: true, Outputs: []*contractv1.OutputChunk{
			{Stream: "diagnosis", Content: diag.Conclusion},
		}}, nil
	}
}

// markerParams 构造 params.marker。
func markerParams(markerID string) *structpb.Struct {
	p, _ := structpb.NewStruct(map[string]any{"marker": markerID})
	return p
}

// fileExists 经同一 SSH 连接检查标记文件是否存在（不经过计数器）。
func fileExists(inner exec.Runner, markerID string) (bool, error) {
	res, err := inner.Run(context.Background(),
		[]string{"test", "-f", testwrite.MarkerPath(markerID)}, exec.RunOptions{})
	if err != nil {
		return false, err
	}
	return res.ExitCode == 0, nil
}
