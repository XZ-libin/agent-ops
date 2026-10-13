package grpcwire

// OIDC × gRPC 集成测试（第十九轮 A2 集成 + 用例 ⑫）。
//
// 真实路径：真实 gRPC 客户端 ↔ 真实 gRPC 服务 ↔ 真实 PostgreSQL（独立 run schema）
// ↔ 真实生产能力目录（adapters/linux/manifest.yaml）。唯一"本地替身"是
// **本地 JWKS 端点**（httptest）与**运行时生成的 RSA 密钥**——按裁决要求，
// 不连接任何真实身份提供商、不提交任何密钥文件。

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"

	contractv1 "github.com/ORG/agent-ops/contract/gen/go/agent_ops/contract/v1"

	"github.com/ORG/agent-ops/gateway/internal/approvals"
	"github.com/ORG/agent-ops/gateway/internal/gateway"
	"github.com/ORG/agent-ops/gateway/internal/prodcatalog"
	"github.com/ORG/agent-ops/internal/audit"
	"github.com/ORG/agent-ops/internal/idempotency"
	"github.com/ORG/agent-ops/internal/testdb"
)

// prodManifestPath 生产能力清单（仓库内相对路径；集成测试从模块目录运行）。
const prodManifestPath = "../../../adapters/linux/manifest.yaml"

// TestOIDCIntegrationGRPCActorMatchesSub（A2 集成 + ⑫）：
// 通过真实 gRPC 客户端用 OIDC 令牌调用 SubmitExecute 与 GetApproval，
// 断言审计中的 actor 与令牌 sub 一致；并断言生产目录中写能力为 0、
// 执行通道未接线（返回未实现错误）且没有产生任何执行/审批记录。
func TestOIDCIntegrationGRPCActorMatchesSub(t *testing.T) {
	rs := testdb.NewRunSchema(t)
	if rs == nil {
		return
	}
	pool := rs.Pool()
	ctx := context.Background()

	// —— 真实存储（独立 run schema，test_ 前缀表名）——
	auditTable := fmt.Sprintf("test_audit_events_oidc_%d", time.Now().UnixNano())
	aud := audit.NewTestStore(pool, auditTable)
	if err := aud.EnsureSchema(ctx); err != nil {
		t.Fatalf("审计建表失败：%v", err)
	}
	approvalTable := fmt.Sprintf("test_approvals_oidc_%d", time.Now().UnixNano())
	apStore := approvals.NewTestPostgresStore(pool, approvalTable)
	if err := apStore.EnsureSchema(ctx); err != nil {
		t.Fatalf("审批建表失败：%v", err)
	}
	idemStore := idempotency.NewPostgresStore(pool)
	if err := idemStore.EnsureSchema(ctx); err != nil {
		t.Fatalf("幂等建表失败：%v", err)
	}

	// —— 真实生产能力目录 ——
	reg := gateway.NewRegistry()
	caps, err := prodcatalog.Load(reg, prodManifestPath)
	if err != nil {
		t.Fatalf("加载生产清单失败：%v", err)
	}
	if err := reg.AssertNoTestOnly(); err != nil {
		t.Fatalf("生产启动守卫：%v", err)
	}
	// 硬性约束 5：生产目录中写能力数量必须为 0。
	writeCount := 0
	for _, c := range caps {
		if c.GetRiskTier() != contractv1.RiskTier_RISK_TIER_READ_ONLY {
			writeCount++
		}
	}
	if writeCount != 0 {
		t.Fatalf("生产目录中写能力数量必须为 0，实际 %d（能力清单 %v）", writeCount, caps)
	}
	t.Logf("[A2⑫] 生产目录：%d 项能力，其中非只读（写）能力 %d 项", len(caps), writeCount)

	svc, err := gateway.New(gateway.DefaultConfig(), idemStore, aud, apStore, reg)
	if err != nil {
		t.Fatalf("组装网关服务失败：%v", err)
	}

	// —— OIDC（运行时生成密钥 + 本地 JWKS）——
	f := newTestFixture(t)
	auth := f.newAuth(t)
	// 生产门禁：OIDC 放行、静态令牌拒绝。
	if err := GuardAuth(ModeProd, auth); err != nil {
		t.Fatalf("mode=prod 应放行 OIDCAuth：%v", err)
	}
	if err := GuardAuth(ModeProd, NewStaticTokenAuth(map[string]string{"t": "a"})); err == nil {
		t.Fatal("mode=prod 下静态令牌必须拒绝启动")
	}

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

	token := f.signToken(t, "RS256", f.kid, f.baseClaims())
	callCtx := metadata.NewOutgoingContext(ctx, metadata.Pairs(MetaAuthorization, "Bearer "+token))

	// —— 1) SubmitExecute：只读能力 → 执行通道未接线 → 返回错误（非 UNAUTHENTICATED）——
	req := &contractv1.SubmitExecuteRequest{
		Action: &contractv1.Action{
			Capability: "diagnose.disk_usage",
			Target:     &contractv1.AssetTarget{AssetId: "ast_oidc", Access: contractv1.AccessKind_ACCESS_SSH},
			Params:     mustStruct(t, map[string]any{"path": "/"}),
		},
		Environment:    contractv1.Environment_ENVIRONMENT_TEST,
		IdempotencyKey: fmt.Sprintf("idem-oidc-%d", time.Now().UnixNano()),
	}
	_, err = client.SubmitExecute(callCtx, req)
	if err == nil {
		t.Fatal("生产执行通道未接线：SubmitExecute 必须返回错误（不得静默成功）")
	}
	st, _ := status.FromError(err)
	if st.Code() == codes.Unauthenticated {
		t.Fatalf("有效 OIDC 令牌不得被判为未认证：%v", err)
	}
	if st.Code() == codes.PermissionDenied {
		t.Fatalf("只读能力不应被策略拒绝（应走到执行通道）：%v", err)
	}
	t.Logf("[A2⑫] SubmitExecute（OIDC）返回未实现类错误：code=%s（未绕过门控、未执行任何动作）", st.Code())

	// —— 2) GetApproval：认证通过但审批不存在 → NOT_FOUND（证明 actor 已认证）——
	_, err = client.GetApproval(callCtx, &contractv1.GetApprovalRequest{ApprovalId: "ap-not-exist"})
	if err == nil {
		t.Fatal("不存在的审批应返回错误")
	}
	st2, _ := status.FromError(err)
	if st2.Code() == codes.Unauthenticated {
		t.Fatalf("有效 OIDC 令牌不得被判为未认证：%v", err)
	}
	t.Logf("[A2 集成] GetApproval（OIDC）认证通过，返回 code=%s", st2.Code())

	// —— 3) 审计：actor 必须等于令牌 sub ——
	events := auditEvents(t, aud)
	if len(events) == 0 {
		t.Fatal("执行尝试必须留下审计事件（fail-closed 且可审计）")
	}
	sawActor := false
	for _, ev := range events {
		if ev.Actor != "operator-alice" {
			t.Fatalf("审计 actor 必须等于令牌 sub（operator-alice），实际 %q（action=%s）", ev.Actor, ev.Action)
		}
		if ev.Actor == "spoofed-bob" || ev.Actor == "spoofed-carol" {
			t.Fatalf("审计 actor 不得取自自报字段：%q", ev.Actor)
		}
		sawActor = true
	}
	if !sawActor {
		t.Fatal("未找到任何审计事件")
	}
	// 令牌内容不得出现在审计 payload 中（约束 7）。
	for _, ev := range events {
		if s := string(ev.Payload); len(s) > 0 {
			if containsAny(s, []string{token, "Bearer ", "-----BEGIN"}) {
				t.Fatalf("审计 payload 不得包含令牌或密钥材料：%s", s)
			}
		}
	}
	t.Logf("[A2 集成] 审计 actor 与令牌 sub 一致：%q（共 %d 条事件，action=%v）",
		events[0].Actor, len(events), actionsOf(events))

	// —— 4) 不写入任何执行/审批记录 ——
	var approvals int64
	if err := pool.QueryRow(ctx, fmt.Sprintf(`SELECT count(*) FROM %s`, approvalTable)).Scan(&approvals); err != nil {
		t.Fatal(err)
	}
	if approvals != 0 {
		t.Fatalf("生产执行通道未接线时不得产生审批记录，实际 %d 条", approvals)
	}
	// 审计里不得出现"执行成功"类事件（只有失败/拒绝）。
	for _, ev := range events {
		if ev.Action == "action.succeeded" || ev.Action == "execution.succeeded" {
			t.Fatalf("未接线时不得出现成功执行事件：%s", ev.Action)
		}
	}
	t.Log("[A2⑫] 未接线：审批记录 0 条、无成功执行事件（未写入任何执行记录）")

	// —— 5) 无效令牌 → UNAUTHENTICATED ——
	badCtx := metadata.NewOutgoingContext(ctx, metadata.Pairs(MetaAuthorization, "Bearer not-a-jwt"))
	if _, err := client.SubmitExecute(badCtx, req); err == nil {
		t.Fatal("非法令牌必须被拒绝")
	} else if st3, _ := status.FromError(err); st3.Code() != codes.Unauthenticated {
		t.Fatalf("非法令牌应映射 UNAUTHENTICATED，实际 %s", st3.Code())
	}
	t.Log("[A2 集成] 非法令牌 → UNAUTHENTICATED")
}

// auditEvents 读取审计表的全部事件（按 seq 升序）。
// 覆盖网关实际写入的动作名（见 gateway/internal/gateway/audit_events.go）。
func auditEvents(t *testing.T, st *audit.Store) []audit.StoredEvent {
	t.Helper()
	ctx := context.Background()
	var out []audit.StoredEvent
	for _, action := range []string{
		"gateway.decision", "gateway.executing", "gateway.execution.skipped",
		"gateway.execution.replayed", "gateway.execution.abandoned",
		"approval.created", "approval.approved", "approval.rejected",
	} {
		evs, err := st.ListByAction(ctx, action)
		if err != nil {
			t.Fatalf("读取审计事件（%s）失败：%v", action, err)
		}
		out = append(out, evs...)
	}
	return out
}

func actionsOf(evs []audit.StoredEvent) []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range evs {
		if !seen[e.Action] {
			seen[e.Action] = true
			out = append(out, e.Action)
		}
	}
	return out
}

func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if sub != "" && len(s) >= len(sub) && indexOfStr(s, sub) >= 0 {
			return true
		}
	}
	return false
}

func indexOfStr(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// mustStruct 构造 protobuf Struct（失败即 fatal）。
func mustStruct(t *testing.T, m map[string]any) *structpb.Struct {
	t.Helper()
	s, err := structpb.NewStruct(m)
	if err != nil {
		t.Fatalf("构造 Struct 失败：%v", err)
	}
	return s
}

// 编译期断言：JSON 解析辅助（保持 json 导入被使用，便于扩展 payload 断言）。
var _ = json.Marshal
