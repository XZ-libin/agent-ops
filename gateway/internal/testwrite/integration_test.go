package testwrite

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"

	contractv1 "github.com/XZ-libin/agent-ops/contract/gen/go/agent_ops/contract/v1"

	"github.com/XZ-libin/agent-ops/adapters/linux"
	"github.com/XZ-libin/agent-ops/gateway/internal/approvals"
	"github.com/XZ-libin/agent-ops/gateway/internal/gateway"
	"github.com/XZ-libin/agent-ops/internal/audit"
	"github.com/XZ-libin/agent-ops/internal/exec"
	"github.com/XZ-libin/agent-ops/internal/exec/ssh"
	"github.com/XZ-libin/agent-ops/internal/exec/ssh/sshdtest"
	"github.com/XZ-libin/agent-ops/internal/idempotency"
	"github.com/XZ-libin/agent-ops/internal/testdb"
)

// TestIntegrationApprovedWriteMarkerAndRollback 第九轮 sshd 容器端到端集成（D3）：
// Docker 可用则真跑本地 sshd 测试容器（临时密钥、127.0.0.1 随机端口）；
// 不可用则 skip 并输出原因。PostgreSQL（55432）不可用同样 skip 并输出原因
// （本用例需要真实审计表断言 seq 连续性）。
//
// 链路：提交写请求 → pending → 四眼批准（同人被拒）→ ExecuteApproved
// （策略重评 → executing → 幂等 → SSH 执行 → executed → consumed）
// → 断言标记文件存在 → 断言审计 executing→executed 同 execution_id 且 seq 连续
// → consumed 后拒绝再次执行 → PlanRollback 回滚（删除标记，测试清单 auto）
// → 断言文件已删除 → destructive 即使已批准也在网关被拒且未到达 SSH 层。
func TestIntegrationApprovedWriteMarkerAndRollback(t *testing.T) {
	sshd := sshdtest.StartLocalSSHD(t)
	pool := integrationPool(t)
	ctx := context.Background()

	// 真实审计表（test_ 前缀，每次运行独立表）。
	auditTable := fmt.Sprintf("test_audit_events_itest_%d", time.Now().UnixNano())
	aud := audit.NewTestStore(pool, auditTable)
	if err := aud.EnsureSchema(ctx); err != nil {
		t.Fatalf("审计建表失败（非 skip）：%v", err)
	}
	// 真实审批表（test_ 前缀；清理残留保证断言干净）。
	// 审批表按运行唯一命名（第十二轮修复：固定表名会被并行运行的其它包清空）。
	approvalTable := fmt.Sprintf("test_approvals_itest10_%d", time.Now().UnixNano())
	apStore := approvals.NewTestPostgresStore(pool, approvalTable)
	if err := apStore.EnsureSchema(ctx); err != nil {
		t.Fatalf("审批建表失败（非 skip）：%v", err)
	}

	// 真实 SSH Runner + 计数器（断言「未到达 SSH 层」）。
	inner, err := ssh.New(ssh.Options{Addr: sshd.Addr, User: sshd.User, Signer: sshd.Signer, HostKey: sshd.HostKey})
	if err != nil {
		t.Fatalf("构建 SSH Runner 失败：%v", err)
	}
	t.Cleanup(func() { _ = inner.Close() })
	counter := &countingRunner{inner: inner}

	// 注册表（仅测试）：Linux 只读诊断能力 + 测试写能力（test_only）。
	reg := gateway.NewTestRegistry() // 仅测试
	lin, err := linux.New(counter)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Register(&contractv1.Capability{
		Name: "diagnose.disk_usage", RiskTier: contractv1.RiskTier_RISK_TIER_READ_ONLY,
		Rollbackable: false, // R2
		Timeout:      durationpb.New(60 * time.Second),
	}, diagnoseHandler(lin)); err != nil {
		t.Fatal(err)
	}
	if err := Register(reg, counter); err != nil {
		t.Fatalf("注册测试写能力失败：%v", err)
	}
	// 仅测试：破坏性能力（断言「已批准也拒绝且未到达 SSH」）。
	if err := reg.Register(&contractv1.Capability{
		Name: "test.destroy.disk", RiskTier: contractv1.RiskTier_RISK_TIER_LOW,
		Rollbackable: true, Destructive: true, TestOnly: true, // 仅测试
		Timeout: durationpb.New(60 * time.Second),
	}, diagnoseHandler(lin)); err != nil {
		t.Fatal(err)
	}

	cfg := gateway.DefaultConfig()
	cfg.AutoExecAllowlist = map[string]bool{CapDeleteMarker: true} // 仅测试：回滚删除走 auto
	svc, err := gateway.New(cfg, idempotency.NewMemoryStore(), aud, apStore, reg)
	if err != nil {
		t.Fatal(err)
	}

	// 1) 提交写请求 → pending。
	markerID := "itest9a"
	req := markerReq("ops-lead", "k-marker", CapWriteMarker, markerID)
	resp, err := svc.Execute(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != gateway.StatusPendingApproval || resp.ApprovalID == "" {
		t.Fatalf("写请求应转审批：%+v", resp)
	}
	approvalID := resp.ApprovalID

	// 2) 四眼原则（无例外，含测试环境）：同人审批被拒。
	if _, err := svc.Approve(ctx, approvalID, "ops-lead", ""); err == nil || !strings.Contains(err.Error(), "四眼") {
		t.Fatalf("同人审批应被四眼原则拒绝：%v", err)
	}
	if _, err := svc.Approve(ctx, approvalID, "ops-auditor", "同意执行"); err != nil {
		t.Fatalf("不同审批人应可批准：%v", err)
	}

	// 3) ExecuteApproved：执行成功，审计 executing → executed 且 seq 连续。
	callsBefore := counter.Count()
	execRes, err := svc.ExecuteApproved(ctx, req, approvalID)
	if err != nil {
		t.Fatal(err)
	}
	if execRes.Status != gateway.StatusSuccess {
		t.Fatalf("批准后执行应成功：%+v", execRes)
	}
	if counter.Count() <= callsBefore {
		t.Fatal("执行未到达 SSH 层")
	}
	assertSeqContinuous(t, aud)

	// 4) 标记文件存在。
	exists, err := fileExists(inner, markerID)
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatalf("标记文件应存在：%s", markerPath(markerID))
	}

	// 5) consumed 后拒绝再次执行，且 SSH 调用数不变。
	callsBefore = counter.Count()
	if again, err := svc.ExecuteApproved(ctx, req, approvalID); err != nil {
		t.Fatal(err)
	} else if again.Status != gateway.StatusDenied || !strings.Contains(again.Message, "consumed") {
		t.Fatalf("consumed 后应拒绝再次执行：%+v", again)
	}
	if counter.Count() != callsBefore {
		t.Fatal("consumed 拒绝不应触达 SSH 层")
	}

	// 6) 回滚：PlanRollback → 删除标记（测试清单 auto 执行）→ 文件已删除。
	tw := New(counter)
	plan, err := tw.PlanRollback(&contractv1.ActionRecord{Action: req.Action, Target: req.Action.Target})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan) != 1 || plan[0].Capability != CapDeleteMarker {
		t.Fatalf("回滚计划应为删除标记动作：%+v", plan)
	}
	rollReq := gateway.Request{
		Actor:          "ops-lead",
		IdempotencyKey: "k-rollback",
		Action:         plan[0],
		Environment:    contractv1.Environment_ENVIRONMENT_TEST,
	}
	rollRes, err := svc.Execute(ctx, rollReq)
	if err != nil {
		t.Fatal(err)
	}
	if rollRes.Status != gateway.StatusSuccess {
		t.Fatalf("回滚删除应成功（仅测试清单）：%+v", rollRes)
	}
	exists, err = fileExists(inner, markerID)
	if err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatalf("回滚后标记文件应已删除：%s", markerPath(markerID))
	}

	// 7) destructive 即使已批准也被网关拒绝，且未到达 SSH 层（约束 4）。
	destReq := markerReq("ops-lead", "k-destroy", "test.destroy.disk", "")
	destReq.Action.Params = nil
	rec, err := apStore.Create(ctx, approvals.NewRecord{
		Actor: "ops-lead", Capability: "test.destroy.disk",
		RequestHash: gateway.HashRequest(destReq), IdempotencyKey: "k-destroy",
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := apStore.Approve(ctx, rec.ID, "ops-auditor", ""); err != nil {
		t.Fatal(err)
	}
	callsBefore = counter.Count()
	destRes, err := svc.ExecuteApproved(ctx, destReq, rec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if destRes.Status != gateway.StatusDenied || !strings.Contains(destRes.Message, "破坏性") {
		t.Fatalf("已批准的破坏性能力仍应拒绝：%+v", destRes)
	}
	if counter.Count() != callsBefore {
		t.Fatalf("破坏性请求到达了 SSH 层：before=%d after=%d", callsBefore, counter.Count())
	}

	// 8) 只读能力 sanity：诊断经同一链路可用（第八轮回归）。
	dReq := markerReq("ops-lead", "k-diag", "diagnose.disk_usage", "")
	dReq.Action.Params = nil
	dRes, err := svc.Execute(ctx, dReq)
	if err != nil {
		t.Fatal(err)
	}
	if dRes.Status != gateway.StatusSuccess {
		t.Fatalf("只读诊断应成功：%+v", dRes)
	}
}

// TestIntegrationRequireApprovalRealPath 第十轮 F1 的真实路径集成（D3）：
// Docker 可用则真跑本地 sshd 容器，PostgreSQL（55432）不可用则 skip 并输出原因。
//
//  1. 生产环境提交写请求 → 策略 require_approval（环境等级下限升级为 MEDIUM）
//     → pending → 四眼批准 → ExecuteApproved：执行期重评为 require_approval，
//     由有效审批满足 → 真实 SSH 执行（标记文件落盘）；
//  2. 同一能力、无有效审批（pending 未批准）→ 拒绝执行，SSH 调用数不变、
//     标记文件未创建（约束：无审批不得触达执行层）。
func TestIntegrationRequireApprovalRealPath(t *testing.T) {
	sshd := sshdtest.StartLocalSSHD(t)
	pool := integrationPool(t)
	ctx := context.Background()

	auditTable := fmt.Sprintf("test_audit_events_itest10_%d", time.Now().UnixNano())
	aud := audit.NewTestStore(pool, auditTable)
	if err := aud.EnsureSchema(ctx); err != nil {
		t.Fatalf("审计建表失败（非 skip）：%v", err)
	}
	approvalTable := fmt.Sprintf("test_approvals_itest_%d", time.Now().UnixNano())
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
		_, _ = inner.Run(context.Background(), []string{"rm", "-f",
			markerPath("itest10a"), markerPath("itest10b")}, exec.RunOptions{})
	})

	reg := gateway.NewTestRegistry() // 仅测试
	if err := Register(reg, counter); err != nil {
		t.Fatal(err)
	}
	svc, err := gateway.New(gateway.DefaultConfig(), idempotency.NewMemoryStore(), aud, apStore, reg)
	if err != nil {
		t.Fatal(err)
	}

	// 1) 生产环境写请求 → require_approval → 批准 → 执行成功（重评由有效审批满足）。
	req := gateway.Request{
		Actor:          "ops-lead",
		IdempotencyKey: "k-itest10-a",
		Action: &contractv1.Action{
			Capability: CapWriteMarker,
			Params:     markerParams("itest10a"),
			Target:     &contractv1.AssetTarget{AssetId: "ast_itest", Access: contractv1.AccessKind_ACCESS_SSH},
		},
		Environment: contractv1.Environment_ENVIRONMENT_PROD,
	}
	submitted, err := svc.Execute(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if submitted.Status != gateway.StatusPendingApproval ||
		submitted.Decision != contractv1.Decision_DECISION_REQUIRE_APPROVAL {
		t.Fatalf("生产环境写请求应转审批：%+v", submitted)
	}
	if _, err := svc.Approve(ctx, submitted.ApprovalID, "ops-auditor", "同意"); err != nil {
		t.Fatal(err)
	}
	callsBefore := counter.Count()
	done, err := svc.ExecuteApproved(ctx, req, submitted.ApprovalID)
	if err != nil {
		t.Fatal(err)
	}
	if done.Status != gateway.StatusSuccess {
		t.Fatalf("有效审批应满足 require_approval 门控（真实路径）：%+v", done)
	}
	if counter.Count() <= callsBefore {
		t.Fatal("执行未到达 SSH 层")
	}
	exists, err := fileExists(inner, "itest10a")
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatal("标记文件应已写入")
	}

	// 2) 同一能力、无有效审批（pending 未批准）→ 拒绝，不触达 SSH 层。
	noApproval := gateway.Request{
		Actor:          "ops-lead",
		IdempotencyKey: "k-itest10-b",
		Action: &contractv1.Action{
			Capability: CapWriteMarker,
			Params:     markerParams("itest10b"),
			Target:     &contractv1.AssetTarget{AssetId: "ast_itest", Access: contractv1.AccessKind_ACCESS_SSH},
		},
		Environment: contractv1.Environment_ENVIRONMENT_PROD,
	}
	pending, err := svc.Execute(ctx, noApproval)
	if err != nil {
		t.Fatal(err)
	}
	if pending.Status != gateway.StatusPendingApproval || pending.ApprovalID == "" {
		t.Fatalf("应创建待审批记录：%+v", pending)
	}
	callsBefore = counter.Count()
	denied, err := svc.ExecuteApproved(ctx, noApproval, pending.ApprovalID)
	if err != nil {
		t.Fatal(err)
	}
	if denied.Status != gateway.StatusDenied {
		t.Fatalf("无有效审批应拒绝执行：%+v", denied)
	}
	if counter.Count() != callsBefore {
		t.Fatalf("无审批的请求到达了 SSH 层：before=%d after=%d", callsBefore, counter.Count())
	}
	exists, err = fileExists(inner, "itest10b")
	if err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("无审批不得写入标记文件")
	}
	rec, err := apStore.Get(ctx, pending.ApprovalID)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != approvals.StatusPending {
		t.Fatalf("被拒后审批应保持 pending：%+v", rec)
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

// markerReq 构造网关请求（params.marker）。
func markerReq(actor, key, capability, markerID string) gateway.Request {
	params, _ := structpb.NewStruct(map[string]any{"marker": markerID})
	return gateway.Request{
		Actor:          actor,
		IdempotencyKey: key,
		Action: &contractv1.Action{
			Capability: capability,
			Params:     params,
			Target:     &contractv1.AssetTarget{AssetId: "ast_itest", Access: contractv1.AccessKind_ACCESS_SSH},
		},
		Environment: contractv1.Environment_ENVIRONMENT_TEST,
	}
}

// fileExists 经同一 SSH 连接检查标记文件是否存在于容器内（argv，不经过计数器）。
func fileExists(inner exec.Runner, markerID string) (bool, error) {
	res, err := inner.Run(context.Background(), []string{"test", "-f", markerPath(markerID)}, exec.RunOptions{})
	if err != nil {
		return false, err
	}
	return res.ExitCode == 0, nil
}

// assertSeqContinuous 断言最后一条 executing 与其后 executed 为同一 execution_id
// 且 seq 连续（R4 / C：executing → executed，seq 连续）。
func assertSeqContinuous(t *testing.T, aud *audit.Store) {
	t.Helper()
	ctx := context.Background()
	executing, err := aud.ListByAction(ctx, "gateway.executing")
	if err != nil || len(executing) == 0 {
		t.Fatalf("读取 executing 事件失败：%v n=%d", err, len(executing))
	}
	executed, err := aud.ListByAction(ctx, "gateway.executed")
	if err != nil || len(executed) == 0 {
		t.Fatalf("读取 executed 事件失败：%v n=%d", err, len(executed))
	}
	lastExec := executing[len(executing)-1]
	lastDone := executed[len(executed)-1]
	var p1, p2 struct {
		ExecutionID string `json:"execution_id"`
	}
	if err := json.Unmarshal(lastExec.Payload, &p1); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(lastDone.Payload, &p2); err != nil {
		t.Fatal(err)
	}
	if p1.ExecutionID == "" || p1.ExecutionID != p2.ExecutionID {
		t.Fatalf("executing/executed 应携带同一 execution_id：%q vs %q", p1.ExecutionID, p2.ExecutionID)
	}
	if lastDone.Seq != lastExec.Seq+1 {
		t.Fatalf("executed 的 seq 应紧跟 executing（seq 连续）：executing=%d executed=%d", lastExec.Seq, lastDone.Seq)
	}
}

// markerParams 构造 params.marker（仅测试标记 ID）。
func markerParams(markerID string) *structpb.Struct {
	p, _ := structpb.NewStruct(map[string]any{"marker": markerID})
	return p
}
