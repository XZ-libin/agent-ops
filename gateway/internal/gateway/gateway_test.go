package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"

	contractv1 "github.com/ORG/agent-ops/contract/gen/go/agent_ops/contract/v1"

	"github.com/ORG/agent-ops/gateway/internal/approvals"
	"github.com/ORG/agent-ops/internal/audit"
	"github.com/ORG/agent-ops/internal/idempotency"
	"github.com/ORG/agent-ops/internal/policy"
)

// —— 测试替身 ——

// fakeAudit 捕获审计事件；可注入失败（failAppend 对所有 Append 失败、
// failOnAction 对指定事件类型失败一次）。实现 ListByAction（对账用）。
type fakeAudit struct {
	mu           sync.Mutex
	events       []audit.Event
	failAppend   error
	failOnAction string
}

func (f *fakeAudit) Append(_ context.Context, ev audit.Event) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failAppend != nil {
		return "", f.failAppend
	}
	if f.failOnAction != "" && ev.Action == f.failOnAction {
		return "", fmt.Errorf("模拟审计写入失败（action=%s）", ev.Action)
	}
	f.events = append(f.events, ev)
	return "hash", nil
}

// ListByAction 按事件类型返回已存事件（模拟 audit.Store 的只读查询）。
func (f *fakeAudit) ListByAction(_ context.Context, action string) ([]audit.StoredEvent, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []audit.StoredEvent
	for i, ev := range f.events {
		if ev.Action != action {
			continue
		}
		raw, _ := json.Marshal(ev.Payload)
		out = append(out, audit.StoredEvent{
			ID: ev.ID, Actor: ev.Actor, Action: ev.Action, Target: ev.Target,
			Seq: int64(i) + 1, Payload: raw,
		})
	}
	return out, nil
}

// actions 按写入顺序返回事件动作列表。
func (f *fakeAudit) actions() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.events))
	for i, e := range f.events {
		out[i] = e.Action
	}
	return out
}

// payloadStrings 全部事件 payload 的 JSON 文本（凭据泄露断言用）。
func (f *fakeAudit) payloadStrings() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.events))
	for i, e := range f.events {
		out[i] = fmt.Sprintf("%v", e.Payload)
	}
	return out
}

// lastDecisionPayload 最后一条 gateway.decision 的载荷。
func (f *fakeAudit) lastDecisionPayload() (decisionPayload, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := len(f.events) - 1; i >= 0; i-- {
		if f.events[i].Action == "gateway.decision" {
			p, ok := f.events[i].Payload.(decisionPayload)
			return p, ok
		}
	}
	return decisionPayload{}, false
}

// fakeApprovals 网关审批依赖的内存实现（与 approvals.PostgresStore 语义等价：
// F3 按 (actor, request_hash) 去重、同键不同内容 422、四眼、30 分钟窗口、
// 先占后执行（Claim/Consume/MarkAbandoned）；时钟可注入，仅测试替身）。
type fakeApprovals struct {
	mu       sync.Mutex
	recs     map[string]approvals.Record
	byKey    map[string]string // actor+"\x00"+idemKey → pending 记录 ID（同键不同内容冲突）
	byHash   map[string]string // actor+"\x00"+requestHash → pending 记录 ID（去重键）
	created  []approvals.Record
	seq      int
	fail     error // Create 失败注入
	renewErr error // Renew 失败注入（H1：执行中止路径）
	clock    func() time.Time
	window   time.Duration
}

func newFakeApprovals() *fakeApprovals {
	return &fakeApprovals{
		recs:   map[string]approvals.Record{},
		byKey:  map[string]string{},
		byHash: map[string]string{},
		clock:  time.Now,
		window: approvals.DefaultApprovalWindow,
	}
}

// now 注入时钟（未注入时用真实时钟，避免零值替身 panic）。
func (f *fakeApprovals) now() time.Time {
	if f.clock == nil {
		return time.Now()
	}
	return f.clock()
}

// win 审批窗口（未设置时用默认值）。
func (f *fakeApprovals) win() time.Duration {
	if f.window <= 0 {
		return approvals.DefaultApprovalWindow
	}
	return f.window
}

func (f *fakeApprovals) Create(_ context.Context, n approvals.NewRecord) (approvals.Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return approvals.Record{}, f.fail
	}
	// 1) 同幂等键：内容不同 → 422（冲突判定优先）。
	key := n.Actor + "\x00" + n.IdempotencyKey
	if id, ok := f.byKey[key]; ok {
		existing := f.recs[id]
		if existing.RequestHash != n.RequestHash {
			return approvals.Record{}, approvals.ErrContentConflict
		}
		f.created = append(f.created, existing)
		return existing, nil
	}
	// 2) 同内容不同键 → 返回已有审批 ID（F3 去重键为 (actor, request_hash)）。
	hkey := n.Actor + "\x00" + n.RequestHash
	if id, ok := f.byHash[hkey]; ok {
		existing := f.recs[id]
		f.created = append(f.created, existing)
		return existing, nil
	}
	f.seq++
	rec := approvals.Record{
		ID:             fmt.Sprintf("apr-fake-%d", f.seq),
		Actor:          n.Actor,
		Capability:     n.Capability,
		RequestHash:    n.RequestHash,
		IdempotencyKey: n.IdempotencyKey,
		Status:         approvals.StatusPending,
		CreatedAt:      f.now(),
		UpdatedAt:      f.now(),
		ExpiresAt:      n.ExpiresAt,
	}
	f.recs[rec.ID] = rec
	f.byKey[key] = rec.ID
	f.byHash[hkey] = rec.ID
	f.created = append(f.created, rec)
	return rec, nil
}

func (f *fakeApprovals) Get(_ context.Context, id string) (approvals.Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rec, ok := f.recs[id]
	if !ok {
		return approvals.Record{}, approvals.ErrNotFound
	}
	return rec, nil
}

func (f *fakeApprovals) Approve(_ context.Context, id, approver, reason string) (approvals.Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rec, ok := f.recs[id]
	if !ok {
		return approvals.Record{}, approvals.ErrNotFound
	}
	if rec.Status != approvals.StatusPending {
		return approvals.Record{}, approvals.ErrIllegalTransition
	}
	if strings.TrimSpace(approver) == "" || rec.Actor == approver {
		return approvals.Record{}, approvals.ErrApproverMustDiffer
	}
	rec.Status = approvals.StatusApproved
	now := f.now()
	rec.ApprovedAt = &now
	rec.UpdatedAt = now
	rec.DecidedBy = approver
	rec.Reason = reason
	f.recs[id] = rec
	f.dropPendingIndexes(rec)
	return rec, nil
}

// dropPendingIndexes 记录离开 pending 后释放去重索引（键与内容哈希）。
func (f *fakeApprovals) dropPendingIndexes(rec approvals.Record) {
	delete(f.byKey, rec.Actor+"\x00"+rec.IdempotencyKey)
	delete(f.byHash, rec.Actor+"\x00"+rec.RequestHash)
}

func (f *fakeApprovals) Reject(_ context.Context, id, decider, reason string) (approvals.Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rec, ok := f.recs[id]
	if !ok {
		return approvals.Record{}, approvals.ErrNotFound
	}
	if rec.Status != approvals.StatusPending {
		return approvals.Record{}, approvals.ErrIllegalTransition
	}
	rec.Status = approvals.StatusRejected
	rec.UpdatedAt = f.now()
	rec.DecidedBy = decider
	rec.Reason = reason
	f.recs[id] = rec
	f.dropPendingIndexes(rec)
	return rec, nil
}

func (f *fakeApprovals) CheckExecutable(_ context.Context, id string) (approvals.Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rec, ok := f.recs[id]
	if !ok {
		return approvals.Record{}, approvals.ErrNotFound
	}
	if rec.Status != approvals.StatusApproved || rec.ApprovedAt == nil {
		return rec, approvals.ErrNotApproved
	}
	if !f.now().Before(rec.ApprovedAt.Add(f.win())) {
		rec.Status = approvals.StatusExpired
		rec.DecidedBy = "system"
		rec.UpdatedAt = f.now()
		rec.Reason = "approved 超过 30 分钟执行窗口，已作废"
		f.recs[id] = rec
		return rec, approvals.ErrApprovalVoided
	}
	return rec, nil
}

// Claim 先占后执行（第十轮）：approved → executing 的原子 CAS（内存替身以互斥锁模拟）。
func (f *fakeApprovals) Claim(_ context.Context, id string, lease time.Duration) (approvals.Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rec, ok := f.recs[id]
	if !ok {
		return approvals.Record{}, approvals.ErrNotFound
	}
	if rec.Status != approvals.StatusApproved || rec.ApprovedAt == nil {
		return approvals.Record{}, approvals.ErrNotClaimable
	}
	if !f.now().Before(rec.ApprovedAt.Add(f.win())) {
		rec.Status = approvals.StatusExpired
		rec.DecidedBy = "system"
		rec.UpdatedAt = f.now()
		rec.Reason = "approved 超过 30 分钟执行窗口，已作废"
		f.recs[id] = rec
		return approvals.Record{}, approvals.ErrApprovalVoided
	}
	rec.Status = approvals.StatusExecuting
	rec.UpdatedAt = f.now()
	rec.Reason = "审批已被执行抢占（executing）"
	until := f.now().Add(lease)
	rec.LeaseUntil = &until
	f.recs[id] = rec
	return rec, nil
}

// Renew 续期租约（H1）：executing 且未过期时可续期；renewErr 注入用于中止路径测试。
func (f *fakeApprovals) Renew(_ context.Context, id string, lease time.Duration) (approvals.Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.renewErr != nil {
		return approvals.Record{}, f.renewErr
	}
	rec, ok := f.recs[id]
	if !ok {
		return approvals.Record{}, approvals.ErrNotFound
	}
	if rec.Status != approvals.StatusExecuting {
		return approvals.Record{}, approvals.ErrNotExecuting
	}
	if rec.LeaseUntil == nil || !f.now().Before(*rec.LeaseUntil) {
		return approvals.Record{}, approvals.ErrExecutionLeaseExpired
	}
	until := f.now().Add(lease)
	rec.LeaseUntil = &until
	rec.UpdatedAt = f.now()
	f.recs[id] = rec
	return rec, nil
}

// Consume executing → consumed（第十轮：消费只发生在抢占成功之后）。
func (f *fakeApprovals) Consume(_ context.Context, id string) (approvals.Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rec, ok := f.recs[id]
	if !ok {
		return approvals.Record{}, approvals.ErrNotFound
	}
	if rec.Status != approvals.StatusExecuting || rec.ApprovedAt == nil {
		return approvals.Record{}, approvals.ErrNotExecuting
	}
	if !f.now().Before(rec.ApprovedAt.Add(f.win())) {
		rec.Status = approvals.StatusExpired
		rec.DecidedBy = "system"
		rec.UpdatedAt = f.now()
		f.recs[id] = rec
		return approvals.Record{}, approvals.ErrApprovalVoided
	}
	rec.Status = approvals.StatusConsumed
	rec.UpdatedAt = f.now()
	rec.DecidedBy = "system"
	rec.Reason = "审批已消费（执行完成）"
	f.recs[id] = rec
	return rec, nil
}

// MarkAbandoned executing → abandoned（对账用；已 abandoned 时幂等）。
func (f *fakeApprovals) MarkAbandoned(_ context.Context, id string) (approvals.Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rec, ok := f.recs[id]
	if !ok {
		return approvals.Record{}, approvals.ErrNotFound
	}
	if rec.Status == approvals.StatusAbandoned {
		return rec, nil
	}
	if rec.Status != approvals.StatusExecuting {
		return approvals.Record{}, approvals.ErrNotExecuting
	}
	rec.Status = approvals.StatusAbandoned
	rec.UpdatedAt = f.now()
	rec.DecidedBy = "system"
	rec.Reason = "抢占后无终态事件，已放弃（不重放）"
	f.recs[id] = rec
	return rec, nil
}

// ListExecuting 列出处于 executing 的审批（单实例守卫用）。
func (f *fakeApprovals) ListExecuting(_ context.Context) ([]approvals.Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []approvals.Record
	for _, rec := range f.recs {
		if rec.Status == approvals.StatusExecuting {
			out = append(out, rec)
		}
	}
	return out, nil
}

// ListExpiredExecuting 列出租约已过期的 executing 审批（对账扫描，H1）。
func (f *fakeApprovals) ListExpiredExecuting(_ context.Context, now time.Time) ([]approvals.Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []approvals.Record
	for _, rec := range f.recs {
		if rec.Status != approvals.StatusExecuting {
			continue
		}
		if rec.LeaseUntil == nil || !now.Before(*rec.LeaseUntil) {
			out = append(out, rec)
		}
	}
	return out, nil
}

// countingHandler 记录调用次数的执行逻辑。
type countingHandler struct {
	mu     sync.Mutex
	calls  int
	result *contractv1.ActionResult
	err    error
}

func (h *countingHandler) handle(_ context.Context, _ Request) (*contractv1.ActionResult, error) {
	h.mu.Lock()
	h.calls++
	h.mu.Unlock()
	return h.result, h.err
}

func (h *countingHandler) callCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.calls
}

// —— 能力声明与请求构造 ——

// testCapTimeout 测试能力声明的执行超时（第十二轮 H6：超时必填，
// 执行租约由它推导）。
const testCapTimeout = 60 * time.Second

// testLease 测试用执行租约（= testCapTimeout + 2×续期间隔）。
func testLease() time.Duration { return approvals.LeaseFor(testCapTimeout) }

func capDecl(name string, tier contractv1.RiskTier, destructive bool) *contractv1.Capability {
	return &contractv1.Capability{
		Name: name, RiskTier: tier, Rollbackable: true, Destructive: destructive,
		Timeout: durationpb.New(testCapTimeout),
	}
}

func actionReq(capability string, params map[string]any) *contractv1.Action {
	st, _ := structpb.NewStruct(normalizeParams(params))
	return &contractv1.Action{
		Capability: capability,
		Params:     st,
		Target:     &contractv1.AssetTarget{AssetId: "ast_01HX", Access: contractv1.AccessKind_ACCESS_SSH},
	}
}

func normalizeParams(in map[string]any) map[string]any {
	if in == nil {
		return map[string]any{}
	}
	return in
}

func execReq(actor, key, capability string, params map[string]any) Request {
	return Request{
		Actor:          actor,
		IdempotencyKey: key,
		Action:         actionReq(capability, params),
		Environment:    contractv1.Environment_ENVIRONMENT_TEST,
	}
}

// newTestService 组装被测服务：生产默认配置（自动执行清单为空）。
func newTestService(t *testing.T, ms *idempotency.MemoryStore, af *fakeAudit, ap *fakeApprovals) (*Service, *Registry) {
	t.Helper()
	reg := NewRegistry()
	svc, err := New(DefaultConfig(), ms, af, ap, reg)
	if err != nil {
		t.Fatalf("组装服务失败：%v", err)
	}
	return svc, reg
}

// newTestServiceReg 组装被测服务（自定义配置 + 指定注册表，供第九轮仅测试能力用例）。
func newTestServiceReg(t *testing.T, ms *idempotency.MemoryStore, af *fakeAudit, ap *fakeApprovals,
	cfg Config, reg *Registry) *Service {
	t.Helper()
	svc, err := New(cfg, ms, af, ap, reg)
	if err != nil {
		t.Fatalf("组装服务失败：%v", err)
	}
	return svc
}

// okResult 成功结果。
func okResult() *contractv1.ActionResult {
	return &contractv1.ActionResult{Success: true}
}

// —— 用例 ——

// TestAllowExecutesAfterPolicyAndIdempotency 只读能力：策略 allow → 执行，
// 决策与执行结果均写审计；同键重放不再执行。
func TestAllowExecutesAfterPolicyAndIdempotency(t *testing.T) {
	af := &fakeAudit{}
	handler := &countingHandler{result: okResult()}
	svc, reg := newTestService(t, idempotency.NewMemoryStore(), af, newFakeApprovals())
	if err := reg.Register(capDecl("diagnose.disk_usage", contractv1.RiskTier_RISK_TIER_READ_ONLY, false), handler.handle); err != nil {
		t.Fatal(err)
	}

	req := execReq("ops-lead", "k-1", "diagnose.disk_usage", nil)
	resp, err := svc.Execute(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != StatusSuccess || resp.Decision != contractv1.Decision_DECISION_AUTO {
		t.Fatalf("应成功执行且决策 allow：%+v", resp)
	}
	if handler.callCount() != 1 {
		t.Fatalf("应恰好执行 1 次，got %d", handler.callCount())
	}
	if got := af.actions(); len(got) != 2 || got[0] != "gateway.decision" || got[1] != "gateway.executed" {
		t.Fatalf("审计事件序列不符：%v", got)
	}
	if p, ok := af.lastDecisionPayload(); !ok || p.Decision != "allow" {
		t.Fatalf("决策审计应为 allow：%+v ok=%v", p, ok)
	}

	// 同键同内容重放：不重新执行，返回已存结果。
	resp2, err := svc.Execute(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !resp2.Replayed || resp2.Status != StatusSuccess || handler.callCount() != 1 {
		t.Fatalf("重放不执行：resp=%+v calls=%d", resp2, handler.callCount())
	}
}

// TestHardDenyRuleNoExecution 硬拒绝名称规则命中：deny 且不执行。
func TestHardDenyRuleNoExecution(t *testing.T) {
	af := &fakeAudit{}
	handler := &countingHandler{result: okResult()}
	svc, reg := newTestService(t, idempotency.NewMemoryStore(), af, newFakeApprovals())
	if err := reg.Register(capDecl("volume.delete.snapshot", contractv1.RiskTier_RISK_TIER_LOW, false), handler.handle); err != nil {
		t.Fatal(err)
	}

	resp, err := svc.Execute(context.Background(), execReq("ops-lead", "k-1", "volume.delete.snapshot", nil))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != StatusDenied || resp.Decision != contractv1.Decision_DECISION_DENY {
		t.Fatalf("应拒绝：%+v", resp)
	}
	if handler.callCount() != 0 {
		t.Fatalf("deny 不得执行：calls=%d", handler.callCount())
	}
	if p, ok := af.lastDecisionPayload(); !ok || p.Decision != "deny" {
		t.Fatalf("决策审计应为 deny：%+v ok=%v", p, ok)
	}
}

// TestRequireApprovalCreatesPendingOnly require_approval 只创建 pending 记录并返回
// pending，不执行（第八轮约束 5）。本用例经低风险白名单门控进入该分支
// （生产自动执行清单为空 → 低风险 auto 转审批）。
func TestRequireApprovalCreatesPendingOnly(t *testing.T) {
	af := &fakeAudit{}
	ap := newFakeApprovals()
	handler := &countingHandler{result: okResult()}
	svc, reg := newTestService(t, idempotency.NewMemoryStore(), af, ap)
	if err := reg.Register(capDecl("restart.service", contractv1.RiskTier_RISK_TIER_LOW, false), handler.handle); err != nil {
		t.Fatal(err)
	}

	resp, err := svc.Execute(context.Background(), execReq("ops-lead", "k-1", "restart.service", nil))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != StatusPendingApproval || resp.Decision != contractv1.Decision_DECISION_REQUIRE_APPROVAL {
		t.Fatalf("应返回 pending：%+v", resp)
	}
	if resp.ApprovalID == "" {
		t.Fatal("应返回审批记录 ID")
	}
	if handler.callCount() != 0 {
		t.Fatalf("require_approval 不得执行：calls=%d", handler.callCount())
	}
	if len(ap.created) != 1 || ap.created[0].Status != approvals.StatusPending {
		t.Fatalf("应恰好创建 1 条 pending 记录：%v", ap.created)
	}
	actions := af.actions()
	if len(actions) != 2 || actions[0] != "gateway.decision" || actions[1] != "approval.created" {
		t.Fatalf("审计事件序列不符：%v", actions)
	}
	if p, ok := af.lastDecisionPayload(); !ok || p.Decision != "require_approval" {
		t.Fatalf("决策审计应为 require_approval：%+v ok=%v", p, ok)
	}
	// F3（第十轮）：pending 去重键为 (actor, request_hash)——同一内容重复提交
	// （即使换幂等键）返回同一审批 ID，不再新建。
	again, err := svc.Execute(context.Background(), execReq("ops-lead", "k-1", "restart.service", nil))
	if err != nil {
		t.Fatal(err)
	}
	if again.ApprovalID != resp.ApprovalID {
		t.Fatalf("同内容重复提交应返回同一审批 ID：%s vs %s", resp.ApprovalID, again.ApprovalID)
	}
	if len(ap.recs) != 1 {
		t.Fatalf("同内容重复提交不得新建审批记录：recs=%d", len(ap.recs))
	}
}

// TestLowRiskAllowlistedExecutes 低风险能力在测试配置的「仅测试」清单内 → 自动执行。
// 本用例的 AutoExecAllowlist 仅测试（生产清单保持为空，见 DefaultConfig）。
func TestLowRiskAllowlistedExecutes(t *testing.T) {
	af := &fakeAudit{}
	handler := &countingHandler{result: okResult()}
	cfg := DefaultConfig()
	cfg.AutoExecAllowlist = map[string]bool{"restart.service": true} // 仅测试
	reg := NewRegistry()
	svc, err := New(cfg, idempotency.NewMemoryStore(), af, newFakeApprovals(), reg)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Register(capDecl("restart.service", contractv1.RiskTier_RISK_TIER_LOW, false), handler.handle); err != nil {
		t.Fatal(err)
	}

	resp, err := svc.Execute(context.Background(), execReq("ops-lead", "k-1", "restart.service", nil))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != StatusSuccess || handler.callCount() != 1 {
		t.Fatalf("清单内低风险能力应自动执行：%+v calls=%d", resp, handler.callCount())
	}
}

// TestDestructiveDeniedAtGateway destructive 在网关层直接拒绝：
// 不进入审批、不执行、不触达 Handler（第八轮约束 4）。
func TestDestructiveDeniedAtGateway(t *testing.T) {
	af := &fakeAudit{}
	ap := newFakeApprovals()
	handler := &countingHandler{result: okResult()}
	svc, reg := newTestService(t, idempotency.NewMemoryStore(), af, ap)
	// 测试专用破坏性能力声明（仅测试；生产清单无任何 destructive 能力）。
	if err := reg.Register(capDecl("test.destroy.disk", contractv1.RiskTier_RISK_TIER_READ_ONLY, true), handler.handle); err != nil {
		t.Fatal(err)
	}

	resp, err := svc.Execute(context.Background(), execReq("ops-lead", "k-1", "test.destroy.disk", nil))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != StatusDenied {
		t.Fatalf("破坏性能力应被拒绝：%+v", resp)
	}
	if !strings.Contains(resp.Message, "破坏性") || !strings.Contains(resp.Message, "网关") {
		t.Fatalf("错误信息应明确说明网关直接拒绝破坏性操作：%q", resp.Message)
	}
	if handler.callCount() != 0 {
		t.Fatalf("destructive 不得触达执行层：calls=%d", handler.callCount())
	}
	if len(ap.created) != 0 {
		t.Fatalf("destructive 不得进入审批：created=%d", len(ap.created))
	}
	if p, ok := af.lastDecisionPayload(); !ok || p.Decision != "deny" ||
		!strings.Contains(strings.Join(p.Reasons, "；"), "destructive") {
		t.Fatalf("拒绝理由应明确为 destructive：%+v ok=%v", p, ok)
	}
}

// TestAuditDecisionFailurePreventsExecution 决策审计失败 → fail-closed：
// 阻止执行并返回错误。
func TestAuditDecisionFailurePreventsExecution(t *testing.T) {
	af := &fakeAudit{failAppend: errors.New("审计库不可用")}
	handler := &countingHandler{result: okResult()}
	svc, reg := newTestService(t, idempotency.NewMemoryStore(), af, newFakeApprovals())
	if err := reg.Register(capDecl("diagnose.disk_usage", contractv1.RiskTier_RISK_TIER_READ_ONLY, false), handler.handle); err != nil {
		t.Fatal(err)
	}

	if _, err := svc.Execute(context.Background(), execReq("ops-lead", "k-1", "diagnose.disk_usage", nil)); err == nil {
		t.Fatal("决策审计失败应返回错误（fail closed）")
	}
	if handler.callCount() != 0 {
		t.Fatalf("审计失败不得执行：calls=%d", handler.callCount())
	}
}

// TestAuditExecutionFailureFailsRequest 执行结果审计写入失败 → 请求按失败返回
// （执行已发生，只读能力无副作用；审计语义 fail-closed）。
func TestAuditExecutionFailureFailsRequest(t *testing.T) {
	af := &fakeAudit{failOnAction: "gateway.executed"}
	handler := &countingHandler{result: okResult()}
	svc, reg := newTestService(t, idempotency.NewMemoryStore(), af, newFakeApprovals())
	if err := reg.Register(capDecl("diagnose.disk_usage", contractv1.RiskTier_RISK_TIER_READ_ONLY, false), handler.handle); err != nil {
		t.Fatal(err)
	}

	req := execReq("ops-lead", "k-1", "diagnose.disk_usage", nil)
	resp, err := svc.Execute(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != StatusFailed || !strings.Contains(resp.Message, "审计") {
		t.Fatalf("执行结果审计失败应按失败返回：%+v", resp)
	}
	if handler.callCount() != 1 {
		t.Fatalf("执行应已发生：calls=%d", handler.callCount())
	}

	// 恢复审计后同键请求：重放已存的失败结果，不再执行。
	af.mu.Lock()
	af.failOnAction = ""
	af.mu.Unlock()
	resp2, err := svc.Execute(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !resp2.Replayed || resp2.Status != StatusFailed || handler.callCount() != 1 {
		t.Fatalf("应重放已存失败结果且不再执行：%+v calls=%d", resp2, handler.callCount())
	}
}

// TestExecutionFailureAudited 执行失败：审计 failed、响应失败、错误信息脱敏。
func TestExecutionFailureAudited(t *testing.T) {
	af := &fakeAudit{}
	handler := &countingHandler{err: errors.New("boom password=hunter2secret 执行出错")}
	svc, reg := newTestService(t, idempotency.NewMemoryStore(), af, newFakeApprovals())
	if err := reg.Register(capDecl("diagnose.disk_usage", contractv1.RiskTier_RISK_TIER_READ_ONLY, false), handler.handle); err != nil {
		t.Fatal(err)
	}

	resp, err := svc.Execute(context.Background(), execReq("ops-lead", "k-1", "diagnose.disk_usage", nil))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != StatusFailed {
		t.Fatalf("执行失败应返回 failed：%+v", resp)
	}
	if strings.Contains(resp.Message, "hunter2secret") {
		t.Fatalf("错误信息应脱敏：%q", resp.Message)
	}
	if !strings.Contains(resp.Message, "password=***") {
		t.Fatalf("凭据字段应掩码：%q", resp.Message)
	}
	actions := af.actions()
	if len(actions) != 2 || actions[1] != "gateway.execution.failed" {
		t.Fatalf("审计事件序列不符：%v", actions)
	}
}

// TestCredentialsNeverLeak 凭据保护（约束 11）：凭据引用与凭据形态参数
// 不得出现在任何审计 payload 中；错误信息经脱敏。
func TestCredentialsNeverLeak(t *testing.T) {
	af := &fakeAudit{}
	handler := &countingHandler{err: errors.New("处理参数失败 secret=ultra-hunter2, user param credential=abc123")}
	svc, reg := newTestService(t, idempotency.NewMemoryStore(), af, newFakeApprovals())
	if err := reg.Register(capDecl("diagnose.disk_usage", contractv1.RiskTier_RISK_TIER_READ_ONLY, false), handler.handle); err != nil {
		t.Fatal(err)
	}

	st, err := structpb.NewStruct(map[string]any{
		"password": "p@ssword-plain",
		"unit":     "nginx",
	})
	if err != nil {
		t.Fatal(err)
	}
	req := Request{
		Actor:          "ops-lead",
		IdempotencyKey: "k-1",
		Action: &contractv1.Action{
			Capability: "diagnose.disk_usage",
			Params:     st,
			Target: &contractv1.AssetTarget{
				AssetId: "ast_01HX",
				Credential: &contractv1.CredentialRef{
					Id: "cred-ref-ultra-secret",
				},
			},
		},
		Environment: contractv1.Environment_ENVIRONMENT_TEST,
	}
	resp, err := svc.Execute(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != StatusFailed {
		t.Fatalf("前置：应执行失败：%+v", resp)
	}
	for _, s := range af.payloadStrings() {
		for _, secret := range []string{"ultra-hunter2", "abc123", "p@ssword-plain", "cred-ref-ultra-secret"} {
			if strings.Contains(s, secret) {
				t.Fatalf("审计 payload 泄露凭据 %q：%s", secret, s)
			}
		}
	}
	if strings.Contains(resp.Message, "ultra-hunter2") || strings.Contains(resp.Message, "abc123") {
		t.Fatalf("响应错误信息泄露凭据：%q", resp.Message)
	}
}

// TestIdempotencyConflictAndInProgress 幂等三种状态：
// 同键同内容重放、同键不同内容 422、处理中 409。
func TestIdempotencyConflictAndInProgress(t *testing.T) {
	af := &fakeAudit{}
	ms := idempotency.NewMemoryStore()
	handler := &countingHandler{result: okResult()}
	svc, reg := newTestService(t, ms, af, newFakeApprovals())
	if err := reg.Register(capDecl("diagnose.disk_usage", contractv1.RiskTier_RISK_TIER_READ_ONLY, false), handler.handle); err != nil {
		t.Fatal(err)
	}

	// 1) 同键不同内容 → 422（冲突）。
	base := execReq("ops-lead", "k-conflict", "diagnose.disk_usage", map[string]any{"unit": "a"})
	if _, err := svc.Execute(context.Background(), base); err != nil {
		t.Fatal(err)
	}
	other := execReq("ops-lead", "k-conflict", "diagnose.disk_usage", map[string]any{"unit": "b"})
	resp, err := svc.Execute(context.Background(), other)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != StatusConflict {
		t.Fatalf("同键不同内容应为 conflict（422）：%+v", resp)
	}
	if handler.callCount() != 1 {
		t.Fatalf("冲突请求不得执行：calls=%d", handler.callCount())
	}

	// 2) 处理中 → 409。预置同键 processing 记录。
	scope := idempotency.Scope{Actor: "ops-lead", API: ScopeAPI, Key: "k-progress"}
	pending := execReq("ops-lead", "k-progress", "diagnose.disk_usage", nil)
	if _, err := ms.Begin(context.Background(), scope, canonicalRequestBytes(pending)); err != nil {
		t.Fatal(err)
	}
	resp, err = svc.Execute(context.Background(), pending)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != StatusInProgress {
		t.Fatalf("处理中应为 in_progress（409）：%+v", resp)
	}
	if handler.callCount() != 1 {
		t.Fatalf("处理中请求不得执行：calls=%d", handler.callCount())
	}
}

// TestInvalidRequestRejected 边界校验：缺 actor/幂等键/动作一律拒绝且不写审计。
func TestInvalidRequestRejected(t *testing.T) {
	af := &fakeAudit{}
	handler := &countingHandler{result: okResult()}
	svc, reg := newTestService(t, idempotency.NewMemoryStore(), af, newFakeApprovals())
	if err := reg.Register(capDecl("diagnose.disk_usage", contractv1.RiskTier_RISK_TIER_READ_ONLY, false), handler.handle); err != nil {
		t.Fatal(err)
	}

	cases := []Request{
		{Actor: "", IdempotencyKey: "k", Action: actionReq("diagnose.disk_usage", nil)},
		{Actor: "a", IdempotencyKey: "", Action: actionReq("diagnose.disk_usage", nil)},
		{Actor: "a", IdempotencyKey: "k", Action: nil},
		{Actor: "a", IdempotencyKey: "k", Action: actionReq("", nil)},
	}
	for i, req := range cases {
		if _, err := svc.Execute(context.Background(), req); err == nil {
			t.Fatalf("case %d：非法请求应返回错误", i)
		}
	}
	if handler.callCount() != 0 || len(af.actions()) != 0 {
		t.Fatalf("非法请求不得执行、不得写审计：calls=%d events=%v", handler.callCount(), af.actions())
	}
}

// TestUnknownCapabilityDenied 未声明能力拒绝并写 deny 审计。
func TestUnknownCapabilityDenied(t *testing.T) {
	af := &fakeAudit{}
	handler := &countingHandler{result: okResult()}
	svc, reg := newTestService(t, idempotency.NewMemoryStore(), af, newFakeApprovals())
	if err := reg.Register(capDecl("diagnose.disk_usage", contractv1.RiskTier_RISK_TIER_READ_ONLY, false), handler.handle); err != nil {
		t.Fatal(err)
	}
	resp, err := svc.Execute(context.Background(), execReq("ops-lead", "k-1", "diagnose.nothing", nil))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != StatusDenied || handler.callCount() != 0 {
		t.Fatalf("未声明能力应拒绝且不执行：%+v calls=%d", resp, handler.callCount())
	}
	if p, ok := af.lastDecisionPayload(); !ok || p.Decision != "deny" {
		t.Fatalf("决策审计应为 deny：%+v ok=%v", p, ok)
	}
}

// TestApprovalCreateFailure 审批创建失败返回错误（pending 分支 fail）。
func TestApprovalCreateFailure(t *testing.T) {
	af := &fakeAudit{}
	ap := &fakeApprovals{fail: errors.New("审批表不可用")}
	handler := &countingHandler{result: okResult()}
	svc, reg := newTestService(t, idempotency.NewMemoryStore(), af, ap)
	if err := reg.Register(capDecl("restart.service", contractv1.RiskTier_RISK_TIER_LOW, false), handler.handle); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Execute(context.Background(), execReq("ops-lead", "k-1", "restart.service", nil)); err == nil {
		t.Fatal("审批创建失败应返回错误")
	}
	if handler.callCount() != 0 {
		t.Fatal("审批创建失败不得执行")
	}
}

// TestRegistryValidation 注册表校验：非法名称/缺等级/缺 Handler/重复注册。
func TestRegistryValidation(t *testing.T) {
	reg := NewRegistry()
	h := (&countingHandler{result: okResult()}).handle
	cases := []struct {
		name  string
		decl  *contractv1.Capability
		errOK bool
	}{
		{"nil-decl", nil, true},
		{"bad-name", capDecl("Volume.Delete", contractv1.RiskTier_RISK_TIER_LOW, false), true},
		{"no-tier", capDecl("restart.service", contractv1.RiskTier_RISK_TIER_UNSPECIFIED, false), true},
		{"no-handler", capDecl("restart.service", contractv1.RiskTier_RISK_TIER_LOW, false), true},
		{"ok", capDecl("restart.service", contractv1.RiskTier_RISK_TIER_LOW, false), false},
		{"dup", capDecl("restart.service", contractv1.RiskTier_RISK_TIER_LOW, false), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handler := h
			if tc.name == "no-handler" {
				handler = nil
			}
			err := reg.Register(tc.decl, handler)
			if tc.errOK && err == nil {
				t.Fatal("应报错")
			}
			if !tc.errOK && err != nil {
				t.Fatalf("不应报错：%v", err)
			}
		})
	}
	if _, ok := reg.Lookup("missing.cap"); ok {
		t.Fatal("未注册能力不应命中")
	}
	if _, ok := reg.Lookup("restart.service"); !ok {
		t.Fatal("已注册能力应命中")
	}
}

// —— 用例（第九轮：审批通过后的受控执行） ——

// testWriteDecl 仅测试写能力声明（test_only=true；生产能力目录不存在）。
func testWriteDecl() *contractv1.Capability {
	return &contractv1.Capability{
		Name: "test.unit.write", RiskTier: contractv1.RiskTier_RISK_TIER_LOW,
		Rollbackable: true, TestOnly: true, // 仅测试
		Timeout: durationpb.New(testCapTimeout),
	}
}

// setupApprovedWrite 组装「测试配置 + 已进入审批流的写请求」环境：
// 返回服务、审批替身、handler 计数器、审批 ID 与请求。
func setupApprovedWrite(t *testing.T, ap *fakeApprovals, cfg Config) (*Service, *countingHandler, *fakeAudit, string, Request) {
	t.Helper()
	af := &fakeAudit{}
	handler := &countingHandler{result: okResult()}
	reg := NewTestRegistry() // 仅测试
	svc := newTestServiceReg(t, idempotency.NewMemoryStore(), af, ap, cfg, reg)
	if err := reg.Register(testWriteDecl(), handler.handle); err != nil {
		t.Fatal(err)
	}
	req := execReq("ops-lead", "k-w1", "test.unit.write", nil)
	resp, err := svc.Execute(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != StatusPendingApproval {
		t.Fatalf("低风险非清单能力应转审批：%+v", resp)
	}
	return svc, handler, af, resp.ApprovalID, req
}

// TestApprovalDedupGateway 审批去重（R3，网关层）：同键同内容重复提交返回同一
// 审批 ID；同键不同内容 → 422 冲突。
func TestApprovalDedupGateway(t *testing.T) {
	af := &fakeAudit{}
	ap := newFakeApprovals()
	handler := &countingHandler{result: okResult()}
	reg := NewTestRegistry() // 仅测试
	svc := newTestServiceReg(t, idempotency.NewMemoryStore(), af, ap, DefaultConfig(), reg)
	if err := reg.Register(testWriteDecl(), handler.handle); err != nil {
		t.Fatal(err)
	}
	req := execReq("ops-lead", "k-dedup", "test.unit.write", nil)
	resp1, err := svc.Execute(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	resp2, err := svc.Execute(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp1.Status != StatusPendingApproval || resp2.ApprovalID != resp1.ApprovalID {
		t.Fatalf("重复提交应返回同一审批 ID：%+v %+v", resp1, resp2)
	}
	if len(ap.recs) != 1 {
		t.Fatalf("去重后应只有 1 条审批记录：%d", len(ap.recs))
	}
	other := execReq("ops-lead", "k-dedup", "test.unit.write", map[string]any{"marker": "x"})
	resp3, err := svc.Execute(context.Background(), other)
	if err != nil {
		t.Fatal(err)
	}
	if resp3.Status != StatusConflict {
		t.Fatalf("同键不同内容应为 422：%+v", resp3)
	}
	if handler.callCount() != 0 {
		t.Fatalf("审批路径不得执行：calls=%d", handler.callCount())
	}
}

// TestExecuteApprovedFullFlowAndConsumedOnce 完整审批执行链路：
// pending → 四眼批准 → ExecuteApproved（重评策略 → executing → 幂等 → 执行
// → executed → consumed）；consumed 后再次执行被拒且不重复执行。
func TestExecuteApprovedFullFlowAndConsumedOnce(t *testing.T) {
	ap := newFakeApprovals()
	svc, handler, af, approvalID, req := setupApprovedWrite(t, ap, DefaultConfig())

	// 四眼原则（gateway.Approve 层，第九轮决策）：同人审批被拒。
	if _, err := svc.Approve(context.Background(), approvalID, "ops-lead", "自批"); err == nil ||
		!strings.Contains(err.Error(), "四眼") {
		t.Fatalf("同人审批应被四眼原则拒绝：%v", err)
	}
	// 不同审批人批准。
	if _, err := svc.Approve(context.Background(), approvalID, "ops-auditor", "同意执行"); err != nil {
		t.Fatalf("不同审批人应可批准：%v", err)
	}

	resp, err := svc.ExecuteApproved(context.Background(), req, approvalID)
	if err != nil {
		t.Fatalf("执行失败：%v", err)
	}
	if resp.Status != StatusSuccess || resp.Decision != contractv1.Decision_DECISION_AUTO {
		t.Fatalf("批准后执行应成功：%+v", resp)
	}
	if handler.callCount() != 1 {
		t.Fatalf("应恰好执行 1 次：%d", handler.callCount())
	}
	// 审计序列：executing 后紧接 executed（R4）。
	actions := af.actions()
	idx := -1
	for i, a := range actions {
		if a == "gateway.executing" {
			idx = i
		}
	}
	if idx < 0 || idx+1 >= len(actions) || actions[idx+1] != "gateway.executed" {
		t.Fatalf("executing 后应紧接 executed：%v", actions)
	}
	// 审批已消费。
	gotRec, _ := ap.Get(context.Background(), approvalID)
	if gotRec.Status != approvals.StatusConsumed {
		t.Fatalf("执行后审批应为 consumed：%+v", gotRec)
	}
	// consumed 后拒绝再次执行，且不再执行。
	resp2, err := svc.ExecuteApproved(context.Background(), req, approvalID)
	if err != nil {
		t.Fatal(err)
	}
	if resp2.Status != StatusDenied || !strings.Contains(resp2.Message, "consumed") {
		t.Fatalf("consumed 后应拒绝：%+v", resp2)
	}
	if handler.callCount() != 1 {
		t.Fatalf("consumed 后不得再次执行：calls=%d", handler.callCount())
	}
}

// TestExecuteApprovedPolicyRecheckDenies 执行期策略重评（第十轮 F1 语义）：
// 重评只拦截「不可通过审批解除」的条件——本例为策略硬拒绝命中（deny）。
// 注：require_approval 已由有效审批满足（见

// mediumTestWriteDecl 仅测试的中风险写能力声明（MEDIUM 等级 → 策略
// require_approval；生产注册表拒绝加载）。
func mediumTestWriteDecl() *contractv1.Capability {
	return &contractv1.Capability{
		Name: "test.unit.write", RiskTier: contractv1.RiskTier_RISK_TIER_MEDIUM,
		Rollbackable: true, TestOnly: true, // 仅测试
		Timeout: durationpb.New(testCapTimeout),
	}
}

// setupMediumFlow 组装「中风险能力（策略 require_approval）+ 已提交待审批」的环境。
func setupMediumFlow(t *testing.T, ap *fakeApprovals, cfg Config, key string) (*Service, *countingHandler, *fakeAudit, string, Request) {
	t.Helper()
	af := &fakeAudit{}
	handler := &countingHandler{result: okResult()}
	reg := NewTestRegistry() // 仅测试
	svc := newTestServiceReg(t, idempotency.NewMemoryStore(), af, ap, cfg, reg)
	if err := reg.Register(mediumTestWriteDecl(), handler.handle); err != nil {
		t.Fatal(err)
	}
	req := execReq("ops-lead", key, "test.unit.write", nil)
	resp, err := svc.Execute(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != StatusPendingApproval || resp.Decision != contractv1.Decision_DECISION_REQUIRE_APPROVAL {
		t.Fatalf("中风险能力应转审批：%+v", resp)
	}
	return svc, handler, af, resp.ApprovalID, req
}

// TestExecuteApprovedRequireApprovalSatisfiedByValidApproval），不再因
// "重评结果非 auto" 被拦截（第九轮该行为是阻塞缺陷）。
func TestExecuteApprovedPolicyRecheckDenies(t *testing.T) {
	ap := newFakeApprovals()
	svc, handler, _, approvalID, req := setupApprovedWrite(t, ap, DefaultConfig())
	if _, err := svc.Approve(context.Background(), approvalID, "ops-auditor", ""); err != nil {
		t.Fatal(err)
	}

	// 模拟审批期间策略收紧：新增命中该能力的硬拒绝规则（重评 → deny）。
	cfg := DefaultConfig()
	cfg.Policy.HardDeny = append(cfg.Policy.HardDeny,
		policy.HardDenyRule{Pattern: "test.unit.write", Reason: "审批后禁用该能力"})
	af := &fakeAudit{}
	svc2 := newTestServiceReg(t, idempotency.NewMemoryStore(), af, ap, cfg, svc.registry)

	resp, err := svc2.ExecuteApproved(context.Background(), req, approvalID)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != StatusDenied || !strings.Contains(resp.Message, "重评") {
		t.Fatalf("重评返回 deny 应拒绝：%+v", resp)
	}
	if handler.callCount() != 0 {
		t.Fatalf("重评拒绝不得执行：calls=%d", handler.callCount())
	}
	if p, ok := af.lastDecisionPayload(); !ok || p.Decision != "deny" {
		t.Fatalf("拒绝决策应写审计：%+v ok=%v", p, ok)
	}
	// 重评拒绝发生在抢占之前：审批保持 approved（未抢占、未消费）。
	rec, err := ap.Get(context.Background(), approvalID)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != approvals.StatusApproved {
		t.Fatalf("重评拒绝不应抢占/消费审批：%+v", rec)
	}
	for _, a := range af.actions() {
		if a == "gateway.executing" {
			t.Fatal("重评拒绝不应写入 executing 事件")
		}
	}
}

// TestExecuteApprovedVoidedByWindow 批准后 30 分钟未执行即作废（决定二）：
// 超窗执行被拒 + 审批置 expired + approval.expired 审计。
func TestExecuteApprovedVoidedByWindow(t *testing.T) {
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	ap := newFakeApprovals()
	ap.clock = func() time.Time { return base }
	cfg := DefaultConfig()
	cfg.Now = ap.clock
	svc, handler, _, approvalID, req := setupApprovedWrite(t, ap, cfg)
	if _, err := svc.Approve(context.Background(), approvalID, "ops-auditor", ""); err != nil {
		t.Fatal(err)
	}

	base = base.Add(31 * time.Minute) // 超过 30 分钟执行窗口
	af := &fakeAudit{}
	svc2 := newTestServiceReg(t, idempotency.NewMemoryStore(), af, ap, cfg, svc.registry)

	resp, err := svc2.ExecuteApproved(context.Background(), req, approvalID)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != StatusDenied || !strings.Contains(resp.Message, "30 分钟") {
		t.Fatalf("超窗应作废拒绝：%+v", resp)
	}
	rec, _ := ap.Get(context.Background(), approvalID)
	if rec.Status != approvals.StatusExpired {
		t.Fatalf("超窗审批应作废为 expired：%+v", rec)
	}
	if handler.callCount() != 0 {
		t.Fatalf("作废审批不得执行：calls=%d", handler.callCount())
	}
	found := false
	for _, a := range af.actions() {
		if a == "approval.expired" {
			found = true
		}
	}
	if !found {
		t.Fatal("应写入 approval.expired 审计")
	}
}

// TestExecuteApprovedContentMismatch 请求内容与审批记录不一致 → 拒绝执行。
func TestExecuteApprovedContentMismatch(t *testing.T) {
	ap := newFakeApprovals()
	svc, handler, _, approvalID, _ := setupApprovedWrite(t, ap, DefaultConfig())
	if _, err := svc.Approve(context.Background(), approvalID, "ops-auditor", ""); err != nil {
		t.Fatal(err)
	}
	tampered := execReq("ops-lead", "k-w1", "test.unit.write", map[string]any{"marker": "other"})
	resp, err := svc.ExecuteApproved(context.Background(), tampered, approvalID)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != StatusDenied || !strings.Contains(resp.Message, "不一致") {
		t.Fatalf("内容不一致应拒绝：%+v", resp)
	}
	if handler.callCount() != 0 {
		t.Fatalf("内容不一致不得执行：calls=%d", handler.callCount())
	}
}

// TestDestructiveApprovedDeniedEvenApproved destructive 即使已批准也直接拒绝
// （约束 4）：不执行、未写 executing、审批保持 approved（未消费）。
func TestDestructiveApprovedDeniedEvenApproved(t *testing.T) {
	af := &fakeAudit{}
	ap := newFakeApprovals()
	handler := &countingHandler{result: okResult()}
	reg := NewTestRegistry() // 仅测试：破坏性测试能力声明
	svc := newTestServiceReg(t, idempotency.NewMemoryStore(), af, ap, DefaultConfig(), reg)
	if err := reg.Register(&contractv1.Capability{
		Name: "test.destroy.disk", RiskTier: contractv1.RiskTier_RISK_TIER_LOW,
		Rollbackable: true, Destructive: true, TestOnly: true, // 仅测试
		Timeout: durationpb.New(testCapTimeout),
	}, handler.handle); err != nil {
		t.Fatal(err)
	}

	req := execReq("ops-lead", "k-d1", "test.destroy.disk", nil)
	// 直接构造已批准记录（destructive 在提交时就被网关拒绝，无法走正常审批流）。
	rec, err := ap.Create(context.Background(), approvals.NewRecord{
		Actor: "ops-lead", Capability: "test.destroy.disk",
		RequestHash: hashRequest(req), IdempotencyKey: "k-d1",
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ap.Approve(context.Background(), rec.ID, "ops-auditor", ""); err != nil {
		t.Fatal(err)
	}

	resp, err := svc.ExecuteApproved(context.Background(), req, rec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != StatusDenied || !strings.Contains(resp.Message, "破坏性") {
		t.Fatalf("已批准的破坏性能力仍应拒绝：%+v", resp)
	}
	if handler.callCount() != 0 {
		t.Fatalf("破坏性不得触达执行层：calls=%d", handler.callCount())
	}
	after, _ := ap.Get(context.Background(), rec.ID)
	if after.Status != approvals.StatusApproved {
		t.Fatalf("拒绝后审批不应被消费：%+v", after)
	}
	for _, a := range af.actions() {
		if a == "gateway.executing" {
			t.Fatal("破坏性拒绝不应写入 executing 事件")
		}
	}
}

// TestProductionCatalogInvisibleToTestOnly 生产配置/注册表下 test_only 能力不可见
// （约束 5/6）：执行直接"未声明"拒绝；注册直接报错。
func TestProductionCatalogInvisibleToTestOnly(t *testing.T) {
	af := &fakeAudit{}
	handler := &countingHandler{result: okResult()}
	svc, reg := newTestService(t, idempotency.NewMemoryStore(), af, newFakeApprovals())
	if err := reg.Register(capDecl("diagnose.disk_usage", contractv1.RiskTier_RISK_TIER_READ_ONLY, false), handler.handle); err != nil {
		t.Fatal(err)
	}
	// 生产注册表拒绝加载 test_only 声明。
	if err := reg.Register(testWriteDecl(), handler.handle); err == nil {
		t.Fatal("生产注册表必须拒绝 test_only 能力")
	}
	if _, ok := reg.Lookup("test.unit.write"); ok {
		t.Fatal("生产能力目录中 test_only 能力必须不可见")
	}
	// 通过生产服务执行测试能力 → 未声明拒绝。
	resp, err := svc.Execute(context.Background(), execReq("ops-lead", "k-t1", "test.unit.write", nil))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != StatusDenied || !strings.Contains(resp.Message, "未声明") {
		t.Fatalf("生产配置应不可见测试能力：%+v", resp)
	}
	if handler.callCount() != 0 {
		t.Fatal("不可见能力不得执行")
	}
}

// TestCrashReconcileAbandonedNoReplay 崩溃对账（R4 + 第十轮 F2 + 第十一轮 H1）：
// 抢占成功 + executing 审计已写 + 幂等 processing 后进程崩溃，且执行租约已过期
// （lease_until < now）→ Reconcile 写 abandoned 审计事件并把审批标记 abandoned；
// 重启后同请求绝不重放（审批状态拒绝 → FAILED_PRECONDITION），handler 调用恒为 0。
// 租约未过期时一律跳过（见 TestReconcileSkipsLiveLease）。
func TestCrashReconcileAbandonedNoReplay(t *testing.T) {
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	var clockMu sync.Mutex
	clock := func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return base
	}
	advance := func(d time.Duration) {
		clockMu.Lock()
		defer clockMu.Unlock()
		base = base.Add(d)
	}

	ap := newFakeApprovals()
	ap.clock = clock
	cfg := DefaultConfig()
	cfg.Now = clock
	svc, handler, _, approvalID, req := setupApprovedWrite(t, ap, cfg)
	if _, err := svc.Approve(context.Background(), approvalID, "ops-auditor", ""); err != nil {
		t.Fatal(err)
	}

	// 模拟崩溃：抢占成功（写入租约）+ executing 审计 + 幂等 processing，进程死亡。
	af := &fakeAudit{}
	ms := idempotency.NewMemoryStore(idempotency.WithClock(clock))
	svc2 := newTestServiceReg(t, ms, af, ap, cfg, svc.registry)
	if _, err := ap.Claim(context.Background(), approvalID, testLease()); err != nil {
		t.Fatalf("崩溃模拟前置（抢占）失败：%v", err)
	}
	if err := svc2.auditExecuting(context.Background(), req, "exec-crash-1", approvalID); err != nil {
		t.Fatal(err)
	}
	scope := idempotency.Scope{Actor: req.Actor, API: ScopeAPI, Key: req.IdempotencyKey}
	if br, err := ms.Begin(context.Background(), scope, canonicalRequestBytes(req)); err != nil || !br.Fresh {
		t.Fatalf("崩溃模拟前置失败：%v fresh=%v", err, br.Fresh)
	}

	// 重启（同 store 的新服务）→ 对账：租约已过期，两层都标记 abandoned。
	advance(testLease() + time.Second) // 租约过期
	svc3 := newTestServiceReg(t, ms, af, ap, cfg, svc.registry)
	n, err := svc3.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("应标记 1 条 abandoned，got %d", n)
	}
	found := false
	for _, a := range af.actions() {
		if a == "gateway.execution.abandoned" {
			found = true
		}
	}
	if !found {
		t.Fatal("对账应写入 gateway.execution.abandoned")
	}
	found = false
	for _, a := range af.actions() {
		if a == "approval.abandoned" {
			found = true
		}
	}
	if !found {
		t.Fatal("对账应把审批标记 abandoned 并写 approval.abandoned")
	}
	rec, _ := ap.Get(context.Background(), approvalID)
	if rec.Status != approvals.StatusAbandoned {
		t.Fatalf("崩溃未执行的审批应标记 abandoned：%+v", rec)
	}

	// 重启后重试：审批已 abandoned → 拒绝执行（绝不重放）。
	resp, err := svc3.ExecuteApproved(context.Background(), req, approvalID)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != StatusDenied || !strings.Contains(resp.Message, "放弃") {
		t.Fatalf("abandoned 审批应拒绝执行：%+v", resp)
	}
	if resp.Code != CodeApprovalState {
		t.Fatalf("审批状态不允许应映射 FAILED_PRECONDITION（CodeApprovalState）：%+v", resp)
	}
	advance(6 * time.Minute) // 超过幂等租约（5 分钟）
	resp, err = svc3.ExecuteApproved(context.Background(), req, approvalID)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != StatusDenied {
		t.Fatalf("租约超时后仍应拒绝（不重放）：%+v", resp)
	}
	if handler.callCount() != 0 {
		t.Fatalf("abandoned 的写操作绝不自动重放：calls=%d", handler.callCount())
	}
}

// TestCrashReconcileClaimWithoutExecutingAudit 崩溃发生在「抢占之后、executing 审计
// 之前」：审计层无 executing 事件可扫，对账必须靠审批层；且 H1 之后**只处理租约
// 已过期**的 executing 记录——本例先验证租约未过期时跳过（H1 ①），再验证租约
// 过期后标记 abandoned 且不重放（H1 ②）。
func TestCrashReconcileClaimWithoutExecutingAudit(t *testing.T) {
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return base }
	ap := newFakeApprovals()
	ap.clock = clock
	cfg := DefaultConfig()
	cfg.Now = clock
	svc, handler, _, approvalID, req := setupApprovedWrite(t, ap, cfg)
	if _, err := svc.Approve(context.Background(), approvalID, "ops-auditor", ""); err != nil {
		t.Fatal(err)
	}

	// 崩溃模拟：只完成抢占（无 executing 审计、无幂等记录、租约刚写入）。
	if _, err := ap.Claim(context.Background(), approvalID, testLease()); err != nil {
		t.Fatal(err)
	}
	af := &fakeAudit{}
	svc2 := newTestServiceReg(t, idempotency.NewMemoryStore(), af, ap, cfg, svc.registry)

	// H1 ①：租约未过期 → 对账不动它（可能仍在执行）。
	n, err := svc2.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("无 executing 事件时审计层不应标记：got %d", n)
	}
	rec, _ := ap.Get(context.Background(), approvalID)
	if rec.Status != approvals.StatusExecuting {
		t.Fatalf("租约未过期时审批应保持 executing：%+v", rec)
	}
	for _, a := range af.actions() {
		if a == "approval.abandoned" {
			t.Fatal("租约未过期不得标记 abandoned")
		}
	}

	// H1 ②：租约过期后对账 → abandoned，且重启后不重放。
	// cfg.Now 与审批存储时钟必须一起拨到租约过期之后。
	ap.clock = func() time.Time { return base.Add(testLease() + time.Second) }
	cfg2 := DefaultConfig()
	cfg2.Now = ap.clock
	svc3 := newTestServiceReg(t, idempotency.NewMemoryStore(), af, ap, cfg2, svc.registry)
	if _, err := svc3.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	rec, _ = ap.Get(context.Background(), approvalID)
	if rec.Status != approvals.StatusAbandoned {
		t.Fatalf("抢占后无终态且租约过期的审批应标记 abandoned：%+v", rec)
	}
	resp, err := svc3.ExecuteApproved(context.Background(), req, approvalID)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != StatusDenied || handler.callCount() != 0 {
		t.Fatalf("abandoned 审批应拒绝且不执行：%+v calls=%d", resp, handler.callCount())
	}
}

// TestExecuteApprovedRenewFailureAbortsExecution 续期失败时执行被中止并写 failed
// 审计（H1 ③）：审批标记 abandoned（不重放、不消费），handler 未跑完。
// 说明：续期由独立 goroutine 按 cfg.LeaseRenewInterval 触发，本例用极短间隔
// 并在 handler 阻塞期间注入续期失败。
func TestExecuteApprovedRenewFailureAbortsExecution(t *testing.T) {
	ap := newFakeApprovals()
	ap.renewErr = approvals.ErrExecutionLeaseExpired // 续期必失败
	cfg := DefaultConfig()
	cfg.LeaseRenewInterval = 10 * time.Millisecond // 仅测试：缩短续期间隔
	// handler 阻塞足够长，让续期 goroutine 至少触发一次（ renewal interval 10ms）。
	slow := newBlockingHandler(okResult())
	slow.block = 200 * time.Millisecond
	reg := NewTestRegistry() // 仅测试
	af := &fakeAudit{}
	svc := newTestServiceReg(t, idempotency.NewMemoryStore(), af, ap, cfg, reg)
	if err := reg.Register(mediumTestWriteDecl(), slow.handle); err != nil {
		t.Fatal(err)
	}
	req := execReq("ops-lead", "k-renew-fail", "test.unit.write", nil)
	submitted, err := svc.Execute(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if submitted.Status != StatusPendingApproval {
		t.Fatalf("前置：应转审批：%+v", submitted)
	}
	approvalID := submitted.ApprovalID
	if _, err := svc.Approve(context.Background(), approvalID, "ops-auditor", "同意"); err != nil {
		t.Fatal(err)
	}

	resp, err := svc.ExecuteApproved(context.Background(), req, approvalID)
	if err != nil {
		t.Fatalf("续期失败应返回 failed 结局而不是错误：%v", err)
	}
	if resp.Status != StatusFailed {
		t.Fatalf("续期失败应使执行失败：%+v", resp)
	}
	if !strings.Contains(resp.Message, "执行租约") {
		t.Fatalf("失败原因应标明执行租约（不重放）：%q", resp.Message)
	}
	if !slow.cancelled() {
		t.Fatal("续期失败应取消执行上下文（执行被中止）")
	}
	// 审计序列：executing → failed → abandoned（H1：续期失败写 failed 并放弃审批）。
	actions := af.actions()
	idxExec, idxFail, idxAbandon := -1, -1, -1
	for i, a := range actions {
		switch a {
		case "gateway.executing":
			idxExec = i
		case "gateway.execution.failed":
			idxFail = i
		case "approval.abandoned":
			idxAbandon = i
		}
	}
	if idxExec < 0 || idxFail != idxExec+1 || idxAbandon != idxFail+1 {
		t.Fatalf("应写 executing → failed → approval.abandoned：%v", actions)
	}
	// 审批 abandoned：不消费、不重放。
	rec, _ := ap.Get(context.Background(), approvalID)
	if rec.Status != approvals.StatusAbandoned {
		t.Fatalf("续期失败后审批应 abandoned：%+v", rec)
	}
	// 重试同一审批 → 拒绝。
	retry, err := svc.ExecuteApproved(context.Background(), req, approvalID)
	if err != nil {
		t.Fatal(err)
	}
	if retry.Status != StatusDenied || slow.callCount() != 1 {
		t.Fatalf("abandoned 后不得重放：%+v calls=%d", retry, slow.callCount())
	}
}

// TestGuardSingleInstanceRejectsLiveLease 单实例守卫（H1 ④）：第二个实例启动时
// 检测到其他实例持有的有效执行租约 → 拒绝启动。
func TestGuardSingleInstanceRejectsLiveLease(t *testing.T) {
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	ap := newFakeApprovals()
	ap.clock = func() time.Time { return base }
	cfg := DefaultConfig()
	cfg.Now = ap.clock
	svc, _, _, approvalID, _ := setupApprovedWrite(t, ap, cfg)
	if _, err := svc.Approve(context.Background(), approvalID, "ops-auditor", ""); err != nil {
		t.Fatal(err)
	}

	// 实例 A：抢占并持有有效租约。
	if _, err := ap.Claim(context.Background(), approvalID, testLease()); err != nil {
		t.Fatal(err)
	}
	// 实例 B：同一存储上启动 → 守卫拒绝。
	if err := svc.GuardSingleInstance(context.Background()); err == nil {
		t.Fatal("存在有效租约时第二个实例必须拒绝启动")
	} else if !strings.Contains(err.Error(), "单实例") {
		t.Fatalf("拒绝原因应说明单实例约束：%v", err)
	}

	// 租约过期后（持有者已崩溃）→ 允许启动。
	ap.clock = func() time.Time { return base.Add(testLease() + time.Second) }
	cfg2 := DefaultConfig()
	cfg2.Now = ap.clock
	svc2 := newTestServiceReg(t, idempotency.NewMemoryStore(), &fakeAudit{}, ap, cfg2, svc.registry)
	if err := svc2.GuardSingleInstance(context.Background()); err != nil {
		t.Fatalf("租约过期后应允许启动：%v", err)
	}
}

// blockingHandler 阻塞式执行逻辑（并发抢占/续期失败用例用）：
// block>0 时阻塞该时长并观察取消；否则等待 release()。
type blockingHandler struct {
	mu       sync.Mutex
	calls    int
	aborted  bool // Handler 是否观察到执行上下文被取消
	result   *contractv1.ActionResult
	block    time.Duration
	called   chan struct{}
	gate     chan struct{}
	onceCall sync.Once
	onceRel  sync.Once
}

func newBlockingHandler(result *contractv1.ActionResult) *blockingHandler {
	return &blockingHandler{result: result, called: make(chan struct{}), gate: make(chan struct{})}
}

func (h *blockingHandler) handle(ctx context.Context, _ Request) (*contractv1.ActionResult, error) {
	h.mu.Lock()
	h.calls++
	h.mu.Unlock()
	h.onceCall.Do(func() { close(h.called) })
	if h.block > 0 {
		select {
		case <-time.After(h.block):
			return h.result, nil
		case <-ctx.Done():
			h.mu.Lock()
			h.aborted = true
			h.mu.Unlock()
			return nil, ctx.Err()
		}
	}
	select {
	case <-h.gate:
		return h.result, nil
	case <-ctx.Done():
		h.mu.Lock()
		h.aborted = true
		h.mu.Unlock()
		return nil, ctx.Err()
	}
}

// waitCalled 等待某个调用方进入执行（超时即失败，避免用例挂死）。
func (h *blockingHandler) waitCalled(t *testing.T, d time.Duration) {
	t.Helper()
	select {
	case <-h.called:
	case <-time.After(d):
		t.Fatal("等待执行开始超时")
	}
}

func (h *blockingHandler) release() { h.onceRel.Do(func() { close(h.gate) }) }

func (h *blockingHandler) callCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.calls
}

// cancelled 报告 Handler 是否观察到执行上下文被取消。
func (h *blockingHandler) cancelled() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.aborted
}

// —— 用例（第十二轮 H6：租约时长按能力超时动态设定） ——

// TestLeaseForDerivesFromCapabilityTimeout 租约推导（H6 ①）：
// 超时 300 秒的能力，租约 = 300 + 2×20 = 340 秒；且该租约满足强约束。
func TestLeaseForDerivesFromCapabilityTimeout(t *testing.T) {
	lease := approvals.LeaseFor(300 * time.Second)
	if lease != 340*time.Second {
		t.Fatalf("300s 能力超时应推导出 340s 租约，实际 %v", lease)
	}
	if err := approvals.ValidateLease(lease, approvals.DefaultLeaseRenewInterval); err != nil {
		t.Fatalf("340s 租约应满足强约束：%v", err)
	}
	if approvals.DefaultLeaseRenewInterval != 20*time.Second {
		t.Fatalf("续期间隔固定为 20 秒，实际 %v", approvals.DefaultLeaseRenewInterval)
	}
}

// TestLongCapabilityNotMisjudgedByReconcile（H6 ①）：300 秒超时的能力在
// 长耗时执行中不会被对账误判——只要执行未超过能力超时，租约（340s）始终有效。
func TestLongCapabilityNotMisjudgedByReconcile(t *testing.T) {
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	var clockMu sync.Mutex
	clock := func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return base
	}
	advance := func(d time.Duration) {
		clockMu.Lock()
		defer clockMu.Unlock()
		base = base.Add(d)
	}

	ap := newFakeApprovals()
	ap.clock = clock
	cfg := DefaultConfig()
	cfg.Now = clock
	af := &fakeAudit{}
	handler := &countingHandler{result: okResult()}
	reg := NewTestRegistry() // 仅测试
	svc := newTestServiceReg(t, idempotency.NewMemoryStore(), af, ap, cfg, reg)
	// 300 秒超时的能力（仅测试）。
	if err := reg.Register(&contractv1.Capability{
		Name: "test.unit.write", RiskTier: contractv1.RiskTier_RISK_TIER_MEDIUM,
		Rollbackable: true, TestOnly: true,
		Timeout: durationpb.New(300 * time.Second),
	}, handler.handle); err != nil {
		t.Fatal(err)
	}
	req := execReq("ops-lead", "k-long", "test.unit.write", nil)
	submitted, err := svc.Execute(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Approve(context.Background(), submitted.ApprovalID, "ops-auditor", "同意"); err != nil {
		t.Fatal(err)
	}
	// 抢占（写入 340s 租约）后模拟"执行仍在进行"：推进 300 秒（未超能力超时）。
	if _, err := ap.Claim(context.Background(), submitted.ApprovalID,
		approvals.LeaseFor(300*time.Second)); err != nil {
		t.Fatal(err)
	}
	advance(300 * time.Second)
	// 对账不得标记 abandoned（租约 340s > 300s）。
	n, err := svc.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("长耗时执行不得被对账误判：abandoned=%d", n)
	}
	rec, _ := ap.Get(context.Background(), submitted.ApprovalID)
	if rec.Status != approvals.StatusExecuting {
		t.Fatalf("执行中（未超租约）的审批应保持 executing：%+v", rec)
	}
	if rec.LeaseUntil == nil || !rec.LeaseUntil.Equal(base.Add(40*time.Second)) {
		t.Fatalf("租约应到期于抢占时刻 + 340s：%v", rec.LeaseUntil)
	}
	// 推进到超过租约（340s 之后）→ 对账标记 abandoned（不重放）。
	advance(41 * time.Second)
	if _, err := svc.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	rec, _ = ap.Get(context.Background(), submitted.ApprovalID)
	if rec.Status != approvals.StatusAbandoned {
		t.Fatalf("超过租约后对账应标记 abandoned：%+v", rec)
	}
	if handler.callCount() != 0 {
		t.Fatalf("对账不重放：calls=%d", handler.callCount())
	}
}

// TestValidateLeaseRejectsTooShortLease（H6 ②）：续期间隔不小于租约一半时
// 强校验失败（租约必须 > 2×续期间隔）；注册表侧在启动校验中对每个能力检查。
func TestValidateLeaseRejectsTooShortLease(t *testing.T) {
	// 租约 60s、续期间隔 30s：30 >= 60/2 → 拒绝。
	if err := approvals.ValidateLease(60*time.Second, 30*time.Second); err == nil {
		t.Fatal("续期间隔不小于租约一半时应报错")
	}
	// 租约 61s、续期间隔 30s：30 < 30.5 → 通过。
	if err := approvals.ValidateLease(61*time.Second, 30*time.Second); err != nil {
		t.Fatalf("合法组合应通过：%v", err)
	}
	// 续期间隔非正 → 拒绝。
	if err := approvals.ValidateLease(time.Hour, 0); err == nil {
		t.Fatal("续期间隔为 0 应报错")
	}
	// 启动侧：注册表内每个能力都按 LeaseFor 校验（默认 20s 间隔下全部通过）。
	reg := NewTestRegistry() // 仅测试
	h := (&countingHandler{result: okResult()}).handle
	if err := reg.Register(&contractv1.Capability{
		Name: "test.unit.write", RiskTier: contractv1.RiskTier_RISK_TIER_LOW,
		Rollbackable: true, TestOnly: true, Timeout: durationpb.New(60 * time.Second),
	}, h); err != nil {
		t.Fatal(err)
	}
	svc, err := New(DefaultConfig(), idempotency.NewMemoryStore(), &fakeAudit{}, newFakeApprovals(), reg)
	if err != nil {
		t.Fatalf("默认配置应通过启动校验：%v", err)
	}
	if svc == nil {
		t.Fatal("服务应构建成功")
	}
	// 构造一个"续期间隔过大"的配置：租约固定由能力超时推导，
	// 此处直接验证启动校验会拒绝不满足 2× 关系的组合。
	cfg := DefaultConfig()
	cfg.LeaseRenewInterval = 60 * time.Second // 与 60s 能力超时的租约（100s）相比：60 < 50 不成立 → 拒绝
	if _, err := New(cfg, idempotency.NewMemoryStore(), &fakeAudit{}, newFakeApprovals(), reg); err == nil {
		t.Fatal("续期间隔过大（不小于租约一半）时启动应失败")
	}
}

// TestRegisterRejectsCapabilityWithoutTimeout（H6 ③）：超时为 0 或缺失的能力
// 拒绝注册（租约无法推导）。
func TestRegisterRejectsCapabilityWithoutTimeout(t *testing.T) {
	reg := NewTestRegistry() // 仅测试
	h := (&countingHandler{result: okResult()}).handle
	cases := []struct {
		name string
		decl *contractv1.Capability
	}{
		{"超时缺失", &contractv1.Capability{
			Name: "test.unit.write", RiskTier: contractv1.RiskTier_RISK_TIER_LOW, Rollbackable: true,
		}},
		{"超时为 0", &contractv1.Capability{
			Name: "test.unit.write", RiskTier: contractv1.RiskTier_RISK_TIER_LOW, Rollbackable: true,
			Timeout: durationpb.New(0),
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := reg.Register(tc.decl, h); err == nil {
				t.Fatal("缺少正超时的能力必须拒绝注册")
			}
			if _, ok := reg.Lookup("test.unit.write"); ok {
				t.Fatal("被拒能力不得进入注册表")
			}
		})
	}
}
