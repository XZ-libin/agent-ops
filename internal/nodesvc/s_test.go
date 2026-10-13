package nodesvc

// T2 服务端周期扫描测试（第二十四轮，缺口 2）。
//
// 背景：第二十三轮的到期提醒只在**心跳到达时**判定。续期失败的节点恰恰是沉默的
// （心跳不再到达），于是提醒**永远不会触发**。本轮的扫描器把判定搬到服务端周期任务。
//
//	TestS1_ExpiryRiskWithoutAnyHeartbeat  节点完全沉默，扫描仍写 node.cert_expiry_risk
//	TestS2_ExpiryRiskRateLimitedTo6h      6 小时节流
//	TestS3_UnconfirmedIssuedFlaggedAfter24h  issued >24h → node.cert_unconfirmed
//	TestS4_SweeperDoesNotChangeStatus     不改节点状态、不改证书状态
//	TestS5_SweeperTickDrivenNoSleep       推进注入时钟 → 审计条数精确相等
//
// 全部由注入时钟与 tick 驱动，**无 sleep**（硬性约束 11）。

import (
	"context"
	"testing"
	"time"

	"github.com/ORG/agent-ops/internal/nodecerts"
	"github.com/ORG/agent-ops/internal/nodestore"
	"github.com/ORG/agent-ops/internal/nodesweep"
)

// newSweeper 用 Service 的依赖构建扫描器。
func (e *env) newSweeper(t *testing.T) *nodesweep.Sweeper {
	t.Helper()
	sw, err := nodesweep.New(nodesweep.Config{}, e.svc.SweeperDeps())
	if err != nil {
		t.Fatal(err)
	}
	// 默认参数断言（工程默认，待确认）。
	if sw.Interval() != nodesweep.DefaultInterval {
		t.Fatalf("默认扫描周期应为 %s，实际 %s", nodesweep.DefaultInterval, sw.Interval())
	}
	if sw.ExpiryThreshold() != nodesweep.DefaultExpiryThreshold {
		t.Fatalf("默认到期阈值应为 %s，实际 %s",
			nodesweep.DefaultExpiryThreshold, sw.ExpiryThreshold())
	}
	if sw.ThrottleGap() != nodesweep.DefaultThrottleGap {
		t.Fatalf("默认节流间隔应为 %s，实际 %s", nodesweep.DefaultThrottleGap, sw.ThrottleGap())
	}
	if sw.UnconfirmedAge() != nodesweep.DefaultUnconfirmedAge {
		t.Fatalf("默认未确认阈值应为 %s，实际 %s",
			nodesweep.DefaultUnconfirmedAge, sw.UnconfirmedAge())
	}
	return sw
}

// TestS1_ExpiryRiskWithoutAnyHeartbeat（S1）节点**完全沉默**（一次心跳都没有），
// 扫描器仍然写出 node.cert_expiry_risk。
//
// 这是缺口 2 的直接回归：旧实现只在心跳路径判定，本用例在旧实现下**必然失败**
// （因为它从不调用 Heartbeat）。
func TestS1_ExpiryRiskWithoutAnyHeartbeat(t *testing.T) {
	e := newEnv(t)
	if e == nil {
		return
	}
	ctx := context.Background()
	nodeID, serial, _ := e.enrollPlain(t, "s1")

	// 从注册后**不再发送任何心跳**，只把时钟推进到剩余 47 小时。
	e.clock.advance(7*24*time.Hour - 47*time.Hour)

	sw := e.newSweeper(t)
	res, err := sw.RunOnce(ctx)
	if err != nil {
		t.Fatalf("扫描失败：%v", err)
	}
	if len(res.Expiry) != 1 {
		t.Fatalf("应发现 1 条到期风险，实际 %d", len(res.Expiry))
	}
	if res.Expiry[0].NodeID != nodeID || res.Expiry[0].Serial != serial {
		t.Fatalf("风险对象不符：%+v", res.Expiry[0])
	}
	if !res.Expiry[0].Reported {
		t.Fatal("首次发现应写入审计")
	}
	if got := e.auditCount(t, ActionCertExpiryRisk); got != 1 {
		t.Fatalf("应恰好 1 条 node.cert_expiry_risk，实际 %d", got)
	}
	if res.Audited != 1 {
		t.Fatalf("Audited 应为 1，实际 %d", res.Audited)
	}
	// 审计 payload 含剩余量/阈值/到期时刻，且**不含证书材料**。
	evs, err := e.audit.ListByAction(ctx, ActionCertExpiryRisk)
	if err != nil {
		t.Fatal(err)
	}
	payload := string(evs[0].Payload)
	for _, want := range []string{"remaining_ms", "threshold", "not_after", serial} {
		if !containsStr(payload, want) {
			t.Fatalf("payload 应含 %q：%s", want, payload)
		}
	}
	for _, bad := range []string{"BEGIN CERTIFICATE", "PRIVATE KEY", "CERTIFICATE REQUEST"} {
		if containsStr(payload, bad) {
			t.Fatalf("payload 不得含 %q：%s", bad, payload)
		}
	}
	// 节点状态**未被扫描器触碰**（沉默节点此时仍是 online——扫描器不做离线判定）。
	if st := e.nodeStatus(t, nodeID); st != nodestore.StatusOnline {
		t.Fatalf("扫描器不得改变节点状态，实际 %q", st)
	}
	t.Log("[S1] 节点零心跳 → 扫描器仍写出 cert_expiry_risk（1 条），节点状态未被触碰")
}

// TestS2_ExpiryRiskRateLimitedTo6h（S2）同一节点 6 小时内最多一条，且节流状态**持久化**。
func TestS2_ExpiryRiskRateLimitedTo6h(t *testing.T) {
	e := newEnv(t)
	if e == nil {
		return
	}
	ctx := context.Background()
	e.enrollPlain(t, "s2")
	e.clock.advance(7*24*time.Hour - 47*time.Hour)
	sw := e.newSweeper(t)

	// ① 首次 → 写 1 条。
	if _, err := sw.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if got := e.auditCount(t, ActionCertExpiryRisk); got != 1 {
		t.Fatalf("首次应为 1 条，实际 %d", got)
	}
	// ② 节流窗口内多次扫描 → 不新增。
	for i := 0; i < 3; i++ {
		e.clock.advance(time.Hour)
		res, err := sw.RunOnce(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Expiry) != 1 {
			t.Fatalf("第 %d 次扫描应仍发现该风险，实际 %d 条", i+2, len(res.Expiry))
		}
		if res.Expiry[0].Reported {
			t.Fatalf("第 %d 次扫描在节流窗口内不应写审计", i+2)
		}
		if res.Audited != 0 {
			t.Fatalf("第 %d 次扫描 Audited 应为 0，实际 %d", i+2, res.Audited)
		}
	}
	if got := e.auditCount(t, ActionCertExpiryRisk); got != 1 {
		t.Fatalf("6 小时节流内应仍只有 1 条，实际 %d", got)
	}
	// ③ 跨过 6 小时 → 允许再写一条。
	e.clock.advance(3 * time.Hour)
	res, err := sw.RunOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Expiry[0].Reported || res.Audited != 1 {
		t.Fatalf("超过 6 小时后应再写 1 条（Reported=%v Audited=%d）",
			res.Expiry[0].Reported, res.Audited)
	}
	if got := e.auditCount(t, ActionCertExpiryRisk); got != 2 {
		t.Fatalf("超过 6 小时后应为 2 条，实际 %d", got)
	}
	// ④ 节流状态已持久化到表（跨重启有效）。
	var n int
	if err := e.pool.QueryRow(ctx,
		`SELECT count(*) FROM test_node_sweep_state WHERE event = $1`, nodesweep.EventExpiryRisk).
		Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("节流状态表应有 1 行，实际 %d", n)
	}
	t.Log("[S2] 节流：首次 1 条；窗口内 3 次扫描均不写；跨过 6h 后再写 1 条；状态已持久化")
}

// TestS3_UnconfirmedIssuedFlaggedAfter24h（S3）issued 超 24 小时未确认 → node.cert_unconfirmed。
func TestS3_UnconfirmedIssuedFlaggedAfter24h(t *testing.T) {
	e := newEnv(t)
	if e == nil {
		return
	}
	ctx := context.Background()
	nodeID, serial0, cert0 := e.enrollPlain(t, "s3")

	// 造一张 issued（续期成功但响应丢失 → 节点从未用它心跳）。
	e.clock.advance(time.Minute)
	out := e.renewWithNewKey(t, nodeID, serial0, cert0)
	if got := e.certState(t, out.NewSerial); got != nodecerts.StateIssued {
		t.Fatalf("前置：新证书应为 issued，实际 %q", got)
	}
	sw := e.newSweeper(t)

	// ① 未满 24 小时 → 不标记。
	e.clock.advance(23 * time.Hour)
	res, err := sw.RunOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Unconfirmed) != 0 {
		t.Fatalf("未满 24 小时不应标记，实际 %d", len(res.Unconfirmed))
	}
	if got := e.auditCount(t, ActionCertUnconfirmed); got != 0 {
		t.Fatalf("未满 24 小时不应写审计，实际 %d", got)
	}

	// ② 超过 24 小时 → 标记（信息级）。
	e.clock.advance(2 * time.Hour)
	res, err = sw.RunOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Unconfirmed) != 1 {
		t.Fatalf("超过 24 小时应标记 1 条，实际 %d", len(res.Unconfirmed))
	}
	f := res.Unconfirmed[0]
	if f.Serial != out.NewSerial || f.NodeID != nodeID {
		t.Fatalf("标记对象不符：%+v", f)
	}
	if f.Age < 24*time.Hour {
		t.Fatalf("Age 应 ≥24h，实际 %s", f.Age)
	}
	if !f.Reported || res.Audited != 1 {
		t.Fatalf("应写入 1 条审计（Reported=%v Audited=%d）", f.Reported, res.Audited)
	}
	if got := e.auditCount(t, ActionCertUnconfirmed); got != 1 {
		t.Fatalf("应恰好 1 条 node.cert_unconfirmed，实际 %d", got)
	}
	// 证书状态**不变**（仍是 issued，等节点确认）。
	if got := e.certState(t, out.NewSerial); got != nodecerts.StateIssued {
		t.Fatalf("扫描器不得改变证书状态，实际 %q", got)
	}
	t.Logf("[S3] issued 超 24h（实际 %s）→ 1 条 node.cert_unconfirmed；证书仍为 issued",
		f.Age.Round(time.Minute))
}

// TestS4_SweeperDoesNotChangeStatus（S4）扫描器只写审计，不改节点状态与证书状态。
func TestS4_SweeperDoesNotChangeStatus(t *testing.T) {
	e := newEnv(t)
	if e == nil {
		return
	}
	ctx := context.Background()
	nodeID, serial0, cert0 := e.enrollPlain(t, "s4")
	// 再造一张 issued（覆盖两条扫描路径）。
	e.clock.advance(time.Minute)
	out := e.renewWithNewKey(t, nodeID, serial0, cert0)
	e.clock.advance(7*24*time.Hour - 47*time.Hour) // 同时触发到期风险

	// 记录扫描前状态。
	beforeNode, _, err := e.store.GetNode(ctx, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	beforeActive := e.certState(t, serial0)
	beforeIssued := e.certState(t, out.NewSerial)
	beforeRevocations := e.revocationsByReason(t, SupersedeReason)
	beforeTotal, err := e.store.RevocationCount(ctx)
	if err != nil {
		t.Fatal(err)
	}

	sw := e.newSweeper(t)
	res, err := sw.RunOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Audited == 0 {
		t.Fatal("本轮应有审计写入（否则用例失去意义）")
	}

	// 断言：一切状态原样。
	afterNode, _, err := e.store.GetNode(ctx, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	if afterNode.Status != beforeNode.Status {
		t.Fatalf("节点状态被改变：%q → %q", beforeNode.Status, afterNode.Status)
	}
	if !afterNode.LastReceivedAt.Equal(beforeNode.LastReceivedAt) {
		t.Fatal("扫描器不得刷新 last_received_at")
	}
	if got := e.certState(t, serial0); got != beforeActive {
		t.Fatalf("active 证书状态被改变：%q → %q", beforeActive, got)
	}
	if got := e.certState(t, out.NewSerial); got != beforeIssued {
		t.Fatalf("issued 证书状态被改变：%q → %q", beforeIssued, got)
	}
	if got := e.revocationsByReason(t, SupersedeReason); got != beforeRevocations {
		t.Fatalf("吊销表被改变（superseded）：%d → %d", beforeRevocations, got)
	}
	afterTotal, err := e.store.RevocationCount(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if afterTotal != beforeTotal {
		t.Fatalf("吊销表总行数被改变：%d → %d", beforeTotal, afterTotal)
	}
	if got := e.auditCount(t, ActionCertRevoked); got != 0 {
		t.Fatalf("扫描器不得写 cert_revoked，实际 %d", got)
	}
	t.Logf("[S4] 扫描写入 %d 条审计；节点状态、证书状态、吊销表行数**全部未变**", res.Audited)
}

// TestS5_SweeperTickDrivenNoSleep（S5）推进注入时钟 48 小时，断言审计条数**精确相等**。
//
// 目的：证明扫描完全由注入时钟驱动（无真实 sleep），且审计条数可按
// "扫描次数 × 节流窗口"精确预测。
func TestS5_SweeperTickDrivenNoSleep(t *testing.T) {
	e := newEnv(t)
	if e == nil {
		return
	}
	ctx := context.Background()
	e.enrollPlain(t, "s5")
	// 直接进入"剩余 47 小时"的区间（7 天有效期）。
	e.clock.advance(7*24*time.Hour - 47*time.Hour)
	sw := e.newSweeper(t)

	// 以扫描周期为 tick，推进 48 小时（48h / 5min = 576 次扫描）。
	const hours = 48
	ticks := int(time.Duration(hours) * time.Hour / nodesweep.DefaultInterval)
	ticked := time.Duration(0)
	lastScanAt := time.Duration(0)
	for i := 0; i < ticks; i++ {
		if _, err := sw.RunOnce(ctx); err != nil {
			t.Fatal(err)
		}
		lastScanAt = ticked // 本次扫描发生在 ticked 时刻
		e.clock.advance(nodesweep.DefaultInterval)
		ticked += nodesweep.DefaultInterval
	}
	if ticked != time.Duration(hours)*time.Hour {
		t.Fatalf("推进时长应为 %dh，实际 %s", hours, ticked)
	}
	// 精确预期：t=0 首次告警；之后每次告警需距上次满 6 小时。
	// 告警时刻 = 0, 6h, 12h, ... ≤ lastScanAt（最后一次扫描在 47h55m，因此 48h 那一次**不会**发生）。
	want := 1 + int(lastScanAt/nodesweep.DefaultThrottleGap)
	if want != 8 {
		t.Fatalf("自检：按 lastScan=%s 计算应为 8 条，实际公式给出 %d", lastScanAt, want)
	}
	got := e.auditCount(t, ActionCertExpiryRisk)
	if got != want {
		t.Fatalf("推进 %dh（%d 次扫描，末次在 %s）的告警条数应精确等于 %d，实际 %d",
			hours, ticks, lastScanAt, want, got)
	}
	// 未确认事件不应出现（没有 issued 超期）。
	if n := e.auditCount(t, ActionCertUnconfirmed); n != 0 {
		t.Fatalf("不应有 cert_unconfirmed，实际 %d", n)
	}
	t.Logf("[S5] 注入时钟推进 48h（%d 次扫描，无 sleep）→ cert_expiry_risk 精确 %d 条", ticks, got)
}
