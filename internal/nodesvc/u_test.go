package nodesvc

// T1 证书状态机测试（第二十四轮，缺口 1）。
//
// 背景：第二十三轮用 `pending_superseded_serial`（**单个**序列号）记录"续期后待确认的
// 旧证书"。第二次续期会**覆盖**第一次，于是第一份旧证书永远不会被 supersede——
// 它在 7 天有效期内持续有效。这是审核找出的**安全缺口**。
//
// 修复：改为"每证书一条状态记录"（`test_node_certs`）。
//
//	TestU1_RenewTwiceBeforeConfirm          两次续期（第一次响应丢失）→ 确认第二个后全部收敛
//	TestU2_ConfirmSupersedesOlderIssuedOrphans  孤儿序列号在确认时被 supersede
//	TestU3_PendingLimit                     第 6 次未确认续期被拒绝（reason=pending_limit）
//	TestU4_SupersededSerialRejectedOnHeartbeat
//	TestU5_MigrationBackfillAndDown         回填正确、down 可回滚
//	TestU6_NodeStatusUnchangedBySupersede   状态分离

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ORG/agent-ops/internal/nodecerts"
	"github.com/ORG/agent-ops/internal/nodemigrate"
	"github.com/ORG/agent-ops/internal/nodestore"
)

// certState 读取证书状态（不存在返回空串）。
func (e *env) certState(t *testing.T, serial string) nodecerts.State {
	t.Helper()
	rec, found, err := e.certs.Get(context.Background(), serial)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		return ""
	}
	return rec.State
}

// renewWithNewKey 用新密钥续期（返回续期结果）。
func (e *env) renewWithNewKey(t *testing.T, nodeID, serial string, certDER []byte) *RenewOutcome {
	t.Helper()
	out, err := e.svc.Renew(context.Background(), nodeID, serial, certDER, e.newCSRPEM(t))
	if err != nil {
		t.Fatalf("续期应成功：%v", err)
	}
	return out
}

// TestU1_RenewTwiceBeforeConfirm（U1）两次续期（第一次响应丢失）：
// 心跳确认第二个序列号后，两者之前的证书**全部** superseded。
func TestU1_RenewTwiceBeforeConfirm(t *testing.T) {
	e := newEnv(t)
	if e == nil {
		return
	}
	ctx := context.Background()
	nodeID, serial0, cert0 := e.enrollPlain(t, "u1")

	// 第一次续期（响应"丢失"：节点从未用 new1 心跳）。
	e.clock.advance(time.Minute)
	out1 := e.renewWithNewKey(t, nodeID, serial0, cert0)
	if st := e.certState(t, out1.NewSerial); st != nodecerts.StateIssued {
		t.Fatalf("第一次续期后 new1 应为 issued，实际 %q", st)
	}

	// 第二次续期（节点仍用**旧证书**发起，因为 new1 从未到达）。
	e.clock.advance(time.Minute)
	out2, err := e.svc.Renew(ctx, nodeID, serial0, cert0, e.newCSRPEM(t))
	if err != nil {
		t.Fatalf("第二次续期应成功：%v", err)
	}
	if out2.NewSerial == out1.NewSerial {
		t.Fatal("两次续期的序列号必须不同")
	}
	// 此刻状态：serial0=active（仍在使用），new1=issued（孤儿），new2=issued。
	for serial, want := range map[string]nodecerts.State{
		serial0:        nodecerts.StateActive,
		out1.NewSerial: nodecerts.StateIssued,
		out2.NewSerial: nodecerts.StateIssued,
	} {
		if got := e.certState(t, serial); got != want {
			t.Fatalf("续期后 %s 应为 %s，实际 %q", serial, want, got)
		}
	}

	// 节点现在切换成功并用 **new2** 心跳（确认）。
	e.clock.advance(10 * time.Second)
	if _, err := e.svc.Heartbeat(ctx, nodeID, "01M4RHFDJ0U1SESSION00000000",
		e.clock.now(), out2.NewSerial); err != nil {
		t.Fatalf("新序列号心跳应成功：%v", err)
	}

	// 断言：new2=active；serial0 与 new1 **都**变成 superseded。
	if got := e.certState(t, out2.NewSerial); got != nodecerts.StateActive {
		t.Fatalf("new2 应为 active，实际 %q", got)
	}
	for _, serial := range []string{serial0, out1.NewSerial} {
		if got := e.certState(t, serial); got != nodecerts.StateSuperseded {
			t.Fatalf("%s 应为 superseded（含被覆盖的第一次续期），实际 %q", serial, got)
		}
		// 吊销表也应有对应记录（reason=superseded）。
		reason, found, rerr := e.store.RevocationReason(ctx, serial)
		if rerr != nil || !found {
			t.Fatalf("%s 应写入吊销表：found=%v err=%v", serial, found, rerr)
		}
		if reason != SupersedeReason {
			t.Fatalf("%s 的吊销原因应为 %s，实际 %q", serial, SupersedeReason, reason)
		}
	}
	// 节点状态不变（supersede 与节点状态分离）。
	if st := e.nodeStatus(t, nodeID); st != nodestore.StatusOnline {
		t.Fatalf("supersede 不得改变节点状态，实际 %q", st)
	}
	if got := e.revocationsByReason(t, SupersedeReason); got != 2 {
		t.Fatalf("应有 2 条 superseded 吊销记录，实际 %d", got)
	}
	t.Logf("[U1] 第一次续期响应丢失：new1=%s 为孤儿；确认 new2 后 serial0 与 new1 均 superseded"+
		"（吊销表 2 条），节点保持 online", shortSerial(out1.NewSerial))
}

// TestU2_ConfirmSupersedesOlderIssuedOrphans（U2）多次续期（每次响应都丢失）后，
// 确认最新证书时**全部**更早的孤儿被 supersede。
func TestU2_ConfirmSupersedesOlderIssuedOrphans(t *testing.T) {
	e := newEnv(t)
	if e == nil {
		return
	}
	ctx := context.Background()
	nodeID, serial0, cert0 := e.enrollPlain(t, "u2")

	// 3 次续期（都在"响应丢失"的情况下继续用 serial0 发起）——留在未确认上限之内。
	orphans := make([]string, 0, 3)
	curSerial, curCert := serial0, cert0
	for i := 0; i < 3; i++ {
		e.clock.advance(time.Minute)
		out, err := e.svc.Renew(ctx, nodeID, curSerial, curCert, e.newCSRPEM(t))
		if err != nil {
			t.Fatalf("第 %d 次续期应成功：%v", i+1, err)
		}
		orphans = append(orphans, out.NewSerial)
		// 注意：curSerial/curCert **不更新**——模拟响应丢失，节点仍在用 serial0。
	}
	if got, _ := e.certs.CountByState(ctx, nodeID, nodecerts.StateIssued); got != 3 {
		t.Fatalf("应有 3 张 issued 孤儿证书，实际 %d", got)
	}

	// 节点最终用**最后一张**（orphans[2]）心跳确认。
	e.clock.advance(10 * time.Second)
	if _, err := e.svc.Heartbeat(ctx, nodeID, "01M4RHFDJ0U2SESSION00000000",
		e.clock.now(), orphans[2]); err != nil {
		t.Fatalf("确认最新证书应成功：%v", err)
	}
	// 全部更早者（serial0 + 前两张孤儿）都应 superseded。
	for _, serial := range append([]string{serial0}, orphans[:2]...) {
		if got := e.certState(t, serial); got != nodecerts.StateSuperseded {
			t.Fatalf("孤儿 %s 应被 supersede，实际 %q", shortSerial(serial), got)
		}
	}
	if got := e.certState(t, orphans[2]); got != nodecerts.StateActive {
		t.Fatalf("被确认的证书应为 active，实际 %q", got)
	}
	if got, _ := e.certs.CountByState(ctx, nodeID, nodecerts.StateIssued); got != 0 {
		t.Fatalf("确认后不应残留 issued，实际 %d", got)
	}
	if got := e.revocationsByReason(t, SupersedeReason); got != 3 {
		t.Fatalf("应有 3 条 superseded 吊销记录，实际 %d", got)
	}
	t.Logf("[U2] 3 张孤儿证书在确认最新证书时全部 superseded（吊销表 3 条），无残留 issued")
}

// TestU3_PendingLimit（U3）第 6 次未确认续期被拒绝（reason=pending_limit），状态不变。
func TestU3_PendingLimit(t *testing.T) {
	e := newEnv(t)
	if e == nil {
		return
	}
	ctx := context.Background()
	nodeID, serial0, cert0 := e.enrollPlain(t, "u3")
	limit := e.certs.PendingLimit()
	if limit != nodecerts.DefaultPendingLimit {
		t.Fatalf("默认未确认上限应为 %d，实际 %d", nodecerts.DefaultPendingLimit, limit)
	}

	// 前台把节点打成 offline，验证"拒绝续期不改状态"。
	e.clock.advance(3 * 10 * time.Second)
	if _, err := e.svc.EvaluateOffline(ctx); err != nil {
		t.Fatal(err)
	}
	before := e.nodeStatus(t, nodeID)

	// 连续发起 limit 次未确认续期（每次都用同一份"节点手上的"旧证书）。
	for i := 1; i <= limit; i++ {
		e.clock.advance(time.Minute)
		if _, err := e.svc.Renew(ctx, nodeID, serial0, cert0, e.newCSRPEM(t)); err != nil {
			t.Fatalf("第 %d 次续期应成功（未达上限）：%v", i, err)
		}
	}
	if got, _ := e.certs.CountByState(ctx, nodeID, nodecerts.StateIssued); got != int64(limit) {
		t.Fatalf("应恰好 %d 张 issued，实际 %d", limit, got)
	}

	// 第 limit+1 次 → 拒绝。
	e.clock.advance(time.Minute)
	if _, err := e.svc.Renew(ctx, nodeID, serial0, cert0, e.newCSRPEM(t)); !errors.Is(err, ErrRenewRejected) {
		t.Fatalf("超过未确认上限必须拒绝（ErrRenewRejected），实际 %v", err)
	}
	// 状态与证书数量都不变。
	if got := e.nodeStatus(t, nodeID); got != before {
		t.Fatalf("拒绝续期不得改变节点状态：前 %q 后 %q", before, got)
	}
	if got, _ := e.certs.CountByState(ctx, nodeID, nodecerts.StateIssued); got != int64(limit) {
		t.Fatalf("拒绝后续期不得新增 issued，实际 %d", got)
	}
	// 审计含 reason=pending_limit（内部 reason 只入审计）。
	if got := e.auditCount(t, ActionRenewRejected); got != 1 {
		t.Fatalf("应恰好 1 条 node.renew_rejected，实际 %d", got)
	}
	evs, err := e.audit.ListByAction(ctx, ActionRenewRejected)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 || !containsStr(string(evs[0].Payload), "pending_limit") {
		t.Fatalf("renew_rejected 审计应含 reason=pending_limit，实际 %s", evs[0].Payload)
	}
	t.Logf("[U3] 第 %d 次未确认续期被拒（reason=pending_limit，审计 1 条）；节点状态 %q 与 issued 计数均不变",
		limit+1, before)
}

// TestU4_SupersededSerialRejectedOnHeartbeat（U4）superseded 序列号的心跳被拒绝且不改状态。
func TestU4_SupersededSerialRejectedOnHeartbeat(t *testing.T) {
	e := newEnv(t)
	if e == nil {
		return
	}
	ctx := context.Background()
	nodeID, oldSerial, oldCert := e.enrollPlain(t, "u4")
	const session = "01M4RHFDJ0U4SESSION00000000"

	// 续期并确认 → 旧证书变 superseded。
	e.clock.advance(time.Minute)
	out := e.renewWithNewKey(t, nodeID, oldSerial, oldCert)
	e.clock.advance(10 * time.Second)
	if _, err := e.svc.Heartbeat(ctx, nodeID, session, e.clock.now(), out.NewSerial); err != nil {
		t.Fatal(err)
	}
	if got := e.certState(t, oldSerial); got != nodecerts.StateSuperseded {
		t.Fatalf("旧证书应 superseded，实际 %q", got)
	}
	// 记录当前状态，作为"不改变任何状态"的对照。
	recBefore, _, err := e.store.GetNode(ctx, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	rejBefore := e.auditCount(t, ActionHeartbeatRejected)

	// 用 superseded 序列号心跳 → 拒绝。
	e.clock.advance(10 * time.Second)
	_, herr := e.svc.Heartbeat(ctx, nodeID, session, e.clock.now(), oldSerial)
	if herr == nil {
		t.Fatal("superseded 序列号的心跳必须被拒绝")
	}
	if !errors.Is(herr, ErrCertSuperseded) {
		t.Fatalf("应为 ErrCertSuperseded，实际 %v", herr)
	}
	// 状态与存活时间都不变。
	recAfter, _, err := e.store.GetNode(ctx, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	if recAfter.Status != recBefore.Status {
		t.Fatalf("拒绝不得改变节点状态：前 %q 后 %q", recBefore.Status, recAfter.Status)
	}
	if !recAfter.LastReceivedAt.Equal(recBefore.LastReceivedAt) {
		t.Fatalf("拒绝不得刷新 last_received_at：前 %v 后 %v",
			recBefore.LastReceivedAt, recAfter.LastReceivedAt)
	}
	// 证书状态不变，且写了一条 heartbeat_rejected 审计。
	if got := e.certState(t, oldSerial); got != nodecerts.StateSuperseded {
		t.Fatalf("拒绝不得改变证书状态，实际 %q", got)
	}
	if got := e.auditCount(t, ActionHeartbeatRejected); got != rejBefore+1 {
		t.Fatalf("应新增 1 条 heartbeat_rejected，实际 %d→%d", rejBefore, got)
	}
	t.Logf("[U4] superseded 序列号心跳被拒（ErrCertSuperseded）；节点状态/存活时间/证书状态均不变")
}

// TestU5_MigrationBackfillAndDown（U5）迁移回填正确、down 可回滚。
func TestU5_MigrationBackfillAndDown(t *testing.T) {
	e := newEnv(t)
	if e == nil {
		return
	}
	ctx := context.Background()
	nodes, tokens, revocations, certs, sweepState := e.store.AllTables()
	mig, err := nodemigrate.New(e.pool, nodemigrate.Tables{
		Nodes: nodes, Tokens: tokens, Revocations: revocations,
		Certs: certs, SweepState: sweepState,
	})
	if err != nil {
		t.Fatal(err)
	}

	// 造一个"第二十五轮之前的旧 schema"：回滚 004（删证书表）后，
	// 用节点表的 cert_serial 表示"既有活跃证书"。
	if err := mig.Down(ctx); err != nil {
		t.Fatalf("Down 失败：%v", err)
	}
	if ok, err := mig.TableExists(ctx, certs); err != nil || ok {
		t.Fatalf("Down 后证书表应不存在（ok=%v err=%v）", ok, err)
	}
	// 插入一行带 cert_serial 的节点（模拟旧数据）。
	const legacySerial = "legacy-serial-u5"
	if _, err := e.pool.Exec(ctx, "INSERT INTO "+nodes+
		` (node_id, status, display_label, cert_serial, created_at)
          VALUES ($1,'online','legacy',$2, now())`,
		"nod_01M4RHFDJ0LEGACYU500000000", legacySerial); err != nil {
		t.Fatalf("插入旧节点失败：%v", err)
	}

	// Up → 回填为 active。
	if _, err := mig.Up(ctx); err != nil {
		t.Fatalf("Up 失败：%v", err)
	}
	if ok, err := mig.TableExists(ctx, certs); err != nil || !ok {
		t.Fatalf("Up 后证书表应存在（ok=%v err=%v）", ok, err)
	}
	rec, found, err := e.certs.Get(ctx, legacySerial)
	if err != nil || !found {
		t.Fatalf("既有 cert_serial 应被回填：found=%v err=%v", found, err)
	}
	if rec.State != nodecerts.StateActive {
		t.Fatalf("回填状态应为 active，实际 %q", rec.State)
	}
	if rec.NodeID != "nod_01M4RHFDJ0LEGACYU500000000" {
		t.Fatalf("回填的 node_id 不符：%q", rec.NodeID)
	}
	if rec.ConfirmedAt.IsZero() {
		t.Fatal("回填的 active 证书应带 confirmed_at")
	}
	// 幂等：重复 Up 不报错，也不产生重复行。
	if _, err := mig.Up(ctx); err != nil {
		t.Fatalf("Up 应幂等：%v", err)
	}
	var cnt int
	if err := e.pool.QueryRow(ctx,
		`SELECT count(*) FROM `+certs+` WHERE serial = $1`, legacySerial).Scan(&cnt); err != nil {
		t.Fatal(err)
	}
	if cnt != 1 {
		t.Fatalf("重复 Up 后应仍只有 1 行，实际 %d", cnt)
	}
	// 再 Down → 表消失（可回滚）。
	if err := mig.Down(ctx); err != nil {
		t.Fatalf("再次 Down 失败：%v", err)
	}
	if ok, err := mig.TableExists(ctx, certs); err != nil || ok {
		t.Fatalf("再次 Down 后证书表应不存在（ok=%v err=%v）", ok, err)
	}
	// 恢复迁移状态，避免影响同一 schema 的其它断言（用例结束时 schema 会删除）。
	if _, err := mig.Up(ctx); err != nil {
		t.Fatal(err)
	}
	t.Logf("[U5] 旧 cert_serial=%s 回填为 active（含 confirmed_at）；Up 幂等；Down 可回滚删表",
		legacySerial)
}

// TestU6_NodeStatusUnchangedBySupersede（U6）supersede 只动证书状态，不动节点状态。
func TestU6_NodeStatusUnchangedBySupersede(t *testing.T) {
	e := newEnv(t)
	if e == nil {
		return
	}
	ctx := context.Background()
	nodeID, serial0, cert0 := e.enrollPlain(t, "u6")
	const session = "01M4RHFDJ0U6SESSION00000000"

	// 制造 offline 的节点（更严格：证明 supersede 不会把它"顺手"改成 revoked 或 online）。
	e.clock.advance(3 * 10 * time.Second)
	if _, err := e.svc.EvaluateOffline(ctx); err != nil {
		t.Fatal(err)
	}
	if st := e.nodeStatus(t, nodeID); st != nodestore.StatusOffline {
		t.Fatalf("前置：节点应为 offline，实际 %q", st)
	}

	// 续期（此时节点 offline）→ 成功且不改变状态。
	e.clock.advance(time.Minute)
	out := e.renewWithNewKey(t, nodeID, serial0, cert0)
	if st := e.nodeStatus(t, nodeID); st != nodestore.StatusOffline {
		t.Fatalf("续期不得改变节点状态，实际 %q", st)
	}

	// 用新序列号心跳 → 触发 supersede（同时节点会因为心跳回到 online，这是心跳的语义）。
	if _, err := e.svc.Heartbeat(ctx, nodeID, session, e.clock.now(), out.NewSerial); err != nil {
		t.Fatal(err)
	}
	if got := e.certState(t, serial0); got != nodecerts.StateSuperseded {
		t.Fatalf("旧证书应 superseded，实际 %q", got)
	}
	// 关键断言：不因 supersede 出现 revoked / cert_revoked 审计。
	if st := e.nodeStatus(t, nodeID); st == nodestore.StatusRevoked {
		t.Fatal("supersede 绝不得把节点置为 revoked")
	}
	if got := e.auditCount(t, ActionCertRevoked); got != 0 {
		t.Fatalf("supersede 不得写 cert_revoked 审计，实际 %d", got)
	}
	// supersede 审计里含被取代的序列号（可追溯）。
	evs, err := e.audit.ListByAction(ctx, ActionCertSuperseded)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 {
		t.Fatalf("应恰好 1 条 cert_superseded，实际 %d", len(evs))
	}
	if !containsStr(string(evs[0].Payload), serial0) {
		t.Fatalf("supersede 审计应含被取代的序列号：%s", evs[0].Payload)
	}
	t.Logf("[U6] supersede 只改证书状态（%s→superseded），节点状态与 revoked 计数均不受影响",
		shortSerial(serial0))
}

// —— 辅助 ——

// shortSerial 截断序列号便于日志可读（不做任何敏感信息处理：序列号本身可公开）。
func shortSerial(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:6] + "…" + s[len(s)-4:]
}

// containsStr 简易子串判断。
func containsStr(s, sub string) bool {
	if sub == "" {
		return false
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
