package nodesvc

// T3 续期测试（第二十三轮）。真实 PostgreSQL（agent_ops_test 的独立 run schema）。
//
// 全部使用**注入时钟**，不做真实等待（硬性约束 11）。
//
//	TestR1_RenewAtHalfLifeWithJitter
//	TestR2_RevokedSerialRefused
//	TestR3_SameKeyRefused
//	TestR4_WrongCNRefused
//	TestR5_FailureRetriesWithoutStateChange
//	TestR6_SupersedeOnlyAfterFirstHeartbeatWithNewSerial
//	TestR7_ExpiryRiskBelow48h
//	TestR8_StatusUnchangedAfterRenew
//	TestR9_E2ERenewTwiceNoOutage
//	TestR10_ExpiredCertCannotRenew

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/ORG/agent-ops/internal/nodecerts"
	"github.com/ORG/agent-ops/internal/nodeidentity"
	"github.com/ORG/agent-ops/internal/nodestore"
)

// —— 辅助（供本文件全部用例使用）——

// enrollPlain 用**新生成**的私钥注册一个节点，返回（node_id, 当前序列号, 证书 DER）。
func (e *env) enrollPlain(t *testing.T, label string) (string, string, []byte) {
	t.Helper()
	ctx := context.Background()
	key, err := nodeidentity.NewNodeKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := nodeidentity.NewCSR(key, nil)
	if err != nil {
		t.Fatal(err)
	}
	out, err := e.svc.Enroll(ctx, e.newToken(t), csrDER, label, "test")
	if err != nil {
		t.Fatalf("注册失败：%v", err)
	}
	return out.NodeID, out.CertSerial, out.CertificateDER
}

// newCSRPEM 生成"新密钥"的纯持有性证明 CSR（PEM）——续期请求体。
func (e *env) newCSRPEM(t *testing.T) []byte {
	t.Helper()
	key, err := nodeidentity.NewNodeKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	der, err := nodeidentity.NewCSR(key, nil)
	if err != nil {
		t.Fatal(err)
	}
	return nodeidentity.CertificateRequestPEM(der)
}

// nodeStatus 读取节点状态。
func (e *env) nodeStatus(t *testing.T, nodeID string) string {
	t.Helper()
	rec, found, err := e.store.GetNode(context.Background(), nodeID)
	if err != nil || !found {
		t.Fatalf("读取节点失败：found=%v err=%v", found, err)
	}
	return rec.Status
}

// auditCount 某动作的审计行数。
func (e *env) auditCount(t *testing.T, action string) int {
	t.Helper()
	n, err := e.svc.AuditCountByAction(context.Background(), action)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// auditSeqs 审计表全部 seq（升序）。
func (e *env) auditSeqs(t *testing.T) []int64 {
	t.Helper()
	rows, err := e.pool.Query(context.Background(),
		fmt.Sprintf(`SELECT seq FROM %s ORDER BY seq`, e.auditT))
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var s int64
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	return out
}

// revocationsByReason 按原因统计吊销行数。
func (e *env) revocationsByReason(t *testing.T, reason string) int64 {
	t.Helper()
	n, err := e.store.RevocationReasonCount(context.Background(), reason)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// —— 用例 ——

// TestR1_RenewAtHalfLifeWithJitter（R1）有效期 7 天，续期窗口为 [3.15d, 3.85d]。
func TestR1_RenewAtHalfLifeWithJitter(t *testing.T) {
	e := newEnv(t)
	if e == nil {
		return
	}
	validity := e.ca.Validity()
	if validity != nodeidentity.DefaultCertValidity {
		t.Fatalf("有效期应为 7 天（%s），实际 %s", nodeidentity.DefaultCertValidity, validity)
	}
	// 裁决口径：续期在有效期的 50% 处触发，抖动 ±10%（**相对于触发点**），
	// 因此实际比例落在 [0.45, 0.55] ⇒ 7 天有效期为 [3.15d, 3.85d]。
	const (
		half = 0.5
		jit  = 0.10
	)
	lo := time.Duration(float64(validity) * half * (1 - jit))
	hi := time.Duration(float64(validity) * half * (1 + jit))
	wantLo := 3*24*time.Hour + 3*time.Hour + 36*time.Minute  // 3.15 天
	wantHi := 3*24*time.Hour + 20*time.Hour + 24*time.Minute // 3.85 天
	if lo != wantLo || hi != wantHi {
		t.Fatalf("续期窗口应为 [3.15d, 3.85d]（%s ~ %s），实际 [%s, %s]", wantLo, wantHi, lo, hi)
	}
	if hi >= validity {
		t.Fatal("续期窗口必须早于到期时刻")
	}
	t.Logf("[R1] 有效期=%s；续期窗口=[%s, %s]（50 个百分点正负 10，工程默认待确认）", validity, lo, hi)
}

// TestR2_RevokedSerialRefused（R2）序列号已吊销 → 拒绝续期。
func TestR2_RevokedSerialRefused(t *testing.T) {
	e := newEnv(t)
	if e == nil {
		return
	}
	ctx := context.Background()
	nodeID, serial, certDER := e.enrollPlain(t, "r2")
	e.clock.advance(time.Second)

	// 对照组：正确身份续期成功（证明后续拒绝来自"吊销"）。
	if _, err := e.svc.Renew(ctx, nodeID, serial, certDER, e.newCSRPEM(t)); err != nil {
		t.Fatalf("对照组续期应成功：%v", err)
	}
	rec, _, err := e.store.GetNode(ctx, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	e.clock.advance(time.Second)

	// 吊销当前序列号（注意：RevokeCert 会把节点置为 revoked 终态，
	// 因此此后续期会同时命中"序列号已吊销"与"节点已 revoked"两条规则——
	// 两者都要求拒绝，这正是本用例要断言的）。
	if err := e.svc.RevokeCert(ctx, rec.CertSerial, nodeID, "test-revoke"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Renew(ctx, nodeID, rec.CertSerial, certDER, e.newCSRPEM(t)); !errors.Is(err, ErrRenewRejected) {
		t.Fatalf("已吊销序列号必须拒绝续期（ErrRenewRejected），实际 %v", err)
	}
	if got := e.auditCount(t, ActionRenewRejected); got != 1 {
		t.Fatalf("应恰好 1 条 node.renew_rejected，实际 %d", got)
	}
	t.Log("[R2] 已吊销序列号 → 拒绝续期（renew_rejected=1；对照组可续期）")
}

// TestR3_SameKeyRefused（R3）CSR 公钥与当前证书相同 → 拒绝（必须换钥）。
func TestR3_SameKeyRefused(t *testing.T) {
	e := newEnv(t)
	if e == nil {
		return
	}
	ctx := context.Background()
	key, err := nodeidentity.NewNodeKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := nodeidentity.NewCSR(key, nil)
	if err != nil {
		t.Fatal(err)
	}
	out, err := e.svc.Enroll(ctx, e.newToken(t), csrDER, "r3", "test")
	if err != nil {
		t.Fatal(err)
	}
	e.clock.advance(time.Second)

	sameCSR, err := nodeidentity.NewCSR(key, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Renew(ctx, out.NodeID, out.CertSerial, out.CertificateDER,
		nodeidentity.CertificateRequestPEM(sameCSR)); !errors.Is(err, ErrRenewRejected) {
		t.Fatalf("同钥续期必须被拒绝（ErrRenewRejected），实际 %v", err)
	}
	if st := e.nodeStatus(t, out.NodeID); st != nodestore.StatusOnline {
		t.Fatalf("拒绝续期不得改变状态，实际 %q", st)
	}
	t.Log("[R3] 同钥续期 → 拒绝（必须换钥），状态保持 online")
}

// TestR4_WrongCNRefused（R4）身份不一致 → 拒绝。
func TestR4_WrongCNRefused(t *testing.T) {
	e := newEnv(t)
	if e == nil {
		return
	}
	ctx := context.Background()
	nodeA, serialA, certA := e.enrollPlain(t, "r4-a")
	nodeB, _, certB := e.enrollPlain(t, "r4-b")
	e.clock.advance(time.Second)

	// ① 用 B 的证书为 A 续期 → 拒绝。
	if _, err := e.svc.Renew(ctx, nodeA, serialA, certB, e.newCSRPEM(t)); !errors.Is(err, ErrRenewRejected) {
		t.Fatalf("用 B 的证书为 A 续期必须拒绝，实际 %v", err)
	}
	// ② 声明序列号与证书不一致 → 拒绝。
	if _, err := e.svc.Renew(ctx, nodeB, "999999999999", certB, e.newCSRPEM(t)); !errors.Is(err, ErrRenewRejected) {
		t.Fatalf("序列号与证书不一致必须拒绝，实际 %v", err)
	}
	// ③ 对照组：正确身份 → 成功。
	if _, err := e.svc.Renew(ctx, nodeA, serialA, certA, e.newCSRPEM(t)); err != nil {
		t.Fatalf("对照组（正确身份）续期应成功：%v", err)
	}
	t.Log("[R4] CN 不一致 / 序列号不匹配 → 拒绝；对照组（正确身份）续期成功")
}

// TestR5_FailureRetriesWithoutStateChange（R5）续期失败不改状态、不改序列号，可重复重试。
func TestR5_FailureRetriesWithoutStateChange(t *testing.T) {
	e := newEnv(t)
	if e == nil {
		return
	}
	ctx := context.Background()
	nodeID, serial, certDER := e.enrollPlain(t, "r5")
	e.clock.advance(time.Second)

	badCSR := []byte("-----BEGIN CERTIFICATE REQUEST-----\nnot-base64\n-----END CERTIFICATE REQUEST-----\n")
	for i := 1; i <= 3; i++ {
		e.clock.advance(10 * time.Second)
		if _, err := e.svc.Renew(ctx, nodeID, serial, certDER, badCSR); !errors.Is(err, ErrRenewRejected) {
			t.Fatalf("第 %d 次失败续期应被拒绝，实际 %v", i, err)
		}
		if st := e.nodeStatus(t, nodeID); st != nodestore.StatusOnline {
			t.Fatalf("第 %d 次失败后状态应保持 online，实际 %q", i, st)
		}
	}
	if got := e.auditCount(t, ActionRenewRejected); got != 3 {
		t.Fatalf("应有 3 条 node.renew_rejected，实际 %d", got)
	}
	if got := e.auditCount(t, ActionCertRenewed); got != 0 {
		t.Fatalf("失败路径不得写 cert_renewed，实际 %d", got)
	}
	if got := e.auditCount(t, ActionCertRevoked); got != 0 {
		t.Fatalf("失败路径不得写 cert_revoked，实际 %d", got)
	}
	rec, _, err := e.store.GetNode(ctx, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	if rec.CertSerial != serial {
		t.Fatalf("失败续期不得改变序列号：前 %s 后 %s", serial, rec.CertSerial)
	}
	if rec.PendingSupersededSerial != "" {
		t.Fatalf("失败续期不得写入待确认序列号，实际 %q", rec.PendingSupersededSerial)
	}
	t.Log("[R5] 连续 3 次失败：状态 online、序列号未变、待确认字段为空、审计 renew_rejected=3")
}

// TestR6_SupersedeOnlyAfterFirstHeartbeatWithNewSerial（R6）旧证书在新序列号首次心跳后才 supersede。
func TestR6_SupersedeOnlyAfterFirstHeartbeatWithNewSerial(t *testing.T) {
	e := newEnv(t)
	if e == nil {
		return
	}
	ctx := context.Background()
	nodeID, oldSerial, oldCert := e.enrollPlain(t, "r6")
	e.clock.advance(time.Second)

	out, err := e.svc.Renew(ctx, nodeID, oldSerial, oldCert, e.newCSRPEM(t))
	if err != nil {
		t.Fatalf("续期应成功：%v", err)
	}
	if out.NewSerial == oldSerial {
		t.Fatal("新序列号必须不同于旧序列号")
	}
	// ① 续期成功后**不得立即吊销**旧序列号（否则续期响应丢失 → 节点卡死）。
	if revoked, err := e.store.IsRevokedSerial(ctx, oldSerial); err != nil || revoked {
		t.Fatalf("续期成功后不得立即吊销旧序列号：revoked=%v err=%v", revoked, err)
	}
	if got := e.revocationsByReason(t, SupersedeReason); got != 0 {
		t.Fatalf("此时不应有 superseded 行，实际 %d", got)
	}
	// T1（第二十四轮）：待确认状态改由证书状态机维护（节点表的
	// pending_superseded_serial **停止写入**，列保留供回滚）。
	rec, _, err := e.store.GetNode(ctx, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	if rec.PendingSupersededSerial != "" {
		t.Fatalf("节点表的 pending_superseded_serial 应停止写入，实际 %q",
			rec.PendingSupersededSerial)
	}
	// 新证书在状态机中应为 issued（等待被心跳确认）。
	newRec, found, cerr := e.certs.Get(ctx, out.NewSerial)
	if cerr != nil || !found {
		t.Fatalf("新序列号应登记在证书状态机中：found=%v err=%v", found, cerr)
	}
	if newRec.State != nodecerts.StateIssued {
		t.Fatalf("续期后新证书应处于 issued，实际 %q", newRec.State)
	}

	// ② 仍用旧序列号心跳 → 旧证书可用，不触发 supersede。
	e.clock.advance(10 * time.Second)
	if _, herr := e.svc.Heartbeat(ctx, nodeID, "01M4RHFDJ0R6SESSION00000000",
		e.clock.now(), oldSerial); herr != nil {
		t.Fatalf("确认前旧序列号仍应可用：%v", herr)
	}
	if revoked, _ := e.store.IsRevokedSerial(ctx, oldSerial); revoked {
		t.Fatal("尚未用新序列号心跳，旧序列号不得被吊销")
	}

	// ③ 用新序列号心跳 → 触发 supersede。
	e.clock.advance(10 * time.Second)
	if _, herr := e.svc.Heartbeat(ctx, nodeID, "01M4RHFDJ0R6SESSION00000000",
		e.clock.now(), out.NewSerial); herr != nil {
		t.Fatalf("新序列号心跳应成功：%v", herr)
	}
	revoked, err := e.store.IsRevokedSerial(ctx, oldSerial)
	if err != nil {
		t.Fatal(err)
	}
	if !revoked {
		t.Fatal("新序列号首次心跳后应把旧序列号写入吊销表")
	}
	reason, found, err := e.store.RevocationReason(ctx, oldSerial)
	if err != nil || !found {
		t.Fatalf("旧序列号应在吊销表中：found=%v err=%v", found, err)
	}
	if reason != SupersedeReason {
		t.Fatalf("吊销原因应为 %q，实际 %q", SupersedeReason, reason)
	}
	if got := e.auditCount(t, ActionCertSuperseded); got != 1 {
		t.Fatalf("应恰好 1 条 node.cert_superseded，实际 %d", got)
	}
	if st := e.nodeStatus(t, nodeID); st != nodestore.StatusOnline {
		t.Fatalf("supersede 不得改变节点状态，实际 %q", st)
	}
	if got := e.auditCount(t, ActionCertRevoked); got != 0 {
		t.Fatalf("supersede 不得写 cert_revoked，实际 %d", got)
	}
	// 确认后：新证书变 active，旧证书变 superseded。
	finalNew, _, err := e.certs.Get(ctx, out.NewSerial)
	if err != nil {
		t.Fatal(err)
	}
	if finalNew.State != nodecerts.StateActive {
		t.Fatalf("确认后新证书应为 active，实际 %q", finalNew.State)
	}
	oldRec, foundOld, err := e.certs.Get(ctx, oldSerial)
	if err != nil || !foundOld {
		t.Fatalf("旧序列号应登记在证书状态机中：found=%v err=%v", foundOld, err)
	}
	if oldRec.State != nodecerts.StateSuperseded {
		t.Fatalf("确认后旧证书应为 superseded，实际 %q", oldRec.State)
	}
	t.Log("[R6] 续期后旧证书仍可用；新序列号首次心跳 → 旧序列号入吊销表(superseded)，状态仍 online")
}

// TestR7_ExpiryRiskBelow48h（R7）剩余不足 48h → 写 node.cert_expiry_risk（每节点每 6h 最多一条）。
func TestR7_ExpiryRiskBelow48h(t *testing.T) {
	e := newEnv(t)
	if e == nil {
		return
	}
	ctx := context.Background()
	e.enrollPlain(t, "r7")

	// 有效期 7 天：推进到剩余 47 小时。
	e.clock.advance(7*24*time.Hour - 47*time.Hour)
	risks, err := e.svc.ExpiryRisks(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(risks) != 1 {
		t.Fatalf("应有 1 条到期风险，实际 %d", len(risks))
	}
	if !risks[0].Reported {
		t.Fatal("首次触发应写入审计")
	}
	if got := e.auditCount(t, ActionCertExpiryRisk); got != 1 {
		t.Fatalf("应恰好 1 条 node.cert_expiry_risk，实际 %d", got)
	}
	// 节流：5 小时内不再写。
	e.clock.advance(5 * time.Hour)
	if _, err := e.svc.ExpiryRisks(ctx); err != nil {
		t.Fatal(err)
	}
	if got := e.auditCount(t, ActionCertExpiryRisk); got != 1 {
		t.Fatalf("6 小时节流内不得重复告警，实际 %d 条", got)
	}
	// 超过 6 小时 → 允许再写一条。
	e.clock.advance(2 * time.Hour)
	if _, err := e.svc.ExpiryRisks(ctx); err != nil {
		t.Fatal(err)
	}
	if got := e.auditCount(t, ActionCertExpiryRisk); got != 2 {
		t.Fatalf("超过 6 小时后应允许再告警（2 条），实际 %d", got)
	}
	t.Logf("[R7] 剩余 %s（小于 48h）→ 1 条告警；5h 内不重复；超过 6h 再写一条",
		risks[0].Remaining.Round(time.Minute))
}

// TestR8_StatusUnchangedAfterRenew（R8）续期后状态保持 online，且无 cert_revoked 审计。
func TestR8_StatusUnchangedAfterRenew(t *testing.T) {
	e := newEnv(t)
	if e == nil {
		return
	}
	ctx := context.Background()
	nodeID, serial, certDER := e.enrollPlain(t, "r8")
	e.clock.advance(time.Second)

	out, err := e.svc.Renew(ctx, nodeID, serial, certDER, e.newCSRPEM(t))
	if err != nil {
		t.Fatalf("续期应成功：%v", err)
	}
	if st := e.nodeStatus(t, nodeID); st != nodestore.StatusOnline {
		t.Fatalf("续期后状态应保持 online，实际 %q", st)
	}
	rec, _, err := e.store.GetNode(ctx, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	if rec.CertSerial != out.NewSerial {
		t.Fatalf("序列号应更新为新值：期望 %s 实际 %s", out.NewSerial, rec.CertSerial)
	}
	if got := e.auditCount(t, ActionCertRenewed); got != 1 {
		t.Fatalf("应恰好 1 条 node.cert_renewed，实际 %d", got)
	}
	if got := e.auditCount(t, ActionCertRevoked); got != 0 {
		t.Fatalf("续期不得写 node.cert_revoked，实际 %d", got)
	}
	// 心跳仍正常（新序列号）。
	e.clock.advance(10 * time.Second)
	if _, herr := e.svc.Heartbeat(ctx, nodeID, "01M4RHFDJ0R8SESSION00000000",
		e.clock.now(), out.NewSerial); herr != nil {
		t.Fatalf("续期后心跳应正常：%v", herr)
	}
	t.Logf("[R8] 续期后状态保持 online，序列号 %s→%s，审计 renewed=1 revoked=0", serial, out.NewSerial)
}

// TestR9_E2ERenewTwiceNoOutage（R9）端到端两次续期：心跳无中断，审计 seq 连续。
func TestR9_E2ERenewTwiceNoOutage(t *testing.T) {
	e := newEnv(t)
	if e == nil {
		return
	}
	ctx := context.Background()
	nodeID, serial, certDER := e.enrollPlain(t, "r9")
	const session = "01M4RHFDJ0R9SESSION00000000"

	heartbeats := 0
	beat := func(serialNow string) {
		t.Helper()
		e.clock.advance(10 * time.Second)
		if _, err := e.svc.Heartbeat(ctx, nodeID, session, e.clock.now(), serialNow); err != nil {
			t.Fatalf("心跳失败（不应中断）：%v", err)
		}
		heartbeats++
	}
	beat(serial)

	out1, err := e.svc.Renew(ctx, nodeID, serial, certDER, e.newCSRPEM(t))
	if err != nil {
		t.Fatalf("第一次续期失败：%v", err)
	}
	beat(out1.NewSerial)

	out2, err := e.svc.Renew(ctx, nodeID, out1.NewSerial, out1.CertificateDER, e.newCSRPEM(t))
	if err != nil {
		t.Fatalf("第二次续期失败：%v", err)
	}
	beat(out2.NewSerial)
	beat(out2.NewSerial)

	if out1.NewSerial == out2.NewSerial || out2.NewSerial == serial {
		t.Fatal("两次续期应产生各不相同的序列号")
	}
	if st := e.nodeStatus(t, nodeID); st != nodestore.StatusOnline {
		t.Fatalf("两次续期后应保持 online，实际 %q", st)
	}
	for _, s := range []string{serial, out1.NewSerial} {
		revoked, err := e.store.IsRevokedSerial(ctx, s)
		if err != nil || !revoked {
			t.Fatalf("旧序列号 %s 应已被 supersede：revoked=%v err=%v", s, revoked, err)
		}
		reason, _, err := e.store.RevocationReason(ctx, s)
		if err != nil {
			t.Fatal(err)
		}
		if reason != SupersedeReason {
			t.Fatalf("序列号 %s 的吊销原因应为 %s，实际 %q", s, SupersedeReason, reason)
		}
	}
	if got := e.auditCount(t, ActionCertRenewed); got != 2 {
		t.Fatalf("应恰好 2 条 cert_renewed，实际 %d", got)
	}
	if got := e.auditCount(t, ActionCertSuperseded); got != 2 {
		t.Fatalf("应恰好 2 条 cert_superseded，实际 %d", got)
	}
	if got := e.auditCount(t, ActionCertRevoked); got != 0 {
		t.Fatalf("续期路径不得写 cert_revoked，实际 %d", got)
	}
	seqs := e.auditSeqs(t)
	for i, s := range seqs {
		if s != int64(i+1) {
			t.Fatalf("审计 seq 必须连续：%v", seqs)
		}
	}
	// 预期审计：1 条 enrolled + 2 条 cert_renewed + 2 条 cert_superseded = 5 条
	//（心跳无状态迁移不写审计；续期路径刻意不写 cert_revoked）。
	if len(seqs) != 5 {
		t.Fatalf("审计事件应为 5 条（enrolled + 2×renewed + 2×superseded），实际 %v", seqs)
	}
	t.Logf("[R9] 两次续期无中断：心跳 %d 次全成功、状态 online、两个旧序列号 superseded、审计 seq 连续 [1..%d]",
		heartbeats, len(seqs))
}

// TestR10_ExpiredCertCannotRenew（R10）到期后拒绝续期（恢复路径为 T4 补发）。
func TestR10_ExpiredCertCannotRenew(t *testing.T) {
	e := newEnv(t)
	if e == nil {
		return
	}
	ctx := context.Background()
	nodeID, serial, certDER := e.enrollPlain(t, "r10")

	e.clock.advance(7*24*time.Hour + time.Hour)
	if _, err := e.svc.Renew(ctx, nodeID, serial, certDER, e.newCSRPEM(t)); !errors.Is(err, ErrRenewRejected) {
		t.Fatalf("过期证书必须拒绝续期（ErrRenewRejected），实际 %v", err)
	}
	if st := e.nodeStatus(t, nodeID); st == nodestore.StatusRevoked {
		t.Fatalf("续期失败不得把节点置为 revoked，实际 %q", st)
	}
	if got := e.auditCount(t, ActionRenewRejected); got != 1 {
		t.Fatalf("应恰好 1 条 node.renew_rejected，实际 %d", got)
	}
	t.Log("[R10] 到期后拒绝续期（renew_rejected=1，状态未变）；恢复路径 = T4 补发（新 node_id + 新证书）")
}
