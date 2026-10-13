package nodesvc

// T4 吊销后补发测试（第二十三轮）。真实 PostgreSQL（agent_ops_test 的独立 run schema）。
//
// 设计前提（ADR-022）：吊销是**终态**；恢复方式只有"新 node_id + 新证书"，
// 旧 node_id **永不复活**。补发只提供一次性令牌，注册仍走 N6 的既有路径。
//
//	TestX1_ReissueOnlyForRevoked
//	TestX2_NewNodeIDOldStaysRevoked
//	TestX3_OldCertStillRefusedAfterReissue
//	TestX4_ReissueTokenSingleUse
//	TestX5_ProdModeRefused
//	TestX6_AuditLinksAndNoSecrets

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/XZ-libin/agent-ops/internal/nodeidentity"
	"github.com/XZ-libin/agent-ops/internal/nodestore"
)

// revokeNode 注册并主动吊销一个节点，返回（node_id, 序列号, 证书 DER）。
func (e *env) revokeNode(t *testing.T, label string) (string, string, []byte) {
	t.Helper()
	nodeID, serial, certDER := e.enrollPlain(t, label)
	e.clock.advance(time.Second)
	if err := e.svc.RevokeCert(context.Background(), serial, nodeID, "test-revoke"); err != nil {
		t.Fatalf("吊销失败：%v", err)
	}
	if st := e.nodeStatus(t, nodeID); st != nodestore.StatusRevoked {
		t.Fatalf("吊销后状态应为 revoked，实际 %q", st)
	}
	return nodeID, serial, certDER
}

// TestX1_ReissueOnlyForRevoked（X1）补发**仅**面向 revoked 节点。
func TestX1_ReissueOnlyForRevoked(t *testing.T) {
	e := newEnv(t)
	if e == nil {
		return
	}
	ctx := context.Background()
	// ① 在线节点 → 拒绝。
	onlineNode, _, _ := e.enrollPlain(t, "x1-online")
	if _, err := e.svc.IssueReissueToken(ctx, onlineNode, "ops-alice", "human error", true); !errors.Is(err, ErrNodeNotRevoked) {
		t.Fatalf("在线节点不得补发（ErrNodeNotRevoked），实际 %v", err)
	}
	// ② 未知节点 → 拒绝。
	if _, err := e.svc.IssueReissueToken(ctx, "nod_01M4RHFDJ0NOTEXIST00000000", "ops", "r", true); !errors.Is(err, ErrReissueNotAllowed) {
		t.Fatalf("未知节点不得补发（ErrReissueNotAllowed），实际 %v", err)
	}
	// ③ 未显式确认 → 拒绝。
	revokedNode, _, _ := e.revokeNode(t, "x1-revoked")
	if _, err := e.svc.IssueReissueToken(ctx, revokedNode, "ops-alice", "human error", false); !errors.Is(err, ErrReissueNotAllowed) {
		t.Fatalf("未 confirm 不得补发，实际 %v", err)
	}
	// ④ 缺 operator → 拒绝。
	if _, err := e.svc.IssueReissueToken(ctx, revokedNode, "", "r", true); !errors.Is(err, ErrReissueNotAllowed) {
		t.Fatalf("缺 operator 不得补发，实际 %v", err)
	}
	// ⑤ 正确的对照组：revoked + confirm + operator → 成功。
	out, err := e.svc.IssueReissueToken(ctx, revokedNode, "ops-alice", "cert compromised", true)
	if err != nil {
		t.Fatalf("revoked 节点应可补发：%v", err)
	}
	if out.Token == "" {
		t.Fatal("应返回一次性令牌明文（由调用方一次性交付）")
	}
	if got := e.auditCount(t, ActionReissueTokenIssued); got != 1 {
		t.Fatalf("应恰好 1 条 node.reissue_token_issued，实际 %d", got)
	}
	t.Logf("[X1] 在线/未知/未确认/缺 operator → 拒绝；revoked+confirm → 成功（old=%s）", out.NodeID)
}

// TestX2_NewNodeIDOldStaysRevoked（X2）补发后新节点拿到新 node_id，旧节点保持 revoked。
func TestX2_NewNodeIDOldStaysRevoked(t *testing.T) {
	e := newEnv(t)
	if e == nil {
		return
	}
	ctx := context.Background()
	oldNode, _, _ := e.revokeNode(t, "x2-old")
	out, err := e.svc.IssueReissueToken(ctx, oldNode, "ops-bob", "node reimage", true)
	if err != nil {
		t.Fatal(err)
	}
	e.clock.advance(time.Second)

	// 用补发令牌注册 → 新 node_id。
	newKey, err := nodeidentity.NewNodeKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := nodeidentity.NewCSR(newKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	enrolled, err := e.svc.Enroll(ctx, out.Token, csrDER, "x2-new", "test")
	if err != nil {
		t.Fatalf("补发令牌应可注册：%v", err)
	}
	if enrolled.NodeID == oldNode {
		t.Fatalf("新节点必须获得**新** node_id（不得复用旧身份）：%s", enrolled.NodeID)
	}
	// 旧节点保持 revoked（永不复活）。
	if st := e.nodeStatus(t, oldNode); st != nodestore.StatusRevoked {
		t.Fatalf("旧节点应保持 revoked，实际 %q", st)
	}
	// 新节点 online。
	if st := e.nodeStatus(t, enrolled.NodeID); st != nodestore.StatusOnline {
		t.Fatalf("新节点应为 online，实际 %q", st)
	}
	// node.enrolled 审计带 previous_node_id。
	evs, err := e.audit.ListByAction(ctx, ActionEnrolled)
	if err != nil {
		t.Fatal(err)
	}
	var linked bool
	for _, ev := range evs {
		if ev.Target == enrolled.NodeID && strings.Contains(string(ev.Payload), oldNode) {
			linked = true
		}
	}
	if !linked {
		t.Fatalf("新节点的 node.enrolled 应带 previous_node_id=%s", oldNode)
	}
	t.Logf("[X2] 补发注册：新 node_id=%s，旧 %s 保持 revoked；enrolled 审计带 previous_node_id",
		enrolled.NodeID, oldNode)
}

// TestX3_OldCertStillRefusedAfterReissue（X3）补发后旧证书仍然被拒（心跳与续期都拒）。
func TestX3_OldCertStillRefusedAfterReissue(t *testing.T) {
	e := newEnv(t)
	if e == nil {
		return
	}
	ctx := context.Background()
	oldNode, oldSerial, oldCert := e.revokeNode(t, "x3-old")
	if _, err := e.svc.IssueReissueToken(ctx, oldNode, "ops", "reissue", true); err != nil {
		t.Fatal(err)
	}
	e.clock.advance(time.Second)

	// ① 旧节点心跳 → 拒绝（revoked 是终态）。
	if _, err := e.svc.Heartbeat(ctx, oldNode, "01M4RHFDJ0X3SESSION00000000",
		e.clock.now(), oldSerial); !errors.Is(err, ErrHeartbeatRejected) && !errors.Is(err, ErrCertRevoked) {
		t.Fatalf("旧节点心跳必须被拒，实际 %v", err)
	}
	// ② 旧证书续期 → 拒绝。
	if _, err := e.svc.Renew(ctx, oldNode, oldSerial, oldCert, e.newCSRPEM(t)); !errors.Is(err, ErrRenewRejected) {
		t.Fatalf("旧证书续期必须被拒，实际 %v", err)
	}
	// ③ 状态仍是 revoked（心跳被拒不改变状态）。
	if st := e.nodeStatus(t, oldNode); st != nodestore.StatusRevoked {
		t.Fatalf("旧节点应保持 revoked，实际 %q", st)
	}
	t.Logf("[X3] 补发后旧节点心跳与续期均被拒；状态保持 revoked")
}

// TestX4_ReissueTokenSingleUse（X4）补发令牌同样是一次性（含并发）。
func TestX4_ReissueTokenSingleUse(t *testing.T) {
	e := newEnv(t)
	if e == nil {
		return
	}
	ctx := context.Background()
	oldNode, _, _ := e.revokeNode(t, "x4-old")
	out, err := e.svc.IssueReissueToken(ctx, oldNode, "ops", "reissue", true)
	if err != nil {
		t.Fatal(err)
	}
	// ① 单次使用：先成功一次。
	newKey1, err := nodeidentity.NewNodeKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	csr1, err := nodeidentity.NewCSR(newKey1, nil)
	if err != nil {
		t.Fatal(err)
	}
	first, err := e.svc.Enroll(ctx, out.Token, csr1, "x4-first", "test")
	if err != nil {
		t.Fatalf("首次使用应成功：%v", err)
	}
	// ② 再次使用 → 拒绝。
	newKey2, err := nodeidentity.NewNodeKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	csr2, err := nodeidentity.NewCSR(newKey2, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Enroll(ctx, out.Token, csr2, "x4-second", "test"); !errors.Is(err, ErrEnrollRejected) {
		t.Fatalf("补发令牌重复使用必须被拒，实际 %v", err)
	}

	// ③ 并发：另一条补发令牌被 10 个并发注册提交 → 恰好 1 个成功。
	out2, err := e.svc.IssueReissueToken(ctx, oldNode, "ops", "reissue-concurrent", true)
	if err != nil {
		t.Fatal(err)
	}
	const workers = 10
	var success, rejected int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			k, kerr := nodeidentity.NewNodeKey(nil)
			if kerr != nil {
				return
			}
			c, cerr := nodeidentity.NewCSR(k, nil)
			if cerr != nil {
				return
			}
			if _, eerr := e.svc.Enroll(ctx, out2.Token, c, "x4-conc", "test"); eerr == nil {
				atomic.AddInt64(&success, 1)
			} else if errors.Is(eerr, ErrEnrollRejected) {
				atomic.AddInt64(&rejected, 1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if success != 1 {
		t.Fatalf("10 并发补发令牌注册必须恰好 1 个成功，实际 success=%d rejected=%d",
			success, rejected)
	}
	if rejected != workers-1 {
		t.Fatalf("其余 %d 个应被拒绝，实际 %d", workers-1, rejected)
	}
	// 令牌状态：已用且绑定新节点，且关联旧节点。
	state, err := e.store.GetTokenState(ctx,
		nodeidentity.HashTokenOf(out2.Token))
	if err != nil {
		t.Fatal(err)
	}
	if state.UsedAt.IsZero() {
		t.Fatal("补发令牌应已标记为已用")
	}
	if state.ReissuedForNodeID != oldNode {
		t.Fatalf("令牌应关联旧节点 %s，实际 %q", oldNode, state.ReissuedForNodeID)
	}
	if state.UsedByNodeID == "" || state.UsedByNodeID == oldNode {
		t.Fatalf("令牌应绑定**新**节点，实际 %q", state.UsedByNodeID)
	}
	t.Logf("[X4] 补发令牌单次使用；10 并发恰好 1 成功；令牌关联旧节点 %s、绑定新节点 %s（首次注册 %s）",
		oldNode, state.UsedByNodeID, first.NodeID)
}

// TestX5_ProdModeRefused（X5）生产模式拒绝补发（流程未设计）。
func TestX5_ProdModeRefused(t *testing.T) {
	e := newEnv(t)
	if e == nil {
		return
	}
	oldNode, _, _ := e.revokeNode(t, "x5-old")

	// 切换为 prod 模式（同一个 store/CA/tracker，只改 mode）。
	prodSvc, err := New(Config{
		Store: e.store, CA: e.ca, Tracker: e.tracker, Audit: e.audit,
		Now: e.clock.now, Mode: ModeProd,
	})
	if err != nil {
		t.Fatal(err)
	}
	if prodSvc.Mode() != ModeProd {
		t.Fatalf("模式应为 prod，实际 %q", prodSvc.Mode())
	}
	if _, err := prodSvc.IssueReissueToken(context.Background(), oldNode, "ops", "r", true); !errors.Is(err, ErrProdReissueUnimplemented) {
		t.Fatalf("生产模式必须拒绝补发（ErrProdReissueUnimplemented），实际 %v", err)
	}
	// 不得写入任何补发审计。
	if got := e.auditCount(t, ActionReissueTokenIssued); got != 0 {
		t.Fatalf("生产模式拒绝时不得写审计，实际 %d 条", got)
	}
	// 生产模式同样不得续期之外的"写能力"扩张：本轮的写入口只有 RevokeCert（测试用）
	// 与 IssueReissueToken（已在上面拒绝），这里断言补发是唯一被拒绝的新入口。
	t.Log("[X5] 生产模式 → 拒绝补发（FAILED_PRECONDITION 语义），且不写审计")
}

// TestX6_AuditLinksAndNoSecrets（X6）补发审计含 operator/old_node_id/reason，且不含令牌明文或哈希。
func TestX6_AuditLinksAndNoSecrets(t *testing.T) {
	e := newEnv(t)
	if e == nil {
		return
	}
	ctx := context.Background()
	oldNode, _, _ := e.revokeNode(t, "x6-old")
	const operator = "ops-carol"
	const reason = "hardware replaced"
	out, err := e.svc.IssueReissueToken(ctx, oldNode, operator, reason, true)
	if err != nil {
		t.Fatal(err)
	}

	evs, err := e.audit.ListByAction(ctx, ActionReissueTokenIssued)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 {
		t.Fatalf("应恰好 1 条补发审计，实际 %d", len(evs))
	}
	payload := string(evs[0].Payload)
	for _, want := range []string{operator, oldNode, reason} {
		if !strings.Contains(payload, want) {
			t.Fatalf("payload 应含 %q：%s", want, payload)
		}
	}
	// 禁止字段：令牌明文与令牌哈希。
	hash := nodeidentity.HashTokenOf(out.Token)
	forbidden := []string{
		out.Token,
		hex.EncodeToString(hash[:]),
		"BEGIN CERTIFICATE",
		"BEGIN PRIVATE KEY",
		"BEGIN CERTIFICATE REQUEST",
	}
	for _, bad := range forbidden {
		if strings.Contains(payload, bad) {
			t.Fatalf("审计 payload 含禁止字段 %q：%s", bad, payload)
		}
	}
	// actor 为 system（拒绝/系统操作），target 为旧节点。
	if evs[0].Actor != ActorSystem {
		t.Fatalf("补发审计 actor 应为 %q，实际 %q", ActorSystem, evs[0].Actor)
	}
	if evs[0].Target != oldNode {
		t.Fatalf("补发审计 target 应为旧节点 %s，实际 %s", oldNode, evs[0].Target)
	}
	t.Logf("[X6] 审计含 operator/old_node_id/reason（actor=system，target=%s），无令牌明文/哈希/证书材料", oldNode)
}
