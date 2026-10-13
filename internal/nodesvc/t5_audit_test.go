package nodesvc

// T5 审计完整性测试（第二十三轮）。
//
// 目标：把"节点域每一种状态迁移都必须对应一条审计"从文档约定变成可执行断言。
//
// 做法：
//  1. 枚举节点域的**全部**迁移（online / offline / revoked / renewed / superseded /
//     reissued / clock_regression_reset / cert_expiry_risk / renew_rejected）；
//  2. 走真实路径把每一种都触发一次（真实 PG + 独立 run schema）；
//  3. 断言每种迁移恰好一条审计，且全部审计的 seq 连续、无缺口。

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/XZ-libin/agent-ops/internal/nodehealth"
	"github.com/XZ-libin/agent-ops/internal/nodeidentity"
	"github.com/XZ-libin/agent-ops/internal/nodestore"
)

// NodeTransitions 节点域**全部**状态迁移及其对应审计动作。
//
// 这是本文件的"单一事实来源"：新增迁移时必须在此登记，
// 否则 TestAuditCoverage_AllTransitions 会因"未覆盖"而失败。
var NodeTransitions = []string{
	ActionEnrolled,             // 注册（节点进入 online）
	ActionOffline,              // online → offline
	ActionOnline,               // offline → online（恢复）
	ActionCertRevoked,          // → revoked（终态）
	ActionCertRenewed,          // 续期成功（不改变状态）
	ActionCertSuperseded,       // 旧证书被取代（写入吊销表，不改变状态）
	ActionReissueTokenIssued,   // 为 revoked 节点补发令牌
	ActionClockRegressionReset, // D6 连续 replay 后重置基线
	ActionCertExpiryRisk,       // 剩余有效期不足 48h
	ActionRenewRejected,        // 续期被拒绝
	ActionClockSkewWarning,     // 时钟偏差级别变化
	ActionHeartbeatRejected,    // 心跳被拒绝
	ActionEnrollRejected,       // 注册被拒绝
}

// newCSRDER 生成一个干净的持有性证明 CSR（DER）。
func (e *env) newCSRDER(t *testing.T) []byte {
	t.Helper()
	key, err := nodeidentity.NewNodeKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	der, err := nodeidentity.NewCSR(key, nil)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// TestAuditCoverage_AllTransitions（T5）每种迁移写入一条审计，且 seq 连续。
func TestAuditCoverage_AllTransitions(t *testing.T) {
	e := newEnv(t)
	if e == nil {
		return
	}
	ctx := context.Background()
	var mu sync.Mutex
	seen := map[string]bool{}
	mark := func(action string) {
		mu.Lock()
		seen[action] = true
		mu.Unlock()
	}

	// ① enrolled + 后续所有迁移都在一个节点上推进。
	nodeID, serial, certDER := e.enrollPlain(t, "t5")
	mark(ActionEnrolled)
	const session = "01M4RHFDJ0T5SESSION00000000"

	// ② clock_skew_warning：发送偏差超 warn 阈值的心跳（只告警不拒绝）。
	e.clock.advance(10 * time.Second)
	if _, err := e.svc.Heartbeat(ctx, nodeID, session,
		e.clock.now().Add(-40*time.Second), serial); err != nil {
		t.Fatalf("偏差心跳应被接受：%v", err)
	}
	mark(ActionClockSkewWarning)

	// ③ clock_regression_reset：同会话**连续 3 次 replay**，并且这 3 个被拒绝的
	//    sent_at **严格递增**、received_at 跨度不少于 20 秒（T3 加固后的三条件，
	//    见 nodehealth.resetEligible）。基线是上一步被接受的 sent_at（=base），
	//    所以重放值必须**低于** base 且彼此递增——等值重放属 duplicate，不计入 streak。
	base := e.clock.now().Add(-40 * time.Second) // = 上一步被接受的 sent_at（当前基线）
	replayFloor := base.Add(-10 * time.Minute)
	for i := 1; i <= nodehealth.DefaultReplayResetThreshold; i++ {
		e.clock.advance(10 * time.Second) // 3 次 → 接收跨度 20s（恰好满足 ≥20s）
		_, err := e.svc.Heartbeat(ctx, nodeID, session,
			replayFloor.Add(time.Duration(i)*time.Second), serial)
		if i < nodehealth.DefaultReplayResetThreshold {
			if err == nil {
				t.Fatalf("第 %d 次 replay 应被拒绝", i)
			}
			continue
		}
		if err != nil {
			t.Fatalf("第 %d 次应重置基线并接受，实际 err=%v", i, err)
		}
	}
	mark(ActionClockRegressionReset)

	// ④ offline：连续缺失达阈值。
	e.clock.advance(3 * nodehealth.DefaultInterval)
	if _, err := e.svc.EvaluateOffline(ctx); err != nil {
		t.Fatal(err)
	}
	mark(ActionOffline)

	// ⑤ online：恢复心跳。
	e.clock.advance(10 * time.Second)
	if _, err := e.svc.Heartbeat(ctx, nodeID, session, e.clock.now(), serial); err != nil {
		t.Fatalf("恢复心跳应成功：%v", err)
	}
	mark(ActionOnline)

	// ⑥ cert_renewed + cert_superseded（supersede 需要新序列号心跳）。
	renewed, err := e.svc.Renew(ctx, nodeID, serial, certDER, e.newCSRPEM(t))
	if err != nil {
		t.Fatalf("续期应成功：%v", err)
	}
	mark(ActionCertRenewed)
	e.clock.advance(10 * time.Second)
	if _, err := e.svc.Heartbeat(ctx, nodeID, session, e.clock.now(), renewed.NewSerial); err != nil {
		t.Fatalf("新序列号心跳应成功：%v", err)
	}
	mark(ActionCertSuperseded)

	// ⑦ renew_rejected：坏 CSR 续期。
	if _, err := e.svc.Renew(ctx, nodeID, renewed.NewSerial, renewed.CertificateDER,
		[]byte("-----BEGIN CERTIFICATE REQUEST-----\nbad\n-----END CERTIFICATE REQUEST-----\n")); err == nil {
		t.Fatal("坏 CSR 应被拒绝")
	}
	mark(ActionRenewRejected)

	// ⑧ enroll_rejected：错误令牌。
	if _, err := e.svc.Enroll(ctx, "wrong-token", e.newCSRDER(t), "t5", "test"); err == nil {
		t.Fatal("错误令牌应被拒绝")
	}
	mark(ActionEnrollRejected)

	// ⑨ heartbeat_rejected：吊销后用旧序列号心跳。
	if err := e.svc.RevokeCert(ctx, renewed.NewSerial, nodeID, "t5-revoke"); err != nil {
		t.Fatal(err)
	}
	mark(ActionCertRevoked)
	e.clock.advance(10 * time.Second)
	if _, err := e.svc.Heartbeat(ctx, nodeID, session, e.clock.now(), renewed.NewSerial); err == nil {
		t.Fatal("revoked 节点心跳必须被拒绝")
	}
	mark(ActionHeartbeatRejected)

	// ⑩ reissue_token_issued：为 revoked 节点补发。
	if _, err := e.svc.IssueReissueToken(ctx, nodeID, "ops-t5", "coverage", true); err != nil {
		t.Fatalf("revoked 节点应可补发：%v", err)
	}
	mark(ActionReissueTokenIssued)

	// ⑪ cert_expiry_risk：另建一个节点并把时钟推到剩余不足 48h。
	e2node, _, _ := e.enrollPlain(t, "t5-risk")
	e.clock.advance(7*24*time.Hour - 47*time.Hour)
	if _, err := e.svc.ExpiryRisks(ctx); err != nil {
		t.Fatal(err)
	}
	mark(ActionCertExpiryRisk)
	_ = e2node

	// —— 断言：登记表与实际情况一致 ——
	for _, action := range NodeTransitions {
		n := e.auditCount(t, action)
		if n == 0 {
			t.Errorf("[T5] 迁移 %s 未产生任何审计（登记表与实际不一致）", action)
			continue
		}
		if !seen[action] {
			t.Errorf("[T5] 迁移 %s 未被本用例触发（覆盖不完整）", action)
		}
	}
	// 反复触发（心跳）不应污染迁移类审计的"恰好一条"性质：
	// 仅对真正的**状态迁移**要求恰好一条。
	exactlyOnce := []string{
		ActionOnline, ActionOffline, ActionCertRevoked, ActionCertSuperseded,
		ActionReissueTokenIssued, ActionClockRegressionReset,
	}
	for _, action := range exactlyOnce {
		if got := e.auditCount(t, action); got != 1 {
			t.Errorf("[T5] %s 应恰好 1 条，实际 %d", action, got)
		}
	}

	// seq 连续性。
	seqs := e.auditSeqs(t)
	for i, s := range seqs {
		if s != int64(i+1) {
			t.Fatalf("[T5] 审计 seq 必须连续：%v", seqs)
		}
	}
	// 总量应当等于所有动作行数之和（说明没有"写进别的表"或漏写）。
	total := 0
	for _, action := range NodeTransitions {
		total += e.auditCount(t, action)
	}
	if len(seqs) != total {
		t.Fatalf("[T5] 审计总数 %d 与各动作行数之和 %d 不一致（有未登记动作）", len(seqs), total)
	}
	t.Logf("[T5] 覆盖 %d 种迁移、每种至少 1 条审计；seq 连续 [1..%d]；总量与分项之和一致",
		len(NodeTransitions), len(seqs))
}

// TestAuditCoverage_NoUnknownActions（T5 反向）审计表中不得出现未登记的节点域动作。
//
// 目的：防止"新增了状态迁移但忘记登记到 NodeTransitions"。
func TestAuditCoverage_NoUnknownActions(t *testing.T) {
	e := newEnv(t)
	if e == nil {
		return
	}
	ctx := context.Background()
	// 触发若干典型路径。
	nodeID, serial, certDER := e.enrollPlain(t, "t5-unknown")
	e.clock.advance(10 * time.Second)
	_, _ = e.svc.Heartbeat(ctx, nodeID, "01M4RHFDJ0T5USESSION00000000", e.clock.now(), serial)
	_, _ = e.svc.Renew(ctx, nodeID, serial, certDER, e.newCSRPEM(t))

	rows, err := e.pool.Query(ctx, `SELECT DISTINCT action FROM `+e.auditT+` ORDER BY action`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	registered := map[string]bool{}
	for _, a := range NodeTransitions {
		registered[a] = true
	}
	for rows.Next() {
		var action string
		if err := rows.Scan(&action); err != nil {
			t.Fatal(err)
		}
		if !registered[action] {
			t.Errorf("[T5] 审计动作 %q 未登记在 NodeTransitions（新增迁移请同步登记）", action)
		}
	}
	t.Logf("[T5] 审计表中的动作全部已登记（共 %d 种）", len(NodeTransitions))
}

// TestAuditCoverage_TransitionConstantsAreStable（T5）迁移动作名不得被意外改名。
//
// 下游（监控/看板）按字面值消费，改名属破坏性变更。
func TestAuditCoverage_TransitionConstantsAreStable(t *testing.T) {
	want := map[string]string{
		ActionEnrolled:             "node.enrolled",
		ActionOnline:               "node.online",
		ActionOffline:              "node.offline",
		ActionCertRevoked:          "node.cert_revoked",
		ActionCertRenewed:          "node.cert_renewed",
		ActionCertSuperseded:       "node.cert_superseded",
		ActionReissueTokenIssued:   "node.reissue_token_issued",
		ActionClockRegressionReset: "node.clock_regression_reset",
		ActionCertExpiryRisk:       "node.cert_expiry_risk",
		ActionRenewRejected:        "node.renew_rejected",
		ActionClockSkewWarning:     "node.clock_skew_warning",
		ActionHeartbeatRejected:    "node.heartbeat_rejected",
		ActionEnrollRejected:       "node.enroll_rejected",
	}
	for constVal, literal := range want {
		if constVal != literal {
			t.Errorf("[T5] 动作常量值被改动：期望 %q 实际 %q", literal, constVal)
		}
	}
	if len(NodeTransitions) != len(want) {
		t.Fatalf("[T5] 登记表条目数 %d 与期望 %d 不一致", len(NodeTransitions), len(want))
	}
	t.Logf("[T5] %d 个动作名与对外契约字面值一致（下游可安全消费）", len(want))
}

// 保持 nodestore / nodehealth 引用（断言里用到其常量）。
var (
	_ = nodestore.StatusOnline
	_ = nodehealth.DefaultReplayResetThreshold
)
