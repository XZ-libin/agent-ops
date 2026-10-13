package nodesvc

// N6 持久化与审计测试（第二十二轮）。真实 PostgreSQL（agent_ops_test 的独立 run schema）。

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/XZ-libin/agent-ops/internal/audit"
	"github.com/XZ-libin/agent-ops/internal/nodecerts"
	"github.com/XZ-libin/agent-ops/internal/nodehealth"
	"github.com/XZ-libin/agent-ops/internal/nodeidentity"
	"github.com/XZ-libin/agent-ops/internal/nodestore"
	"github.com/XZ-libin/agent-ops/internal/testdb"
)

// testClock 可控注入时钟。
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// env 测试环境。
type env struct {
	svc     *Service
	store   *nodestore.Store
	ca      *nodeidentity.TestCA
	audit   *audit.Store
	tracker *nodehealth.Tracker
	clock   *testClock
	pool    *pgxpool.Pool
	auditT  string
	// certs 证书状态机（T1）：从 svc 暴露便于测试断言证书状态。
	certs *nodecerts.Store
}

func newEnv(t *testing.T) *env {
	t.Helper()
	rs := testdb.NewRunSchema(t)
	if rs == nil {
		return nil
	}
	ctx := context.Background()
	pool := rs.Pool()
	clk := &testClock{t: time.Unix(1791825000, 0).UTC()}

	store, err := nodestore.New(nodestore.Config{Pool: pool, Now: clk.now})
	if err != nil {
		t.Fatal(err)
	}
	// 建表 + 迁移（T3/T4 新增列）在 svc 构造后统一执行（见下方 svc.EnsureSchema）。
	ca, err := nodeidentity.NewTestCA(nodeidentity.CAConfig{
		Now: clk.now(), Validity: nodeidentity.DefaultCertValidity,
		CAValidity: 30 * 24 * time.Hour,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tracker, err := nodehealth.NewTracker(nodehealth.Config{Now: clk.now})
	if err != nil {
		t.Fatal(err)
	}
	auditT := fmt.Sprintf("test_audit_events_node_%d", time.Now().UnixNano())
	aud := audit.NewTestStore(pool, auditT)
	if err := aud.EnsureSchema(ctx); err != nil {
		t.Fatalf("审计建表失败：%v", err)
	}
	svc, err := New(Config{Store: store, CA: ca, Tracker: tracker, Audit: aud, Now: clk.now})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.EnsureSchema(ctx); err != nil {
		t.Fatalf("建表/迁移失败（非 skip）：%v", err)
	}
	_, _, revocations, _, _ := store.AllTables()
	certs, err := nodecerts.New(nodecerts.Config{
		Pool: pool, CertsTable: store.CertsTable(), RevocationsTable: revocations,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &env{svc: svc, store: store, ca: ca, audit: aud, tracker: tracker,
		clock: clk, pool: pool, auditT: auditT, certs: certs}
}

// newToken 生成并保存一次性令牌，返回明文。
func (e *env) newToken(t *testing.T) string {
	t.Helper()
	plain, hash, err := nodeidentity.GenerateToken(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.store.PutToken(context.Background(), hash, e.clock.now().Add(nodeidentity.TokenTTL)); err != nil {
		t.Fatal(err)
	}
	return plain
}

// csr 生成纯持有性证明 CSR。
func csr(t *testing.T) []byte {
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

// TestN6ConcurrentTokenConsumption（N6 ①）同一令牌被 10 个并发 Enroll 提交 → 恰好 1 个成功。
func TestN6ConcurrentTokenConsumption(t *testing.T) {
	e := newEnv(t)
	if e == nil {
		return
	}
	token := e.newToken(t)
	const workers = 10

	var success, rejected, other int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := e.svc.Enroll(context.Background(), token, csr(t), "concurrent", "test")
			switch {
			case err == nil:
				atomic.AddInt64(&success, 1)
			case errors.Is(err, ErrEnrollRejected):
				atomic.AddInt64(&rejected, 1)
			default:
				atomic.AddInt64(&other, 1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if success != 1 {
		t.Fatalf("并发提交同一令牌必须**恰好 1 个**成功，实际 success=%d rejected=%d other=%d",
			success, rejected, other)
	}
	if rejected != workers-1 {
		t.Fatalf("其余 %d 个必须被拒绝，实际 %d", workers-1, rejected)
	}
	// 落库校验：只应有 1 个节点，令牌只被消费一次。
	nodes, err := e.store.ListNodes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 {
		t.Fatalf("应只创建 1 个节点，实际 %d", len(nodes))
	}
	state, err := e.store.GetTokenState(context.Background(), nodeidentity.HashTokenOf(token))
	if err != nil {
		t.Fatal(err)
	}
	if state.UsedAt.IsZero() || state.UsedByNodeID != nodes[0].NodeID {
		t.Fatalf("令牌应恰好被消费一次并绑定该节点：%+v vs %s", state, nodes[0].NodeID)
	}
	t.Logf("[N6①] 10 并发 → success=%d rejected=%d；节点数=1，令牌已用且绑定 node_id=%s",
		success, rejected, state.UsedByNodeID)
}

// TestN6AuditPayloadHasNoForbiddenFields（N6 ②）审计 payload 不含禁止字段。
func TestN6AuditPayloadHasNoForbiddenFields(t *testing.T) {
	e := newEnv(t)
	if e == nil {
		return
	}
	ctx := context.Background()
	token := e.newToken(t)
	out, err := e.svc.Enroll(ctx, token, csr(t), "audit-scan", "0.22.0-test")
	if err != nil {
		t.Fatal(err)
	}
	// 制造若干状态迁移与拒绝事件。
	if _, err := e.svc.Heartbeat(ctx, out.NodeID, "01M4RHFDJ0N6TESTSESSION0000000", e.clock.now().Add(-90*time.Second), out.CertSerial); err != nil {
		t.Fatalf("心跳应成功（偏差只告警）：%v", err)
	}
	e.clock.advance(3 * nodehealth.DefaultInterval)
	if _, err := e.svc.EvaluateOffline(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Enroll(ctx, "wrong-token", csr(t), "x", "test"); err == nil {
		t.Fatal("错误令牌必须被拒绝")
	}

	// 扫描全部审计事件。
	tokenHash := nodeidentity.HashTokenOf(token)
	forbidden := []string{
		token,                            // 令牌明文
		hex.EncodeToString(tokenHash[:]), // 令牌哈希（hex）
		"BEGIN CERTIFICATE",              // 证书 PEM
		"BEGIN PRIVATE KEY",              // 私钥
		"BEGIN RSA PRIVATE KEY",
		"BEGIN OPENSSH PRIVATE KEY",
		"BEGIN CERTIFICATE REQUEST", // CSR PEM
	}
	actions := []string{ActionEnrolled, ActionOnline, ActionOffline, ActionClockSkewWarning,
		ActionCertRevoked, ActionEnrollRejected, ActionHeartbeatRejected}
	scanned := 0
	for _, a := range actions {
		evs, err := e.audit.ListByAction(ctx, a)
		if err != nil {
			t.Fatal(err)
		}
		for _, ev := range evs {
			scanned++
			payload := string(ev.Payload)
			for _, bad := range forbidden {
				if strings.Contains(payload, bad) {
					t.Fatalf("[N6②] 审计 payload 含禁止字段 %q：action=%s payload=%s", bad, ev.Action, payload)
				}
			}
		}
	}
	if scanned == 0 {
		t.Fatal("未扫描到任何审计事件")
	}
	t.Logf("[N6②] 扫描 %d 条审计 payload：无令牌明文/哈希、无证书/私钥/CSR PEM", scanned)
}

// TestN6RestartRecovery（N6 ③）控制面重启后节点状态与令牌已用状态保持一致。
func TestN6RestartRecovery(t *testing.T) {
	e := newEnv(t)
	if e == nil {
		return
	}
	ctx := context.Background()
	token := e.newToken(t)
	out, err := e.svc.Enroll(ctx, token, csr(t), "restart", "test")
	if err != nil {
		t.Fatal(err)
	}
	// 让节点掉线（制造非 online 状态）。
	e.clock.advance(3 * nodehealth.DefaultInterval)
	if _, err := e.svc.EvaluateOffline(ctx); err != nil {
		t.Fatal(err)
	}

	// 模拟重启：全新 tracker + 新 Service（同一 schema / 同一 store）。
	newTracker, err := nodehealth.NewTracker(nodehealth.Config{Now: e.clock.now})
	if err != nil {
		t.Fatal(err)
	}
	svc2, err := New(Config{Store: e.store, CA: e.ca, Tracker: newTracker, Audit: e.audit, Now: e.clock.now})
	if err != nil {
		t.Fatal(err)
	}
	n, err := svc2.Restore(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("应恢复 1 个节点，实际 %d", n)
	}
	// 状态恢复为 offline（不是默认 online）。
	st, _, err := newTracker.Status(out.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	if st != nodehealth.StatusOffline {
		t.Fatalf("重启后状态应恢复为 offline，实际 %s", st)
	}
	// 令牌已用状态保持（再次注册仍被拒绝）。
	if _, err := svc2.Enroll(ctx, token, csr(t), "restart-again", "test"); err == nil {
		t.Fatal("重启后同一令牌仍必须被拒绝")
	}
	// 恢复后心跳可回到 online（必须走**重启后**的 svc2，其 tracker 才是被断言的实例）。
	e.clock.advance(time.Second)
	if _, err := svc2.Heartbeat(ctx, out.NodeID, "01M4RHFDJ0N6TESTSESSION0000000", e.clock.now(), out.CertSerial); err != nil {
		t.Fatalf("恢复后心跳应成功：%v", err)
	}
	st2, _, _ := newTracker.Status(out.NodeID)
	if st2 != nodehealth.StatusOnline {
		t.Fatalf("恢复后心跳应回到 online，实际 %s", st2)
	}
	t.Logf("[N6③] 重启恢复：节点数=%d，状态 offline 保持、令牌已用保持、心跳后回到 online", n)
}

// TestN6OneAuditPerTransition（N6 ④）每个状态迁移恰好一条审计，不重复、不遗漏。
func TestN6OneAuditPerTransition(t *testing.T) {
	e := newEnv(t)
	if e == nil {
		return
	}
	ctx := context.Background()
	token := e.newToken(t)
	out, err := e.svc.Enroll(ctx, token, csr(t), "audit-once", "test")
	if err != nil {
		t.Fatal(err)
	}
	// 心跳（无偏差、无迁移）→ 不应产生状态迁移审计。
	if _, err := e.svc.Heartbeat(ctx, out.NodeID, "01M4RHFDJ0N6TESTSESSION0000000", e.clock.now(), out.CertSerial); err != nil {
		t.Fatal(err)
	}
	// 掉线 → 恰好 1 条 node.offline。
	e.clock.advance(3 * nodehealth.DefaultInterval)
	if _, err := e.svc.EvaluateOffline(ctx); err != nil {
		t.Fatal(err)
	}
	// 重复判定 → 不再产生。
	if _, err := e.svc.EvaluateOffline(ctx); err != nil {
		t.Fatal(err)
	}
	// 恢复心跳 → 恰好 1 条 node.online。
	e.clock.advance(time.Second)
	if _, err := e.svc.Heartbeat(ctx, out.NodeID, "01M4RHFDJ0N6TESTSESSION0000000", e.clock.now(), out.CertSerial); err != nil {
		t.Fatal(err)
	}
	// 吊销 → 恰好 1 条 node.cert_revoked。
	if err := e.svc.RevokeCert(ctx, out.CertSerial, out.NodeID, "test-revoke"); err != nil {
		t.Fatal(err)
	}

	want := map[string]int{
		ActionEnrolled:    1,
		ActionOffline:     1,
		ActionOnline:      1,
		ActionCertRevoked: 1,
	}
	for action, n := range want {
		got, err := e.svc.AuditCountByAction(ctx, action)
		if err != nil {
			t.Fatal(err)
		}
		if got != n {
			t.Fatalf("%s 应恰好 %d 条审计，实际 %d", action, n, got)
		}
	}
	// 吊销表与节点状态。
	rc, err := e.store.RevocationCount(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rc != 1 {
		t.Fatalf("吊销表应恰好 1 行，实际 %d", rc)
	}
	revokedCount, err := e.store.CountByStatus(ctx, nodestore.StatusRevoked)
	if err != nil {
		t.Fatal(err)
	}
	if revokedCount != 1 {
		t.Fatalf("应有 1 个 revoked 节点，实际 %d", revokedCount)
	}
	t.Logf("[N6④] 每个迁移恰好一条审计：enrolled=1 offline=1 online=1 cert_revoked=1；吊销表=1 行")
}
