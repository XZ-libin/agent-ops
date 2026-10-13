package audit

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	contractv1 "github.com/XZ-libin/agent-ops/contract/gen/go/agent_ops/contract/v1"
	"github.com/XZ-libin/agent-ops/internal/policy"
	"github.com/XZ-libin/agent-ops/internal/testdb"
)

// testDSNEnv 测试数据库连接串环境变量；未设置时使用 testdb 的默认值
// （数据库必须为 agent_ops_test，第十一轮 H2）。
const testDSNEnv = testdb.EnvDSN

// auditRunToken 每次测试运行的独立表名（test_ 前缀，测试守卫要求）：
// 链上哈希与测试数据只追加不删除，独立表保证每次运行从干净链开始。
var auditRunToken = fmt.Sprintf("test_audit_events_%d", time.Now().UnixNano())

// auditPoolForTests 建立测试连接池；PostgreSQL 不可用时返回 skip 原因（不静默通过）。
func auditPoolForTests(t *testing.T) *pgxpool.Pool {
	t.Helper()
	// 第十四轮 H5：每轮测试使用独立 schema（test_run_<时间戳>），
	// 断言通过后自动删除；public 不再增长。
	rs := testdb.NewRunSchema(t)
	if rs == nil {
		return nil // 已 skip
	}
	return rs.Pool()
}

// newAuditTestStore 建默认表审计存储；建表失败为真实错误（非 skip）。
func newAuditTestStore(t *testing.T) *Store {
	t.Helper()
	pool := auditPoolForTests(t)
	if pool == nil {
		return nil // 已 skip
	}
	s := NewTestStore(pool, auditRunToken)
	if err := s.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("审计建表失败（非 skip）：%v", err)
	}
	return s
}

// TestChainHashPinned 钉住哈希规范化方式（黄金值）：
// 输入格式固定为 canonicalJSON(["agent-ops-audit-v1", prev, id, actor, action, target, payload])。
func TestChainHashPinned(t *testing.T) {
	payload := []byte(`{"decision":"DECISION_DENY"}`)

	got, err := chainHash("", "evt-1", "alice", "policy.decided", "cp-1", payload)
	if err != nil {
		t.Fatal(err)
	}
	const want = "347ce683f439527537c5b8c500047baf55d7bacb30a29d78d92d4981576e498d"
	if got != want {
		t.Fatalf("哈希黄金值不一致：got %s want %s", got, want)
	}

	// 敏感性与确定性：prev、payload 任一变化，哈希必须不同。
	other, err := chainHash("deadbeef", "evt-1", "alice", "policy.decided", "cp-1", payload)
	if err != nil {
		t.Fatal(err)
	}
	if other == got {
		t.Fatal("prev_hash 变化后哈希应不同")
	}
	got2, err := chainHash("", "evt-1", "alice", "policy.decided", "cp-1", payload)
	if err != nil {
		t.Fatal(err)
	}
	if got2 != got {
		t.Fatal("相同输入哈希不相同（确定性被破坏）")
	}
}

func sampleEvent(id string) Event {
	return Event{
		ID:     id,
		Actor:  "alice",
		Action: "policy.decided",
		Target: "cp-1",
		Payload: PolicyDecision{
			Capability: "restart.service",
			Tier:       "RISK_TIER_LOW",
			Decision:   "DECISION_AUTO",
			Reasons:    []string{"最终等级 low，决策 auto"},
		},
	}
}

// TestAppendAndVerifyOK 正常追加后 Verify 全链通过。
func TestAppendAndVerifyOK(t *testing.T) {
	store := newAuditTestStore(t)
	if store == nil {
		return
	}
	ctx := context.Background()

	h, err := store.Append(ctx, sampleEvent("evt-1"))
	if err != nil {
		t.Fatal(err)
	}
	if len(h) != 64 {
		t.Fatalf("hash 应为 sha256 hex（64 位），got %q", h)
	}
	if _, err := store.Append(ctx, sampleEvent("evt-2")); err != nil {
		t.Fatal(err)
	}

	bad, err := store.Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if bad != 0 {
		t.Fatalf("未篡改链条 Verify 应通过（0），got seq=%d", bad)
	}
}

// TestWriterRoleDeniedUpdateDelete 以专用角色 audit_writer 执行 UPDATE 与 DELETE，
// 必须被数据库拒绝（角色仅 INSERT/SELECT）。
func TestWriterRoleDeniedUpdateDelete(t *testing.T) {
	store := newAuditTestStore(t)
	if store == nil {
		return
	}
	ctx := context.Background()
	if _, err := store.Append(ctx, sampleEvent("evt-w1")); err != nil {
		t.Fatal(err)
	}

	conn, err := store.pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, "SET ROLE audit_writer"); err != nil {
		t.Fatalf("设置 audit_writer 角色失败：%v", err)
	}
	_, uerr := conn.Exec(ctx, fmt.Sprintf("UPDATE %s SET actor = 'hacker' WHERE seq = 1", store.table))
	if uerr == nil || !strings.Contains(uerr.Error(), "denied") {
		t.Fatalf("audit_writer 的 UPDATE 应被拒绝（permission denied），got %v", uerr)
	}
	_, derr := conn.Exec(ctx, fmt.Sprintf("DELETE FROM %s WHERE seq = 1", store.table))
	if derr == nil || !strings.Contains(derr.Error(), "denied") {
		t.Fatalf("audit_writer 的 DELETE 应被拒绝（permission denied），got %v", derr)
	}
	if _, err := conn.Exec(ctx, "RESET ROLE"); err != nil {
		t.Fatal(err)
	}
}

// TestMutationRejectedByTrigger 超级用户也无法绕过触发器：
// UPDATE/DELETE 直接被触发器拒绝（数据库层防护，不只靠权限）。
func TestMutationRejectedByTrigger(t *testing.T) {
	store := newAuditTestStore(t)
	if store == nil {
		return
	}
	ctx := context.Background()
	if _, err := store.Append(ctx, sampleEvent("evt-t1")); err != nil {
		t.Fatal(err)
	}

	_, uerr := store.pool.Exec(ctx, fmt.Sprintf("UPDATE %s SET actor = 'hacker' WHERE seq = 1", store.table))
	if uerr == nil || !strings.Contains(uerr.Error(), "被禁止") {
		t.Fatalf("UPDATE 应被触发器拒绝（含「被禁止」），got %v", uerr)
	}
	_, derr := store.pool.Exec(ctx, fmt.Sprintf("DELETE FROM %s WHERE seq = 1", store.table))
	if derr == nil || !strings.Contains(derr.Error(), "被禁止") {
		t.Fatalf("DELETE 应被触发器拒绝（含「被禁止」），got %v", derr)
	}
}

// TestConcurrentAppend20Verify 20 个 goroutine 并发追加：
// Verify 仍通过，且 seq 连续无空洞（advisory lock 串行化生效）。
func TestConcurrentAppend20Verify(t *testing.T) {
	store := newAuditTestStore(t)
	if store == nil {
		return
	}
	ctx := context.Background()

	var baseMax int64
	if err := store.pool.QueryRow(ctx,
		fmt.Sprintf("SELECT COALESCE(max(seq), 0) FROM %s", store.table)).Scan(&baseMax); err != nil {
		t.Fatal(err)
	}

	const n = 20
	start := make(chan struct{})
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, errs[i] = store.Append(ctx, Event{
				ID:      fmt.Sprintf("evt-c-%d", i),
				Actor:   "load-test",
				Action:  "test.concurrent",
				Target:  "cp-1",
				Payload: map[string]any{"i": i},
			})
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("第 %d 个并发追加失败：%v", i, err)
		}
	}

	bad, err := store.Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if bad != 0 {
		t.Fatalf("并发追加后 Verify 应通过（0），got seq=%d", bad)
	}

	var cnt, minSeq, maxSeq int64
	if err := store.pool.QueryRow(ctx,
		fmt.Sprintf(`SELECT count(*), COALESCE(min(seq), 0), COALESCE(max(seq), 0)
FROM %s WHERE seq > $1`, store.table), baseMax).Scan(&cnt, &minSeq, &maxSeq); err != nil {
		t.Fatal(err)
	}
	if cnt != n {
		t.Fatalf("应新增 %d 行，got %d", n, cnt)
	}
	if maxSeq-minSeq+1 != n {
		t.Fatalf("seq 应连续无空洞：min=%d max=%d", minSeq, maxSeq)
	}
}

// TestTamperDetection 模拟篡改，验证校验逻辑：
// 以超级用户临时禁用触发器、修改一行 payload，Verify 必须报告该 seq。
// 使用一次性独立表，避免污染主链（测试数据不删除，只追加）。
func TestTamperDetection(t *testing.T) {
	pool := auditPoolForTests(t)
	if pool == nil {
		return
	}
	ctx := context.Background()

	store := NewTestStore(pool, fmt.Sprintf("test_audit_events_tamper_%d", time.Now().UnixNano()))
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatalf("篡改测试建表失败：%v", err)
	}
	if _, err := store.Append(ctx, sampleEvent("evt-tamper-1")); err != nil {
		t.Fatal(err)
	}

	var seq int64
	if err := pool.QueryRow(ctx,
		fmt.Sprintf("SELECT max(seq) FROM %s", store.table)).Scan(&seq); err != nil {
		t.Fatal(err)
	}

	// 模拟篡改：禁用触发器后修改一行（仅校验逻辑验证，不留后门）。
	if _, err := pool.Exec(ctx,
		fmt.Sprintf("ALTER TABLE %s DISABLE TRIGGER ALL", store.table)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx,
		fmt.Sprintf(`UPDATE %s SET payload = '{"tampered":true}'::jsonb WHERE seq = $1`, store.table), seq); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx,
		fmt.Sprintf("ALTER TABLE %s ENABLE TRIGGER ALL", store.table)); err != nil {
		t.Fatal(err)
	}

	bad, err := store.Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if bad != seq {
		t.Fatalf("篡改后 Verify 应报告 seq=%d，got %d", seq, bad)
	}
}

// TestRecordPolicyDecisionDeny 破坏性能力被策略拒绝时，
// 通过 Recorder 产生一条 policy.decided 且 decision 为 deny 的审计事件。
func TestRecordPolicyDecisionDeny(t *testing.T) {
	store := newAuditTestStore(t)
	if store == nil {
		return
	}
	ctx := context.Background()

	res := policy.Evaluate(policy.DefaultConfig(), policy.Request{
		Capability: &contractv1.Capability{
			Name:         "config.apply_batch",
			RiskTier:     contractv1.RiskTier_RISK_TIER_LOW,
			Rollbackable: true,
			Destructive:  true,
		},
		Environment: contractv1.Environment_ENVIRONMENT_STAGING,
		ImpactScope: policy.ImpactScopeSingle,
	})
	if res.Decision != contractv1.Decision_DECISION_DENY {
		t.Fatalf("destructive 能力应被 deny，got %v", res.Decision)
	}

	if err := store.RecordPolicyDecision(ctx, PolicyDecision{
		Capability: "config.apply_batch",
		Tier:       res.Tier.String(),
		Decision:   res.Decision.String(),
		Reasons:    res.Reasons,
	}); err != nil {
		t.Fatal(err)
	}

	var payloadDecision string
	if err := store.pool.QueryRow(ctx,
		fmt.Sprintf(`SELECT payload->>'decision' FROM %s
WHERE action = 'policy.decided' ORDER BY seq DESC LIMIT 1`, store.table)).Scan(&payloadDecision); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(payloadDecision, "DENY") {
		t.Fatalf("policy.decided 事件应记录 decision≈DENY，got %q", payloadDecision)
	}

	bad, err := store.Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if bad != 0 {
		t.Fatalf("Verify 应通过（0），got seq=%d", bad)
	}
}

// TestSeqHoleDetected 模拟篡改：以超级用户临时禁用触发器、删除中间一行，
// 制造 seq 空洞；VerifyWithReason 必须报告首个空洞位置及原因。
func TestSeqHoleDetected(t *testing.T) {
	store := newAuditTestStore(t)
	if store == nil {
		return
	}
	ctx := context.Background()

	for i := 1; i <= 3; i++ {
		if _, err := store.Append(ctx, sampleEvent(fmt.Sprintf("evt-hole-%d", i))); err != nil {
			t.Fatal(err)
		}
	}
	// 模拟篡改：临时禁用触发器删除第 2 行（仅校验逻辑验证）。
	if _, err := store.pool.Exec(ctx,
		fmt.Sprintf("ALTER TABLE %s DISABLE TRIGGER ALL", store.table)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx,
		fmt.Sprintf("DELETE FROM %s WHERE seq = 2", store.table)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx,
		fmt.Sprintf("ALTER TABLE %s ENABLE TRIGGER ALL", store.table)); err != nil {
		t.Fatal(err)
	}

	seq, reason, err := store.VerifyWithReason(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if seq == 0 {
		t.Fatal("seq 空洞必须被检测到（seq 不应为 0）")
	}
	if !strings.Contains(reason, "空洞或乱序") {
		t.Fatalf("原因应说明空洞/乱序，got %q", reason)
	}
}

// TestGuardRejectsNonTestTable 测试守卫：测试模式下非 test_ 前缀的表名，
// 建表与写入都必须被直接拒绝。
func TestGuardRejectsNonTestTable(t *testing.T) {
	pool := auditPoolForTests(t)
	if pool == nil {
		return
	}
	ctx := context.Background()

	store := NewTestStore(pool, "audit_events")
	if err := store.EnsureSchema(ctx); err == nil || !strings.Contains(err.Error(), "test_") {
		t.Fatalf("非 test_ 表名建表应被守卫拒绝，got %v", err)
	}
	if _, err := store.Append(ctx, sampleEvent("evt-guard")); err == nil || !strings.Contains(err.Error(), "test_") {
		t.Fatalf("非 test_ 表名写入应被守卫拒绝，got %v", err)
	}
}
