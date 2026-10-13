package approvals

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/XZ-libin/agent-ops/internal/testdb"
)

// testDSNEnv 测试数据库连接串环境变量；未设置时使用 testdb 默认值（agent_ops_test）。
const testDSNEnv = testdb.EnvDSN

// testApprovalsTable 本轮要求的测试表名（test_ 前缀，测试守卫要求；约束 8）。
const testApprovalsTable = "test_approvals"

// approvalsPoolForTests 建立测试连接池；PostgreSQL 不可用时 skip 并输出原因
// （不静默通过；约束 2：只连接本地 55432 的部署实例）。
func approvalsPoolForTests(t *testing.T) *pgxpool.Pool {
	t.Helper()
	// 第十四轮 H5：每轮测试使用独立 schema（test_run_<时间戳>），
	// 断言通过后自动删除；public 不再增长。
	rs := testdb.NewRunSchema(t)
	if rs == nil {
		return nil // 已 skip
	}
	return rs.Pool()
}

// fakeClock 可拨动的时钟（两个窗口的判定统一用注入时钟）。
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (f *fakeClock) now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.t
}

func (f *fakeClock) advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.t = f.t.Add(d)
}

// newApprovalsTestStore 建立测试存储；建表失败为真实错误（非 skip）。
// 每次建立前清空测试表：审批表是状态机存储（非只追加），
// 残留记录会让批量断言在不同运行间漂移。
func newApprovalsTestStore(t *testing.T, opts ...Option) *PostgresStore {
	t.Helper()
	pool := approvalsPoolForTests(t)
	if pool == nil {
		return nil // 已 skip
	}
	// 先清空残留再建表：第九轮遗留的 pending 行可能与第十轮的新唯一索引
	// （(actor, request_hash) 去重 / (actor, idem_key) 冲突判定）冲突，
	// 导致 EnsureSchema 建索引失败。表不存在时静默跳过（EnsureSchema 会建表）。
	if _, err := pool.Exec(context.Background(),
		`DO $$ BEGIN IF to_regclass('`+testApprovalsTable+`') IS NOT NULL THEN DELETE FROM `+testApprovalsTable+`; END IF; END $$;`); err != nil {
		t.Fatalf("清空测试表失败：%v", err)
	}
	s := NewTestPostgresStore(pool, testApprovalsTable, opts...)
	if err := s.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("审批建表失败（非 skip）：%v", err)
	}
	return s
}

// testLeaseDuration 测试用执行租约时长（第十二轮 H6：
// 租约 = 能力超时 + 2×续期间隔；此处取 300s 能力超时 + 40s）。
var testLeaseDuration = LeaseFor(300 * time.Second)

// requester / approver 两个不同账号（四眼原则在测试环境同样强制）。
const (
	requester = "ops-lead"
	approver  = "ops-auditor"
)

// newPending 创建一条 pending 记录。
// suffix 参与幂等键与哈希：同一测试内的多条记录必须使用不同 suffix
// （否则会被 R3 去重合并成同一条）。
func newPending(t *testing.T, s *PostgresStore, suffix string) Record {
	t.Helper()
	rec, err := s.Create(context.Background(), NewRecord{
		Actor:          requester,
		Capability:     "test.write.marker",
		RequestHash:    "hash-" + t.Name() + "/" + suffix,
		IdempotencyKey: "key-" + t.Name() + "/" + suffix,
		ExpiresAt:      time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("创建 pending 记录失败：%v", err)
	}
	if rec.Status != StatusPending {
		t.Fatalf("新记录应为 pending，got %s", rec.Status)
	}
	return rec
}

// TestCreateAndGet pending 创建与读取。
func TestCreateAndGet(t *testing.T) {
	s := newApprovalsTestStore(t)
	if s == nil {
		return
	}
	rec := newPending(t, s, "a")
	got, err := s.Get(context.Background(), rec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != rec.ID || got.Status != StatusPending || got.Actor != requester {
		t.Fatalf("读取结果不符：%+v", got)
	}
	if got.ApprovedAt != nil {
		t.Fatalf("pending 记录 ApprovedAt 应为空：%+v", got)
	}
}

// TestApproveReject 状态迁移：pending → approved / rejected，含字段回填与终态保护。
func TestApproveReject(t *testing.T) {
	s := newApprovalsTestStore(t)
	if s == nil {
		return
	}
	rec := newPending(t, s, "a")
	got, err := s.Approve(context.Background(), rec.ID, approver, "同意执行")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusApproved || got.DecidedBy != approver || got.Reason != "同意执行" {
		t.Fatalf("批准结果不符：%+v", got)
	}
	if got.ApprovedAt == nil || !got.ApprovedAt.After(rec.CreatedAt) {
		t.Fatalf("ApprovedAt 应记录批准时刻：%+v", got.ApprovedAt)
	}
	// 终态保护：approved 不能再被 Approve/Reject。
	if _, err := s.Approve(context.Background(), rec.ID, approver, ""); !errors.Is(err, ErrIllegalTransition) {
		t.Fatalf("approved 再审批应为非法迁移：%v", err)
	}

	rec2 := newPending(t, s, "b")
	got, err = s.Reject(context.Background(), rec2.ID, approver, "窗口外")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusRejected {
		t.Fatalf("拒绝结果不符：%+v", got)
	}
	if _, err := s.Approve(context.Background(), rec2.ID, approver, ""); !errors.Is(err, ErrIllegalTransition) {
		t.Fatalf("rejected 再审批应为非法迁移：%v", err)
	}
}

// TestApproveFourEyes 四眼原则（第九轮决策，无例外）：
// 审批人与请求人相同 → ErrApproverMustDiffer 且记录保持 pending。
func TestApproveFourEyes(t *testing.T) {
	s := newApprovalsTestStore(t)
	if s == nil {
		return
	}
	rec := newPending(t, s, "a")
	if _, err := s.Approve(context.Background(), rec.ID, requester, ""); !errors.Is(err, ErrApproverMustDiffer) {
		t.Fatalf("同人审批应拒绝（四眼）：%v", err)
	}
	if _, err := s.Approve(context.Background(), rec.ID, " ", ""); !errors.Is(err, ErrApproverMustDiffer) {
		t.Fatalf("空审批人应拒绝（四眼）：%v", err)
	}
	got, err := s.Get(context.Background(), rec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusPending {
		t.Fatalf("四眼拒绝后记录应保持 pending：%+v", got)
	}
	// 不同审批人可通过。
	if _, err := s.Approve(context.Background(), rec.ID, "ops-auditor-2", "ok"); err != nil {
		t.Fatalf("不同审批人应可通过：%v", err)
	}
}

// TestConsumeOnlyApprovedAndOnce 只有 approved 可消费，且消费一次后不可再次执行。
func TestConsumeOnlyApprovedAndOnce(t *testing.T) {
	s := newApprovalsTestStore(t)
	if s == nil {
		return
	}
	rec := newPending(t, s, "a")
	if _, err := s.Consume(context.Background(), rec.ID); !errors.Is(err, ErrNotExecuting) {
		t.Fatalf("未抢占的消费应报未处于 executing：%v", err)
	}
	if _, err := s.Approve(context.Background(), rec.ID, approver, "ok"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Consume(context.Background(), rec.ID); !errors.Is(err, ErrNotExecuting) {
		t.Fatalf("approved 但未抢占不得消费（第十轮：先占后执行）：%v", err)
	}
	// 先占后执行（F2）：抢占成功的执行方才能消费。
	claimed, err := s.Claim(context.Background(), rec.ID, testLeaseDuration)
	if err != nil {
		t.Fatal(err)
	}
	if claimed.Status != StatusExecuting {
		t.Fatalf("抢占后应为 executing：%+v", claimed)
	}
	got, err := s.Consume(context.Background(), rec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusConsumed || got.DecidedBy != "system" {
		t.Fatalf("消费结果不符：%+v", got)
	}
	if _, err := s.Consume(context.Background(), rec.ID); !errors.Is(err, ErrNotExecuting) {
		t.Fatalf("consumed 再消费应拒绝：%v", err)
	}
	if _, err := s.Approve(context.Background(), rec.ID, approver, ""); !errors.Is(err, ErrIllegalTransition) {
		t.Fatalf("consumed 再审批应为非法迁移：%v", err)
	}
}

// TestApprovedWindowVoid 批准后 30 分钟执行窗口（注入时钟）：
// 窗口内可消费；超窗则作废（置 expired）且不可消费。
func TestApprovedWindowVoid(t *testing.T) {
	clock := &fakeClock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	s := newApprovalsTestStore(t, WithClock(clock.now))
	if s == nil {
		return
	}

	rec := newPending(t, s, "a")
	if _, err := s.Approve(context.Background(), rec.ID, approver, "ok"); err != nil {
		t.Fatal(err)
	}

	// 窗口内（29 分钟）→ 可抢占并消费。
	clock.advance(29 * time.Minute)
	if _, err := s.Claim(context.Background(), rec.ID, testLeaseDuration); err != nil {
		t.Fatalf("窗口内应可抢占：%v", err)
	}
	got, err := s.Consume(context.Background(), rec.ID)
	if err != nil {
		t.Fatalf("窗口内应可消费：%v", err)
	}
	if got.Status != StatusConsumed {
		t.Fatalf("应为 consumed：%+v", got)
	}

	// 超窗（31 分钟）→ 作废。
	rec2 := newPending(t, s, "b")
	if _, err := s.Approve(context.Background(), rec2.ID, approver, "ok"); err != nil {
		t.Fatal(err)
	}
	clock.advance(31 * time.Minute) // rec2 批准后 31 分钟：超出执行窗口
	if _, err := s.Claim(context.Background(), rec2.ID, testLeaseDuration); !errors.Is(err, ErrApprovalVoided) {
		t.Fatalf("超窗抢占应报作废：%v", err)
	}
	if _, err := s.Consume(context.Background(), rec2.ID); !errors.Is(err, ErrNotExecuting) {
		t.Fatalf("超窗作废后不得消费：%v", err)
	}
	got, err = s.Get(context.Background(), rec2.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusExpired {
		t.Fatalf("超窗后记录应作废为 expired：%+v", got)
	}
	if _, err := s.Consume(context.Background(), rec2.ID); !errors.Is(err, ErrNotExecuting) {
		t.Fatalf("作废后再消费应拒绝：%v", err)
	}
}

// TestExpireApprovedBatch 批量作废只影响超窗的 approved。
func TestExpireApprovedBatch(t *testing.T) {
	clock := &fakeClock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	s := newApprovalsTestStore(t, WithClock(clock.now))
	if s == nil {
		return
	}
	early := newPending(t, s, "a")
	late := newPending(t, s, "b")
	if _, err := s.Approve(context.Background(), early.ID, approver, ""); err != nil {
		t.Fatal(err)
	}
	clock.advance(31 * time.Minute)
	if _, err := s.Approve(context.Background(), late.ID, approver, ""); err != nil {
		t.Fatal(err)
	}
	n, err := s.ExpireApproved(context.Background(), clock.now())
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("应只作废 1 条，got %d", n)
	}
	got, _ := s.Get(context.Background(), early.ID)
	if got.Status != StatusExpired {
		t.Fatalf("超窗审批应作废：%+v", got)
	}
	got, _ = s.Get(context.Background(), late.ID)
	if got.Status != StatusApproved {
		t.Fatalf("窗口内审批不得作废：%+v", got)
	}
}

// TestExpirePendingBatch 批量过期只影响到期 pending（迁移自第八轮）。
func TestExpirePendingBatch(t *testing.T) {
	s := newApprovalsTestStore(t)
	if s == nil {
		return
	}
	now := time.Now()
	fresh := newPending(t, s, "a")
	stale := newPending(t, s, "b")
	pool := s.pool
	if _, err := pool.Exec(context.Background(),
		`UPDATE test_approvals SET expires_at=$2 WHERE id=$1 AND status='pending'`,
		fresh.ID, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(),
		`UPDATE test_approvals SET expires_at=$2 WHERE id=$1 AND status='pending'`,
		stale.ID, now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	n, err := s.ExpirePending(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("应只过期 1 条，got %d", n)
	}
	got, _ := s.Get(context.Background(), stale.ID)
	if got.Status != StatusExpired {
		t.Fatalf("到期记录应 expired：%+v", got)
	}
	got, _ = s.Get(context.Background(), fresh.ID)
	if got.Status != StatusPending {
		t.Fatalf("未到期记录不应过期：%+v", got)
	}
}

// TestCreateDedupSameKey 审批去重（R3）：同 (actor, 幂等键) 同内容
// 在 pending 期间重复提交 → 返回已有审批 ID，不新建。
func TestCreateDedupSameKey(t *testing.T) {
	s := newApprovalsTestStore(t)
	if s == nil {
		return
	}
	n := NewRecord{
		Actor: requester, Capability: "test.write.marker",
		RequestHash: "hash-dedup", IdempotencyKey: "key-dedup",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	first, err := s.Create(context.Background(), n)
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.Create(context.Background(), n)
	if err != nil {
		t.Fatal(err)
	}
	if second.ID != first.ID {
		t.Fatalf("同键同内容应返回已有审批 ID：first=%s second=%s", first.ID, second.ID)
	}
	// 表里只有一条 pending。
	var cnt int
	if err := s.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM test_approvals WHERE status='pending' AND idem_key=$1`,
		n.IdempotencyKey).Scan(&cnt); err != nil {
		t.Fatal(err)
	}
	if cnt != 1 {
		t.Fatalf("pending 去重失效：count=%d", cnt)
	}
}

// TestCreateDedupConflict 同键不同内容 → ErrContentConflict（422 语义）。
func TestCreateDedupConflict(t *testing.T) {
	s := newApprovalsTestStore(t)
	if s == nil {
		return
	}
	if _, err := s.Create(context.Background(), NewRecord{
		Actor: requester, Capability: "test.write.marker",
		RequestHash: "hash-a", IdempotencyKey: "key-conflict",
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	_, err := s.Create(context.Background(), NewRecord{
		Actor: requester, Capability: "test.write.marker",
		RequestHash: "hash-b", IdempotencyKey: "key-conflict",
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if !errors.Is(err, ErrContentConflict) {
		t.Fatalf("同键不同内容应报冲突（422）：%v", err)
	}
}

// TestCreateDedupConcurrent 并发去重（R3）：多个并发同键提交恰好创建一条，
// 且全部拿到同一审批 ID。
func TestCreateDedupConcurrent(t *testing.T) {
	s := newApprovalsTestStore(t)
	if s == nil {
		return
	}
	const n = 10
	nr := NewRecord{
		Actor: requester, Capability: "test.write.marker",
		RequestHash: "hash-concurrent", IdempotencyKey: "key-concurrent-" + t.Name(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		ids  []string
		errs []error
	)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec, err := s.Create(context.Background(), nr)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				ids = append(ids, rec.ID)
			} else {
				errs = append(errs, err)
			}
		}()
	}
	wg.Wait()
	if len(errs) != 0 {
		t.Fatalf("并发去重不应返回错误：%v", errs)
	}
	unique := map[string]bool{}
	for _, id := range ids {
		unique[id] = true
	}
	if len(unique) != 1 {
		t.Fatalf("并发同键提交应全部拿到同一审批 ID：unique=%d", len(unique))
	}
}

// TestCreateDedupFreedAfterConsume 消费后同键可重新提交（部分唯一索引只约束 pending）。
func TestCreateDedupFreedAfterConsume(t *testing.T) {
	s := newApprovalsTestStore(t)
	if s == nil {
		return
	}
	nr := NewRecord{
		Actor: requester, Capability: "test.write.marker",
		RequestHash: "hash-reuse", IdempotencyKey: "key-reuse-" + t.Name(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	first, err := s.Create(context.Background(), nr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Approve(context.Background(), first.ID, approver, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Claim(context.Background(), first.ID, testLeaseDuration); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Consume(context.Background(), first.ID); err != nil {
		t.Fatal(err)
	}
	second, err := s.Create(context.Background(), nr)
	if err != nil {
		t.Fatal(err)
	}
	if second.ID == first.ID || second.Status != StatusPending {
		t.Fatalf("消费后同键应可重新提交：%+v", second)
	}
}

// TestTransitionNotFound 不存在的记录返回 ErrNotFound。
func TestTransitionNotFound(t *testing.T) {
	s := newApprovalsTestStore(t)
	if s == nil {
		return
	}
	if _, err := s.Approve(context.Background(), "apr-does-not-exist", approver, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("应为 ErrNotFound：%v", err)
	}
	if _, err := s.Consume(context.Background(), "apr-does-not-exist"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("应为 ErrNotFound：%v", err)
	}
}

// TestTestGuardRejectsNonTestTable 测试守卫：非 test_ 前缀表名拒绝建表与写入。
func TestTestGuardRejectsNonTestTable(t *testing.T) {
	pool := approvalsPoolForTests(t)
	if pool == nil {
		return
	}
	bad := NewTestPostgresStore(pool, "approvals")
	if err := bad.EnsureSchema(context.Background()); err == nil {
		t.Fatal("非 test_ 表名应被测试守卫拒绝")
	}
	if _, err := bad.Create(context.Background(), NewRecord{
		Actor: "a", Capability: "b", RequestHash: "h", IdempotencyKey: "k",
		ExpiresAt: time.Now(),
	}); err == nil {
		t.Fatal("非 test_ 表名写入应被测试守卫拒绝")
	}
}

// TestCanTransition 状态迁移表（第十轮：pending 三方向 + approved 两方向
// + executing 两方向）。
func TestCanTransition(t *testing.T) {
	if !CanTransition(StatusPending, StatusApproved) ||
		!CanTransition(StatusPending, StatusRejected) ||
		!CanTransition(StatusPending, StatusExpired) ||
		!CanTransition(StatusApproved, StatusExecuting) ||
		!CanTransition(StatusApproved, StatusExpired) ||
		!CanTransition(StatusExecuting, StatusConsumed) ||
		!CanTransition(StatusExecuting, StatusAbandoned) {
		t.Fatal("合法迁移必须全部放行")
	}
	illegal := [][2]Status{
		{StatusApproved, StatusPending}, {StatusRejected, StatusApproved},
		{StatusExpired, StatusApproved}, {StatusConsumed, StatusApproved},
		{StatusApproved, StatusApproved}, {StatusPending, StatusPending},
		{StatusRejected, StatusConsumed}, {StatusExpired, StatusConsumed},
		// 第十轮：未抢占不得消费/放弃；终态不得回退或再抢占。
		{StatusPending, StatusExecuting}, {StatusApproved, StatusConsumed},
		{StatusApproved, StatusAbandoned}, {StatusExecuting, StatusApproved},
		{StatusExecuting, StatusExecuting}, {StatusConsumed, StatusExecuting},
		{StatusAbandoned, StatusExecuting}, {StatusAbandoned, StatusApproved},
		{StatusConsumed, StatusAbandoned}, {StatusAbandoned, StatusConsumed},
	}
	for _, p := range illegal {
		if CanTransition(p[0], p[1]) {
			t.Fatalf("非法迁移 %s → %s 必须禁止", p[0], p[1])
		}
	}
}

// —— 用例（第十轮：F2 先占后执行 / F3 pending 去重粒度） ——

// TestCreateDedupByContentDifferentKey pending 去重粒度（F3）：同一请求内容
// （同一 request_hash）换幂等键重复提交 → 返回已有 pending 审批 ID，不新建。
func TestCreateDedupByContentDifferentKey(t *testing.T) {
	s := newApprovalsTestStore(t)
	if s == nil {
		return
	}
	base := NewRecord{
		Actor: requester, Capability: "test.write.marker",
		RequestHash:    "hash-same-content-" + t.Name(),
		IdempotencyKey: "key-content-a-" + t.Name(),
		ExpiresAt:      time.Now().Add(time.Hour),
	}
	first, err := s.Create(context.Background(), base)
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.Create(context.Background(), NewRecord{
		Actor: base.Actor, Capability: base.Capability,
		RequestHash:    base.RequestHash,
		IdempotencyKey: "key-content-b-" + t.Name(), // 同内容、不同键
		ExpiresAt:      base.ExpiresAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	if second.ID != first.ID {
		t.Fatalf("同内容不同键应返回已有审批 ID：first=%s second=%s", first.ID, second.ID)
	}
	var cnt int
	if err := s.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM test_approvals WHERE status='pending' AND request_hash=$1`,
		base.RequestHash).Scan(&cnt); err != nil {
		t.Fatal(err)
	}
	if cnt != 1 {
		t.Fatalf("同内容只应保留一条 pending：count=%d", cnt)
	}
}

// TestClaimConcurrentOnce 先占后执行（F2，真实数据库）：并发抢占同一审批
// 恰好只有一个成功，其余返回 ErrNotClaimable。
func TestClaimConcurrentOnce(t *testing.T) {
	s := newApprovalsTestStore(t)
	if s == nil {
		return
	}
	rec := newPending(t, s, "a")
	if _, err := s.Approve(context.Background(), rec.ID, approver, "ok"); err != nil {
		t.Fatal(err)
	}

	const n = 10
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		ok       int
		notClaim int
		errList  []error
	)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.Claim(context.Background(), rec.ID, testLeaseDuration)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				ok++
			case errors.Is(err, ErrNotClaimable):
				notClaim++
			default:
				errList = append(errList, err)
			}
		}()
	}
	wg.Wait()
	if len(errList) != 0 {
		t.Fatalf("并发抢占不应返回其他错误：%v", errList)
	}
	if ok != 1 {
		t.Fatalf("并发抢占应恰好成功 1 个：ok=%d", ok)
	}
	if notClaim != n-1 {
		t.Fatalf("其余并发抢占应全部返回 ErrNotClaimable：got %d", notClaim)
	}
	got, err := s.Get(context.Background(), rec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusExecuting {
		t.Fatalf("抢占后应为 executing：%+v", got)
	}
	// 抢占后不可再次抢占（consumed 窗口已消除）。
	if _, err := s.Claim(context.Background(), rec.ID, testLeaseDuration); !errors.Is(err, ErrNotClaimable) {
		t.Fatalf("executing 再抢占应拒绝：%v", err)
	}
}

// TestClaimThenConsumeOnce 抢占 → 消费（executing → consumed）→ 不可再次抢占/消费。
func TestClaimThenConsumeOnce(t *testing.T) {
	s := newApprovalsTestStore(t)
	if s == nil {
		return
	}
	rec := newPending(t, s, "a")
	if _, err := s.Approve(context.Background(), rec.ID, approver, "ok"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Claim(context.Background(), rec.ID, testLeaseDuration); err != nil {
		t.Fatal(err)
	}
	consumed, err := s.Consume(context.Background(), rec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if consumed.Status != StatusConsumed || consumed.DecidedBy != "system" {
		t.Fatalf("消费结果不符：%+v", consumed)
	}
	if _, err := s.Claim(context.Background(), rec.ID, testLeaseDuration); !errors.Is(err, ErrNotClaimable) {
		t.Fatalf("consumed 不得再抢占：%v", err)
	}
	if _, err := s.Consume(context.Background(), rec.ID); !errors.Is(err, ErrNotExecuting) {
		t.Fatalf("consumed 不得再消费：%v", err)
	}
	// 消费后同键可重新提交（部分唯一索引只约束 pending）。
	again, err := s.Create(context.Background(), NewRecord{
		Actor: requester, Capability: rec.Capability,
		RequestHash:    rec.RequestHash,
		IdempotencyKey: rec.IdempotencyKey,
		ExpiresAt:      time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if again.ID == rec.ID || again.Status != StatusPending {
		t.Fatalf("消费后同键应可重新提交：%+v", again)
	}
}

// TestMarkAbandonedAndListExecuting 抢占后无终态 → 对账标记 abandoned：
// ListExecuting 可见 → MarkAbandoned 后不可见且幂等；abandoned 不可再抢占/消费。
func TestMarkAbandonedAndListExecuting(t *testing.T) {
	s := newApprovalsTestStore(t)
	if s == nil {
		return
	}
	// 前置：无 executing 记录。
	if recs, err := s.ListExecuting(context.Background()); err != nil {
		t.Fatal(err)
	} else if len(recs) != 0 {
		t.Fatalf("初始不应有 executing 记录：%d", len(recs))
	}

	rec := newPending(t, s, "a")
	if _, err := s.Approve(context.Background(), rec.ID, approver, "ok"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Claim(context.Background(), rec.ID, testLeaseDuration); err != nil {
		t.Fatal(err)
	}
	recs, err := s.ListExecuting(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].ID != rec.ID {
		t.Fatalf("对账应列出 1 条 executing：%+v", recs)
	}

	marked, err := s.MarkAbandoned(context.Background(), rec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if marked.Status != StatusAbandoned || marked.DecidedBy != "system" {
		t.Fatalf("放弃结果不符：%+v", marked)
	}
	// 幂等：重复标记不报错。
	if _, err := s.MarkAbandoned(context.Background(), rec.ID); err != nil {
		t.Fatalf("重复 MarkAbandoned 应幂等：%v", err)
	}
	if recs, err := s.ListExecuting(context.Background()); err != nil {
		t.Fatal(err)
	} else if len(recs) != 0 {
		t.Fatalf("标记后不应再有 executing：%d", len(recs))
	}
	// abandoned 是终态：不可再抢占、不可消费（不重放）。
	if _, err := s.Claim(context.Background(), rec.ID, testLeaseDuration); !errors.Is(err, ErrNotClaimable) {
		t.Fatalf("abandoned 不得再抢占：%v", err)
	}
	if _, err := s.Consume(context.Background(), rec.ID); !errors.Is(err, ErrNotExecuting) {
		t.Fatalf("abandoned 不得消费：%v", err)
	}
	// 非 executing 状态标记放弃 → ErrNotExecuting。
	other := newPending(t, s, "b")
	if _, err := s.MarkAbandoned(context.Background(), other.ID); !errors.Is(err, ErrNotExecuting) {
		t.Fatalf("pending 标记放弃应拒绝：%v", err)
	}
}

// TestClaimVoidedByWindow 抢占超窗：approved 超过 30 分钟执行窗口 → 作废（expired）
// 并返回 ErrApprovalVoided，不进入 executing。
func TestClaimVoidedByWindow(t *testing.T) {
	clock := &fakeClock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	s := newApprovalsTestStore(t, WithClock(clock.now))
	if s == nil {
		return
	}
	rec := newPending(t, s, "a")
	if _, err := s.Approve(context.Background(), rec.ID, approver, "ok"); err != nil {
		t.Fatal(err)
	}
	clock.advance(31 * time.Minute)
	if _, err := s.Claim(context.Background(), rec.ID, testLeaseDuration); !errors.Is(err, ErrApprovalVoided) {
		t.Fatalf("超窗抢占应报作废：%v", err)
	}
	got, err := s.Get(context.Background(), rec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusExpired {
		t.Fatalf("超窗审批应作废为 expired：%+v", got)
	}
}

// —— 用例（第十一轮 H1：执行租约） ——

// TestClaimWritesLease 抢占写入执行租约（H6）：lease_until = now + 传入租约
// （租约由能力超时经 LeaseFor 推导）。
func TestClaimWritesLease(t *testing.T) {
	clock := &fakeClock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	s := newApprovalsTestStore(t, WithClock(clock.now))
	if s == nil {
		return
	}
	rec := newPending(t, s, "a")
	if _, err := s.Approve(context.Background(), rec.ID, approver, "ok"); err != nil {
		t.Fatal(err)
	}
	claimed, err := s.Claim(context.Background(), rec.ID, testLeaseDuration)
	if err != nil {
		t.Fatal(err)
	}
	if claimed.LeaseUntil == nil {
		t.Fatal("抢占应写入执行租约 lease_until")
	}
	want := clock.now().Add(testLeaseDuration)
	if !claimed.LeaseUntil.Equal(want) {
		t.Fatalf("租约应到期于 %v，实际 %v", want, *claimed.LeaseUntil)
	}
}

// TestRenewExtendsLease 续期延长租约（H1）；租约过期后续期返回
// ErrExecutionLeaseExpired（调用方必须中止执行）。
func TestRenewExtendsLease(t *testing.T) {
	clock := &fakeClock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	s := newApprovalsTestStore(t, WithClock(clock.now))
	if s == nil {
		return
	}
	rec := newPending(t, s, "a")
	if _, err := s.Approve(context.Background(), rec.ID, approver, "ok"); err != nil {
		t.Fatal(err)
	}
	claimed, err := s.Claim(context.Background(), rec.ID, testLeaseDuration)
	if err != nil {
		t.Fatal(err)
	}
	firstLease := *claimed.LeaseUntil

	// 续期：租约应整体后移一个租约时长。
	clock.advance(30 * time.Second)
	renewed, err := s.Renew(context.Background(), rec.ID, testLeaseDuration)
	if err != nil {
		t.Fatalf("租约未过期应可续期：%v", err)
	}
	if !renewed.LeaseUntil.After(firstLease) {
		t.Fatalf("续期应延长租约：%v → %v", firstLease, *renewed.LeaseUntil)
	}
	if !renewed.LeaseUntil.Equal(clock.now().Add(testLeaseDuration)) {
		t.Fatalf("续期后租约应为 now+lease：%v", *renewed.LeaseUntil)
	}

	// 超过租约后续期 → ErrExecutionLeaseExpired，且状态不变（等待对账）。
	clock.advance(testLeaseDuration)
	if _, err := s.Renew(context.Background(), rec.ID, testLeaseDuration); !errors.Is(err, ErrExecutionLeaseExpired) {
		t.Fatalf("租约过后续期应返回 ErrExecutionLeaseExpired：%v", err)
	}
	got, err := s.Get(context.Background(), rec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusExecuting {
		t.Fatalf("续期失败不应改变状态：%+v", got)
	}
}

// TestListExpiredExecutingFiltersLiveLease 对账只列出租约过期的 executing
// （H1）：未过期的一律不出现在结果里。
func TestListExpiredExecutingFiltersLiveLease(t *testing.T) {
	clock := &fakeClock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	s := newApprovalsTestStore(t, WithClock(clock.now))
	if s == nil {
		return
	}
	live := newPending(t, s, "live")
	dead := newPending(t, s, "dead")
	if _, err := s.Approve(context.Background(), live.ID, approver, "ok"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Approve(context.Background(), dead.ID, approver, "ok"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Claim(context.Background(), live.ID, testLeaseDuration); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Claim(context.Background(), dead.ID, testLeaseDuration); err != nil {
		t.Fatal(err)
	}
	// 租约内：两条均未过期 → 对账列表为空。
	clock.advance(30 * time.Second)
	recs, err := s.ListExpiredExecuting(context.Background(), clock.now())
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 0 {
		t.Fatalf("租约未过期时对账不得列出发执行：%+v", recs)
	}
	// 超过租约：两条均已过期 → 对账列表包含两者。
	clock.advance(testLeaseDuration)
	recs, err = s.ListExpiredExecuting(context.Background(), clock.now())
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("两条执行均应过期：%+v", recs)
	}
}

// TestMarkAbandonedClearsLease 放弃执行时清空租约（H1）：abandoned 记录不再
// 被对账重复列出。
func TestMarkAbandonedClearsLease(t *testing.T) {
	clock := &fakeClock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	s := newApprovalsTestStore(t, WithClock(clock.now))
	if s == nil {
		return
	}
	rec := newPending(t, s, "a")
	if _, err := s.Approve(context.Background(), rec.ID, approver, "ok"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Claim(context.Background(), rec.ID, testLeaseDuration); err != nil {
		t.Fatal(err)
	}
	clock.advance(testLeaseDuration + time.Minute)
	if _, err := s.MarkAbandoned(context.Background(), rec.ID); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(context.Background(), rec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusAbandoned || got.LeaseUntil != nil {
		t.Fatalf("abandoned 应清空租约：%+v", got)
	}
	if recs, err := s.ListExpiredExecuting(context.Background(), clock.now()); err != nil {
		t.Fatal(err)
	} else if len(recs) != 0 {
		t.Fatalf("abandoned 后不应再被对账列出：%+v", recs)
	}
}
