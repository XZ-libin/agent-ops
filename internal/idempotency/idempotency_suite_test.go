package idempotency

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/XZ-libin/agent-ops/internal/audit"
	"github.com/XZ-libin/agent-ops/internal/testdb"
)

// fakeRecorder 捕获审计事件的测试替身（实现 audit.Recorder）。
type fakeRecorder struct {
	mu        sync.Mutex
	abandoned []audit.IdempotencyAbandoned
	decisions []audit.PolicyDecision
}

func newFakeRecorder() *fakeRecorder { return &fakeRecorder{} }

func (r *fakeRecorder) RecordPolicyDecision(_ context.Context, d audit.PolicyDecision) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.decisions = append(r.decisions, d)
	return nil
}

func (r *fakeRecorder) RecordIdempotencyAbandoned(_ context.Context, d audit.IdempotencyAbandoned) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.abandoned = append(r.abandoned, d)
	return nil
}

func (r *fakeRecorder) lastAbandoned() (audit.IdempotencyAbandoned, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.abandoned) == 0 {
		return audit.IdempotencyAbandoned{}, 0
	}
	return r.abandoned[len(r.abandoned)-1], len(r.abandoned)
}

// testDSNEnv 测试数据库连接串环境变量；未设置时使用 DefaultLocalDSN（本地占位）。
// testDSNEnv 测试数据库连接串环境变量；未设置时使用 testdb 默认值（agent_ops_test）。
const testDSNEnv = testdb.EnvDSN

// runToken 本次测试运行的唯一前缀：PostgresStore 的记录跨进程残留，
// 用它保证每个子用例的 key 在两次运行之间互不冲突（内存实现不受影响）。
var runToken = fmt.Sprintf("run-%d", time.Now().UnixNano())

// fakeClockT 可手动拨动的时钟（过期/租约判定统一用注入时钟，两 Store 一致）。
type fakeClockT struct{ t time.Time }

func (f *fakeClockT) now() time.Time { return f.t }
func (f *fakeClockT) set(t time.Time) {
	f.t = t
}
func (f *fakeClockT) advance(d time.Duration) {
	f.t = f.t.Add(d)
}

// testScopeKey 每个子用例独立 key（子测试名 + 运行前缀），避免用例间及运行间相互影响。
func testScopeKey(t *testing.T) Scope {
	return Scope{Actor: "ops-lead", API: "POST /change-plans", Key: runToken + "/" + t.Name()}
}

// storeImpl 一种存储实现与其构造器；PostgreSQL 不可用时整组 skip。
type storeImpl struct {
	name     string
	newStore func(t *testing.T, opts ...Option) Store
	skip     string // 非空时整组 skip（PostgreSQL 不可用）
}

// TestStoreSuite 对 MemoryStore 与 PostgresStore 运行同一组用例，
// 两者的行为必须一致。
func TestStoreSuite(t *testing.T) {
	impls := []storeImpl{
		{
			name: "memory",
			newStore: func(t *testing.T, opts ...Option) Store {
				t.Helper()
				return NewMemoryStore(opts...)
			},
		},
	}

	pgPool, skipMsg := postgresPoolForTests(t)
	if pgPool != nil {
		t.Cleanup(pgPool.Close)
		// 第十四轮 H5：每轮 schema 是全新的，必须显式建表
		// （此前依赖 public 中历史遗留的表，属于测试隔离缺陷）。
		if err := NewPostgresStore(pgPool).EnsureSchema(context.Background()); err != nil {
			t.Fatalf("幂等建表失败（非 skip）：%v", err)
		}
		impls = append(impls, storeImpl{
			name: "postgres",
			newStore: func(t *testing.T, opts ...Option) Store {
				t.Helper()
				return NewPostgresStore(pgPool, opts...)
			},
		})
	} else {
		impls = append(impls, storeImpl{name: "postgres", skip: skipMsg})
	}

	for _, impl := range impls {
		t.Run(impl.name, func(t *testing.T) {
			if impl.skip != "" {
				t.Skip(impl.skip)
			}
			runStoreCases(t, impl.newStore)
		})
	}
}

func runStoreCases(t *testing.T, newStore func(t *testing.T, opts ...Option) Store) {
	t.Run("FreshCreate", func(t *testing.T) {
		store := newStore(t)
		got, err := store.Begin(context.Background(), testScopeKey(t), []byte(`{"a":1}`))
		if err != nil {
			t.Fatal(err)
		}
		if !got.Fresh {
			t.Fatal("首次请求应为 Fresh=true")
		}
		if got.Entry.Status != StatusProcessing {
			t.Fatalf("状态应为 processing，got %v", got.Entry.Status)
		}
	})

	t.Run("SameContentReturnsStoredResponse", func(t *testing.T) {
		store := newStore(t)
		scope := testScopeKey(t)
		request := []byte(`{"replicas":6}`)

		if _, err := store.Begin(context.Background(), scope, request); err != nil {
			t.Fatal(err)
		}
		want := map[string]any{"id": "cp-1", "status": "succeeded"}
		if err := store.Complete(context.Background(), scope, want); err != nil {
			t.Fatal(err)
		}

		got, err := store.Begin(context.Background(), scope, request)
		if err != nil {
			t.Fatal(err)
		}
		if got.Fresh {
			t.Fatal("同键同内容已完成，应返回已存记录而非重新执行（Fresh 应为 false）")
		}
		if !reflect.DeepEqual(got.Entry.Response, want) {
			t.Fatalf("应返回已存响应 %v，got %v", want, got.Entry.Response)
		}
	})

	t.Run("DifferentContentConflict422", func(t *testing.T) {
		store := newStore(t)
		scope := testScopeKey(t)

		if _, err := store.Begin(context.Background(), scope, []byte(`{"x":1}`)); err != nil {
			t.Fatal(err)
		}
		_, err := store.Begin(context.Background(), scope, []byte(`{"x":2}`))
		if !errors.Is(err, ErrContentConflict) {
			t.Fatalf("同键不同内容应返回 ErrContentConflict(422)，got %v", err)
		}
	})

	t.Run("InProgress409", func(t *testing.T) {
		store := newStore(t)
		scope := testScopeKey(t)
		request := []byte(`{"x":1}`)

		if _, err := store.Begin(context.Background(), scope, request); err != nil {
			t.Fatal(err)
		}
		_, err := store.Begin(context.Background(), scope, request)
		if !errors.Is(err, ErrInProgress) {
			t.Fatalf("同键处理中应返回 ErrInProgress(409)，got %v", err)
		}
	})

	t.Run("ConcurrentTwoSingleExecution", func(t *testing.T) {
		store := newStore(t)
		scope := testScopeKey(t)
		request := []byte(`{"restart":"pod"}`)

		const n = 2
		start := make(chan struct{})
		var (
			mu       sync.Mutex
			exec     int32 // 最终执行次数（直接计数）
			progress int32 // ErrInProgress(409) 次数
			wg       sync.WaitGroup
		)
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				got, err := store.Begin(context.Background(), scope, request)
				mu.Lock()
				defer mu.Unlock()
				switch {
				case err == nil && got.Fresh:
					exec++
				case errors.Is(err, ErrInProgress):
					progress++
				}
			}()
		}
		close(start)
		wg.Wait()

		if exec != 1 || progress != 1 {
			t.Fatalf("同键并发应恰好执行一次：exec=%d inProgress=%d", exec, progress)
		}

		if err := store.Complete(context.Background(), scope, "done"); err != nil {
			t.Fatal(err)
		}
		got, err := store.Begin(context.Background(), scope, request)
		if err != nil || got.Fresh {
			t.Fatalf("完成后应返回已存响应：fresh=%v err=%v", got.Fresh, err)
		}
		if got.Entry.Response != "done" {
			t.Fatalf("已存响应应为 done，got %v", got.Entry.Response)
		}
	})

	t.Run("ConcurrentTenSingleExecution", func(t *testing.T) {
		store := newStore(t)
		scope := testScopeKey(t)
		request := []byte(`{"scale":"out"}`)

		const n = 10
		start := make(chan struct{})
		var (
			mu       sync.Mutex
			exec     int32
			progress int32
			wg       sync.WaitGroup
		)
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				got, err := store.Begin(context.Background(), scope, request)
				mu.Lock()
				defer mu.Unlock()
				switch {
				case err == nil && got.Fresh:
					exec++
				case errors.Is(err, ErrInProgress):
					progress++
				}
			}()
		}
		close(start)
		wg.Wait()

		if exec != 1 {
			t.Fatalf("10 个并发请求应恰好执行 1 次，实际 exec=%d", exec)
		}
		if progress != 9 {
			t.Fatalf("其余 9 个应为处理中(409)，实际 inProgress=%d", progress)
		}

		if err := store.Complete(context.Background(), scope, "executed"); err != nil {
			t.Fatal(err)
		}
		got, err := store.Begin(context.Background(), scope, request)
		if err != nil || got.Fresh {
			t.Fatalf("完成后应返回已存响应：fresh=%v err=%v", got.Fresh, err)
		}
		if got.Entry.Response != "executed" {
			t.Fatalf("已存响应应为 executed，got %v", got.Entry.Response)
		}
	})

	// ExpiredTTLSeenAsNew 与 CompleteAfterExpiryMissing 用极短 TTL + 真实时钟，
	// 对两种实现同样生效（PostgresStore 用 DB now() 判定过期）。
	t.Run("ExpiredTTLSeenAsNew", func(t *testing.T) {
		store := newStore(t, WithTTL(80*time.Millisecond))
		scope := testScopeKey(t)
		request := []byte(`{"x":1}`)

		if _, err := store.Begin(context.Background(), scope, request); err != nil {
			t.Fatal(err)
		}
		time.Sleep(200 * time.Millisecond)

		got, err := store.Begin(context.Background(), scope, request)
		if err != nil {
			t.Fatal(err)
		}
		if !got.Fresh {
			t.Fatal("过期记录应视为不存在，重新执行（Fresh=true）")
		}
	})

	t.Run("CompleteAfterExpiryMissing", func(t *testing.T) {
		store := newStore(t, WithTTL(80*time.Millisecond))
		scope := testScopeKey(t)

		if _, err := store.Begin(context.Background(), scope, []byte(`{"x":1}`)); err != nil {
			t.Fatal(err)
		}
		time.Sleep(200 * time.Millisecond)

		if err := store.Complete(context.Background(), scope, "resp"); !errors.Is(err, ErrRecordMissing) {
			t.Fatalf("过期后 Complete 应返回 ErrRecordMissing，got %v", err)
		}
	})

	t.Run("ScopeIsolation", func(t *testing.T) {
		store := newStore(t)
		request := []byte(`{"x":1}`)
		api := "POST /change-plans"

		a := Scope{Actor: "alice", API: api, Key: runToken + "/iso-alice"}
		b := Scope{Actor: "bob", API: api, Key: runToken + "/iso-bob"}

		ra, err := store.Begin(context.Background(), a, request)
		if err != nil || !ra.Fresh {
			t.Fatalf("alice 首次应 Fresh，got fresh=%v err=%v", ra.Fresh, err)
		}
		rb, err := store.Begin(context.Background(), b, request)
		if err != nil || !rb.Fresh {
			t.Fatalf("bob 的 key 应与 alice 隔离：got fresh=%v err=%v", rb.Fresh, err)
		}
	})

	// LeaseAbandoned 处理中超时语义：超时后状态转为 abandoned，
	// 同 key 返回 409（ErrAbandoned）且绝不允许重新执行；同时产生一条
	// idempotency.abandoned 审计事件（载荷含 key/操作人/接口与 destructive 标注）。
	t.Run("LeaseAbandoned", func(t *testing.T) {
		const (
			lease = time.Minute
			ttl   = time.Hour
		)
		fc := &fakeClockT{t: time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)}
		rec := newFakeRecorder()
		store := newStore(t, WithClock(fc.now), WithLease(lease), WithTTL(ttl), WithAuditRecorder(rec))
		scope := testScopeKey(t)
		scope.Destructive = true // 该操作的能力被标注 destructive（若可知）
		request := []byte(`{"op":"long-running"}`)

		got, err := store.Begin(context.Background(), scope, request)
		if err != nil || !got.Fresh {
			t.Fatalf("首次应 Fresh，got fresh=%v err=%v", got.Fresh, err)
		}

		fc.advance(lease + time.Nanosecond) // 超过 lease_until，未超过 TTL

		// 处理中超时：第一次同 key 请求触发 abandoned 转换，返回 409。
		_, err = store.Begin(context.Background(), scope, request)
		if !errors.Is(err, ErrAbandoned) {
			t.Fatalf("处理超时应返回 ErrAbandoned(409)，got %v", err)
		}
		if !strings.Contains(err.Error(), "请使用新的 key 重试") {
			t.Fatalf("abandoned 响应应说明请使用新的 key 重试，got %v", err)
		}

		// 已 abandoned 的同 key 再次请求：仍为 409，绝不重新执行。
		_, err = store.Begin(context.Background(), scope, request)
		if !errors.Is(err, ErrAbandoned) {
			t.Fatalf("abandoned 后同 key 必须仍返回 ErrAbandoned（不重新执行），got %v", err)
		}

		// 审计事件：恰好一条 idempotency.abandoned（只在转换时刻记录一次）。
		last, n := rec.lastAbandoned()
		if n != 1 {
			t.Fatalf("应恰好记录 1 条 idempotency.abandoned，got %d", n)
		}
		if last.Key != scope.Key || last.Actor != scope.Actor || last.API != scope.API {
			t.Fatalf("abandoned 事件载荷不符：%+v", last)
		}
		if !last.Destructive {
			t.Fatal("abandoned 事件应携带 Destructive=true")
		}
	})

	// ExpiryBoundary 过期三边界（恰在 expires_at、早 1ns、晚 1ns）：
	t.Run("ExpiryBoundary", func(t *testing.T) {
		const ttl = time.Hour
		fc := &fakeClockT{t: time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)}
		store := newStore(t, WithClock(fc.now), WithTTL(ttl))
		scope := testScopeKey(t)
		request := []byte(`{"b":1}`)

		first, err := store.Begin(context.Background(), scope, request)
		if err != nil || !first.Fresh {
			t.Fatalf("首次应 Fresh，got fresh=%v err=%v", first.Fresh, err)
		}
		if err := store.Complete(context.Background(), scope, "v1"); err != nil {
			t.Fatal(err)
		}

		// 早 1ns：未过期，返回已存响应。
		fc.set(first.Entry.CreatedAt.Add(ttl).Add(-time.Nanosecond))
		early, err := store.Begin(context.Background(), scope, request)
		if err != nil {
			t.Fatal(err)
		}
		if early.Fresh {
			t.Fatal("早 1ns 不应判定过期（应为已存记录）")
		}
		if early.Entry.Response != "v1" {
			t.Fatalf("早 1ns 应返回已存响应 v1，got %v", early.Entry.Response)
		}

		// 恰在 expires_at：按统一语义（now >= expires_at）视为过期 → Fresh。
		fc.set(first.Entry.CreatedAt.Add(ttl))
		atBoundary, err := store.Begin(context.Background(), scope, request)
		if err != nil {
			t.Fatal(err)
		}
		if !atBoundary.Fresh {
			t.Fatal("恰在 expires_at 应判定过期（fresh=true）")
		}

		// 晚 1ns：过期 → Fresh。
		fc.set(atBoundary.Entry.CreatedAt.Add(ttl).Add(time.Nanosecond))
		late, err := store.Begin(context.Background(), scope, request)
		if err != nil {
			t.Fatal(err)
		}
		if !late.Fresh {
			t.Fatal("晚 1ns 应判定过期（fresh=true）")
		}
	})

	// CleanupExpired 清理入口（调度频率 CleanupIntervalDefault=每小时一次，工程默认值）：
	// 只清理已过期的幂等行；未过期记录保留。审计记录不在该方法范围。
	t.Run("CleanupExpired", func(t *testing.T) {
		const ttl = time.Hour
		// 独立远期时间域：PostgresStore 共用一张表，本用例的清理时刻
		// 不得波及同组其他子用例的记录（它们共享 2026 年基准时钟）。
		fc := &fakeClockT{t: time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)}
		store := newStore(t, WithClock(fc.now), WithTTL(ttl))

		// CleanupExpired 是具体实现上的入口（不加入 Store 接口，保持其签名不变），
		// 用局部接口断言获取。
		cleaner, ok := store.(interface {
			CleanupExpired(context.Context) (int64, error)
		})
		if !ok {
			t.Fatalf("存储实现 %T 未提供 CleanupExpired", store)
		}
		// 先清空历史残留的过期行：此后精确数量断言才成立。
		if _, err := cleaner.CleanupExpired(context.Background()); err != nil {
			t.Fatal(err)
		}

		expiredScope := testScopeKey(t)
		if _, err := store.Begin(context.Background(), expiredScope, []byte(`{"a":1}`)); err != nil {
			t.Fatal(err)
		}
		fc.advance(2 * ttl) // 第一条过期

		aliveScope := Scope{Actor: expiredScope.Actor, API: expiredScope.API, Key: expiredScope.Key + "/alive"}
		if _, err := store.Begin(context.Background(), aliveScope, []byte(`{"b":2}`)); err != nil {
			t.Fatal(err)
		}

		n, err := cleaner.CleanupExpired(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Fatalf("删除数量应恰好等于过期行数（1），got %d", n)
		}

		// 过期记录已被清理：同 key 再次 Begin 视为首次。
		again, err := store.Begin(context.Background(), expiredScope, []byte(`{"a":1}`))
		if err != nil || !again.Fresh {
			t.Fatalf("被清理的过期 key 应可重新执行：fresh=%v err=%v", again.Fresh, err)
		}
		// 未过期记录保留：仍处于处理中。
		_, err = store.Begin(context.Background(), aliveScope, []byte(`{"b":2}`))
		if !errors.Is(err, ErrInProgress) {
			t.Fatalf("未过期记录不应被清理，应返回 ErrInProgress，got %v", err)
		}
	})
}

// postgresPoolForTests 建立测试连接池；PostgreSQL 不可用时返回 nil 与 skip 原因。
// 注意：skip 消息与连接串中只含本地占位值，不写入任何真实凭据。
func postgresPoolForTests(t *testing.T) (*pgxpool.Pool, string) {
	t.Helper()
	// 第十四轮 H5：每轮测试使用独立 schema（test_run_<时间戳>），
	// 断言通过后自动删除；public 不再增长。
	rs := testdb.NewRunSchema(t)
	if rs == nil {
		return nil, "PostgreSQL 不可用，跳过 PostgresStore 用例"
	}
	return rs.Pool(), ""
}
