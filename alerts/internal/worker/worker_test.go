package worker

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ORG/agent-ops/alerts/internal/consumer"
	"github.com/ORG/agent-ops/alerts/internal/executor"
	"github.com/ORG/agent-ops/alerts/internal/ingest"
	"github.com/ORG/agent-ops/alerts/internal/planner"
	"github.com/ORG/agent-ops/alerts/internal/store"
	contractv1 "github.com/ORG/agent-ops/contract/gen/go/agent_ops/contract/v1"
	"github.com/ORG/agent-ops/internal/audit"
	"github.com/ORG/agent-ops/internal/policy"
	"github.com/ORG/agent-ops/internal/testdb"
)

// —— 测试环境 ——

type workerEnv struct {
	pool     *pgxpool.Pool
	store    *store.Store
	consumer *consumer.Consumer
	planner  *planner.Planner
	executor *executor.Executor
	audit    *audit.Store
	sink     executor.AuditSink
	rs       *testdb.RunSchema
	now      time.Time
}

// testCaps 返回只读能力注册表；onRun 为每次执行的钩子（可为 nil）。
func testCaps(calls *int, mu *sync.Mutex, onRun func()) map[string]executor.CapEntry {
	names := []string{"diagnose.disk_usage", "diagnose.memory_pressure", "diagnose.load_average"}
	out := map[string]executor.CapEntry{}
	for _, n := range names {
		n := n
		out[n] = executor.CapEntry{
			Decl: &contractv1.Capability{
				Name: n, RiskTier: contractv1.RiskTier_RISK_TIER_READ_ONLY, Idempotent: true,
			},
			Run: func(context.Context, executor.Request) (executor.Report, error) {
				if mu != nil {
					mu.Lock()
				}
				if calls != nil {
					*calls++
				}
				if mu != nil {
					mu.Unlock()
				}
				if onRun != nil {
					onRun()
				}
				return executor.Report{Conclusion: "ok " + n, Success: true}, nil
			},
		}
	}
	return out
}

// newWorkerEnv 建立真实 PG 环境（独立 run schema）+ 全链路组件。
func newWorkerEnv(t *testing.T, caps map[string]executor.CapEntry) *workerEnv {
	t.Helper()
	return newWorkerEnvTimeout(t, caps, 0)
}

// newWorkerEnvTimeout 同上，但可指定单个能力调用超时（F3：测试用短超时）。
func newWorkerEnvTimeout(t *testing.T, caps map[string]executor.CapEntry, capTimeout time.Duration) *workerEnv {
	t.Helper()
	rs := testdb.NewRunSchema(t)
	if rs == nil {
		return nil
	}
	ctx := context.Background()
	pool := rs.Pool()
	now := time.Unix(1791825000, 0)

	st, err := store.New(pool, store.DefaultAlertsTable, store.DefaultOutboxTable)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.EnsureSchema(ctx); err != nil {
		t.Fatalf("outbox 建表失败：%v", err)
	}
	cons, err := consumer.New(consumer.Config{Pool: pool, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if err := cons.EnsureSchema(ctx); err != nil {
		t.Fatalf("请求表建表失败：%v", err)
	}
	pl, err := planner.New(planner.Config{Pool: pool, Now: func() time.Time { return now },
		Profiles: map[string]string{"prometheus": "prometheus"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := pl.EnsureSchema(ctx); err != nil {
		t.Fatalf("计划表建表失败：%v", err)
	}
	ex, err := executor.New(executor.Config{Pool: pool, Caps: caps, Policy: policy.DefaultConfig(),
		Environment: contractv1.Environment_ENVIRONMENT_TEST, Now: func() time.Time { return now },
		CapabilityTimeout: capTimeout})
	if err != nil {
		t.Fatal(err)
	}
	if err := ex.EnsureSchema(ctx); err != nil {
		t.Fatalf("结果表建表失败：%v", err)
	}
	ast := audit.NewTestStore(pool, "test_audit_events_worker_itest")
	if err := ast.EnsureSchema(ctx); err != nil {
		t.Fatalf("审计表建表失败：%v", err)
	}
	return &workerEnv{pool: pool, store: st, consumer: cons, planner: pl, executor: ex,
		audit: ast, sink: NewAuditAdapter(ast), rs: rs, now: now}
}

// seedAlerts 直接写入 n 条告警（走真实 store，含 outbox 事件）。
func (e *workerEnv) seedAlerts(t *testing.T, n int) {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < n; i++ {
		a := ingest.Alert{
			Source: "prometheus", Severity: "critical", AssetID: "ast_worker_itest",
			Fingerprint: fmt.Sprintf("fp-w-%d", i), Summary: "worker 集成测试",
		}
		if _, err := e.store.Record(ctx, a, 5*time.Minute, e.now.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
}

func (e *workerEnv) counts(t *testing.T) (alerts, outbox, requests, plans, results int64) {
	t.Helper()
	ctx := context.Background()
	var err error
	if alerts, outbox, err = e.store.Counts(ctx); err != nil {
		t.Fatal(err)
	}
	if requests, err = e.consumer.RequestCount(ctx); err != nil {
		t.Fatal(err)
	}
	if plans, err = e.planner.PlanCount(ctx); err != nil {
		t.Fatal(err)
	}
	if results, err = e.executor.ResultCount(ctx); err != nil {
		t.Fatal(err)
	}
	return
}

// —— W1 ②：单实例锁 ——

// TestWorkerRejectsSecondInstance（W1 ②）第二个 worker 获取 advisory lock 失败，
// 必须**拒绝启动**而不是并行处理。
func TestWorkerRejectsSecondInstance(t *testing.T) {
	env := newWorkerEnv(t, testCaps(nil, nil, nil))
	if env == nil {
		return
	}
	wk1, err := New(Config{Pool: env.pool, Consumer: env.consumer, Planner: env.planner, Executor: env.executor})
	if err != nil {
		t.Fatal(err)
	}
	wk2, err := New(Config{Pool: env.pool, Consumer: env.consumer, Planner: env.planner, Executor: env.executor})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	release, err := wk1.Acquire(ctx)
	if err != nil {
		t.Fatalf("第一个 worker 应取锁成功：%v", err)
	}
	defer release()

	if _, err := wk2.Acquire(ctx); !errors.Is(err, ErrLockHeld) {
		t.Fatalf("第二个 worker 必须因锁被占用而拒绝启动，实际 err=%v", err)
	}
	t.Log("[断言] ② 第二个 worker 获取锁失败 → ErrLockHeld（拒绝启动，不并行处理）")

	// 释放后第三个实例可以取锁（锁确实被归还）；release 幂等（重复调用安全）。
	release()
	release()
	release2, err := wk2.Acquire(ctx)
	if err != nil {
		t.Fatalf("锁释放后应可重新获取：%v", err)
	}
	release2()
	release2()
	t.Log("[断言] 锁在释放后可被重新获取（release 幂等）")
}

// TestWorkerLockReleasedAfterRun 运行结束后锁必须归还（否则后续实例永远起不来）。
func TestWorkerLockReleasedAfterRun(t *testing.T) {
	env := newWorkerEnv(t, testCaps(nil, nil, nil))
	if env == nil {
		return
	}
	wk, err := New(Config{Pool: env.pool, Consumer: env.consumer, Planner: env.planner,
		Executor: env.executor, AuditSink: env.sink, MaxIterations: 1,
		Sleep: func(context.Context, time.Duration) {}})
	if err != nil {
		t.Fatal(err)
	}
	if err := wk.Run(context.Background()); err != nil {
		t.Fatalf("worker 运行失败：%v", err)
	}
	wk2, err := New(Config{Pool: env.pool, Consumer: env.consumer, Planner: env.planner, Executor: env.executor})
	if err != nil {
		t.Fatal(err)
	}
	release, err := wk2.Acquire(context.Background())
	if err != nil {
		t.Fatalf("worker 退出后锁应已释放：%v", err)
	}
	release()
	t.Log("[断言] worker 退出后 advisory lock 已释放")
}

// —— W1 ③：取消上下文 ——

// TestWorkerCancelStopsAtCapabilityBoundary（W1 ③，第十九轮 F3 修订为**能力粒度**）
// 在某个能力执行期间取消上下文：该能力会跑完（不被打断），但**后续能力不再执行**，
// 计划被标记为 failed(interrupted)，且不得进入第二轮。
//
// 注：本轮之前（第十八轮）停止粒度是"阶段"——阶段内所有能力都跑完。
// F3 裁决后改为逐条停止，本用例同步改写（旧语义由 F3 ① 用例覆盖）。
func TestWorkerCancelStopsAtCapabilityBoundary(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// 第 1 次能力执行时取消上下文：模拟"SIGINT 在某能力执行期间到达"。
	caps := testCaps(&calls, &mu, func() {
		mu.Lock()
		first := calls == 1
		mu.Unlock()
		if first {
			cancel()
		}
	})
	env := newWorkerEnv(t, caps)
	if env == nil {
		return
	}
	env.seedAlerts(t, 3)

	// 单能力超时给足（100s）：本用例只验证"逐条停止"，不触发宽限期。
	wk, err := New(Config{Pool: env.pool, Consumer: env.consumer, Planner: env.planner,
		Executor: env.executor, AuditSink: env.sink, MaxIterations: 1,
		Sleep: func(context.Context, time.Duration) {}})
	if err != nil {
		t.Fatal(err)
	}
	env.executor.SetCapabilityTimeout(100 * time.Second)
	if err := wk.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("worker 运行失败：%v", err)
	}
	stats := wk.Stats()
	if len(stats) != 1 {
		t.Fatalf("取消后不得进入第二轮，实际 %d 轮", len(stats))
	}
	// 第一个计划的第 1 条能力跑完；其余 2 条能力 + 后 2 个计划的能力均不执行。
	mu.Lock()
	gotCalls := calls
	mu.Unlock()
	if gotCalls != 1 {
		t.Fatalf("逐条停止：仅当前能力应完成（1 次调用），实际 %d", gotCalls)
	}
	// 3 个计划都被抢占（CAS 已置 running），但只有第 1 个被落终态；
	// 其余 2 个留在 running（第 2、3 个计划的能力在调用前即检查到停止信号）。
	if stats[0].Executor != 1 {
		t.Fatalf("本轮执行器应对第 1 个计划落终态（后 2 个未完成），实际 %d", stats[0].Executor)
	}
	// 结果只有 1 条 ok（第 1 个计划的第 1 条能力）。
	if n, _ := env.executor.ResultCount(context.Background()); n != 1 {
		t.Fatalf("应有 1 条结果，实际 %d", n)
	}
	// 第 1 个计划应为 failed(interrupted)（取最早的计划行）。
	var status, reason string
	if err := env.pool.QueryRow(context.Background(),
		`SELECT status, reason FROM test_diagnosis_plans ORDER BY id LIMIT 1`).
		Scan(&status, &reason); err != nil {
		t.Fatal(err)
	}
	if status != "failed" || !strings.Contains(reason, "interrupted") {
		t.Fatalf("第 1 个计划应为 failed(interrupted)，实际 status=%q reason=%q", status, reason)
	}
	// 后 2 个计划可能停在 running（能力调用前即检查到停止信号）。
	// 若实现选择"抢占后即落终态"，则它们已是 failed(interrupted)——两种情况
	// 都不允许留下"running 且无终态结果"的残留。
	var running, failedInterrupted int
	if err := env.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM test_diagnosis_plans WHERE status = 'running'`).Scan(&running); err != nil {
		t.Fatal(err)
	}
	if err := env.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM test_diagnosis_plans WHERE status = 'failed' AND reason LIKE 'interrupted%'`).
		Scan(&failedInterrupted); err != nil {
		t.Fatal(err)
	}
	if running != 0 {
		t.Fatalf("停止后不得残留 running 计划（应由对账兜底），实际 %d 条", running)
	}
	if failedInterrupted < 1 {
		t.Fatalf("至少应有 1 条计划被标记 interrupted，实际 %d 条", failedInterrupted)
	}
	// 对账必须能把任何残留 running 收拾干净（这里应为 0 条）。
	if n, err := env.executor.ReconcileRunning(context.Background()); err != nil || n != 0 {
		t.Fatalf("对账不应有可标记项：n=%d err=%v", n, err)
	}
	if stale, _ := env.executor.StaleRunning(context.Background()); stale != 0 {
		t.Fatalf("对账后不应有 running 残留：%d", stale)
	}
	t.Logf("[断言] ③ 中途取消：逐条停止（calls=%d），interrupted 计划 %d 条、running 残留 0 条，"+
		"未进入第二轮", gotCalls, failedInterrupted)
}

// —— W1 ④：停止后无残留 running ——

// TestWorkerStopLeavesNoRunningPlan（W1 ④）worker 正常停止后，
// 不存在"running 且无终态结果"的计划。
func TestWorkerStopLeavesNoRunningPlan(t *testing.T) {
	env := newWorkerEnv(t, testCaps(nil, nil, nil))
	if env == nil {
		return
	}
	env.seedAlerts(t, 4)
	ctx, cancel := context.WithCancel(context.Background())
	wk, err := New(Config{Pool: env.pool, Consumer: env.consumer, Planner: env.planner,
		Executor: env.executor, AuditSink: env.sink,
		Sleep: func(context.Context, time.Duration) {}})
	if err != nil {
		t.Fatal(err)
	}
	// 第一轮结束后取消（OnIteration 在每轮结束后回调）。
	iter := 0
	wk.cfg.OnIteration = func(Stats) {
		iter++
		if iter >= 1 {
			cancel()
		}
	}
	if err := wk.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("worker 运行失败：%v", err)
	}
	n, err := env.executor.StaleRunning(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("停止后不得残留 running 且无终态结果的计划，实际 %d 条", n)
	}
	alertsN, outboxN, reqN, planN, resN := env.counts(t)
	if alertsN != 4 || outboxN != 4 || reqN != 4 || planN != 4 || resN != 12 {
		t.Fatalf("行数应为 alerts=4 outbox=4 requests=4 plans=4 results=12（4 计划 × 3 能力）："+
			"alerts=%d outbox=%d requests=%d plans=%d results=%d",
			alertsN, outboxN, reqN, planN, resN)
	}
	t.Logf("[断言] ④ 停止后无 running 残留；行数 alerts=%d outbox=%d requests=%d plans=%d results=%d",
		alertsN, outboxN, reqN, planN, resN)
}

// TestWorkerReconcileCoversHardKill（W1 ④ 兜底）强杀场景留下的 running 残留
// 必须能被对账标记（证明对账机制对 worker 的残留同样有效）。
func TestWorkerReconcileCoversHardKill(t *testing.T) {
	env := newWorkerEnv(t, testCaps(nil, nil, nil))
	if env == nil {
		return
	}
	ctx := context.Background()
	// 人为制造"被强杀"的残留：计划处于 running 且无结果行。
	if _, err := env.pool.Exec(ctx, `INSERT INTO test_diagnosis_plans
(event_id, fingerprint, source, severity, profile, status, rule_id, capabilities, reason, created_at, updated_at)
VALUES (900,'fp-kill','prometheus','critical','prometheus','running','R-001',
        ARRAY['diagnose.disk_usage'],'', now(), now())`); err != nil {
		t.Fatal(err)
	}
	if n, err := env.executor.StaleRunning(ctx); err != nil || n != 1 {
		t.Fatalf("应识别 1 条强杀残留：n=%d err=%v", n, err)
	}
	n, err := env.executor.ReconcileRunning(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("对账应标记 1 条，实际 %d", n)
	}
	if left, _ := env.executor.StaleRunning(ctx); left != 0 {
		t.Fatalf("对账后不应再有残留：%d", left)
	}
	t.Log("[断言] 强杀残留可被对账标记（stale_running → failed）")
}

// —— W1 正向：一轮完整推进 ——

// TestWorkerRunsChainOnce worker 一轮内必须按 consumer → planner → executor 顺序推进，
// 且批量上限生效。
func TestWorkerRunsChainOnce(t *testing.T) {
	env := newWorkerEnv(t, testCaps(nil, nil, nil))
	if env == nil {
		return
	}
	env.seedAlerts(t, 3)
	wk, err := New(Config{Pool: env.pool, Consumer: env.consumer, Planner: env.planner,
		Executor: env.executor, AuditSink: env.sink, MaxIterations: 1,
		Sleep: func(context.Context, time.Duration) {}})
	if err != nil {
		t.Fatal(err)
	}
	if err := wk.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	stats := wk.Stats()
	if len(stats) != 1 {
		t.Fatalf("应有 1 轮统计，实际 %d", len(stats))
	}
	s := stats[0]
	if s.Consumer != 3 || s.Planner != 3 || s.Executor != 3 {
		t.Fatalf("一轮内三个阶段应各推进 3 条：%+v", s)
	}
	alertsN, outboxN, reqN, planN, resN := env.counts(t)
	if alertsN != 3 || outboxN != 3 || reqN != 3 || planN != 3 || resN != 9 {
		t.Fatalf("行数应为 alerts=3 outbox=3 requests=3 plans=3 results=9（3 计划 × 3 能力）："+
			"alerts=%d outbox=%d requests=%d plans=%d results=%d",
			alertsN, outboxN, reqN, planN, resN)
	}
	// 审计 seq 连续（每次能力执行一条 → 9 条）。
	seqs := auditSeqs(t, env, "test_audit_events_worker_itest")
	if len(seqs) != 9 {
		t.Fatalf("应有 9 条审计事件，实际 %d", len(seqs))
	}
	for i, s := range seqs {
		if s != int64(i+1) {
			t.Fatalf("审计 seq 必须连续：%v", seqs)
		}
	}
	t.Logf("[断言] 一轮推进：%+v；审计 seq 连续 %v", s, seqs)
}

// —— 配置校验 ——

// TestWorkerConfigValidation 配置不完整必须拒绝。
func TestWorkerConfigValidation(t *testing.T) {
	if _, err := New(Config{}); !errors.Is(err, ErrConfig) {
		t.Fatalf("空配置应被拒绝：%v", err)
	}
	env := newWorkerEnv(t, testCaps(nil, nil, nil))
	if env == nil {
		return
	}
	if _, err := New(Config{Pool: env.pool}); !errors.Is(err, ErrConfig) {
		t.Fatalf("缺少 consumer/planner/executor 应被拒绝：%v", err)
	}
	// 默认值填充。
	wk, err := New(Config{Pool: env.pool, Consumer: env.consumer, Planner: env.planner, Executor: env.executor})
	if err != nil {
		t.Fatal(err)
	}
	if wk.cfg.Interval != DefaultInterval || wk.cfg.ConsumerLimit != DefaultConsumerLimit ||
		wk.cfg.PlannerLimit != DefaultPlannerLimit || wk.cfg.ExecutorLimit != DefaultExecutorLimit ||
		wk.cfg.LockKey != DefaultLockKey {
		t.Fatalf("默认值不符：%+v", wk.cfg)
	}
	if DefaultConsumerLimit != 100 || DefaultPlannerLimit != 50 || DefaultExecutorLimit != 50 {
		t.Fatalf("批量上限必须为 100/50/50：%d/%d/%d",
			DefaultConsumerLimit, DefaultPlannerLimit, DefaultExecutorLimit)
	}
	if DefaultInterval != 5*time.Second {
		t.Fatalf("轮询间隔必须为 5s：%v", DefaultInterval)
	}
	t.Logf("[断言] 默认值：interval=%v limits=%d/%d/%d lockKey=%d",
		wk.cfg.Interval, wk.cfg.ConsumerLimit, wk.cfg.PlannerLimit, wk.cfg.ExecutorLimit, wk.cfg.LockKey)
}

// —— 辅助 ——

// mustWorker 构建一个有界迭代的 worker（测试钩子：不真实等待）。
func mustWorker(t *testing.T, env *workerEnv, maxIter int) *Worker {
	t.Helper()
	wk, err := New(Config{Pool: env.pool, Consumer: env.consumer, Planner: env.planner,
		Executor: env.executor, AuditSink: env.sink, MaxIterations: maxIter,
		Sleep: func(context.Context, time.Duration) {}})
	if err != nil {
		t.Fatal(err)
	}
	return wk
}

// auditSeqs 返回审计表 seq（升序）。
func auditSeqs(t *testing.T, env *workerEnv, table string) []int64 {
	t.Helper()
	rows, err := env.pool.Query(context.Background(), fmt.Sprintf(`SELECT seq FROM %s ORDER BY seq`, table))
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

// —— F3：停止粒度与宽限期 ——

// TestStopCompletesCurrentCapabilityOnly（F3 ①）停止信号在某个能力执行期间到达：
// 当前能力完成，后续能力不执行，计划标记 failed(interrupted)。
func TestStopCompletesCurrentCapabilityOnly(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// 第 1 条能力执行完成后取消（模拟"能力执行期间收到 SIGINT"）。
	caps := testCaps(&calls, &mu, func() {
		mu.Lock()
		first := calls == 1
		mu.Unlock()
		if first {
			cancel()
		}
	})
	env := newWorkerEnv(t, caps)
	if env == nil {
		return
	}
	env.seedAlerts(t, 1) // R-001 → 3 条只读能力

	wk := mustWorker(t, env, 1)
	if err := wk.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("worker 运行失败：%v", err)
	}
	mu.Lock()
	got := calls
	mu.Unlock()
	if got != 1 {
		t.Fatalf("停止后应只完成当前能力（1 次调用），实际 %d", got)
	}
	var status, reason string
	if err := env.pool.QueryRow(context.Background(),
		`SELECT status, reason FROM test_diagnosis_plans ORDER BY id LIMIT 1`).Scan(&status, &reason); err != nil {
		t.Fatal(err)
	}
	if status != executor.PlanFailed {
		t.Fatalf("计划终态应为 failed，实际 %q", status)
	}
	if !strings.Contains(reason, executor.ReasonInterrupted) {
		t.Fatalf("reason 应包含 %s：%q", executor.ReasonInterrupted, reason)
	}
	if !strings.Contains(reason, "剩余 2 条未执行") {
		t.Fatalf("reason 应写明剩余未执行的能力数：%q", reason)
	}
	// 只应有 1 条结果行（其余能力未执行 → 不写结果）。
	if n, err := env.executor.ResultCount(context.Background()); err != nil || n != 1 {
		t.Fatalf("应只有 1 条结果行，实际 %d（err=%v）", n, err)
	}
	t.Logf("[F3①] 当前能力完成后停止：calls=%d 终态=%s reason=%q", got, status, reason)
}

// TestGracePeriodExceededMarksInterrupted（F3 ②）停止信号到达后当前能力在宽限期内
// 未完成 → 取消上下文，计划标记 failed(interrupted)，并写审计（seq 连续）。
func TestGracePeriodExceededMarksInterrupted(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// 能力执行中取消停止信号并一直阻塞到能力超时（宽限期耗尽）。
	caps := map[string]executor.CapEntry{}
	for _, n := range []string{"diagnose.disk_usage", "diagnose.memory_pressure", "diagnose.load_average"} {
		n := n
		caps[n] = executor.CapEntry{
			Decl: &contractv1.Capability{
				Name: n, RiskTier: contractv1.RiskTier_RISK_TIER_READ_ONLY, Idempotent: true,
			},
			Run: func(c context.Context, _ executor.Request) (executor.Report, error) {
				mu.Lock()
				calls++
				first := calls == 1
				mu.Unlock()
				if first {
					cancel() // 宽限期内收到停止信号
				}
				<-c.Done() // 阻塞直到能力超时（宽限期耗尽）
				return executor.Report{}, c.Err()
			},
		}
	}
	env := newWorkerEnvTimeout(t, caps, 150*time.Millisecond)
	if env == nil {
		return
	}
	env.seedAlerts(t, 1)

	start := time.Now()
	wk := mustWorker(t, env, 1)
	if err := wk.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("worker 运行失败：%v", err)
	}
	elapsed := time.Since(start)

	var status, reason string
	if err := env.pool.QueryRow(context.Background(),
		`SELECT status, reason FROM test_diagnosis_plans ORDER BY id LIMIT 1`).Scan(&status, &reason); err != nil {
		t.Fatal(err)
	}
	if status != executor.PlanFailed {
		t.Fatalf("计划终态应为 failed，实际 %q", status)
	}
	if !strings.Contains(reason, executor.ReasonInterrupted) || !strings.Contains(reason, "宽限期") {
		t.Fatalf("reason 应写明宽限期超时：%q", reason)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("宽限期应约为 150ms（注入值），实际耗时 %v", elapsed)
	}
	// 审计：1 条 interrupted，且 seq 连续。
	seqs := auditSeqs(t, env, "test_audit_events_worker_itest")
	if len(seqs) != 1 {
		t.Fatalf("应有 1 条审计事件（interrupted），实际 %d（%v）", len(seqs), seqs)
	}
	for i, s := range seqs {
		if s != int64(i+1) {
			t.Fatalf("审计 seq 必须连续：%v", seqs)
		}
	}
	var action string
	if err := env.pool.QueryRow(context.Background(),
		`SELECT action FROM test_audit_events_worker_itest ORDER BY seq LIMIT 1`).Scan(&action); err != nil {
		t.Fatal(err)
	}
	if action != executor.ActionInterrupted {
		t.Fatalf("审计动作应为 %s，实际 %q", executor.ActionInterrupted, action)
	}
	t.Logf("[F3②] 宽限期耗尽：耗时=%v 终态=%s reason=%q 审计=%v(%s)", elapsed, status, reason, seqs, action)
}

// TestStopNoRunningLeftoverF3（F3 ③）停止后不得有 running 且无终态结果的计划。
func TestStopNoRunningLeftoverF3(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	caps := testCaps(&calls, &mu, func() {
		mu.Lock()
		first := calls == 1
		mu.Unlock()
		if first {
			cancel()
		}
	})
	env := newWorkerEnv(t, caps)
	if env == nil {
		return
	}
	env.seedAlerts(t, 3)
	wk := mustWorker(t, env, 1)
	if err := wk.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("worker 运行失败：%v", err)
	}
	if n, err := env.executor.StaleRunning(context.Background()); err != nil || n != 0 {
		t.Fatalf("停止后不得残留 running 计划：n=%d err=%v", n, err)
	}
	var running int
	if err := env.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM test_diagnosis_plans WHERE status = 'running'`).Scan(&running); err != nil {
		t.Fatal(err)
	}
	if running != 0 {
		t.Fatalf("不得存在 running 状态的计划：%d", running)
	}
	// 被中断的计划应能被重新规划/重投（此处只断言终态可读且为 failed）。
	var failed int
	if err := env.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM test_diagnosis_plans WHERE status = $1`, executor.PlanFailed).Scan(&failed); err != nil {
		t.Fatal(err)
	}
	t.Logf("[F3③] 停止后无 running 残留（failed=%d）", failed)
}
