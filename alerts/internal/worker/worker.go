// Package worker 是**仅测试模式**的常驻 worker（第十八轮 W1）。
//
// 职责：把 consumer → planner → executor 串成一个常驻循环，使告警链路在
// 没有测试驱动的情况下也能自动推进。
//
// 安全与正确性约束：
//   - **单实例**：启动时在专用连接上取 PostgreSQL advisory lock
//     （pg_try_advisory_lock，固定键）；取不到锁即**拒绝启动**（不并行处理）；
//   - **有界批量**：每轮 consumer/planner/executor 各有批量上限；
//   - **优雅停止（第十九轮 F3）**：收到停止信号（ctx 取消）后不再进入下一阶段；
//     执行器按**能力**粒度停止——每个能力调用前检查停止信号、单个能力调用 30s
//     超时（即宽限期），超时则把计划标记为 failed(interrupted) 并写审计；
//     强杀场景仍由 executor.ReconcileRunning 对账兜底；
//   - 本包不做任何策略判定：策略闸门在执行器内部（policy.Evaluate）。
package worker

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/XZ-libin/agent-ops/alerts/internal/consumer"
	"github.com/XZ-libin/agent-ops/alerts/internal/executor"
	"github.com/XZ-libin/agent-ops/alerts/internal/planner"
	"github.com/XZ-libin/agent-ops/internal/audit"
)

// DefaultLockKey advisory lock 的固定键（ASCII "AGOPSWK1"）。
// 所有 worker 实例共用该键，保证同一时间只有一个 worker 在跑。
const DefaultLockKey int64 = 0x41474F5053574B31

// 默认批量上限（W1 裁决）。
const (
	// DefaultConsumerLimit 每轮消费者处理的事件上限。
	DefaultConsumerLimit = 100
	// DefaultPlannerLimit 每轮规划器生成的计划上限。
	DefaultPlannerLimit = 50
	// DefaultExecutorLimit 每轮执行器执行的计划上限。
	DefaultExecutorLimit = 50
	// DefaultInterval 轮询间隔。
	DefaultInterval = 5 * time.Second
)

// 错误。
var (
	// ErrLockHeld 已有另一个 worker 持有 advisory lock。
	ErrLockHeld = errors.New("worker：advisory lock 已被其他实例持有，拒绝启动（不允许并行处理）")
	// ErrConfig 配置不完整。
	ErrConfig = errors.New("worker：配置不完整")
)

// Config worker 配置。
type Config struct {
	// Pool 连接池（必填）。
	Pool *pgxpool.Pool
	// Consumer / Planner / Executor 三个阶段的组件（必填）。
	Consumer *consumer.Consumer
	Planner  *planner.Planner
	Executor *executor.Executor
	// AuditSink 执行器审计写入（可为 nil）。
	AuditSink executor.AuditSink
	// Interval 轮询间隔（<=0 用 DefaultInterval）。
	Interval time.Duration
	// ConsumerLimit / PlannerLimit / ExecutorLimit 每轮批量上限（<=0 用默认值）。
	ConsumerLimit int
	PlannerLimit  int
	ExecutorLimit int
	// LockKey advisory lock 键（0 用 DefaultLockKey）。
	LockKey int64
	// MaxIterations >0 时只跑有限轮（测试钩子）；0 表示无限循环直到 ctx 取消。
	MaxIterations int
	// Sleep 注入的等待函数（默认按 Interval 睡眠且可被 ctx 取消）。
	Sleep func(ctx context.Context, d time.Duration)
	// OnIteration 每轮结束后的回调（观测/测试用）。
	OnIteration func(Stats)
}

// Stats 一轮迭代的统计。
type Stats struct {
	// Iteration 轮次（从 1 开始）。
	Iteration int
	// Consumer / Planner / Executor 本轮各自推进的条数。
	Consumer int
	Planner  int
	Executor int
	// Err 本轮首个错误（nil 表示本轮无错）。
	Err error
}

// Worker 常驻 worker。
type Worker struct {
	cfg Config

	mu    sync.Mutex
	stats []Stats
}

// New 构建 worker（只校验配置，不取锁、不连接）。
func New(cfg Config) (*Worker, error) {
	if cfg.Pool == nil || cfg.Consumer == nil || cfg.Planner == nil || cfg.Executor == nil {
		return nil, fmt.Errorf("%w：Pool/Consumer/Planner/Executor 必填", ErrConfig)
	}
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultInterval
	}
	if cfg.ConsumerLimit <= 0 {
		cfg.ConsumerLimit = DefaultConsumerLimit
	}
	if cfg.PlannerLimit <= 0 {
		cfg.PlannerLimit = DefaultPlannerLimit
	}
	if cfg.ExecutorLimit <= 0 {
		cfg.ExecutorLimit = DefaultExecutorLimit
	}
	if cfg.LockKey == 0 {
		cfg.LockKey = DefaultLockKey
	}
	if cfg.Sleep == nil {
		cfg.Sleep = sleepCtx
	}
	return &Worker{cfg: cfg}, nil
}

// sleepCtx 可被 ctx 取消的睡眠。
func sleepCtx(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

// Stats 返回到目前为止的每轮统计（副本）。
func (w *Worker) Stats() []Stats {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]Stats, len(w.stats))
	copy(out, w.stats)
	return out
}

// —— 审计接线 ——

// AuditAdapter 把 *audit.Store 适配为 executor.AuditSink
// （执行器不直接依赖审计包，保持可替换）。
type AuditAdapter struct {
	mu  sync.Mutex
	st  *audit.Store
	seq int
}

// NewAuditAdapter 构建审计适配器。
func NewAuditAdapter(st *audit.Store) *AuditAdapter { return &AuditAdapter{st: st} }

// Append 写一条审计事件（缺 ID 时按序号补一个测试用 ID）。
func (a *AuditAdapter) Append(ctx context.Context, ev executor.AuditEvent) (string, error) {
	a.mu.Lock()
	a.seq++
	id := ev.ID
	if id == "" {
		id = fmt.Sprintf("evt-worker-%d", a.seq)
	}
	a.mu.Unlock()
	return a.st.Append(ctx, audit.Event{
		ID: id, Actor: ev.Actor, Action: ev.Action, Target: ev.Target, Payload: ev.Payload,
	})
}

// —— 单实例锁 ——

// Acquire 取单实例锁。成功返回释放函数；已有实例持锁返回 ErrLockHeld。
//
// 锁必须由**同一个连接**持有并在退出时释放（advisory lock 是会话级的）。
func (w *Worker) Acquire(ctx context.Context) (func(), error) {
	conn, err := w.cfg.Pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("worker：获取数据库连接失败：%w", err)
	}
	var ok bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, w.cfg.LockKey).Scan(&ok); err != nil {
		conn.Release()
		return nil, fmt.Errorf("worker：尝试获取 advisory lock 失败：%w", err)
	}
	if !ok {
		conn.Release()
		return nil, ErrLockHeld
	}
	var once sync.Once
	release := func() {
		once.Do(func() {
			// 释放用独立上下文：停止信号已取消时仍需把锁还回去。
			_, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, w.cfg.LockKey)
			conn.Release()
		})
	}
	return release, nil
}

// Run 取锁并运行（Acquire + Serve）。
//
// 停止语义：ctx 取消后**不再进入下一阶段**，当前阶段用与取消解耦的上下文跑完
// （因此不会留下半完成的 CAS 状态）；随后释放锁并返回。
func (w *Worker) Run(ctx context.Context) error {
	release, err := w.Acquire(ctx)
	if err != nil {
		return err
	}
	return w.Serve(ctx, release)
}

// Serve 在**已持有单实例锁**的前提下运行循环，退出时释放锁。
//
// 供调用方在启动其他组件之前先完成"单实例"校验：cmd/alerts 先同步 Acquire，
// 取锁失败即拒绝启动（不并行处理），成功后再 go Serve(...)。
func (w *Worker) Serve(ctx context.Context, release func()) error {
	if release == nil {
		release = func() {}
	}
	defer release()

	var firstErr error
	for i := 1; ; i++ {
		if err := ctx.Err(); err != nil {
			break // 停止信号：不取新条目
		}
		st := w.iterate(ctx, i)
		w.mu.Lock()
		w.stats = append(w.stats, st)
		w.mu.Unlock()
		if w.cfg.OnIteration != nil {
			w.cfg.OnIteration(st)
		}
		if st.Err != nil && firstErr == nil {
			firstErr = st.Err
		}
		if w.cfg.MaxIterations > 0 && i >= w.cfg.MaxIterations {
			break
		}
		if err := ctx.Err(); err != nil {
			break
		}
		w.cfg.Sleep(ctx, w.cfg.Interval)
	}
	return firstErr
}

// iterate 推进一轮：consumer → planner → executor，阶段间检查停止信号。
//
// 停止粒度（第十九轮 F3）：
//   - 阶段之间检查停止信号（不进入下一阶段）；
//   - **executor 阶段把停止信号本身传下去**，由执行器按**能力**粒度停止：
//     每个能力调用前检查、单个能力调用 30s 超时（即宽限期）、超时则把计划
//     标记为 failed(interrupted) 并写审计；
//   - consumer / planner 的当前批次用与停止信号解耦的上下文跑完（两者幂等，
//     单批上限 100/50，代价可控）；停止过程中出现的错误不计为本轮失败。
func (w *Worker) iterate(ctx context.Context, iteration int) Stats {
	st := Stats{Iteration: iteration}
	detached := context.WithoutCancel(ctx)

	n, err := w.cfg.Consumer.RunOnceLimit(detached, w.cfg.ConsumerLimit)
	st.Consumer = n
	if err != nil {
		if ctx.Err() == nil {
			st.Err = err
		}
		return st
	}
	if ctx.Err() != nil {
		return st
	}

	n, err = w.cfg.Planner.RunOnceLimit(detached, w.cfg.PlannerLimit)
	st.Planner = n
	if err != nil {
		if ctx.Err() == nil {
			st.Err = err
		}
		return st
	}
	if ctx.Err() != nil {
		return st
	}

	// 执行器收到停止信号本身：内部按能力粒度停止并落 interrupted 终态。
	n, err = w.cfg.Executor.RunOnceLimit(ctx, w.cfg.ExecutorLimit, w.cfg.AuditSink)
	st.Executor = n
	if err != nil && ctx.Err() == nil {
		st.Err = err
	}
	return st
}
