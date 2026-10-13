// Package executor 是只读诊断**执行器**（第十七轮 P4；第十八轮 K1/W1）。
//
// 职责边界：
//   - 读取 status=planned 的计划，通过 CAS（UPDATE ... WHERE status='planned'，
//     检查影响行数）抢占为 running；
//   - 对计划中的每一条能力：
//     ① 必须存在只读能力注册项，否则 denied（fail-closed）；
//     ② **必须先调用 policy.Evaluate**，结果必须是 auto 且 tier 为 read_only，
//     否则记为 denied 且不执行；
//     ③ 需要外部集群的能力（RequiresCluster，如 kubernetes 画像）在未配置集群时
//     记为 no_cluster_configured（**不静默降级、不记为 done**），不执行、不发请求；
//     ④ 执行结果写入 test_diagnosis_results（plan_id + capability 唯一，防重复）；
//     ⑤ 每次尝试写一条审计事件（diagnosis.executed / diagnosis.denied /
//     diagnosis.no_cluster_configured）；
//   - 计划终态（ADR-018）：
//     failed       任一能力执行失败（含 interrupted）；
//     done         全部能力执行成功；
//     partial      至少一个能力被执行，且至少一个被拒绝/推迟；
//     not_executed 没有任何能力被执行（全部 no_cluster_configured / denied / deferred）；
//   - 单个计划失败不影响其他计划；
//   - **对账**：ReconcileRunning 把"running 且无终态结果"的残留计划标记为 failed，
//     用于 worker 异常退出后的自愈（第十八轮 W1）。
//
// 硬性约束：只能经 policy.Evaluate 之后调用适配器；只执行只读能力；
// 输出中的凭据类字段必须屏蔽（结果表、审计 payload 均不出现凭据）。
package executor

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	contractv1 "github.com/XZ-libin/agent-ops/contract/gen/go/agent_ops/contract/v1"
	"github.com/XZ-libin/agent-ops/internal/policy"
)

// 默认表名（测试用；生产表名待运维确认）。
const (
	// DefaultPlansTable 计划表（规划器写入）。
	DefaultPlansTable = "test_diagnosis_plans"
	// DefaultResultsTable 诊断结果表。
	DefaultResultsTable = "test_diagnosis_results"
)

// 结果状态。
const (
	// StatusOK 执行成功。
	StatusOK = "ok"
	// StatusDenied 被策略/注册表拒绝（未执行）。
	StatusDenied = "denied"
	// StatusDeferred 本轮不执行（保留状态：当前无产生路径，见 ADR-017）。
	StatusDeferred = "deferred"
	// StatusFailed 执行失败。
	StatusFailed = "failed"
	// StatusNoClusterConfigured 需要集群的能力在未配置集群时记为该状态
	// （第十八轮 K1：不静默降级、不记为 done）。
	StatusNoClusterConfigured = "no_cluster_configured"
)

// 计划终态（与 planner 的状态常量一致）。
const (
	PlanRunning = "running"
	PlanDone    = "done"
	PlanFailed  = "failed"
	// PlanDeferred 全部能力被推迟（保留状态：当前无产生路径，见 ADR-017）。
	PlanDeferred = "deferred"
	// PlanPartial 至少一个能力被执行，且至少一个能力被拒绝/推迟（无失败）。
	PlanPartial = "partial"
	// PlanNotExecuted 没有任何能力被执行（全部 no_cluster_configured 或 denied）。
	// 第十九轮 F2：与 partial 拆分（ADR-018）。
	PlanNotExecuted = "not_executed"
)

// TerminalPlanStates 返回执行器会写入的**计划终态**（监控可消费的最终取值）。
//
// 顺序固定（严重程度由高到低），供运维文档与监控规则比对使用
// （docs/ops/terminal-states.md；一致性由 TestTerminalStatesDocMatchesCode 断言）。
// 注意：running 是**中间态**（已被 CAS 抢占、尚未落终态），不在本列表内。
func TerminalPlanStates() []string {
	return []string{PlanFailed, PlanNotExecuted, PlanPartial, PlanDone}
}

// PlanStateMeanings 返回终态 → 一句话含义（与 docs/ops/terminal-states.md 一一对应）。
func PlanStateMeanings() map[string]string {
	return map[string]string{
		PlanDone:        "全部能力执行成功",
		PlanPartial:     "至少一个能力执行成功，且至少一个能力被拒绝或推迟",
		PlanNotExecuted: "没有任何能力被执行（全部被拒绝 / 未配置集群 / 被推迟）",
		PlanFailed:      "任一能力执行失败（含因停止信号中断 interrupted）",
	}
}

// 审计事件类型。
const (
	// ActionExecuted 已执行（成功或失败）。
	ActionExecuted = "diagnosis.executed"
	// ActionDenied 被拒绝（未执行）。
	ActionDenied = "diagnosis.denied"
	// ActionNoClusterConfigured 因未配置集群而未执行（第十八轮 K1）。
	ActionNoClusterConfigured = "diagnosis.no_cluster_configured"
	// ActionInterrupted 因停止信号/宽限期耗尽而中断（第十九轮 F3）。
	ActionInterrupted = "diagnosis.interrupted"
)

// ReasonNoClusterConfigured 未配置集群时的原因文本（写入结果与审计）。
const ReasonNoClusterConfigured = "未配置集群连接（AGENT_OPS_K8S_KUBECONFIG 未设置）：该能力需要集群，未执行、未发起任何请求"

// ReasonStaleRunning 对账标记原因：计划长时间停留在 running 且无终态结果。
const ReasonStaleRunning = "stale_running：计划停留在 running 且无终态结果，由对账标记为 failed"

// ReasonInterrupted 停止信号导致计划未跑完的原因前缀（第十九轮 F3）。
const ReasonInterrupted = "interrupted"

// tablePattern 表名必须是 test_ 前缀的小写标识符（仅用于 DDL 拼装）。
var tablePattern = regexp.MustCompile(`^test_[a-z0-9_]+$`)

// ErrBadTable 表名不合法。
var ErrBadTable = errors.New("executor：表名必须是 test_ 前缀的合法标识符")

// AuditSink 审计写入（*audit.Store 满足）。
type AuditSink interface {
	Append(ctx context.Context, ev AuditEvent) (string, error)
}

// AuditEvent 审计事件（字段与 internal/audit.Event 一致）。
type AuditEvent struct {
	ID      string
	Actor   string
	Action  string
	Target  string
	Payload any
}

// Report 一条能力的执行产出（只读诊断结论）。
type Report struct {
	// Conclusion 结论摘要（写入结果表前会再次屏蔽凭据）。
	Conclusion string
	// Success 执行是否成功。
	Success bool
}

// CapEntry 只读能力注册项。
type CapEntry struct {
	// Decl 能力声明（tier/read_only/destructive 等；用于 policy.Evaluate）。
	Decl *contractv1.Capability
	// Run 执行逻辑（必须通过适配器的只读方法实现）。
	Run func(ctx context.Context, req Request) (Report, error)
	// RequiresCluster 该能力需要外部集群连接（如 kubernetes 画像）。
	// 当 Config.ClusterConfigured 为 false 时记为 no_cluster_configured，
	// **不调用 Run**（第十八轮 K1）。
	RequiresCluster bool
}

// Request 执行一条能力所需的输入。
type Request struct {
	Capability  string
	AssetID     string
	Fingerprint string
}

// Config 执行器配置。
type Config struct {
	// Pool 连接池（必填）。
	Pool *pgxpool.Pool
	// Caps 只读能力注册表（能力名 → 注册项）。
	Caps map[string]CapEntry
	// Policy 策略配置（生产用 policy.DefaultConfig()）。
	Policy policy.Config
	// Environment 执行环境（默认 test）。
	Environment contractv1.Environment
	// ClusterConfigured 是否配置了集群连接（第十八轮 K1）。
	// 为 false 时，RequiresCluster 的能力记为 no_cluster_configured。
	ClusterConfigured bool
	// CapabilityTimeout 单个能力调用的超时（<=0 用 DefaultCapabilityTimeout=30s）。
	// 该超时同时是"收到停止信号后完成当前能力的宽限期"（第十九轮 F3）。
	CapabilityTimeout time.Duration
	// PlanTimeout 单个计划的整体上限（<=0 用 DefaultPlanTimeout=5m），仅用于
	// 数据库操作的安全网（能力调用由 CapabilityTimeout 约束）。
	PlanTimeout time.Duration
	// PlansTable / ResultsTable 表名（默认见常量）。
	PlansTable   string
	ResultsTable string
	// Now 注入时钟（测试用）。
	Now func() time.Time
}

// Executor 只读诊断执行器。
type Executor struct {
	pool        *pgxpool.Pool
	caps        map[string]CapEntry
	pol         policy.Config
	env         contractv1.Environment
	cluster     bool
	plans       string
	results     string
	capTimeout  time.Duration
	planTimeout time.Duration
	now         func() time.Time
}

// New 构建执行器；表名不合法直接拒绝（fail-closed）。
func New(cfg Config) (*Executor, error) {
	if cfg.Pool == nil {
		return nil, errors.New("executor：连接池为空")
	}
	plans := cfg.PlansTable
	if plans == "" {
		plans = DefaultPlansTable
	}
	results := cfg.ResultsTable
	if results == "" {
		results = DefaultResultsTable
	}
	if !tablePattern.MatchString(plans) || !tablePattern.MatchString(results) {
		return nil, fmt.Errorf("%w（plans=%q results=%q）", ErrBadTable, plans, results)
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	env := cfg.Environment
	if env == contractv1.Environment_ENVIRONMENT_UNSPECIFIED {
		env = contractv1.Environment_ENVIRONMENT_TEST
	}
	capTimeout := cfg.CapabilityTimeout
	if capTimeout <= 0 {
		capTimeout = DefaultCapabilityTimeout
	}
	planTimeout := cfg.PlanTimeout
	if planTimeout <= 0 {
		planTimeout = DefaultPlanTimeout
	}
	return &Executor{
		pool: cfg.Pool, caps: cfg.Caps, pol: cfg.Policy, env: env,
		cluster: cfg.ClusterConfigured,
		plans:   plans, results: results,
		capTimeout: capTimeout, planTimeout: planTimeout,
		now: now,
	}, nil
}

// SetCapabilityTimeout 覆盖单个能力调用的超时（也是停止后的宽限期）。
// 供测试把 30s 缩放到毫秒级；生产不调用（用 Config.CapabilityTimeout 或默认值）。
func (e *Executor) SetCapabilityTimeout(d time.Duration) {
	if d > 0 {
		e.capTimeout = d
	}
}

// EnsureSchema 建结果表（幂等）。plan_id + capability 唯一：重复执行不产生重复结果。
func (e *Executor) EnsureSchema(ctx context.Context) error {
	stmt := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
    id             bigserial   PRIMARY KEY,
    plan_id        bigint      NOT NULL,
    event_id       bigint      NOT NULL DEFAULT 0,
    capability     text        NOT NULL,
    status         text        NOT NULL CHECK (status IN ('ok','denied','deferred','failed','no_cluster_configured')),
    output_summary text        NOT NULL DEFAULT '',
    reason         text        NOT NULL DEFAULT '',
    created_at     timestamptz NOT NULL,
    updated_at     timestamptz NOT NULL,
    UNIQUE (plan_id, capability)
);`, e.results)
	if _, err := e.pool.Exec(ctx, stmt); err != nil {
		return fmt.Errorf("executor：建结果表失败：%w", err)
	}
	return nil
}

// PlannedPlan 一条待执行的计划。
type PlannedPlan struct {
	ID           int64
	EventID      int64
	Profile      string
	Severity     string
	Capabilities []string
}

// DefaultBatchSize 单次执行处理的计划数上限（第十八轮 W1）。
const DefaultBatchSize = 50

// 停止与超时（第十九轮 F3）。
const (
	// DefaultCapabilityTimeout 单个能力调用的超时（也是停止后的宽限期：
	// 收到停止信号后允许当前能力最多再跑这么久）。替代原"阶段超时 2 分钟"。
	DefaultCapabilityTimeout = 30 * time.Second
	// DefaultPlanTimeout 单个计划的整体上限（安全网，防止 DB 操作无限挂住）。
	DefaultPlanTimeout = 5 * time.Minute
)

// RunOnce 执行一批 planned 计划，返回本次抢占并执行的计划数。
func (e *Executor) RunOnce(ctx context.Context, auditSink AuditSink) (int, error) {
	return e.RunOnceLimit(ctx, DefaultBatchSize, auditSink)
}

// RunOnceLimit 执行一批 planned 计划（上限 limit 条），返回本次抢占并执行的计划数。
// limit <= 0 时使用 DefaultBatchSize。
//
// 停止语义（F3）：ctx 被取消即视为"收到停止信号"——
//   - 不再抢占新计划；
//   - 正在执行的计划会在**下一个能力调用之前**停止，剩余能力不执行；
//   - 当前正在执行的能力最多再跑 CapabilityTimeout（宽限期），超时即取消；
//   - 上述两种情况都把计划标记为 failed（reason=interrupted）并写审计。
//
// 数据库操作使用与停止信号**解耦**的上下文（否则停止后无法落终态）。
func (e *Executor) RunOnceLimit(ctx context.Context, limit int, auditSink AuditSink) (int, error) {
	if limit <= 0 {
		limit = DefaultBatchSize
	}
	opCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), e.planTimeout)
	defer cancel()
	plans, err := e.planned(opCtx, limit)
	if err != nil {
		return 0, err
	}
	executed := 0
	for _, pl := range plans {
		if ctx.Err() != nil {
			break // 停止信号：不再抢占新计划
		}
		claimed, cerr := e.claim(opCtx, pl.ID)
		if cerr != nil {
			return executed, cerr
		}
		if !claimed {
			continue // 已被抢占：跳过（CAS 保证不重复执行）
		}
		if err := e.runPlan(ctx, opCtx, pl, auditSink); err != nil {
			// 单个计划失败不影响其他计划。
			_ = e.finish(opCtx, pl.ID, PlanFailed, "执行器内部错误："+maskOutput(err.Error()))
			continue
		}
		executed++
	}
	return executed, nil
}

// planned 读取待执行计划（status=planned，上限 limit 条）。
func (e *Executor) planned(ctx context.Context, limit int) ([]PlannedPlan, error) {
	rows, err := e.pool.Query(ctx, fmt.Sprintf(
		`SELECT id, event_id, profile, severity, capabilities FROM %s WHERE status = 'planned' ORDER BY id LIMIT $1`,
		e.plans), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PlannedPlan
	for rows.Next() {
		var p PlannedPlan
		if err := rows.Scan(&p.ID, &p.EventID, &p.Profile, &p.Severity, &p.Capabilities); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// claim CAS：planned → running（影响行数 0 表示已被抢占）。
func (e *Executor) claim(ctx context.Context, planID int64) (bool, error) {
	tag, err := e.pool.Exec(ctx, fmt.Sprintf(
		`UPDATE %s SET status = $2, updated_at = $3 WHERE id = $1 AND status = 'planned'`,
		e.plans), planID, PlanRunning, e.now().UTC())
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// runPlan 执行一个计划的所有能力，并写结果与终态。
//
// ctx 仅用于**停止信号**判定（ctx.Err()）；opCtx 用于所有数据库操作
// （与停止信号解耦，保证停止后仍能落终态与审计）。
func (e *Executor) runPlan(ctx context.Context, opCtx context.Context, pl PlannedPlan, auditSink AuditSink) error {
	var ok, denied, deferred, failed, noCluster int
	stopped := func() bool { return ctx.Err() != nil }

	for i, capName := range pl.Capabilities {
		// ⓪ 停止信号：每个能力调用前检查（F3）。
		if stopped() {
			return e.finishInterrupted(opCtx, auditSink, pl, i, "收到停止信号，剩余能力不再执行")
		}
		entry, declared := e.caps[capName]
		// ① 未声明能力：fail-closed（不执行、写 denied 结果与审计）。
		if !declared || entry.Decl == nil {
			if err := e.writeResult(opCtx, pl, capName, StatusDenied, "", "能力未在只读注册表声明（fail-closed）"); err != nil {
				return err
			}
			e.audit(opCtx, auditSink, pl, capName, ActionDenied, false, "能力未在只读注册表声明")
			denied++
			continue
		}
		// ② 非只读 / destructive / test_only：拒绝。
		if entry.Decl.Destructive || entry.Decl.RiskTier != contractv1.RiskTier_RISK_TIER_READ_ONLY || entry.Decl.TestOnly {
			reason := fmt.Sprintf("能力不是只读（tier=%s destructive=%v test_only=%v）",
				entry.Decl.RiskTier, entry.Decl.Destructive, entry.Decl.TestOnly)
			if err := e.writeResult(opCtx, pl, capName, StatusDenied, "", reason); err != nil {
				return err
			}
			e.audit(opCtx, auditSink, pl, capName, ActionDenied, false, reason)
			denied++
			continue
		}
		// ③ 策略判定：必须 auto 且 tier 为 read_only（**适配器调用之前的硬闸门**）。
		pres := policy.Evaluate(e.pol, policy.Request{
			Capability:  entry.Decl,
			Environment: e.env,
		})
		if pres.Decision != contractv1.Decision_DECISION_AUTO ||
			pres.Tier != contractv1.RiskTier_RISK_TIER_READ_ONLY {
			reason := fmt.Sprintf("策略判定非 auto/read_only（decision=%s tier=%s）",
				pres.Decision, pres.Tier)
			if err := e.writeResult(opCtx, pl, capName, StatusDenied, "", reason); err != nil {
				return err
			}
			e.audit(opCtx, auditSink, pl, capName, ActionDenied, false, reason)
			denied++
			continue
		}
		// ④ 需要集群但未配置集群：no_cluster_configured（不执行、不发请求、不记为 done）。
		if entry.RequiresCluster && !e.cluster {
			if err := e.writeResult(opCtx, pl, capName, StatusNoClusterConfigured, "", ReasonNoClusterConfigured); err != nil {
				return err
			}
			e.audit(opCtx, auditSink, pl, capName, ActionNoClusterConfigured, false, ReasonNoClusterConfigured)
			noCluster++
			continue
		}
		// ⑤ 执行（只读方法）。单个能力调用有独立超时；该超时同时是**停止宽限期**。
		capCtx, capCancel := context.WithTimeout(context.WithoutCancel(ctx), e.capTimeout)
		rep, rerr := entry.Run(capCtx, Request{
			Capability: capName, AssetID: pl.Profile, Fingerprint: fmt.Sprintf("plan-%d", pl.ID),
		})
		capCancel()
		if rerr != nil || !rep.Success {
			// 停止信号 + 上下文被取消 → 宽限期耗尽，记为 interrupted。
			if stopped() && (errors.Is(rerr, context.DeadlineExceeded) || errors.Is(rerr, context.Canceled)) {
				return e.finishInterrupted(opCtx, auditSink, pl, i+1,
					fmt.Sprintf("停止宽限期（%s）内未完成能力 %s，已取消", e.capTimeout, capName))
			}
			msg := "执行失败"
			if rerr != nil {
				msg = "执行失败：" + maskOutput(rerr.Error())
			}
			if err := e.writeResult(opCtx, pl, capName, StatusFailed, "", msg); err != nil {
				return err
			}
			e.audit(opCtx, auditSink, pl, capName, ActionExecuted, false, "执行失败")
			failed++
			continue
		}
		summary := maskOutputs([]string{rep.Conclusion})
		if err := e.writeResult(opCtx, pl, capName, StatusOK, summary, ""); err != nil {
			return err
		}
		e.audit(opCtx, auditSink, pl, capName, ActionExecuted, true, "执行成功")
		ok++
	}

	// 终态判定（P4 / K1 / F2）：
	//   failed       —— 任一能力执行失败（含 interrupted）
	//   done         —— 全部能力执行成功
	//   partial      —— 至少一个能力被执行，且至少一个被拒绝/推迟
	//   not_executed —— 没有任何能力被执行（全部 no_cluster_configured / denied / deferred）
	switch {
	case failed > 0:
		return e.finish(opCtx, pl.ID, PlanFailed, fmt.Sprintf("有 %d 条能力执行失败", failed))
	case ok > 0 && denied == 0 && deferred == 0 && noCluster == 0:
		return e.finish(opCtx, pl.ID, PlanDone, "")
	case ok > 0:
		return e.finish(opCtx, pl.ID, PlanPartial,
			fmt.Sprintf("部分完成：ok=%d denied=%d deferred=%d no_cluster_configured=%d",
				ok, denied, deferred, noCluster))
	default:
		// 一个能力都没有执行：不得记为 done，也不得记为 partial。
		return e.finish(opCtx, pl.ID, PlanNotExecuted, notExecutedReason(denied, deferred, noCluster))
	}
}

// finishInterrupted 把计划标记为 failed（reason=interrupted）并写一条审计事件。
//
// interrupted 表示"计划未跑完"：剩余能力未执行（executed 为已完成的能力数）。
func (e *Executor) finishInterrupted(opCtx context.Context, sink AuditSink, pl PlannedPlan, executed int, detail string) error {
	remaining := len(pl.Capabilities) - executed
	reason := fmt.Sprintf("%s：%s（已完成 %d/%d 条能力，剩余 %d 条未执行）",
		ReasonInterrupted, detail, executed, len(pl.Capabilities), remaining)
	e.auditInterrupted(opCtx, sink, pl, executed, remaining, reason)
	return e.finish(opCtx, pl.ID, PlanFailed, reason)
}

// notExecutedReason 生成 not_executed 的首要原因。
// 优先级（ADR-018）：集群未配置 > 被拒绝 > 被推迟 > 无能力。
func notExecutedReason(denied, deferred, noCluster int) string {
	switch {
	case noCluster > 0:
		return fmt.Sprintf("没有任何能力被执行（no_cluster_configured=%d denied=%d deferred=%d）；"+
			"首要原因：%s", noCluster, denied, deferred, ReasonNoClusterConfigured)
	case denied > 0:
		return fmt.Sprintf("没有任何能力被执行（denied=%d deferred=%d）；首要原因：能力被拒绝"+
			"（非只读/未声明/策略拒绝）", denied, deferred)
	case deferred > 0:
		return fmt.Sprintf("没有任何能力被执行（deferred=%d）；首要原因：能力被推迟", deferred)
	default:
		return "没有任何能力被执行：计划没有可执行的能力"
	}
}

// writeResult 写入一条结果（plan_id + capability 唯一，重复执行不新增行）。
func (e *Executor) writeResult(ctx context.Context, pl PlannedPlan, capability, status, summary, reason string) error {
	now := e.now().UTC()
	_, err := e.pool.Exec(ctx, fmt.Sprintf(`INSERT INTO %s
(plan_id, event_id, capability, status, output_summary, reason, created_at, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$7)
ON CONFLICT (plan_id, capability) DO NOTHING`, e.results),
		pl.ID, pl.EventID, capability, status, summary, reason, now)
	if err != nil {
		return fmt.Errorf("executor：写结果失败：%w", err)
	}
	return nil
}

// finish 写计划终态。
func (e *Executor) finish(ctx context.Context, planID int64, status, reason string) error {
	_, err := e.pool.Exec(ctx, fmt.Sprintf(
		`UPDATE %s SET status = $2, reason = $3, updated_at = $4 WHERE id = $1`,
		e.plans), planID, status, reason, e.now().UTC())
	return err
}

// audit 写一条诊断审计事件（不含凭据；payload 只有能力/画像/结论标记）。
func (e *Executor) audit(ctx context.Context, sink AuditSink, pl PlannedPlan, capability, action string, success bool, reason string) {
	if sink == nil {
		return
	}
	payload := map[string]any{
		"capability": capability,
		"profile":    pl.Profile,
		"plan_id":    pl.ID,
		"success":    success,
		"reason":     maskOutput(reason),
	}
	_, _ = sink.Append(ctx, AuditEvent{
		Actor:   "diagnosis-executor",
		Action:  action,
		Target:  fmt.Sprintf("plan-%d", pl.ID),
		Payload: payload,
	})
}

// StaleRunning 返回"处于 running 且结果未写齐（无终态结果）"的计划数。
// 这是对账口径：worker 正常停止后该值必须为 0（第十八轮 W1）。
func (e *Executor) StaleRunning(ctx context.Context) (int, error) {
	var n int
	err := e.pool.QueryRow(ctx, fmt.Sprintf(`
SELECT count(*) FROM %s p
WHERE p.status = $1
  AND (SELECT count(*) FROM %s r WHERE r.plan_id = p.id) < cardinality(p.capabilities)`,
		e.plans, e.results), PlanRunning).Scan(&n)
	return n, err
}

// ReconcileRunning 对账：把停留在 running 的计划标记为 failed（原因 stale_running），
// 返回被标记的计划数。用于 worker 被强杀、进程崩溃后残留 CAS 状态的自愈。
//
// 说明：running 表示"已被抢占但未落终态"，在没有存活 worker 的前提下其状态不可信，
// 因此统一标记为 failed 而不是猜测成功——宁可人工重投（redrive/重新规划），
// 也不把不确定的结果记为成功。
func (e *Executor) ReconcileRunning(ctx context.Context) (int, error) {
	rows, err := e.pool.Query(ctx, fmt.Sprintf(
		`SELECT id FROM %s WHERE status = $1 ORDER BY id`, e.plans), PlanRunning)
	if err != nil {
		return 0, err
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	n := 0
	for _, id := range ids {
		if err := e.finish(ctx, id, PlanFailed, ReasonStaleRunning); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// auditInterrupted 写一条"中断"审计事件（F3）：记录已完成/剩余能力数与原因。
func (e *Executor) auditInterrupted(ctx context.Context, sink AuditSink, pl PlannedPlan, executed, remaining int, reason string) {
	if sink == nil {
		return
	}
	payload := map[string]any{
		"profile":   pl.Profile,
		"plan_id":   pl.ID,
		"executed":  executed,
		"remaining": remaining,
		"total":     len(pl.Capabilities),
		"reason":    maskOutput(reason),
	}
	_, _ = sink.Append(ctx, AuditEvent{
		Actor:   "diagnosis-executor",
		Action:  ActionInterrupted,
		Target:  fmt.Sprintf("plan-%d", pl.ID),
		Payload: payload,
	})
}

// ResultRow 一条诊断结果（供测试与后续轮次读取）。
type ResultRow struct {
	PlanID        int64
	Capability    string
	Status        string
	OutputSummary string
	Reason        string
}

// Results 返回全部结果（按 plan_id, capability 升序）。
func (e *Executor) Results(ctx context.Context) ([]ResultRow, error) {
	rows, err := e.pool.Query(ctx, fmt.Sprintf(
		`SELECT plan_id, capability, status, output_summary, reason FROM %s ORDER BY plan_id, capability`,
		e.results))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ResultRow
	for rows.Next() {
		var r ResultRow
		if err := rows.Scan(&r.PlanID, &r.Capability, &r.Status, &r.OutputSummary, &r.Reason); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// PlanStatus 返回某计划的当前状态。
func (e *Executor) PlanStatus(ctx context.Context, planID int64) (string, error) {
	var st string
	err := e.pool.QueryRow(ctx, fmt.Sprintf(`SELECT status FROM %s WHERE id = $1`, e.plans), planID).Scan(&st)
	return st, err
}

// ResultCount 返回结果表行数。
func (e *Executor) ResultCount(ctx context.Context) (int64, error) {
	var n int64
	err := e.pool.QueryRow(ctx, fmt.Sprintf(`SELECT count(*) FROM %s`, e.results)).Scan(&n)
	return n, err
}
