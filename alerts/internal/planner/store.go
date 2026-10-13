package planner

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// 默认表名（测试用；生产表名待运维确认）。
const (
	// DefaultRequestsTable 待诊断请求表（消费者写入）。
	DefaultRequestsTable = "test_diagnosis_requests"
	// DefaultPlansTable 计划表。
	DefaultPlansTable = "test_diagnosis_plans"
)

// tablePattern 表名必须是 test_ 前缀的小写标识符（仅用于 DDL 拼装）。
var tablePattern = regexp.MustCompile(`^test_[a-z0-9_]+$`)

// ErrBadTable 表名不合法。
var ErrBadTable = errors.New("planner：表名必须是 test_ 前缀的合法标识符")

// Planner 规划器（读取待诊断请求 → 写计划）。
type Planner struct {
	pool     *pgxpool.Pool
	requests string
	plans    string
	profiles map[string]string // 源（小写）→ 画像
	now      func() time.Time
}

// Config 规划器配置。
type Config struct {
	// Pool 连接池（必填）。
	Pool *pgxpool.Pool
	// RequestsTable / PlansTable 表名（默认见常量）。
	RequestsTable string
	PlansTable    string
	// Profiles 源 → 画像（第十七轮 P1：规则按画像匹配）。
	Profiles map[string]string
	// Now 注入时钟（测试用）。
	Now func() time.Time
}

// New 构建规划器；表名不合法直接拒绝（fail-closed）。
func New(cfg Config) (*Planner, error) {
	if cfg.Pool == nil {
		return nil, errors.New("planner：连接池为空")
	}
	requests := cfg.RequestsTable
	if requests == "" {
		requests = DefaultRequestsTable
	}
	plans := cfg.PlansTable
	if plans == "" {
		plans = DefaultPlansTable
	}
	if !tablePattern.MatchString(requests) || !tablePattern.MatchString(plans) {
		return nil, fmt.Errorf("%w（requests=%q plans=%q）", ErrBadTable, requests, plans)
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	profiles := map[string]string{}
	for k, v := range cfg.Profiles {
		profiles[strings.ToLower(strings.TrimSpace(k))] = strings.ToLower(strings.TrimSpace(v))
	}
	return &Planner{pool: cfg.Pool, requests: requests, plans: plans, profiles: profiles, now: now}, nil
}

// EnsureSchema 建计划表（幂等）。
func (p *Planner) EnsureSchema(ctx context.Context) error {
	stmt := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
    id          bigserial   PRIMARY KEY,
    event_id    bigint      NOT NULL UNIQUE,
    fingerprint text        NOT NULL DEFAULT '',
    source      text        NOT NULL DEFAULT '',
    severity    text        NOT NULL DEFAULT '',
    profile     text        NOT NULL DEFAULT '',
    status      text        NOT NULL DEFAULT 'planned'
                CHECK (status IN ('planned','no_rule','running','done','failed','deferred','partial','not_executed')),
    rule_id     text        NOT NULL DEFAULT '',
    capabilities text[]     NOT NULL DEFAULT '{}',
    reason      text        NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL,
    updated_at  timestamptz NOT NULL
);`, p.plans)
	if _, err := p.pool.Exec(ctx, stmt); err != nil {
		return fmt.Errorf("planner：建表失败：%w", err)
	}
	return nil
}

// RunOnce 为尚未规划的 pending 请求生成计划，返回本次新增的计划行数。
//
// 第十七轮 P1：按**画像**匹配规则（源 → 画像由配置提供）；
// 无匹配规则时计划状态为 no_rule（不再用 planned 掩盖空计划）。
// 幂等：event_id 唯一约束 + ON CONFLICT DO NOTHING，重复规划不新增行。
// DefaultBatchSize 单次规划处理的请求数上限（第十八轮 W1）。
const DefaultBatchSize = 50

func (p *Planner) RunOnce(ctx context.Context) (int, error) {
	return p.RunOnceLimit(ctx, DefaultBatchSize)
}

// RunOnceLimit 为尚未规划的 pending 请求生成计划（单批上限 limit 条；
// limit <= 0 时用 DefaultBatchSize）。语义与 RunOnce 完全一致。
func (p *Planner) RunOnceLimit(ctx context.Context, limit int) (int, error) {
	if limit <= 0 {
		limit = DefaultBatchSize
	}
	rows, err := p.pool.Query(ctx, fmt.Sprintf(`SELECT r.event_id, r.fingerprint, r.source, r.severity
FROM %s r
LEFT JOIN %s pl ON pl.event_id = r.event_id
WHERE r.status = 'pending' AND pl.id IS NULL
ORDER BY r.event_id LIMIT $1`, p.requests, p.plans), limit)
	if err != nil {
		return 0, fmt.Errorf("planner：读取待规划请求失败：%w", err)
	}
	type req struct {
		eventID     int64
		fingerprint string
		source      string
		severity    string
	}
	var reqs []req
	for rows.Next() {
		var r req
		if err := rows.Scan(&r.eventID, &r.fingerprint, &r.source, &r.severity); err != nil {
			rows.Close()
			return 0, err
		}
		reqs = append(reqs, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	now := p.now().UTC()
	planned := 0
	for _, r := range reqs {
		profile := p.profiles[strings.ToLower(strings.TrimSpace(r.source))]
		plan := PlanFor(profile, r.severity) // 纯函数：无 I/O、不调用适配器
		caps := plan.Capabilities
		if caps == nil {
			caps = []string{}
		}
		status := StatusPlanned
		if plan.Reason != "" {
			status = StatusNoRule // 无匹配规则：状态即 no_rule
		}
		tag, ierr := p.pool.Exec(ctx, fmt.Sprintf(`INSERT INTO %s
(event_id, fingerprint, source, severity, profile, status, rule_id, capabilities, reason, created_at, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$10)
ON CONFLICT (event_id) DO NOTHING`, p.plans),
			r.eventID, r.fingerprint, r.source, r.severity, profile, status,
			plan.RuleID, caps, plan.Reason, now)
		if ierr != nil {
			return planned, fmt.Errorf("planner：写入计划失败：%w", ierr)
		}
		if tag.RowsAffected() == 1 {
			planned++
		}
	}
	return planned, nil
}

// PlanCount 返回计划表行数。
func (p *Planner) PlanCount(ctx context.Context) (int64, error) {
	var n int64
	err := p.pool.QueryRow(ctx, fmt.Sprintf(`SELECT count(*) FROM %s`, p.plans)).Scan(&n)
	return n, err
}

// PlanRow 一条计划记录（供测试与后续轮次读取）。
type PlanRow struct {
	EventID      int64
	Fingerprint  string
	Source       string
	Severity     string
	Profile      string
	Status       string
	RuleID       string
	Capabilities []string
	Reason       string
}

// Plans 返回全部计划记录（按 event_id 升序）。
func (p *Planner) Plans(ctx context.Context) ([]PlanRow, error) {
	rows, err := p.pool.Query(ctx, fmt.Sprintf(`SELECT event_id, fingerprint, source, severity, profile, status, rule_id, capabilities, reason
FROM %s ORDER BY event_id`, p.plans))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PlanRow
	for rows.Next() {
		var r PlanRow
		if err := rows.Scan(&r.EventID, &r.Fingerprint, &r.Source, &r.Severity, &r.Profile, &r.Status,
			&r.RuleID, &r.Capabilities, &r.Reason); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
