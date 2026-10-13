// Package consumer 是 outbox 消费者骨架（第十五轮 C1）。
//
// 职责边界（本轮**只做骨架**）：
//   - 读取 outbox 中 `alert.received` 且未消费的事件，按事件 ID 顺序处理；
//   - 幂等：同一事件只生成一条待诊断记录（test_diagnosis_requests.event_id 唯一约束），
//     重复消费不产生新行；
//   - 处理完成后把 outbox 事件标记为 consumed；
//   - **不做诊断**：不调用任何适配器、不执行任何命令；待诊断记录状态固定 pending。
//
// 崩溃语义：写待诊断记录与标记 consumed 在**两个独立事务**中完成。
// 若进程在两者之间崩溃，事件保持 pending；下次运行会因唯一约束跳过重复写入，
// 并继续标记 consumed——不产生重复记录。
package consumer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ORG/agent-ops/alerts/internal/ingest"
)

// 重试与死信参数（第十六轮 R3，裁决）。
const (
	// MaxAttempts 每个事件的最大尝试次数；第 5 次失败后置 dead。
	MaxAttempts = 5
)

// Backoff 返回第 n 次失败后的退避间隔（n=1..4 → 1s/2s/4s/8s）。
// 第 MaxAttempts 次失败不再退避（直接置 dead）。
func Backoff(attempt int) time.Duration {
	switch attempt {
	case 1:
		return 1 * time.Second
	case 2:
		return 2 * time.Second
	case 3:
		return 4 * time.Second
	case 4:
		return 8 * time.Second
	}
	return 0
}

// 事件状态（outbox.status）。
const (
	// StatusPending 待处理（可被自动重试）。
	StatusPending = "pending"
	// StatusConsumed 已消费（终态）。
	StatusConsumed = "consumed"
	// StatusDead 死信（尝试次数耗尽，**不再自动重试**；数据保留，人工重投由后续轮次实现）。
	StatusDead = "dead"
)

// 默认表名（测试用；生产表名待运维确认）。
const (
	// DefaultOutboxTable outbox 表。
	DefaultOutboxTable = "test_outbox"
	// DefaultRequestsTable 待诊断记录表。
	DefaultRequestsTable = "test_diagnosis_requests"
	// DefaultBatchSize 单次运行处理的事件上限。
	DefaultBatchSize = 100
)

// tablePattern 表名必须是 test_ 前缀的小写标识符（仅用于 DDL 拼装，杜绝注入）。
var tablePattern = regexp.MustCompile(`^test_[a-z0-9_]+$`)

// ErrBadTable 表名不合法。
var ErrBadTable = errors.New("consumer：表名必须是 test_ 前缀的合法标识符")

// Event 一条 outbox 事件。
type Event struct {
	ID      int64
	Type    string
	Payload []byte
}

// Consumer outbox 消费者。
type Consumer struct {
	pool      *pgxpool.Pool
	outbox    string
	requests  string
	batch     int
	now       func() time.Time
	processFn func(ctx context.Context, ev Event) error
}

// Config 消费者配置。
type Config struct {
	// Pool 连接池（必填）。
	Pool *pgxpool.Pool
	// OutboxTable / RequestsTable 表名（默认 DefaultOutboxTable / DefaultRequestsTable）。
	OutboxTable   string
	RequestsTable string
	// BatchSize 单次处理上限（<=0 用 DefaultBatchSize）。
	BatchSize int
	// Now 注入时钟（测试用）。
	Now func() time.Time
	// Process 处理钩子（测试注入失败用）；nil 时使用默认处理（写待诊断记录）。
	Process func(ctx context.Context, ev Event) error
}

// New 构建消费者；表名不合法直接拒绝（fail-closed）。
func New(cfg Config) (*Consumer, error) {
	if cfg.Pool == nil {
		return nil, errors.New("consumer：连接池为空")
	}
	outbox := cfg.OutboxTable
	if outbox == "" {
		outbox = DefaultOutboxTable
	}
	requests := cfg.RequestsTable
	if requests == "" {
		requests = DefaultRequestsTable
	}
	if !tablePattern.MatchString(outbox) || !tablePattern.MatchString(requests) {
		return nil, fmt.Errorf("%w（outbox=%q requests=%q）", ErrBadTable, outbox, requests)
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	c := &Consumer{
		pool:     cfg.Pool,
		outbox:   outbox,
		requests: requests,
		batch:    cfg.BatchSize,
		now:      now,
	}
	if c.batch <= 0 {
		c.batch = DefaultBatchSize
	}
	c.processFn = cfg.Process
	if c.processFn == nil {
		c.processFn = c.CreateDiagnosisRequest
	}
	return c, nil
}

// EnsureSchema 建待诊断记录表（幂等）；outbox 表由 store.EnsureSchema 建立。
func (c *Consumer) EnsureSchema(ctx context.Context) error {
	stmt := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
    id         bigserial   PRIMARY KEY,
    event_id   bigint      NOT NULL UNIQUE,
    fingerprint text       NOT NULL DEFAULT '',
    source     text        NOT NULL DEFAULT '',
    severity   text        NOT NULL DEFAULT '',
    asset_id   text        NOT NULL DEFAULT '',
    status     text        NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','diagnosing','done','skipped')),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);`, c.requests)
	if _, err := c.pool.Exec(ctx, stmt); err != nil {
		return fmt.Errorf("consumer：建表失败：%w", err)
	}
	return nil
}

// RunOnce 处理一批可重试事件，返回本次实际消费的事件数。
//
// 事件按 ID 升序处理；失败的事件按 R3 语义记录尝试次数与退避时间：
//   - 第 1..4 次失败：attempts++ 并设置 next_attempt_at = now + Backoff(attempts)，
//     事件保持 pending（退避时间未到时不会被再次选中）；
//   - 第 5 次（MaxAttempts）失败：状态置 dead，不再自动重试（数据保留）。
//
// 处理失败**不会中断整批**：本批继续处理其余事件，最后返回遇到的第一个错误。
func (c *Consumer) RunOnce(ctx context.Context) (int, error) {
	return c.RunOnceLimit(ctx, c.batch)
}

// RunOnceLimit 处理一批可重试事件（单批上限 limit 条；limit <= 0 时用 c.batch）。
// 语义与 RunOnce 完全一致，仅批量上限可覆盖（第十八轮 W1：worker 每轮上限 100）。
func (c *Consumer) RunOnceLimit(ctx context.Context, limit int) (int, error) {
	if limit <= 0 {
		limit = c.batch
	}
	events, err := c.pending(ctx, limit)
	if err != nil {
		return 0, err
	}
	processed := 0
	var firstErr error
	for _, ev := range events {
		if perr := c.processFn(ctx, ev); perr != nil {
			if ferr := c.recordFailure(ctx, ev.ID, perr); ferr != nil {
				return processed, ferr
			}
			if firstErr == nil {
				firstErr = fmt.Errorf("consumer：事件 %d 处理失败：%w", ev.ID, perr)
			}
			continue
		}
		if merr := c.MarkConsumed(ctx, ev.ID); merr != nil {
			return processed, merr
		}
		processed++
	}
	return processed, firstErr
}

// recordFailure 记录一次失败：attempts++；达到上限置 dead，否则设置退避时间。
func (c *Consumer) recordFailure(ctx context.Context, eventID int64, cause error) error {
	now := c.now().UTC()
	// 先自增并读取当前尝试次数（行级原子）。
	var attempts int
	if err := c.pool.QueryRow(ctx, fmt.Sprintf(
		`UPDATE %s SET attempts = attempts + 1 WHERE id = $1 RETURNING attempts`,
		c.outbox), eventID).Scan(&attempts); err != nil {
		return fmt.Errorf("consumer：记录失败次数失败：%w", err)
	}
	if attempts >= MaxAttempts {
		if _, err := c.pool.Exec(ctx, fmt.Sprintf(
			`UPDATE %s SET status = $2, next_attempt_at = NULL WHERE id = $1`,
			c.outbox), eventID, StatusDead); err != nil {
			return fmt.Errorf("consumer：置死信失败：%w", err)
		}
		return nil
	}
	next := now.Add(Backoff(attempts))
	if _, err := c.pool.Exec(ctx, fmt.Sprintf(
		`UPDATE %s SET next_attempt_at = $2 WHERE id = $1`, c.outbox), eventID, next); err != nil {
		return fmt.Errorf("consumer：设置退避时间失败：%w", err)
	}
	_ = cause // 失败原因不落库（避免把外部错误原文写入存储）
	return nil
}

// Attempts 返回某事件的尝试次数（供测试与运维核对）。
func (c *Consumer) Attempts(ctx context.Context, eventID int64) (int, error) {
	var n int
	err := c.pool.QueryRow(ctx, fmt.Sprintf(`SELECT attempts FROM %s WHERE id = $1`, c.outbox), eventID).Scan(&n)
	return n, err
}

// Status 返回某事件的状态（供测试与运维核对）。
func (c *Consumer) Status(ctx context.Context, eventID int64) (string, error) {
	var st string
	err := c.pool.QueryRow(ctx, fmt.Sprintf(`SELECT status FROM %s WHERE id = $1`, c.outbox), eventID).Scan(&st)
	return st, err
}

// DeadCount 返回死信事件数。
func (c *Consumer) DeadCount(ctx context.Context) (int64, error) {
	var n int64
	err := c.pool.QueryRow(ctx, fmt.Sprintf(
		`SELECT count(*) FROM %s WHERE status = $1`, c.outbox), StatusDead).Scan(&n)
	return n, err
}

// pending 读取未消费的 alert.received 事件（按 ID 升序，上限 limit 条）。
func (c *Consumer) pending(ctx context.Context, limit int) ([]Event, error) {
	rows, err := c.pool.Query(ctx, fmt.Sprintf(`SELECT id, event_type, payload
FROM %s WHERE event_type = $1 AND status = 'pending'
  AND (next_attempt_at IS NULL OR next_attempt_at <= $3)
ORDER BY id LIMIT $2`,
		c.outbox), ingest.OutboxEventType, limit, c.now().UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var ev Event
		var payload []byte
		if err := rows.Scan(&ev.ID, &ev.Type, &payload); err != nil {
			return nil, err
		}
		ev.Payload = payload
		out = append(out, ev)
	}
	return out, rows.Err()
}

// CreateDiagnosisRequest 默认处理：写入一条待诊断记录（幂等，event_id 唯一约束）。
// 本轮不做诊断：状态固定 pending。
func (c *Consumer) CreateDiagnosisRequest(ctx context.Context, ev Event) error {
	fp, source, severity, assetID := parseAlertPayload(ev.Payload)
	now := c.now().UTC()
	_, err := c.pool.Exec(ctx, fmt.Sprintf(`INSERT INTO %s
(event_id, fingerprint, source, severity, asset_id, status, created_at, updated_at)
VALUES ($1,$2,$3,$4,$5,'pending',$6,$6)
ON CONFLICT (event_id) DO NOTHING`, c.requests),
		ev.ID, fp, source, severity, assetID, now)
	if err != nil {
		return fmt.Errorf("consumer：写入待诊断记录失败：%w", err)
	}
	return nil
}

// MarkConsumed 标记 outbox 事件为已消费（幂等）。
func (c *Consumer) MarkConsumed(ctx context.Context, eventID int64) error {
	_, err := c.pool.Exec(ctx, fmt.Sprintf(
		`UPDATE %s SET status = 'consumed', consumed_at = $2 WHERE id = $1 AND status = 'pending'`,
		c.outbox), eventID, c.now().UTC())
	return err
}

// PendingCount 返回未消费事件数（供测试与运维核对）。
func (c *Consumer) PendingCount(ctx context.Context) (int64, error) {
	var n int64
	err := c.pool.QueryRow(ctx, fmt.Sprintf(
		`SELECT count(*) FROM %s WHERE event_type = $1 AND status = 'pending'`,
		c.outbox), ingest.OutboxEventType).Scan(&n)
	return n, err
}

// RequestCount 返回待诊断记录数（供测试核对）。
func (c *Consumer) RequestCount(ctx context.Context) (int64, error) {
	var n int64
	err := c.pool.QueryRow(ctx, fmt.Sprintf(`SELECT count(*) FROM %s`, c.requests)).Scan(&n)
	return n, err
}

// RequestStatuses 返回全部待诊断记录的状态（供测试核对固定为 pending）。
func (c *Consumer) RequestStatuses(ctx context.Context) ([]string, error) {
	rows, err := c.pool.Query(ctx, fmt.Sprintf(`SELECT status FROM %s ORDER BY id`, c.requests))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// parseAlertPayload 从 outbox 负载中提取告警字段（缺失即空串；不解析失败即报错）。
func parseAlertPayload(payload []byte) (fingerprint, source, severity, assetID string) {
	var p struct {
		Source      string `json:"source"`
		Severity    string `json:"severity"`
		AssetID     string `json:"asset_id"`
		Fingerprint string `json:"fingerprint"`
	}
	if err := jsonUnmarshal(payload, &p); err != nil {
		return "", "", "", ""
	}
	return p.Fingerprint, p.Source, p.Severity, p.AssetID
}

// jsonUnmarshal 包装 encoding/json。
func jsonUnmarshal(data []byte, v any) error { return json.Unmarshal(data, v) }
