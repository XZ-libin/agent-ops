// Package redrive 实现**仅测试模式**的人工重投（第十七轮 P3）。
//
// 背景：消费者第 5 次失败后把事件置为 dead（ADR-015），死信不再自动重试。
// 本包提供人工重新投递通道：把 dead 事件置回 pending 并清零尝试次数，
// 同时写入 test_redrive_log（event_id、operator、时间戳、原状态）留痕。
//
// 安全边界：
//   - **仅测试模式**（mode=test）可用；其他模式一律拒绝（生产重投流程待运维设计）；
//   - 必须显式 -confirm 且提供 -operator（缺一即拒绝）；
//   - 只允许对 status=dead 的事件操作（其他状态拒绝）；
//   - 不删除任何数据；不调用任何适配器。
package redrive

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 默认表名（测试用；生产表名待运维确认）。
const (
	// DefaultOutboxTable outbox 表。
	DefaultOutboxTable = "test_outbox"
	// DefaultLogTable 重投日志表。
	DefaultLogTable = "test_redrive_log"
	// ModeTest 允许执行重投的模式。
	ModeTest = "test"
)

// tablePattern 表名必须是 test_ 前缀的小写标识符（仅用于 DDL 拼装）。
var tablePattern = regexp.MustCompile(`^test_[a-z0-9_]+$`)

// 拒绝原因（错误即原因，命令层据此返回非零退出码并打印）。
var (
	// ErrConfirmRequired 缺少 -confirm。
	ErrConfirmRequired = errors.New("redrive：必须显式传入 -confirm 才执行重投")
	// ErrOperatorRequired 缺少 -operator。
	ErrOperatorRequired = errors.New("redrive：必须提供 -operator <名称>（重投需要留痕责任人）")
	// ErrTestModeOnly 非测试模式。
	ErrTestModeOnly = errors.New("redrive：仅 mode=test 可用（生产重投流程待运维确认后再设计）")
	// ErrEventNotFound 事件不存在。
	ErrEventNotFound = errors.New("redrive：事件不存在")
	// ErrNotDead 事件状态不是 dead。
	ErrNotDead = errors.New("redrive：只允许对 dead 状态的事件重投")
	// ErrBadTable 表名不合法。
	ErrBadTable = errors.New("redrive：表名必须是 test_ 前缀的合法标识符")
)

// Redriver 人工重投器。
type Redriver struct {
	pool   *pgxpool.Pool
	outbox string
	log    string
	now    func() time.Time
}

// Config 配置。
type Config struct {
	// Pool 连接池（必填）。
	Pool *pgxpool.Pool
	// OutboxTable / LogTable 表名（默认见常量）。
	OutboxTable string
	LogTable    string
	// Now 注入时钟（测试用）。
	Now func() time.Time
}

// New 构建重投器；表名不合法直接拒绝（fail-closed）。
func New(cfg Config) (*Redriver, error) {
	if cfg.Pool == nil {
		return nil, errors.New("redrive：连接池为空")
	}
	outbox := cfg.OutboxTable
	if outbox == "" {
		outbox = DefaultOutboxTable
	}
	logTable := cfg.LogTable
	if logTable == "" {
		logTable = DefaultLogTable
	}
	if !tablePattern.MatchString(outbox) || !tablePattern.MatchString(logTable) {
		return nil, fmt.Errorf("%w（outbox=%q log=%q）", ErrBadTable, outbox, logTable)
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Redriver{pool: cfg.Pool, outbox: outbox, log: logTable, now: now}, nil
}

// EnsureSchema 建重投日志表（幂等）。
func (r *Redriver) EnsureSchema(ctx context.Context) error {
	stmt := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
    id              bigserial   PRIMARY KEY,
    event_id        bigint      NOT NULL,
    operator        text        NOT NULL,
    previous_status text        NOT NULL,
    created_at      timestamptz NOT NULL
);`, r.log)
	if _, err := r.pool.Exec(ctx, stmt); err != nil {
		return fmt.Errorf("redrive：建表失败：%w", err)
	}
	return nil
}

// Redrive 对指定事件执行人工重投。
// 拒绝条件（任一命中即返回对应错误，不修改任何数据）：
//   - mode 不是 test；缺 confirm；缺 operator；
//   - 事件不存在；事件状态不是 dead。
//
// 成功：状态置 pending、attempts 置 0、next_attempt_at 清空，
// 并写入 test_redrive_log（event_id、operator、时间戳、原状态）。
func (r *Redriver) Redrive(ctx context.Context, eventID int64, operator string, confirm bool, mode string) error {
	if strings.TrimSpace(mode) != ModeTest {
		return ErrTestModeOnly
	}
	if !confirm {
		return ErrConfirmRequired
	}
	op := strings.TrimSpace(operator)
	if op == "" {
		return ErrOperatorRequired
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// 行级锁读取当前状态（并发重投同一事件时串行化）。
	var status string
	err = tx.QueryRow(ctx, fmt.Sprintf(
		`SELECT status FROM %s WHERE id = $1 FOR UPDATE`, r.outbox), eventID).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrEventNotFound
	}
	if err != nil {
		return err
	}
	if status != "dead" {
		return fmt.Errorf("%w（当前状态 %q）", ErrNotDead, status)
	}

	// 置回 pending：attempts 归零、清空退避时间。
	if _, err := tx.Exec(ctx, fmt.Sprintf(`UPDATE %s
SET status = 'pending', attempts = 0, next_attempt_at = NULL, consumed_at = NULL
WHERE id = $1`, r.outbox), eventID); err != nil {
		return err
	}
	// 留痕：event_id、operator、时间戳、原状态。
	if _, err := tx.Exec(ctx, fmt.Sprintf(
		`INSERT INTO %s (event_id, operator, previous_status, created_at) VALUES ($1,$2,$3,$4)`,
		r.log), eventID, op, status, r.now().UTC()); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// LogCount 返回重投日志行数（供测试核对）。
func (r *Redriver) LogCount(ctx context.Context) (int64, error) {
	var n int64
	err := r.pool.QueryRow(ctx, fmt.Sprintf(`SELECT count(*) FROM %s`, r.log)).Scan(&n)
	return n, err
}
