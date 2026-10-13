// Package store 是告警入口的 PostgreSQL 存储（第十四轮 A1）。
//
// 表（只在测试运行 schema 内使用；生产表名待运维确认）：
//   - test_alerts：告警去重表（fingerprint + 窗口内计数）；
//   - test_outbox：outbox 表（每条**新**告警一条 alert.received 事件）。
//
// 表名强制 test_ 前缀（测试守卫）；生产命名表不得删除（本轮不涉及）。
package store

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/XZ-libin/agent-ops/alerts/internal/ingest"
)

// 默认表名（测试用；生产表名待运维确认）。
const (
	DefaultAlertsTable = "test_alerts"
	DefaultOutboxTable = "test_outbox"
)

// tablePattern 表名必须是 test_ 前缀的小写标识符（仅用于 DDL 拼装，杜绝注入）。
var tablePattern = regexp.MustCompile(`^test_[a-z0-9_]+$`)

// ErrBadTable 表名不合法（非 test_ 前缀）。
var ErrBadTable = errors.New("store：表名必须是 test_ 前缀的合法标识符")

// Store PostgreSQL 告警存储。
type Store struct {
	pool        *pgxpool.Pool
	alertsTable string
	outboxTable string
}

// New 构建存储；表名不合法直接拒绝（fail-closed）。
func New(pool *pgxpool.Pool, alertsTable, outboxTable string) (*Store, error) {
	if pool == nil {
		return nil, errors.New("store：连接池为空")
	}
	if alertsTable == "" {
		alertsTable = DefaultAlertsTable
	}
	if outboxTable == "" {
		outboxTable = DefaultOutboxTable
	}
	if !tablePattern.MatchString(alertsTable) || !tablePattern.MatchString(outboxTable) {
		return nil, fmt.Errorf("%w（alerts=%q outbox=%q）", ErrBadTable, alertsTable, outboxTable)
	}
	return &Store{pool: pool, alertsTable: alertsTable, outboxTable: outboxTable}, nil
}

// EnsureSchema 建表（幂等）。
func (s *Store) EnsureSchema(ctx context.Context) error {
	stmts := []string{
		// 第十五轮 R2：fingerprint 为主键——"每个 fingerprint 一行，upsert 计数"。
		// 行数上限由不同 fingerprint 数量决定，不随持续时间增长。
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
    fingerprint text        PRIMARY KEY,
    source      text        NOT NULL,
    severity    text        NOT NULL CHECK (severity IN ('info','warning','critical')),
    asset_id    text        NOT NULL,
    summary     text        NOT NULL DEFAULT '',
    count       bigint      NOT NULL DEFAULT 1,
    window_start timestamptz NOT NULL,
    first_seen  timestamptz NOT NULL,
    last_seen   timestamptz NOT NULL
);`, s.alertsTable),
		// 兼容旧结构（若存在 id 列的表）：补窗口列（幂等）。
		fmt.Sprintf(`ALTER TABLE %s ADD COLUMN IF NOT EXISTS window_start timestamptz;`, s.alertsTable),
		fmt.Sprintf(`UPDATE %s SET window_start = first_seen WHERE window_start IS NULL;`, s.alertsTable),
		// 第十五轮 C1：outbox 增加消费状态（pending / consumed）。
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
    id          bigserial   PRIMARY KEY,
    event_type  text        NOT NULL,
    payload     jsonb       NOT NULL,
    status      text        NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','consumed','dead')),
    attempts    integer     NOT NULL DEFAULT 0,
    next_attempt_at timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now(),
    consumed_at timestamptz
);`, s.outboxTable),
		// 兼容旧结构（幂等）。
		fmt.Sprintf(`ALTER TABLE %s ADD COLUMN IF NOT EXISTS status text NOT NULL DEFAULT 'pending';`, s.outboxTable),
		fmt.Sprintf(`ALTER TABLE %s ADD COLUMN IF NOT EXISTS consumed_at timestamptz;`, s.outboxTable),
		// 第十六轮 R3：重试计数与退避时间（status 增加 dead）。
		fmt.Sprintf(`ALTER TABLE %s ADD COLUMN IF NOT EXISTS attempts integer NOT NULL DEFAULT 0;`, s.outboxTable),
		fmt.Sprintf(`ALTER TABLE %s ADD COLUMN IF NOT EXISTS next_attempt_at timestamptz;`, s.outboxTable),
		fmt.Sprintf(`ALTER TABLE %s DROP CONSTRAINT IF EXISTS %s_status_check;`, s.outboxTable, s.outboxTable),
		fmt.Sprintf(`ALTER TABLE %s ADD CONSTRAINT %s_status_check
CHECK (status IN ('pending','consumed','dead'));`, s.outboxTable, s.outboxTable),
		fmt.Sprintf(`CREATE INDEX IF NOT EXISTS %s_pending_idx ON %s (event_type, status, id);`,
			s.outboxTable, s.outboxTable),
	}
	for _, stmt := range stmts {
		if _, err := s.pool.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("store：建表失败：%w", err)
		}
	}
	return nil
}

// Record 记录一条告警（第十五轮 R2：fingerprint 主键 upsert）。
//
// 语义：
//   - 该 fingerprint **不存在** → 插入一行（count=1，window_start=now），
//     并写入 outbox 事件 alert.received（窗口首次打开）；
//   - 已存在且 `now - window_start < window` → 窗口内重复：只更新 count 与
//     last_seen，**不新增行、不写 outbox**；
//   - 已存在且窗口已过期 → 重新打开窗口：count 重置为 1、window_start=now，
//     并**再次写入** outbox 事件。
//
// 原子性：单条 INSERT ... ON CONFLICT DO UPDATE（行级锁），无需应用层先查后写。
func (s *Store) Record(ctx context.Context, a ingest.Alert, window time.Duration, now time.Time) (ingest.Decision, error) {
	if window <= 0 {
		window = ingest.DefaultDedupWindow
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return ingest.Decision{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// 单条 upsert：窗口内 → count+1；窗口过期 → 重置 count 与窗口起点。
	// 通过 RETURNING 的 count 与 window_start 判定"是否打开了新窗口"。
	var (
		newCount     int64
		windowStart  time.Time
		windowOpened bool
	)
	err = tx.QueryRow(ctx, fmt.Sprintf(`INSERT INTO %s
(fingerprint, source, severity, asset_id, summary, count, window_start, first_seen, last_seen)
VALUES ($1,$2,$3,$4,$5,1,$6,$6,$6)
ON CONFLICT (fingerprint) DO UPDATE SET
  count = CASE
            WHEN %s.window_start <= $7 THEN 1
            ELSE %s.count + 1
          END,
  window_start = CASE
                   WHEN %s.window_start <= $7 THEN $6
                   ELSE %s.window_start
                 END,
  severity = $3,
  summary  = $5,
  last_seen = $6
RETURNING count, window_start, (window_start = $6 AND count = 1) AS opened`,
		s.alertsTable, s.alertsTable, s.alertsTable, s.alertsTable, s.alertsTable),
		a.Fingerprint, a.Source, a.Severity, a.AssetID, a.Summary, now.UTC(), now.Add(-window).UTC()).
		Scan(&newCount, &windowStart, &windowOpened)
	if err != nil {
		return ingest.Decision{}, err
	}

	// windowOpened 由 SQL 判定（window_start = now 且 count = 1）：
	// 只有"本次调用打开了窗口"才写 outbox；并发同刻的重复请求 count > 1，
	// 不会被误判为打开窗口。
	if windowOpened {
		payload, merr := canonicalPayload(a)
		if merr != nil {
			return ingest.Decision{}, merr
		}
		if _, oerr := tx.Exec(ctx, fmt.Sprintf(`INSERT INTO %s (event_type, payload) VALUES ($1,$2)`,
			s.outboxTable), ingest.OutboxEventType, payload); oerr != nil {
			return ingest.Decision{}, oerr
		}
	}
	if cerr := tx.Commit(ctx); cerr != nil {
		return ingest.Decision{}, cerr
	}
	return ingest.Decision{Deduplicated: !windowOpened, ExistingCount: newCount}, nil
}

// Counts 返回两张表的行数（供集成测试断言）。
func (s *Store) Counts(ctx context.Context) (alerts, outbox int64, err error) {
	if err = s.pool.QueryRow(ctx, fmt.Sprintf(`SELECT count(*) FROM %s`, s.alertsTable)).Scan(&alerts); err != nil {
		return 0, 0, err
	}
	if err = s.pool.QueryRow(ctx, fmt.Sprintf(`SELECT count(*) FROM %s`, s.outboxTable)).Scan(&outbox); err != nil {
		return 0, 0, err
	}
	return alerts, outbox, nil
}

// AlertCount 返回某 fingerprint 的当前计数（0 表示不存在）。
// R2：fingerprint 为主键，每个 fingerprint 至多一行。
func (s *Store) AlertCount(ctx context.Context, fingerprint string) (int64, error) {
	var count int64
	err := s.pool.QueryRow(ctx, fmt.Sprintf(
		`SELECT count FROM %s WHERE fingerprint = $1`, s.alertsTable), fingerprint).Scan(&count)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	return count, err
}

// OutboxPayloads 返回 outbox 中指定事件类型的负载（供断言"不含签名/密钥"）。
func (s *Store) OutboxPayloads(ctx context.Context, eventType string) ([]string, error) {
	rows, err := s.pool.Query(ctx, fmt.Sprintf(
		`SELECT payload::text FROM %s WHERE event_type = $1 ORDER BY id`, s.outboxTable), eventType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// canonicalPayload 生成规范化 JSON（键序固定，与 ADR-009 规则一致：
// 结构体字段按声明顺序、无多余空白）。
func canonicalPayload(a ingest.Alert) ([]byte, error) {
	var b strings.Builder
	b.WriteString(`{"source":`)
	b.WriteString(jsonString(a.Source))
	b.WriteString(`,"severity":`)
	b.WriteString(jsonString(a.Severity))
	b.WriteString(`,"asset_id":`)
	b.WriteString(jsonString(a.AssetID))
	b.WriteString(`,"fingerprint":`)
	b.WriteString(jsonString(a.Fingerprint))
	b.WriteString(`,"summary":`)
	b.WriteString(jsonString(a.Summary))
	b.WriteString(`,"received_at":`)
	b.WriteString(jsonString(a.ReceivedAt.UTC().Format(time.RFC3339Nano)))
	b.WriteString(`}`)
	return []byte(b.String()), nil
}

// jsonString 最小化 JSON 字符串转义（仅处理必需字符）。
func jsonString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				b.WriteString(fmt.Sprintf(`\u%04x`, r))
				continue
			}
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
