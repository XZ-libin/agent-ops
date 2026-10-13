// Package audit 实现只追加审计存储（ADR-005）：
//
//   - audit_events 表，哈希链（hash = sha256(「agent-ops-audit-v1」|| prev_hash ||
//     规范化 JSON(id/actor/action/target/payload))），规范化方式固定于 chainHash，
//     并有确定性测试（TestChainHashPinned）。
//   - 数据库层防护：专用角色 audit_writer 仅 INSERT + SELECT；
//     触发器拒绝 UPDATE / DELETE / TRUNCATE；
//     Append 用 advisory lock 串行化「读链尾 + 追加」，避免链分叉。
//   - 约束：只追加、不清理、不删除（保留策略待安全与合规确认）。
//
// 本包不包含任何适配器与执行写操作的业务逻辑。
package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DefaultLocalDSN 本地开发/测试的默认连接串（占位值，非真实凭据），
// 与 deploy/docker-compose.yaml 一致；测试可用环境变量 AGENT_OPS_TEST_DATABASE_URL 覆盖。
const DefaultLocalDSN = "postgres://agent_ops:agent_ops@localhost:55432/agent_ops?sslmode=disable"

// writerRole 审计专用数据库角色：仅授予 INSERT 与 SELECT。
const writerRole = "audit_writer"

// chainVersion 哈希链输入的前缀版本号：规范化方式变更时必须同步升级并留测试。
const chainVersion = "agent-ops-audit-v1"

// identifierPattern 表名/序列名必须是合法的小写标识符（仅用于 DDL 拼装，杜绝注入）。
var identifierPattern = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)

// Event 一条审计事件（写入前）。
type Event struct {
	ID      string // 事件 ID（调用方生成，如 ULID）
	Actor   string // 操作者：人或 Agent
	Action  string // 事件类型，如 "policy.decided"、"idempotency.abandoned"
	Target  string // 对象引用：asset_id / plan_id / key 等
	Payload any    // 事件详情；以规范化 JSON（键排序）存入 jsonb 并参与哈希
}

// StoredEvent 一条已落库的审计事件（只读查询结果；payload 为规范化 JSON）。
type StoredEvent struct {
	ID      string
	Actor   string
	Action  string
	Target  string
	Seq     int64
	Payload json.RawMessage
}

// ListByAction 按事件类型读取事件（按 seq 升序；只读，audit_writer 角色有 SELECT）。
// 供对账流程使用（如 gateway.Reconcile 扫描 executing 事件）。
func (s *Store) ListByAction(ctx context.Context, action string) ([]StoredEvent, error) {
	if err := s.validateTable(); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, fmt.Sprintf(
		`SELECT seq, id, actor, action, target, payload::text FROM %s WHERE action = $1 ORDER BY seq`, s.table), action)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []StoredEvent
	for rows.Next() {
		var (
			ev      StoredEvent
			payload string
		)
		if err := rows.Scan(&ev.Seq, &ev.ID, &ev.Actor, &ev.Action, &ev.Target, &payload); err != nil {
			return nil, err
		}
		ev.Payload = json.RawMessage(payload)
		out = append(out, ev)
	}
	return out, rows.Err()
}

// testTablePrefix 测试守卫要求的前缀：测试用审计表必须以 test_ 开头，
// 防止测试误写生产审计链。
const testTablePrefix = "test_"

// Store 只追加审计存储（PostgreSQL）。
type Store struct {
	pool      *pgxpool.Pool
	table     string // 表名（生产默认 audit_events；测试用 NewTestStore 且必须 test_ 前缀）
	testGuard bool   // 测试守卫：为 true 时仅允许 test_ 前缀表名
}

// NewStore 构建审计存储（生产用；表名默认 audit_events）。
func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool, table: "audit_events"}
}

// NewTestStore 构建测试用审计存储：表名必须以 test_ 开头，
// 否则写入与建表均被拒绝（见 TestGuardRejectsNonTestTable）。
func NewTestStore(pool *pgxpool.Pool, table string) *Store {
	return &Store{pool: pool, table: table, testGuard: true}
}

// TableName 返回生效的审计表名（测试做"seq 连续性"直查时使用）。
func (s *Store) TableName() string { return s.table }

// validateTable 校验表名：必须是合法标识符；测试模式下必须 test_ 前缀。
func (s *Store) validateTable() error {
	if !identifierPattern.MatchString(s.table) {
		return fmt.Errorf("illegal audit table name %q", s.table)
	}
	if s.testGuard && !strings.HasPrefix(s.table, testTablePrefix) {
		return fmt.Errorf("审计测试守卫：表名必须以 %q 开头（当前 %q），拒绝写入", testTablePrefix, s.table)
	}
	return nil
}

// EnsureSchema 建表、禁止改删触发器、专用角色与授权（幂等，可重复执行）。
func (s *Store) EnsureSchema(ctx context.Context) error {
	if err := s.validateTable(); err != nil {
		return err
	}
	t := s.table
	stmts := []string{
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
    seq        bigserial PRIMARY KEY,
    id         text        NOT NULL,
    actor      text        NOT NULL,
    action     text        NOT NULL,
    target     text        NOT NULL,
    payload    jsonb       NOT NULL,
    prev_hash  text        NOT NULL,
    hash       text        NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);`, t),
		fmt.Sprintf(`CREATE INDEX IF NOT EXISTS %s_action_idx ON %s (action);`, t, t),
		fmt.Sprintf(`CREATE OR REPLACE FUNCTION %s_forbid_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION '%s 只追加：%% 被禁止', TG_OP;
END $$;`, t, t),
		fmt.Sprintf(`DROP TRIGGER IF EXISTS %s_no_update ON %s;`, t, t),
		fmt.Sprintf(`CREATE TRIGGER %s_no_update BEFORE UPDATE OR DELETE ON %s
FOR EACH ROW EXECUTE FUNCTION %s_forbid_mutation();`, t, t, t),
		fmt.Sprintf(`DROP TRIGGER IF EXISTS %s_no_truncate ON %s;`, t, t),
		fmt.Sprintf(`CREATE TRIGGER %s_no_truncate BEFORE TRUNCATE ON %s
FOR EACH STATEMENT EXECUTE FUNCTION %s_forbid_mutation();`, t, t, t),
		`DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'audit_writer') THEN
    CREATE ROLE audit_writer NOLOGIN;
  END IF;
END $$;`,
		fmt.Sprintf(`GRANT INSERT, SELECT ON TABLE %s TO %s;`, t, writerRole),
		fmt.Sprintf(`GRANT USAGE, SELECT ON SEQUENCE %s_seq_seq TO %s;`, t, writerRole),
	}
	for _, stmt := range stmts {
		if _, err := s.pool.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("audit schema: %w", err)
		}
	}
	return nil
}

// canonicalPayload 将任意 JSON 归一化为规范字节（键排序、无空白）。
// Append 与 Verify 两端必须使用同一归一化：jsonb 存储会重排键序，
// 只有两端都做 canonicalPayload 才能保证链上哈希一致。
func canonicalPayload(b []byte) ([]byte, error) {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, fmt.Errorf("audit canonical payload: %w", err)
	}
	out, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("audit canonical payload: %w", err)
	}
	return out, nil
}

// chainHash 计算链上记录哈希（规范化方式固定，见测试 TestChainHashPinned）。
// 输入：前缀版本、上一条哈希、当前记录的 id/actor/action/target 与规范化 payload。
func chainHash(prevHash, id, actor, action, target string, payload []byte) (string, error) {
	in, err := json.Marshal([]any{
		chainVersion, prevHash, id, actor, action, target, json.RawMessage(payload),
	})
	if err != nil {
		return "", fmt.Errorf("audit chain hash: %w", err)
	}
	sum := sha256.Sum256(in)
	return hex.EncodeToString(sum[:]), nil
}

// Append 追加一条审计事件，返回该记录链上哈希。
// 事务内：SET LOCAL ROLE audit_writer → advisory lock 串行化 → 读链尾 → 追加。
func (s *Store) Append(ctx context.Context, ev Event) (string, error) {
	if err := s.validateTable(); err != nil {
		return "", err
	}
	raw, err := json.Marshal(ev.Payload) // 键排序
	if err != nil {
		return "", fmt.Errorf("audit append payload: %w", err)
	}
	payload, err := canonicalPayload(raw) // 与 Verify 同一归一化
	if err != nil {
		return "", err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// 以专用角色执行（仅 INSERT/SELECT）。
	if _, err := tx.Exec(ctx, fmt.Sprintf("SET LOCAL ROLE %s", writerRole)); err != nil {
		return "", err
	}
	// 串行化链尾读取与追加，避免并发分叉（锁键取表名的 hashtext）。
	if _, err := tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtext($1)::bigint)`, s.table); err != nil {
		return "", err
	}

	prevHash := ""
	err = tx.QueryRow(ctx,
		fmt.Sprintf("SELECT hash FROM %s ORDER BY seq DESC LIMIT 1", s.table)).Scan(&prevHash)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}

	h, err := chainHash(prevHash, ev.ID, ev.Actor, ev.Action, ev.Target, payload)
	if err != nil {
		return "", err
	}

	var seq int64
	err = tx.QueryRow(ctx,
		fmt.Sprintf(`INSERT INTO %s (id, actor, action, target, payload, prev_hash, hash)
VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING seq`, s.table),
		ev.ID, ev.Actor, ev.Action, ev.Target, payload, prevHash, h).Scan(&seq)
	if err != nil {
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return h, nil
}

// Verify 从头校验整条链（哈希链 + seq 连续/单调），
// 返回第一个问题的 seq（全部一致返回 0）。
func (s *Store) Verify(ctx context.Context) (int64, error) {
	seq, _, err := s.VerifyWithReason(ctx)
	return seq, err
}

// VerifyWithReason 校验哈希链与 seq 连续性/单调性，返回首个问题位置与原因。
// 注意（ADR-005 修订 1）：链内校验能发现中间篡改与空洞，
// 不能发现尾部截断——截断检测依赖外部锚点，待对象存储选型确定后实现。
func (s *Store) VerifyWithReason(ctx context.Context) (int64, string, error) {
	rows, err := s.pool.Query(ctx,
		fmt.Sprintf(`SELECT seq, id, actor, action, target, payload, prev_hash, hash
FROM %s ORDER BY seq`, s.table))
	if err != nil {
		return 0, "", err
	}
	defer rows.Close()

	prevHash := ""
	expected := int64(1) // seq 必须从 1 开始连续递增
	for rows.Next() {
		var (
			seq            int64
			id             string
			actor          string
			action         string
			target         string
			payload        []byte
			prevHashStored string
			hash           string
		)
		if err := rows.Scan(&seq, &id, &actor, &action, &target, &payload, &prevHashStored, &hash); err != nil {
			return 0, "", err
		}
		if seq != expected {
			return seq, fmt.Sprintf("seq 空洞或乱序：实际 %d，期望 %d", seq, expected), nil
		}
		canon, err := canonicalPayload(payload) // 与 Append 同一归一化（jsonb 键序重排兼容）
		if err != nil {
			return 0, "", err
		}
		want, err := chainHash(prevHash, id, actor, action, target, canon)
		if err != nil {
			return 0, "", err
		}
		if prevHashStored != prevHash || hash != want {
			return seq, fmt.Sprintf("哈希链不一致：seq %d 的 prev_hash/hash 与重算值不符", seq), nil
		}
		prevHash = hash
		expected++
	}
	return 0, "", rows.Err()
}
