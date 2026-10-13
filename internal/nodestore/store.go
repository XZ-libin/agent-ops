// Package nodestore 是节点身份与健康的**持久化层**（第二十二轮 N6）。
//
// 三张表（一律 `test_` 前缀；只在 run schema 内创建）：
//
//	test_nodes             节点状态（node_id 主键）
//	test_enroll_tokens     一次性注册令牌（token_hash 主键，只存哈希）
//	test_cert_revocations  证书吊销表（serial 主键）
//
// 关键约束：
//   - **令牌消费必须原子**：单条 UPDATE ... WHERE used_at IS NULL AND expires_at > now，
//     检查影响行数；**不使用"先查后写"**（并发下会双花）；
//   - 只存令牌**哈希**，永不存明文；
//   - 本包实现 nodeidentity.RevocationChecker（每次 mTLS 校验都会查询）。
package nodestore

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ORG/agent-ops/internal/nodeidentity"
)

// 默认表名（一律 test_ 前缀；生产表名待运维确认）。
const (
	// DefaultNodesTable 节点状态表。
	DefaultNodesTable = "test_nodes"
	// DefaultTokensTable 注册令牌表。
	DefaultTokensTable = "test_enroll_tokens"
	// DefaultRevocationsTable 证书吊销表。
	DefaultRevocationsTable = "test_cert_revocations"
	// DefaultCertsTable 证书状态机表（第二十四轮 T1）。
	DefaultCertsTable = "test_node_certs"
	// DefaultSweepStateTable 扫描器告警节流状态表（第二十四轮 T2，由迁移 005 创建）。
	// 名称与 nodemigrate.DefaultTables().SweepState 必须一致。
	DefaultSweepStateTable = "test_node_sweep_state"
)

// tablePattern 表名必须是 test_ 前缀的小写标识符（仅用于 DDL 拼装，杜绝注入）。
var tablePattern = regexp.MustCompile(`^test_[a-z0-9_]+$`)

// ErrBadTable 表名不合法。
var ErrBadTable = errors.New("nodestore：表名必须是 test_ 前缀的合法标识符")

// 节点状态（与 nodehealth.Status 取值一致）。
const (
	StatusOnline  = "online"
	StatusOffline = "offline"
	StatusRevoked = "revoked"
)

// NodeRecord 节点状态记录。
type NodeRecord struct {
	NodeID         string
	Status         string
	DisplayLabel   string
	CertSerial     string
	LastReceivedAt time.Time
	LastSentAt     time.Time
	LastSkew       time.Duration
	CreatedAt      time.Time
	// —— 第二十三轮新增列（见 nodemigrate 迁移 003）——
	// PendingSupersededSerial 待确认的旧序列号（T3：续期成功后记录，
	// 收到**新序列号**的首次心跳后才写入吊销表）。
	PendingSupersededSerial string
	// BootSessionID / SessionSentAt D6 会话基线的持久化（控制面重启后沿用）。
	BootSessionID string
	SessionSentAt time.Time
}

// Config 配置。
type Config struct {
	// Pool 连接池（必填）。
	Pool *pgxpool.Pool
	// NodesTable / TokensTable / RevocationsTable / CertsTable 表名（默认见常量）。
	NodesTable       string
	TokensTable      string
	RevocationsTable string
	CertsTable       string
	// SweepStateTable 扫描器节流状态表名（空则用 DefaultSweepStateTable）。
	SweepStateTable string
	// Now 注入时钟（测试用）。
	Now func() time.Time
}

// Store 持久化存储。
type Store struct {
	pool        *pgxpool.Pool
	nodes       string
	tokens      string
	revocations string
	// certs 证书状态机表名（第二十四轮 T1；本表由 migration 004 创建，
	// Store 不负责建它，只负责把表名传递给需要它的组件）。
	certs string
	// sweepState 扫描器节流状态表名（第二十四轮 T2；本表由 migration 005 创建，
	// 同样由 Store 只负责传递表名，不建表）。
	sweepState string
	now        func() time.Time
}

// New 构建存储；表名不合法直接拒绝（fail-closed）。
func New(cfg Config) (*Store, error) {
	if cfg.Pool == nil {
		return nil, errors.New("nodestore：连接池为空")
	}
	nodes := orDefault(cfg.NodesTable, DefaultNodesTable)
	tokens := orDefault(cfg.TokensTable, DefaultTokensTable)
	revocations := orDefault(cfg.RevocationsTable, DefaultRevocationsTable)
	certs := orDefault(cfg.CertsTable, DefaultCertsTable)
	sweepState := orDefault(cfg.SweepStateTable, DefaultSweepStateTable)
	for _, t := range []string{nodes, tokens, revocations, certs, sweepState} {
		if !tablePattern.MatchString(t) {
			return nil, fmt.Errorf("%w：%q", ErrBadTable, t)
		}
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Store{pool: cfg.Pool, nodes: nodes, tokens: tokens,
		revocations: revocations, certs: certs, sweepState: sweepState, now: now}, nil
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// EnsureSchema 建三张表（幂等）。
// EnsureSchema 建表（幂等）。**只创建初始形态**；第二十三轮新增列由
// internal/nodemigrate 的迁移负责（可回滚），两者必须**一起**调用：
// 先 EnsureSchema（建表），再 nodemigrate.Up（加列与约束）。
func (s *Store) EnsureSchema(ctx context.Context) error {
	stmts := []string{
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
    node_id          text        PRIMARY KEY,
    status           text        NOT NULL CHECK (status IN ('online','offline','revoked')),
    display_label    text        NOT NULL DEFAULT '',
    cert_serial      text        NOT NULL DEFAULT '',
    last_received_at timestamptz,
    last_sent_at     timestamptz,
    last_skew_ms     bigint      NOT NULL DEFAULT 0,
    created_at       timestamptz NOT NULL,
    pending_superseded_serial text NOT NULL DEFAULT '',
    boot_session_id  text        NOT NULL DEFAULT '',
    session_sent_at  timestamptz
);`, s.nodes),
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
    token_hash       bytea       PRIMARY KEY,
    expires_at       timestamptz NOT NULL,
    used_at          timestamptz,
    used_by_node_id  text,
    created_at       timestamptz NOT NULL,
    reissued_for_node_id text
);`, s.tokens),
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
    serial     text        PRIMARY KEY,
    node_id    text        NOT NULL,
    revoked_at timestamptz NOT NULL,
    reason     text        NOT NULL DEFAULT ''
);`, s.revocations),
	}
	for _, stmt := range stmts {
		if _, err := s.pool.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("nodestore：建表失败：%w", err)
		}
	}
	return nil
}

// —— 令牌 ——

// PutToken 保存令牌哈希（明文不落库）。
func (s *Store) PutToken(ctx context.Context, hash nodeidentity.TokenHash, expiresAt time.Time) error {
	_, err := s.pool.Exec(ctx, fmt.Sprintf(
		`INSERT INTO %s (token_hash, expires_at, created_at) VALUES ($1,$2,$3)
         ON CONFLICT (token_hash) DO UPDATE SET expires_at = EXCLUDED.expires_at`,
		s.tokens), hash[:], expiresAt.UTC(), s.now().UTC())
	if err != nil {
		return fmt.Errorf("nodestore：保存令牌失败：%w", err)
	}
	return nil
}

// ConsumeToken **原子**消费令牌：返回 true 表示本次消费成功（恰好一次）。
//
// 单条 UPDATE + 影响行数判定；`used_at IS NULL AND expires_at > now` 保证
// 并发提交时只有一个成功（不使用先查后写）。
func (s *Store) ConsumeToken(ctx context.Context, hash nodeidentity.TokenHash, nodeID string, now time.Time) (bool, error) {
	tag, err := s.pool.Exec(ctx, fmt.Sprintf(
		`UPDATE %s SET used_at = $1, used_by_node_id = $2
         WHERE token_hash = $3 AND used_at IS NULL AND expires_at > $1`,
		s.tokens), now.UTC(), nodeID, hash[:])
	if err != nil {
		return false, fmt.Errorf("nodestore：消费令牌失败：%w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// PutReissueToken 保存**补发**令牌哈希（T4）：关联被替代的旧节点，明文不落库。
func (s *Store) PutReissueToken(ctx context.Context, hash nodeidentity.TokenHash,
	expiresAt time.Time, reissuedForNodeID string) error {
	_, err := s.pool.Exec(ctx, fmt.Sprintf(
		`INSERT INTO %s (token_hash, expires_at, created_at, reissued_for_node_id)
         VALUES ($1,$2,$3,$4)
         ON CONFLICT (token_hash) DO UPDATE SET expires_at = EXCLUDED.expires_at`,
		s.tokens), hash[:], expiresAt.UTC(), s.now().UTC(), reissuedForNodeID)
	if err != nil {
		return fmt.Errorf("nodestore：保存补发令牌失败：%w", err)
	}
	return nil
}

// TokenState 令牌状态（重启恢复与测试断言用）。
type TokenState struct {
	Found        bool
	ExpiresAt    time.Time
	UsedAt       time.Time
	UsedByNodeID string
	// ReissuedForNodeID 补发令牌关联的旧节点（T4；普通令牌为空）。
	ReissuedForNodeID string
}

// GetTokenState 读取令牌状态（**只读**；不改变 used_at）。
func (s *Store) GetTokenState(ctx context.Context, hash nodeidentity.TokenHash) (TokenState, error) {
	var st TokenState
	var usedAt *time.Time
	var usedBy, reissuedFor *string
	err := s.pool.QueryRow(ctx, fmt.Sprintf(
		`SELECT expires_at, used_at, used_by_node_id, reissued_for_node_id
         FROM %s WHERE token_hash = $1`, s.tokens),
		hash[:]).Scan(&st.ExpiresAt, &usedAt, &usedBy, &reissuedFor)
	if errors.Is(err, pgx.ErrNoRows) {
		return TokenState{}, nil
	}
	if err != nil {
		return TokenState{}, fmt.Errorf("nodestore：读取令牌状态失败：%w", err)
	}
	st.Found = true
	if usedAt != nil {
		st.UsedAt = *usedAt
	}
	if usedBy != nil {
		st.UsedByNodeID = *usedBy
	}
	if reissuedFor != nil {
		st.ReissuedForNodeID = *reissuedFor
	}
	return st, nil
}

// —— 节点 ——

// UpsertNode 写入/更新节点（注册成功时调用）。
func (s *Store) UpsertNode(ctx context.Context, rec NodeRecord) error {
	_, err := s.pool.Exec(ctx, fmt.Sprintf(
		`INSERT INTO %s (node_id, status, display_label, cert_serial,
                         last_received_at, last_sent_at, last_skew_ms, created_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
         ON CONFLICT (node_id) DO UPDATE SET
           status = EXCLUDED.status,
           display_label = EXCLUDED.display_label,
           cert_serial = EXCLUDED.cert_serial`,
		s.nodes), rec.NodeID, rec.Status, rec.DisplayLabel, rec.CertSerial,
		nullTime(rec.LastReceivedAt), nullTime(rec.LastSentAt),
		rec.LastSkew.Milliseconds(), rec.CreatedAt.UTC())
	if err != nil {
		return fmt.Errorf("nodestore：写入节点失败：%w", err)
	}
	return nil
}

// GetNode 读取节点（found=false 表示不存在）。
func (s *Store) GetNode(ctx context.Context, nodeID string) (NodeRecord, bool, error) {
	var rec NodeRecord
	var lastRecv, lastSent *time.Time
	var skewMs int64
	var pending string
	var bootSession string
	var sessionSent *time.Time
	err := s.pool.QueryRow(ctx, fmt.Sprintf(
		`SELECT node_id, status, display_label, cert_serial,
                last_received_at, last_sent_at, last_skew_ms, created_at,
                pending_superseded_serial, boot_session_id, session_sent_at
         FROM %s WHERE node_id = $1`, s.nodes), nodeID).
		Scan(&rec.NodeID, &rec.Status, &rec.DisplayLabel, &rec.CertSerial,
			&lastRecv, &lastSent, &skewMs, &rec.CreatedAt,
			&pending, &bootSession, &sessionSent)
	if errors.Is(err, pgx.ErrNoRows) {
		return NodeRecord{}, false, nil
	}
	if err != nil {
		return NodeRecord{}, false, fmt.Errorf("nodestore：读取节点失败：%w", err)
	}
	if lastRecv != nil {
		rec.LastReceivedAt = *lastRecv
	}
	if lastSent != nil {
		rec.LastSentAt = *lastSent
	}
	rec.LastSkew = time.Duration(skewMs) * time.Millisecond
	rec.PendingSupersededSerial = pending
	rec.BootSessionID = bootSession
	if sessionSent != nil {
		rec.SessionSentAt = *sessionSent
	}
	return rec, true, nil
}

// ListNodes 列出全部节点（按 node_id 升序）。
func (s *Store) ListNodes(ctx context.Context) ([]NodeRecord, error) {
	rows, err := s.pool.Query(ctx, fmt.Sprintf(
		`SELECT node_id, status, display_label, cert_serial,
                last_received_at, last_sent_at, last_skew_ms, created_at,
                pending_superseded_serial, boot_session_id, session_sent_at
         FROM %s ORDER BY node_id`, s.nodes))
	if err != nil {
		return nil, fmt.Errorf("nodestore：列出节点失败：%w", err)
	}
	defer rows.Close()
	var out []NodeRecord
	for rows.Next() {
		var rec NodeRecord
		var lastRecv, lastSent, sessionSent *time.Time
		var skewMs int64
		if err := rows.Scan(&rec.NodeID, &rec.Status, &rec.DisplayLabel, &rec.CertSerial,
			&lastRecv, &lastSent, &skewMs, &rec.CreatedAt,
			&rec.PendingSupersededSerial, &rec.BootSessionID, &sessionSent); err != nil {
			return nil, err
		}
		if sessionSent != nil {
			rec.SessionSentAt = *sessionSent
		}
		if lastRecv != nil {
			rec.LastReceivedAt = *lastRecv
		}
		if lastSent != nil {
			rec.LastSentAt = *lastSent
		}
		rec.LastSkew = time.Duration(skewMs) * time.Millisecond
		out = append(out, rec)
	}
	return out, rows.Err()
}

// UpdateNodeState 更新节点的存活与偏差字段（心跳处理后调用）。
func (s *Store) UpdateNodeState(ctx context.Context, nodeID, status string,
	lastReceived, lastSent time.Time, skew time.Duration) error {
	_, err := s.pool.Exec(ctx, fmt.Sprintf(
		`UPDATE %s SET status = $2, last_received_at = $3, last_sent_at = $4, last_skew_ms = $5
         WHERE node_id = $1`, s.nodes),
		nodeID, status, nullTime(lastReceived), nullTime(lastSent), skew.Milliseconds())
	if err != nil {
		return fmt.Errorf("nodestore：更新节点状态失败：%w", err)
	}
	return nil
}

// UpdateNodeSession 写入 D6 会话基线（心跳处理后调用；控制面重启后沿用）。
func (s *Store) UpdateNodeSession(ctx context.Context, nodeID, bootSessionID string,
	sessionSentAt time.Time) error {
	_, err := s.pool.Exec(ctx, fmt.Sprintf(
		`UPDATE %s SET boot_session_id = $2, session_sent_at = $3 WHERE node_id = $1`, s.nodes),
		nodeID, bootSessionID, nullTime(sessionSentAt))
	if err != nil {
		return fmt.Errorf("nodestore：写入会话基线失败：%w", err)
	}
	return nil
}

// RotateCert 续期落库（**同一事务**）：更新节点表的当前序列号。
//
// 节点状态**不变**——续期不是状态迁移（续期失败/成功都不应改变 online/offline）。
//
// **第二十四轮 T1 起**：`pending_superseded_serial` **停止写入**（列保留不删，供回滚）。
// 待确认/孤儿的收敛改由 `internal/nodecerts` 的证书状态机负责——单个字符串列
// 只能存一份，第二次续期会覆盖第一次，导致旧证书永不被 supersede（安全缺口）。
func (s *Store) RotateCert(ctx context.Context, nodeID, newSerial string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("nodestore：开启事务失败：%w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, fmt.Sprintf(
		`UPDATE %s SET cert_serial = $2 WHERE node_id = $1`,
		s.nodes), nodeID, newSerial); err != nil {
		return fmt.Errorf("nodestore：续期更新节点失败：%w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("nodestore：提交续期事务失败：%w", err)
	}
	return nil
}

// RevokeSerial 只写吊销表（**不改节点状态**）。
//
// T3 用："旧证书被新证书取代"（reason=superseded）只应阻止旧证书继续使用，
// 节点本身仍然健康——若顺手置为 revoked，节点会**永久失联**（D3 的 revoked 是终态）。
func (s *Store) RevokeSerial(ctx context.Context, serial, nodeID, reason string, at time.Time) error {
	if _, err := s.pool.Exec(ctx, fmt.Sprintf(
		`INSERT INTO %s (serial, node_id, revoked_at, reason) VALUES ($1,$2,$3,$4)
         ON CONFLICT (serial) DO NOTHING`, s.revocations),
		serial, nodeID, at.UTC(), reason); err != nil {
		return fmt.Errorf("nodestore：写吊销表失败：%w", err)
	}
	return nil
}

// ClearPendingSuperseded 清空待确认旧序列号（写入吊销表后调用）。
func (s *Store) ClearPendingSuperseded(ctx context.Context, nodeID string) error {
	_, err := s.pool.Exec(ctx, fmt.Sprintf(
		`UPDATE %s SET pending_superseded_serial = '' WHERE node_id = $1`, s.nodes), nodeID)
	if err != nil {
		return fmt.Errorf("nodestore：清空待确认序列号失败：%w", err)
	}
	return nil
}

// RevocationReason 读取某序列号的吊销原因（测试断言用）。
func (s *Store) RevocationReason(ctx context.Context, serial string) (string, bool, error) {
	var reason string
	err := s.pool.QueryRow(ctx, fmt.Sprintf(
		`SELECT reason FROM %s WHERE serial = $1`, s.revocations), serial).Scan(&reason)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("nodestore：查询吊销原因失败：%w", err)
	}
	return reason, true, nil
}

// SetNodeStatus 只更新状态（offline / revoked 迁移用）。
func (s *Store) SetNodeStatus(ctx context.Context, nodeID, status string) error {
	_, err := s.pool.Exec(ctx, fmt.Sprintf(
		`UPDATE %s SET status = $2 WHERE node_id = $1`, s.nodes), nodeID, status)
	if err != nil {
		return fmt.Errorf("nodestore：设置节点状态失败：%w", err)
	}
	return nil
}

// —— 吊销 ——

// Revoke 把证书写入吊销表并把节点状态置为 revoked（幂等）。
func (s *Store) Revoke(ctx context.Context, serial, nodeID, reason string, at time.Time) error {
	if _, err := s.pool.Exec(ctx, fmt.Sprintf(
		`INSERT INTO %s (serial, node_id, revoked_at, reason) VALUES ($1,$2,$3,$4)
         ON CONFLICT (serial) DO NOTHING`, s.revocations),
		serial, nodeID, at.UTC(), reason); err != nil {
		return fmt.Errorf("nodestore：写吊销表失败：%w", err)
	}
	return s.SetNodeStatus(ctx, nodeID, StatusRevoked)
}

// IsRevokedSerial 查询某 serial 是否已被吊销。
func (s *Store) IsRevokedSerial(ctx context.Context, serial string) (bool, error) {
	var n int
	if err := s.pool.QueryRow(ctx, fmt.Sprintf(
		`SELECT count(*) FROM %s WHERE serial = $1`, s.revocations), serial).Scan(&n); err != nil {
		return false, fmt.Errorf("nodestore：查询吊销表失败：%w", err)
	}
	return n > 0, nil
}

// RevocationChecker 返回绑定了 ctx 的 nodeidentity.RevocationChecker
// （供 CA 的 mTLS 校验每次查询吊销表）。
func (s *Store) RevocationChecker(ctx context.Context) nodeidentity.RevocationChecker {
	return ctxRevocations{ctx: ctx, s: s}
}

// ctxRevocations 把 ctx 绑定到存储，满足 nodeidentity.RevocationChecker。
type ctxRevocations struct {
	ctx context.Context
	s   *Store
}

// IsRevoked 实现 nodeidentity.RevocationChecker。
func (c ctxRevocations) IsRevoked(serial string) (bool, error) {
	return c.s.IsRevokedSerial(c.ctx, serial)
}

// RevocationReasonCount 按 reason 统计吊销行数（测试断言用）。
func (s *Store) RevocationReasonCount(ctx context.Context, reason string) (int64, error) {
	var n int64
	err := s.pool.QueryRow(ctx, fmt.Sprintf(
		`SELECT count(*) FROM %s WHERE reason = $1`, s.revocations), reason).Scan(&n)
	return n, err
}

// RevocationCount 吊销表行数（测试断言用）。
func (s *Store) RevocationCount(ctx context.Context) (int64, error) {
	var n int64
	err := s.pool.QueryRow(ctx, fmt.Sprintf(`SELECT count(*) FROM %s`, s.revocations)).Scan(&n)
	return n, err
}

// Pool 返回底层连接池（供迁移执行器与测试使用）。
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// Tables 返回生效的表名（供 nodemigrate 对齐同一组表）。
func (s *Store) Tables() (nodes, tokens, revocations string) {
	return s.nodes, s.tokens, s.revocations
}

// CertsTable 返回证书状态机表名。
func (s *Store) CertsTable() string { return s.certs }

// SweepStateTable 返回扫描器节流状态表名（第二十四轮 T2/R2b：
// 迁移 005 的表名必须与 Store 实际使用的名字同源，否则测试环境传入空名
// 会被 nodemigrate.New 的 fail-closed 校验拒绝）。
func (s *Store) SweepStateTable() string { return s.sweepState }

// AllTables 返回全部表名（供迁移与测试使用）。
func (s *Store) AllTables() (nodes, tokens, revocations, certs, sweepState string) {
	return s.nodes, s.tokens, s.revocations, s.certs, s.sweepState
}

// CountByStatus 按状态统计节点数（测试断言用）。
func (s *Store) CountByStatus(ctx context.Context, status string) (int64, error) {
	var n int64
	err := s.pool.QueryRow(ctx, fmt.Sprintf(
		`SELECT count(*) FROM %s WHERE status = $1`, s.nodes), status).Scan(&n)
	return n, err
}

// nullTime 零值时间写入 NULL。
func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC()
}
