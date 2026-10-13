// Package nodecerts 是**证书状态机**（第二十四轮 T1）。
//
// 为什么需要独立的状态机：第二十三轮用 `test_nodes.pending_superseded_serial`
// （**单个**序列号）记录"续期后待确认的旧证书"。第二次续期会**覆盖**第一次，
// 于是第一份旧证书永远不会被 supersede——它在 7 天有效期内持续有效，是一个安全缺口。
//
// 本包改为"**每证书一条状态记录**"，任意数量的未确认证书都能被正确收敛。
//
// 状态机（每张证书恰好处于一个状态）：
//
//	issued ──(心跳确认该序列号)──► active
//	   │                              │
//	   └──(同节点更早且未确认)────────┴──► superseded   （写吊销表 reason=superseded）
//	                                      revoked      （人工吊销，终态，仅经吊销表）
//
// 关键约束：
//   - **证书状态与节点状态（online/offline/revoked）完全分离**：`superseded` 只说明
//     "这张证书不该再被使用"，**不改变**节点状态（否则会误把健康节点打成 revoked 终态）；
//   - `superseded` / `revoked` 的序列号出现在心跳里 → **拒绝**（PermissionDenied），
//     且不改变任何状态；
//   - 未确认（`issued`）证书数量有上限，防止无限堆积。
package nodecerts

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// State 证书状态。
type State string

const (
	// StateIssued 已签发但**尚未被任何心跳确认**（可能还在路上，或响应丢失）。
	StateIssued State = "issued"
	// StateActive 已被心跳确认：这是节点当前实际使用的证书。
	StateActive State = "active"
	// StateSuperseded 已被更新的证书取代（写吊销表 reason=superseded）。
	StateSuperseded State = "superseded"
	// StateRevoked 被人工吊销（终态；由吊销表驱动，节点状态同时为 revoked）。
	StateRevoked State = "revoked"
)

// DefaultPendingLimit 同一节点允许处于 issued 状态的证书数量上限（工程默认，待确认）。
//
// 取值理由：正常路径下 issued 只会在"续期响应在途"的极短时间内存在 1 份；
// 允许 5 份足以覆盖"响应连续丢失若干次"的抖动，同时防止无限堆积。
const DefaultPendingLimit = 5

// tablePattern 表名必须是 test_ 前缀的小写标识符（DDL 拼装，杜绝注入）。
var tablePattern = regexp.MustCompile(`^test_[a-z0-9_]+$`)

// ErrBadTable 表名不合法。
var ErrBadTable = errors.New("nodecerts：表名必须以 test_ 开头且为合法标识符")

// ErrPendingLimit 未确认证书数量达到上限（Renew 会被拒绝，reason=pending_limit）。
var ErrPendingLimit = errors.New("nodecerts：未确认证书数量达到上限")

// Record 一条证书状态记录。
type Record struct {
	// Serial 证书序列号（与吊销表主键一致）。
	Serial string
	// NodeID 所属节点。
	NodeID string
	// State 当前状态。
	State State
	// IssuedAt 签发时刻（用于"更早的证书"判定）。
	IssuedAt time.Time
	// NotAfter 证书到期时刻。
	NotAfter time.Time
	// ConfirmedAt 被心跳确认的时刻（仅 active 有意义）。
	ConfirmedAt time.Time
}

// Store 证书状态机存储。
type Store struct {
	pool    *pgxpool.Pool
	certs   string
	revokes string
	// pendingLimit 未确认上限（<=0 用 DefaultPendingLimit）。
	pendingLimit int
}

// Config 配置。
type Config struct {
	// Pool 连接池（必填）。
	Pool *pgxpool.Pool
	// CertsTable 证书状态表名（默认 test_node_certs）。
	CertsTable string
	// RevocationsTable 吊销表名（默认 test_cert_revocations）。
	RevocationsTable string
	// PendingLimit 未确认上限（<=0 用 DefaultPendingLimit）。
	PendingLimit int
}

// New 构建存储（表名校验，fail-closed）。
func New(cfg Config) (*Store, error) {
	if cfg.Pool == nil {
		return nil, errors.New("nodecerts：连接池为空")
	}
	certs := cfg.CertsTable
	if certs == "" {
		certs = "test_node_certs"
	}
	revokes := cfg.RevocationsTable
	if revokes == "" {
		revokes = "test_cert_revocations"
	}
	for _, t := range []string{certs, revokes} {
		if !tablePattern.MatchString(t) {
			return nil, fmt.Errorf("%w：%q", ErrBadTable, t)
		}
	}
	limit := cfg.PendingLimit
	if limit <= 0 {
		limit = DefaultPendingLimit
	}
	return &Store{pool: cfg.Pool, certs: certs, revokes: revokes, pendingLimit: limit}, nil
}

// PendingLimit 返回生效的未确认上限。
func (s *Store) PendingLimit() int { return s.pendingLimit }

// CertsTable 返回生效的证书表名（测试断言用）。
func (s *Store) CertsTable() string { return s.certs }

// —— 签发 ——

// Issue 记录一张**新签发**的证书（state=issued）。
//
// 返回 ErrPendingLimit 表示未确认证书已达上限（调用方应拒绝 Renew 并写
// `node.renew_rejected`，reason=pending_limit）。
func (s *Store) Issue(ctx context.Context, rec Record) error {
	if rec.Serial == "" || rec.NodeID == "" {
		return errors.New("nodecerts：serial 与 node_id 必填")
	}
	// 上限判定与插入**在同一事务**内完成，避免并发续期绕过上限。
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("nodecerts：开启事务失败：%w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var pending int
	if err := tx.QueryRow(ctx, fmt.Sprintf(
		`SELECT count(*) FROM %s WHERE node_id = $1 AND state = 'issued'`, s.certs),
		rec.NodeID).Scan(&pending); err != nil {
		return fmt.Errorf("nodecerts：统计未确认证书失败：%w", err)
	}
	if pending >= s.pendingLimit {
		return ErrPendingLimit
	}
	if _, err := tx.Exec(ctx, fmt.Sprintf(
		`INSERT INTO %s (serial, node_id, state, issued_at, not_after, confirmed_at)
         VALUES ($1,$2,'issued',$3,$4,NULL)
         ON CONFLICT (serial) DO UPDATE SET state = 'issued', issued_at = EXCLUDED.issued_at`,
		s.certs), rec.Serial, rec.NodeID, rec.IssuedAt.UTC(), rec.NotAfter.UTC()); err != nil {
		return fmt.Errorf("nodecerts：写入证书记录失败：%w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("nodecerts：提交事务失败：%w", err)
	}
	return nil
}

// —— 心跳确认 ——

// ConfirmOutcome 一次心跳确认的结果。
type ConfirmOutcome struct {
	// Serial 本次心跳携带的序列号。
	Serial string
	// State 确认后的状态（issued → active 后为 active；本来就是 active 时也是 active）。
	State State
	// NewlyActive true 表示本次把 issued 提升为 active（首次确认）。
	NewlyActive bool
	// Superseded 本次被取代的序列号（**同节点中 issued_at 早于本次序列号的所有
	// issued/active 证书**；含孤儿证书）。
	Superseded []string
}

// Confirm 处理"心跳携带序列号 S"（T1 状态迁移规则）。
//
// 顺序：
//  1. S 不存在于证书表 → 由调用方按"未知序列号"处理（本方法返回 ErrUnknown）；
//  2. S 为 superseded / revoked → 拒绝（ErrNotUsable），**不改变任何状态**；
//  3. S 为 issued → 变 active + 写 confirmed_at；同节点 `issued_at` **早于 S** 的
//     所有 issued/active 证书变 superseded，并写入吊销表 reason=superseded；
//  4. S 为 active → 无变化（`NewlyActive=false`，`Superseded` 为空）。
//
// 全部在同一事务内完成；**不改动节点状态**（由调用方负责，且应保持不变）。
func (s *Store) Confirm(ctx context.Context, nodeID, serial string, at time.Time) (*ConfirmOutcome, error) {
	if nodeID == "" || serial == "" {
		return nil, errors.New("nodecerts：node_id 与 serial 必填")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("nodecerts：开启事务失败：%w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var state State
	var issuedAt time.Time
	err = tx.QueryRow(ctx, fmt.Sprintf(
		`SELECT state, issued_at FROM %s WHERE serial = $1 AND node_id = $2`, s.certs),
		serial, nodeID).Scan(&state, &issuedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrUnknownSerial
	}
	if err != nil {
		return nil, fmt.Errorf("nodecerts：读取证书状态失败：%w", err)
	}

	// ② 已失效的序列号 → 拒绝，不改状态。
	if state == StateSuperseded || state == StateRevoked {
		return &ConfirmOutcome{Serial: serial, State: state}, ErrNotUsable
	}
	// ④ 已是 active → 无变化。
	if state == StateActive {
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return &ConfirmOutcome{Serial: serial, State: StateActive}, nil
	}

	// ③ issued → active。
	now := at.UTC()
	if _, err := tx.Exec(ctx, fmt.Sprintf(
		`UPDATE %s SET state = 'active', confirmed_at = $2 WHERE serial = $1`, s.certs),
		serial, now); err != nil {
		return nil, fmt.Errorf("nodecerts：提升 active 失败：%w", err)
	}

	// 同节点中 **issued_at 早于本次确认证书** 的 issued/active → superseded。
	// 这一条同时覆盖两类目标：
	//   - 上一轮续期留下的"待确认旧证书"（正常路径）；
	//   - 因响应丢失而从未被确认的**孤儿证书**（本缺口的直接修复对象）。
	rows, err := tx.Query(ctx, fmt.Sprintf(
		`UPDATE %s SET state = 'superseded'
          WHERE node_id = $1 AND serial <> $2
            AND state IN ('issued','active')
            AND issued_at < $3
          RETURNING serial`, s.certs), nodeID, serial, issuedAt)
	if err != nil {
		return nil, fmt.Errorf("nodecerts：标记 superseded 失败：%w", err)
	}
	var superseded []string
	for rows.Next() {
		var old string
		if err := rows.Scan(&old); err != nil {
			rows.Close()
			return nil, err
		}
		superseded = append(superseded, old)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// 写吊销表（reason=superseded）——**不改节点状态**。
	for _, old := range superseded {
		if _, err := tx.Exec(ctx, fmt.Sprintf(
			`INSERT INTO %s (serial, node_id, revoked_at, reason) VALUES ($1,$2,$3,'superseded')
             ON CONFLICT (serial) DO NOTHING`, s.revokes), old, nodeID, now); err != nil {
			return nil, fmt.Errorf("nodecerts：写吊销表失败：%w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("nodecerts：提交事务失败：%w", err)
	}
	return &ConfirmOutcome{Serial: serial, State: StateActive,
		NewlyActive: true, Superseded: superseded}, nil
}

// —— 查询 ——

// Get 读取单张证书的状态（found=false 表示不存在）。
func (s *Store) Get(ctx context.Context, serial string) (Record, bool, error) {
	var rec Record
	var confirmed *time.Time
	err := s.pool.QueryRow(ctx, fmt.Sprintf(
		`SELECT serial, node_id, state, issued_at, not_after, confirmed_at
           FROM %s WHERE serial = $1`, s.certs), serial).
		Scan(&rec.Serial, &rec.NodeID, &rec.State, &rec.IssuedAt, &rec.NotAfter, &confirmed)
	if errors.Is(err, pgx.ErrNoRows) {
		return Record{}, false, nil
	}
	if err != nil {
		return Record{}, false, fmt.Errorf("nodecerts：读取证书失败：%w", err)
	}
	if confirmed != nil {
		rec.ConfirmedAt = *confirmed
	}
	return rec, true, nil
}

// ListByNode 列出某节点的全部证书（按 issued_at 升序）。
func (s *Store) ListByNode(ctx context.Context, nodeID string) ([]Record, error) {
	rows, err := s.pool.Query(ctx, fmt.Sprintf(
		`SELECT serial, node_id, state, issued_at, not_after, confirmed_at
           FROM %s WHERE node_id = $1 ORDER BY issued_at, serial`, s.certs), nodeID)
	if err != nil {
		return nil, fmt.Errorf("nodecerts：列出证书失败：%w", err)
	}
	defer rows.Close()
	var out []Record
	for rows.Next() {
		var rec Record
		var confirmed *time.Time
		if err := rows.Scan(&rec.Serial, &rec.NodeID, &rec.State, &rec.IssuedAt,
			&rec.NotAfter, &confirmed); err != nil {
			return nil, err
		}
		if confirmed != nil {
			rec.ConfirmedAt = *confirmed
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// CountByState 统计某节点某状态的证书数量（测试断言用）。
func (s *Store) CountByState(ctx context.Context, nodeID string, state State) (int64, error) {
	var n int64
	err := s.pool.QueryRow(ctx, fmt.Sprintf(
		`SELECT count(*) FROM %s WHERE node_id = $1 AND state = $2`, s.certs),
		nodeID, string(state)).Scan(&n)
	return n, err
}

// ExpiringActive 返回剩余有效期早于 threshold 时刻的 active 证书（T2 扫描用）。
func (s *Store) ExpiringActive(ctx context.Context, before time.Time) ([]Record, error) {
	rows, err := s.pool.Query(ctx, fmt.Sprintf(
		`SELECT serial, node_id, state, issued_at, not_after, confirmed_at
           FROM %s WHERE state = 'active' AND not_after < $1 ORDER BY not_after`, s.certs),
		before.UTC())
	if err != nil {
		return nil, fmt.Errorf("nodecerts：查询到期证书失败：%w", err)
	}
	defer rows.Close()
	var out []Record
	for rows.Next() {
		var rec Record
		var confirmed *time.Time
		if err := rows.Scan(&rec.Serial, &rec.NodeID, &rec.State, &rec.IssuedAt,
			&rec.NotAfter, &confirmed); err != nil {
			return nil, err
		}
		if confirmed != nil {
			rec.ConfirmedAt = *confirmed
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// UnconfirmedIssued 返回签发后超过 maxAge 仍未被确认的 issued 证书（T2 扫描用）。
func (s *Store) UnconfirmedIssued(ctx context.Context, issuedBefore time.Time) ([]Record, error) {
	rows, err := s.pool.Query(ctx, fmt.Sprintf(
		`SELECT serial, node_id, state, issued_at, not_after, confirmed_at
           FROM %s WHERE state = 'issued' AND issued_at < $1 ORDER BY issued_at`, s.certs),
		issuedBefore.UTC())
	if err != nil {
		return nil, fmt.Errorf("nodecerts：查询未确认证书失败：%w", err)
	}
	defer rows.Close()
	var out []Record
	for rows.Next() {
		var rec Record
		var confirmed *time.Time
		if err := rows.Scan(&rec.Serial, &rec.NodeID, &rec.State, &rec.IssuedAt,
			&rec.NotAfter, &confirmed); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// ErrUnknownSerial 序列号不在状态机中（可能是伪造或早于本表引入）。
var ErrUnknownSerial = errors.New("nodecerts：未知序列号（不在证书状态机中）")

// ErrNotUsable 序列号已 superseded / revoked（心跳必须被拒绝）。
var ErrNotUsable = errors.New("nodecerts：该序列号已失效（superseded/revoked）")
