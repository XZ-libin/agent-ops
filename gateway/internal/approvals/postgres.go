package approvals

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DefaultLocalDSN 本地开发/测试的默认连接串（占位值，非真实凭据）。
// 宿主端口 55432 与 deploy/docker-compose.yaml 一致（第八轮约束 2：
// 绝不触碰 5432 的 opsforge-postgres）；测试可用 AGENT_OPS_TEST_DATABASE_URL 覆盖。
const DefaultLocalDSN = "postgres://agent_ops:agent_ops@localhost:55432/agent_ops?sslmode=disable"

// schemaDDL 审批记录表结构（第九轮：+idem_key/+approved_at/consumed；
// 第十轮：+executing/+abandoned（先占后执行）；第十一轮 H1：+lease_until
// （执行租约）。CHECK 约束在库层兜底状态取值）。
func schemaDDL(table string) string {
	return fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
    id           text        PRIMARY KEY,
    actor        text        NOT NULL,
    capability   text        NOT NULL,
    request_hash text        NOT NULL,
    idem_key     text        NOT NULL DEFAULT '',
    status       text        NOT NULL CHECK (status IN ('pending','approved','rejected','expired','executing','consumed','abandoned')),
    created_at   timestamptz NOT NULL,
    updated_at   timestamptz NOT NULL,
    expires_at   timestamptz NOT NULL,
    approved_at  timestamptz,
    decided_by   text        NOT NULL DEFAULT '',
    reason       text        NOT NULL DEFAULT '',
    lease_until  timestamptz
);`, table)
}

// schemaDDLMigrate 对旧表结构的迁移语句（幂等）：
// 补列、更新状态 CHECK、重建 R3 的「仅 pending」部分唯一索引。
//
// 第十轮修订（F3）：去重键由 (actor, idem_key) 改为 (actor, request_hash)——
// 同一请求内容即使换了幂等键也只保留一条 pending。(actor, idem_key) 的唯一约束
// 保留（改名 pending_key），仅用于原子判定「同幂等键、不同内容」的 422 冲突。
// 旧索引（同名、旧定义）必须先 DROP 再建，否则 IF NOT EXISTS 会让旧定义残留。
func schemaDDLMigrate(table string) []string {
	return []string{
		fmt.Sprintf(`ALTER TABLE %s ADD COLUMN IF NOT EXISTS idem_key text NOT NULL DEFAULT '';`, table),
		fmt.Sprintf(`ALTER TABLE %s ADD COLUMN IF NOT EXISTS approved_at timestamptz;`, table),
		// H1：执行租约列（旧表补齐；NULL 表示无租约）。
		fmt.Sprintf(`ALTER TABLE %s ADD COLUMN IF NOT EXISTS lease_until timestamptz;`, table),
		fmt.Sprintf(`ALTER TABLE %s DROP CONSTRAINT IF EXISTS %s_status_check;`, table, table),
		fmt.Sprintf(`ALTER TABLE %s ADD CONSTRAINT %s_status_check
CHECK (status IN ('pending','approved','rejected','expired','executing','consumed','abandoned'));`, table, table),
		// 旧去重索引（第九轮定义在 (actor, idem_key) 上）先删除，避免同名旧定义残留。
		fmt.Sprintf(`DROP INDEX IF EXISTS %s_pending_dedup;`, table),
		// R3（第十轮）：pending 期间 (actor, request_hash) 唯一——内容去重。
		fmt.Sprintf(`CREATE UNIQUE INDEX IF NOT EXISTS %s_pending_dedup ON %s (actor, request_hash) WHERE status = 'pending';`, table, table),
		// 同幂等键在 pending 期间只允许一条：原子地产生「同键不同内容」的 422 冲突。
		// 消费/过期/放弃后该键可重新提交（部分索引只约束 pending）。
		fmt.Sprintf(`CREATE UNIQUE INDEX IF NOT EXISTS %s_pending_key ON %s (actor, idem_key) WHERE status = 'pending';`, table, table),
	}
}

// PostgresStore PostgreSQL 审批存储实现。
// 全部时间由应用以注入时钟写入，不使用数据库 now()（与幂等/审计包一致）。
type PostgresStore struct {
	pool      *pgxpool.Pool
	table     string
	cfg       storeConfig
	testGuard bool // 测试模式：表名必须 test_ 前缀
}

// NewPostgresStore 构建生产用存储（表名默认 approvals，试点阶段名称，待定）。
func NewPostgresStore(pool *pgxpool.Pool, table string, opts ...Option) *PostgresStore {
	return &PostgresStore{pool: pool, table: table, cfg: applyOptions(opts...)}
}

// NewTestPostgresStore 构建测试用存储：表名必须 test_ 前缀，
// 否则建表与写入均被拒绝（约束 8）。
func NewTestPostgresStore(pool *pgxpool.Pool, table string, opts ...Option) *PostgresStore {
	return &PostgresStore{pool: pool, table: table, cfg: applyOptions(opts...), testGuard: true}
}

// EnsureSchema 建表 + 迁移（幂等，可重复执行）。
func (s *PostgresStore) EnsureSchema(ctx context.Context) error {
	if err := validateTable(s.table, s.testGuard); err != nil {
		return err
	}
	if _, err := s.pool.Exec(ctx, schemaDDL(s.table)); err != nil {
		return err
	}
	for _, stmt := range schemaDDLMigrate(s.table) {
		if _, err := s.pool.Exec(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

// Create 创建 pending 记录（R3 去重，第十轮修订：去重键为 (actor, request_hash)）：
//   - (actor, request_hash) 无 pending → 新建；
//   - 已有 pending 且内容相同（同一哈希，幂等键可不同）→ 返回已有记录（去重）；
//   - 已有 pending 且 (actor, idem_key) 相同但内容不同 → ErrContentConflict（422）。
//
// 原子性：两条「仅 pending」部分唯一索引 + INSERT ... ON CONFLICT DO NOTHING
// （不指定冲突目标，任意唯一冲突均跳过）：
//   - 并发同内容提交只有一个创建方，其余读回同一行；
//   - 同键不同内容无法并发插入两行（(actor, idem_key) 部分索引保证）。
func (s *PostgresStore) Create(ctx context.Context, n NewRecord) (Record, error) {
	if err := validateTable(s.table, s.testGuard); err != nil {
		return Record{}, err
	}
	if n.Actor == "" || n.Capability == "" || n.RequestHash == "" ||
		n.IdempotencyKey == "" || n.ExpiresAt.IsZero() {
		return Record{}, errors.New("审批创建参数不完整（actor/capability/request_hash/idem_key/expires_at 必填）")
	}
	now := s.cfg.now()
	id := "apr-" + randomHex(16)

	const (
		selectCols = `id, actor, capability, request_hash, idem_key, status,
created_at, updated_at, expires_at, approved_at, decided_by, reason, lease_until`
	)
	// 最多重试 2 次：pending 行恰在插入与读取之间迁移时重走插入路径。
	for attempt := 0; attempt < 2; attempt++ {
		tag, err := s.pool.Exec(ctx, fmt.Sprintf(`INSERT INTO %s
    (id, actor, capability, request_hash, idem_key, status, created_at, updated_at, expires_at)
VALUES ($1,$2,$3,$4,$5,'pending',$6,$6,$7)
ON CONFLICT DO NOTHING`, s.table),
			id, n.Actor, n.Capability, n.RequestHash, n.IdempotencyKey, now, n.ExpiresAt)
		if err != nil {
			return Record{}, err
		}
		if tag.RowsAffected() == 1 {
			return Record{
				ID: id, Actor: n.Actor, Capability: n.Capability,
				RequestHash: n.RequestHash, IdempotencyKey: n.IdempotencyKey,
				Status: StatusPending, CreatedAt: now, UpdatedAt: now, ExpiresAt: n.ExpiresAt,
			}, nil
		}

		// 冲突：先按幂等键判定「同键不同内容」→ 422。
		row := s.pool.QueryRow(ctx, fmt.Sprintf(`SELECT %s FROM %s
WHERE actor=$1 AND idem_key=$2 AND status='pending' FOR UPDATE`, selectCols, s.table),
			n.Actor, n.IdempotencyKey)
		rec, err := scanRecord(row)
		if err == nil {
			if rec.RequestHash != n.RequestHash {
				return Record{}, ErrContentConflict
			}
			// 同键同内容：返回已有审批 ID（不新建）。
			return rec, nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return Record{}, err
		}

		// 同内容不同键：按去重键 (actor, request_hash) 读回已有的 pending。
		row2 := s.pool.QueryRow(ctx, fmt.Sprintf(`SELECT %s FROM %s
WHERE actor=$1 AND request_hash=$2 AND status='pending' FOR UPDATE`, selectCols, s.table),
			n.Actor, n.RequestHash)
		rec2, err := scanRecord(row2)
		if errors.Is(err, pgx.ErrNoRows) {
			continue // pending 恰已迁移，重试插入
		}
		if err != nil {
			return Record{}, err
		}
		return rec2, nil
	}
	return Record{}, ErrNotFound // 防御性兜底
}

// Get 读取记录。
func (s *PostgresStore) Get(ctx context.Context, id string) (Record, error) {
	if err := validateTable(s.table, s.testGuard); err != nil {
		return Record{}, err
	}
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`SELECT id, actor, capability, request_hash, idem_key, status,
created_at, updated_at, expires_at, approved_at, decided_by, reason, lease_until FROM %s WHERE id = $1`, s.table), id)
	rec, err := scanRecord(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Record{}, ErrNotFound
	}
	return rec, err
}

// Approve pending → approved。四眼原则：审批人必须与请求人不同（无例外）。
// 先读后写判定（actor 一经创建不变，无竞争窗口）。
func (s *PostgresStore) Approve(ctx context.Context, id, approver, reason string) (Record, error) {
	if err := validateTable(s.table, s.testGuard); err != nil {
		return Record{}, err
	}
	if strings.TrimSpace(approver) == "" {
		return Record{}, ErrApproverMustDiffer
	}
	cur, err := s.Get(ctx, id)
	if err != nil {
		return Record{}, err
	}
	if cur.Status != StatusPending {
		return Record{}, ErrIllegalTransition
	}
	if cur.Actor == approver {
		return Record{}, ErrApproverMustDiffer
	}
	now := s.cfg.now()
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`UPDATE %s
SET status='approved', approved_at=$2, updated_at=$2, decided_by=$3, reason=$4
WHERE id=$1 AND status='pending'
RETURNING id, actor, capability, request_hash, idem_key, status,
created_at, updated_at, expires_at, approved_at, decided_by, reason, lease_until`, s.table),
		id, now, approver, reason)
	rec, err := scanRecord(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Record{}, ErrIllegalTransition
	}
	return rec, err
}

// Reject pending → rejected。
func (s *PostgresStore) Reject(ctx context.Context, id, decider, reason string) (Record, error) {
	if err := validateTable(s.table, s.testGuard); err != nil {
		return Record{}, err
	}
	now := s.cfg.now()
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`UPDATE %s
SET status='rejected', updated_at=$2, decided_by=$3, reason=$4
WHERE id=$1 AND status='pending'
RETURNING id, actor, capability, request_hash, idem_key, status,
created_at, updated_at, expires_at, approved_at, decided_by, reason, lease_until`, s.table),
		id, now, decider, reason)
	return scanOrError(s, ctx, row)
}

// CheckExecutable approved 且在执行窗口内的记录可执行；
// 超窗则把记录作废（置 expired）并返回 ErrApprovalVoided；
// 其他状态返回 ErrNotApproved。只读校验，不改变可执行记录。
func (s *PostgresStore) CheckExecutable(ctx context.Context, id string) (Record, error) {
	if err := validateTable(s.table, s.testGuard); err != nil {
		return Record{}, err
	}
	rec, err := s.Get(ctx, id)
	if err != nil {
		return Record{}, err
	}
	if rec.Status != StatusApproved {
		return rec, ErrNotApproved
	}
	if rec.ApprovedAt == nil {
		return rec, ErrNotApproved
	}
	if !s.cfg.now().Before(rec.ApprovedAt.Add(s.cfg.window)) {
		// 超窗：作废。
		if _, uerr := s.pool.Exec(ctx, fmt.Sprintf(`UPDATE %s
SET status='expired', updated_at=$2, decided_by='system', reason='approved 超过 30 分钟执行窗口，已作废'
WHERE id=$1 AND status='approved'`, s.table), id, s.cfg.now()); uerr != nil {
			return rec, uerr
		}
		return rec, ErrApprovalVoided
	}
	return rec, nil
}

// Claim 先占后执行（第十轮 F2）：单条 UPDATE ... WHERE status='approved' 的原子 CAS，
// approved → executing。同一审批只可能被一个执行方抢占：
//   - 影响行数 1 → 抢占成功（返回 executing 记录）；
//   - 影响行数 0 → 已被抢占/已消费/已放弃/状态不允许 → ErrNotClaimable；
//     若当前仍为 approved 但已超窗（或缺失 approved_at）→ 作废并返回 ErrApprovalVoided。
//
// lease 为本次执行的租约时长（第十二轮 H6：由调用方按能力超时经 LeaseFor 推导，
// 通常 = 能力超时 + 40s），抢占成功时写入 lease_until = now + lease。
// lease <= 0 直接拒绝（fail-closed：无租约的执行无法参与对账）。
func (s *PostgresStore) Claim(ctx context.Context, id string, lease time.Duration) (Record, error) {
	if err := validateTable(s.table, s.testGuard); err != nil {
		return Record{}, err
	}
	if lease <= 0 {
		return Record{}, errors.New("审批抢占缺少正的执行租约时长（lease 必须由能力超时推导）")
	}
	now := s.cfg.now()
	bound := now.Add(-s.cfg.window) // 窗口下界：approved_at 必须晚于此
	// 注：抢占不覆盖 decided_by——保留审批人身份（审计与复核需要）。
	leaseUntil := now.Add(lease)
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`UPDATE %s
SET status='executing', updated_at=$2, reason='审批已被执行抢占（executing）', lease_until=$4
WHERE id=$1 AND status='approved' AND approved_at IS NOT NULL AND approved_at > $3
RETURNING id, actor, capability, request_hash, idem_key, status,
created_at, updated_at, expires_at, approved_at, decided_by, reason, lease_until`, s.table),
		id, now, bound, leaseUntil)
	rec, err := scanRecord(row)
	if errors.Is(err, pgx.ErrNoRows) {
		cur, gerr := s.Get(ctx, id)
		switch {
		case errors.Is(gerr, ErrNotFound):
			return Record{}, ErrNotFound
		case gerr != nil:
			return Record{}, gerr
		case cur.Status == StatusApproved:
			// 仍为 approved 却抢占失败：只可能是超过执行窗口（或 approved_at 缺失）。
			if _, uerr := s.pool.Exec(ctx, fmt.Sprintf(`UPDATE %s
SET status='expired', updated_at=$2, decided_by='system', reason='approved 超过 30 分钟执行窗口，已作废'
WHERE id=$1 AND status IN ('approved','executing')`, s.table), id, now); uerr != nil {
				return Record{}, uerr
			}
			return Record{}, ErrApprovalVoided
		}
		return Record{}, ErrNotClaimable
	}
	return rec, err
}

// Consume executing → consumed（第十轮：消费只发生在抢占成功之后，
// 消除「执行后写 consumed」窗口）。超窗时先作废（置 expired）并返回
// ErrApprovalVoided（不消费）；非 executing 状态返回 ErrNotExecuting。
func (s *PostgresStore) Consume(ctx context.Context, id string) (Record, error) {
	if err := validateTable(s.table, s.testGuard); err != nil {
		return Record{}, err
	}
	now := s.cfg.now()
	bound := now.Add(-s.cfg.window) // 窗口下界：approved_at 必须晚于此
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`UPDATE %s
SET status='consumed', updated_at=$2, decided_by='system', reason='审批已消费（执行完成）'
WHERE id=$1 AND status='executing' AND approved_at IS NOT NULL AND approved_at > $3
RETURNING id, actor, capability, request_hash, idem_key, status,
created_at, updated_at, expires_at, approved_at, decided_by, reason, lease_until`, s.table),
		id, now, bound)
	rec, err := scanRecord(row)
	if errors.Is(err, pgx.ErrNoRows) {
		cur, gerr := s.Get(ctx, id)
		switch {
		case errors.Is(gerr, ErrNotFound):
			return Record{}, ErrNotFound
		case gerr != nil:
			return Record{}, gerr
		case cur.Status == StatusExecuting, cur.Status == StatusApproved:
			// 消费失败只可能因为：抢占/未抢占状态下的超窗，或调用方顺序错误。
			// 仅超窗时作废（void）；否则保持原状并返回 ErrNotExecuting。
			if cur.ApprovedAt != nil && !now.Before(cur.ApprovedAt.Add(s.cfg.window)) {
				if _, uerr := s.pool.Exec(ctx, fmt.Sprintf(`UPDATE %s
SET status='expired', updated_at=$2, decided_by='system', reason='approved 超过 30 分钟执行窗口，已作废'
WHERE id=$1 AND status IN ('approved','executing')`, s.table), id, now); uerr != nil {
					return Record{}, uerr
				}
				return Record{}, ErrApprovalVoided
			}
			return Record{}, ErrNotExecuting
		}
		return Record{}, ErrNotExecuting
	}
	return rec, err
}

// MarkAbandoned executing → abandoned（第十轮：抢占后无终态，对账标记，不重放）。
// 已是 abandoned 时幂等返回；其他状态返回 ErrNotExecuting。
func (s *PostgresStore) MarkAbandoned(ctx context.Context, id string) (Record, error) {
	if err := validateTable(s.table, s.testGuard); err != nil {
		return Record{}, err
	}
	now := s.cfg.now()
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`UPDATE %s
SET status='abandoned', updated_at=$2, decided_by='system', reason='抢占后无终态事件或租约过期，已放弃（不重放）', lease_until=NULL
WHERE id=$1 AND status='executing'
RETURNING id, actor, capability, request_hash, idem_key, status,
created_at, updated_at, expires_at, approved_at, decided_by, reason, lease_until`, s.table), id, now)
	rec, err := scanRecord(row)
	if errors.Is(err, pgx.ErrNoRows) {
		cur, gerr := s.Get(ctx, id)
		if errors.Is(gerr, ErrNotFound) {
			return Record{}, ErrNotFound
		}
		if gerr != nil {
			return Record{}, gerr
		}
		if cur.Status == StatusAbandoned {
			return cur, nil // 幂等：对账可重复执行
		}
		return Record{}, ErrNotExecuting
	}
	return rec, err
}

// Renew 续期执行租约（第十一轮 H1 / 第十二轮 H6）：仅 executing 且
// lease_until > now 时可续期，lease_until = now + lease（lease 必须与 Claim 时
// 一致，由调用方按同一能力超时推导）。租约已过期 / 记录不在 executing → 返回错误，
// 调用方必须中止执行（不重放、不消费，由对账标记 abandoned）。
func (s *PostgresStore) Renew(ctx context.Context, id string, lease time.Duration) (Record, error) {
	if err := validateTable(s.table, s.testGuard); err != nil {
		return Record{}, err
	}
	if lease <= 0 {
		return Record{}, errors.New("审批续期缺少正的执行租约时长（lease 必须与 Claim 时一致）")
	}
	now := s.cfg.now()
	leaseUntil := now.Add(lease)
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`UPDATE %s
SET updated_at=$2, lease_until=$3
WHERE id=$1 AND status='executing' AND lease_until IS NOT NULL AND lease_until > $2
RETURNING id, actor, capability, request_hash, idem_key, status,
created_at, updated_at, expires_at, approved_at, decided_by, reason, lease_until`, s.table),
		id, now, leaseUntil)
	rec, err := scanRecord(row)
	if errors.Is(err, pgx.ErrNoRows) {
		// 未更新：记录不存在、不在 executing，或租约已过期。
		cur, gerr := s.Get(ctx, id)
		if errors.Is(gerr, ErrNotFound) {
			return Record{}, ErrNotFound
		}
		if gerr != nil {
			return Record{}, gerr
		}
		if cur.Status == StatusExecuting {
			return Record{}, ErrExecutionLeaseExpired
		}
		return Record{}, ErrNotExecuting
	}
	return rec, err
}

// ListExpiredExecuting 列出 executing 且 lease_until <= now 的审批（对账用，H1）：
// 未过期的执行一律跳过（可能仍在执行中）。lease_until 为 NULL 的 executing 记录
// 也视为已过期（无租约即无续期保障）。
func (s *PostgresStore) ListExpiredExecuting(ctx context.Context, now time.Time) ([]Record, error) {
	if err := validateTable(s.table, s.testGuard); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, fmt.Sprintf(`SELECT id, actor, capability, request_hash, idem_key, status,
created_at, updated_at, expires_at, approved_at, decided_by, reason, lease_until FROM %s
WHERE status='executing' AND (lease_until IS NULL OR lease_until <= $1)
ORDER BY created_at, id`, s.table), now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Record
	for rows.Next() {
		rec, err := scanRecord(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// ListExecuting 列出处于 executing 的审批（对账扫描用，按创建时间升序）。
func (s *PostgresStore) ListExecuting(ctx context.Context) ([]Record, error) {
	if err := validateTable(s.table, s.testGuard); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, fmt.Sprintf(`SELECT id, actor, capability, request_hash, idem_key, status,
created_at, updated_at, expires_at, approved_at, decided_by, reason, lease_until FROM %s
WHERE status='executing' ORDER BY created_at, id`, s.table))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Record
	for rows.Next() {
		rec, err := scanRecord(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// ExpirePending 批量过期（pending 且 expires_at <= now）。
func (s *PostgresStore) ExpirePending(ctx context.Context, now time.Time) (int64, error) {
	if err := validateTable(s.table, s.testGuard); err != nil {
		return 0, err
	}
	tag, err := s.pool.Exec(ctx, fmt.Sprintf(`UPDATE %s
SET status='expired', updated_at=$1, decided_by='system', reason='审批超时过期'
WHERE status='pending' AND expires_at <= $1`, s.table), now)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// ExpireApproved 批量作废（approved 且 approved_at + window <= now）。
func (s *PostgresStore) ExpireApproved(ctx context.Context, now time.Time) (int64, error) {
	if err := validateTable(s.table, s.testGuard); err != nil {
		return 0, err
	}
	bound := now.Add(-s.cfg.window)
	tag, err := s.pool.Exec(ctx, fmt.Sprintf(`UPDATE %s
SET status='expired', updated_at=$1, decided_by='system', reason='approved 超过 30 分钟执行窗口，已作废'
WHERE status='approved' AND approved_at IS NOT NULL AND approved_at <= $2`, s.table), now, bound)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// scanOrError 扫描一行迁移结果；未命中时区分不存在与非法迁移。
func scanOrError(s *PostgresStore, ctx context.Context, row pgx.Row) (Record, error) {
	rec, err := scanRecord(row)
	if !errors.Is(err, pgx.ErrNoRows) {
		return rec, err
	}
	return Record{}, ErrIllegalTransition
}

type rowScanner interface {
	Scan(dest ...any) error
}

// scanRecord 读取一行（列顺序与 DDL SELECT 一致；approved_at 可空）。
func scanRecord(row rowScanner) (Record, error) {
	var (
		r          Record
		status     string
		decidedBy  string
		reason     string
		approvedAt *time.Time
		leaseUntil *time.Time
	)
	err := row.Scan(&r.ID, &r.Actor, &r.Capability, &r.RequestHash, &r.IdempotencyKey,
		&status, &r.CreatedAt, &r.UpdatedAt, &r.ExpiresAt, &approvedAt, &decidedBy, &reason,
		&leaseUntil)
	if err != nil {
		return Record{}, err
	}
	r.Status = Status(status)
	r.DecidedBy = decidedBy
	r.Reason = reason
	r.ApprovedAt = approvedAt
	r.LeaseUntil = leaseUntil
	return r, nil
}

// randomHex 随机 hex（crypto/rand；失败属环境异常，直接暴露）。
func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
