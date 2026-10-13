// Package nodemigrate 是**节点域**的 schema 迁移（第二十三轮 T3/T4）。
//
// 为什么需要它：第二十二轮的建表语句（nodestore.EnsureSchema）只能创建"初始形态"；
// 本轮新增的列（吊销原因、补发关联、待确认旧序列号、会话基线）必须以
// **可回滚的迁移**方式添加，而不是改 CREATE TABLE——否则已存在的测试 schema
// 不会得到新列，且无法验证回滚。
//
// 约定：
//   - 只允许 **test_** 前缀的表名（与 nodestore 的守卫一致）；
//   - 每条迁移同时提供 Up（前进）与 Down（回滚）；
//   - 全部语句幂等（IF NOT EXISTS / DROP ... IF EXISTS），可重复执行；
//   - 迁移记录表 test_node_schema_migrations 只用于可观测性，**不参与幂等判定**
//     （幂等由语句自身的 IF 判定保证，避免"记录丢失即重复执行"的风险）。
package nodemigrate

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// tablePattern 表名必须是 test_ 前缀的小写标识符（DDL 拼装，杜绝注入）。
var tablePattern = regexp.MustCompile(`^test_[a-z0-9_]+$`)

// ErrBadTable 表名不合法。
var ErrBadTable = errors.New("nodemigrate：表名必须以 test_ 开头且为合法标识符")

// Tables 迁移涉及的表名（可覆盖，便于测试使用独立表名）。
type Tables struct {
	// Nodes 节点状态表。
	Nodes string
	// Tokens 注册令牌表。
	Tokens string
	// Revocations 证书吊销表。
	Revocations string
	// Certs 证书状态机表（第二十四轮 T1）。
	Certs string
	// SweepState 扫描器状态表（第二十四轮 T2：告警节流的持久化）。
	SweepState string
}

// DefaultTables 默认表名（与 nodestore 的默认值一致）。
func DefaultTables() Tables {
	return Tables{
		Nodes:       "test_nodes",
		Tokens:      "test_enroll_tokens",
		Revocations: "test_cert_revocations",
		Certs:       "test_node_certs",
		SweepState:  "test_node_sweep_state",
	}
}

// Migration 一条迁移。
type Migration struct {
	// Version 单调递增的版本号。
	Version int
	// Name 简述（写入迁移记录表）。
	Name string
	// Up 前进语句（必须幂等）。
	Up []string
	// Down 回滚语句（必须幂等）。
	Down []string
}

// All 返回全部迁移（按版本升序）。
//
// 002 是"第二十三轮"引入的三组新列：
//   - 吊销表 reason 的取值约束（revoked | superseded）；
//   - 令牌表的补发关联列 reissued_for_node_id；
//   - 节点表的待确认旧序列号与 D6 会话基线列。
func All(t Tables) []Migration {
	return []Migration{
		{
			Version: 1,
			Name:    "revocations_reason_check",
			Up: []string{
				// 列在第二十二轮已存在（DEFAULT ''），这里补上取值约束并把历史行回填为 revoked。
				fmt.Sprintf(`UPDATE %s SET reason = 'revoked' WHERE reason = '' OR reason IS NULL`, t.Revocations),
				fmt.Sprintf(`ALTER TABLE %s DROP CONSTRAINT IF EXISTS %s_reason_check`,
					t.Revocations, t.Revocations),
				fmt.Sprintf(`ALTER TABLE %s ADD CONSTRAINT %s_reason_check
                    CHECK (reason IN ('revoked','superseded'))`,
					t.Revocations, t.Revocations),
			},
			Down: []string{
				fmt.Sprintf(`ALTER TABLE %s DROP CONSTRAINT IF EXISTS %s_reason_check`,
					t.Revocations, t.Revocations),
			},
		},
		{
			Version: 2,
			Name:    "tokens_reissued_for_node_id",
			Up: []string{
				fmt.Sprintf(`ALTER TABLE %s ADD COLUMN IF NOT EXISTS reissued_for_node_id text`,
					t.Tokens),
			},
			Down: []string{
				fmt.Sprintf(`ALTER TABLE %s DROP COLUMN IF EXISTS reissued_for_node_id`, t.Tokens),
			},
		},
		{
			Version: 3,
			Name:    "nodes_pending_supersede_and_session",
			Up: []string{
				// T3：续期后**待确认**的旧序列号——收到新序列号首次心跳后才写吊销表。
				fmt.Sprintf(`ALTER TABLE %s ADD COLUMN IF NOT EXISTS pending_superseded_serial text NOT NULL DEFAULT ''`,
					t.Nodes),
				// T1/D6：会话基线，控制面重启后继续沿用（否则重启会丢失会话维度）。
				fmt.Sprintf(`ALTER TABLE %s ADD COLUMN IF NOT EXISTS boot_session_id text NOT NULL DEFAULT ''`,
					t.Nodes),
				fmt.Sprintf(`ALTER TABLE %s ADD COLUMN IF NOT EXISTS session_sent_at timestamptz`,
					t.Nodes),
			},
			Down: []string{
				fmt.Sprintf(`ALTER TABLE %s DROP COLUMN IF EXISTS session_sent_at`, t.Nodes),
				fmt.Sprintf(`ALTER TABLE %s DROP COLUMN IF EXISTS boot_session_id`, t.Nodes),
				fmt.Sprintf(`ALTER TABLE %s DROP COLUMN IF EXISTS pending_superseded_serial`, t.Nodes),
			},
		},
		{
			// 第二十四轮 T1：证书状态机表。
			//
			// 为什么需要它：`pending_superseded_serial` 只能存**一个**序列号，
			// 第二次续期会覆盖第一次，导致第一份旧证书**永不被 supersede**
			// （在 7 天有效期内持续有效）——这是一个安全缺口。
			// 改为"每证书一条状态记录"后，任意数量的未确认证书都能被正确收敛。
			Version: 4,
			Name:    "node_certs_state_machine",
			Up: []string{
				fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
    serial       text        PRIMARY KEY,
    node_id      text        NOT NULL,
    state        text        NOT NULL CHECK (state IN ('issued','active','superseded','revoked')),
    issued_at    timestamptz NOT NULL,
    not_after    timestamptz NOT NULL,
    confirmed_at timestamptz
)`, t.Certs),
				fmt.Sprintf(`CREATE INDEX IF NOT EXISTS %s_node_state_idx ON %s (node_id, state)`,
					t.Certs, t.Certs),
				// 从既有 test_nodes.cert_serial 回填为 active（旧列保留、停止写入：见 ADR-023 §1）。
				fmt.Sprintf(`INSERT INTO %s (serial, node_id, state, issued_at, not_after, confirmed_at)
SELECT n.cert_serial, n.node_id, 'active', coalesce(n.created_at, now()),
       coalesce(n.created_at, now()) + interval '7 days', coalesce(n.last_received_at, n.created_at)
  FROM %s n
 WHERE n.cert_serial <> ''
   AND NOT EXISTS (SELECT 1 FROM %s c WHERE c.serial = n.cert_serial)`,
					t.Certs, t.Nodes, t.Certs),
			},
			Down: []string{
				fmt.Sprintf(`DROP TABLE IF EXISTS %s`, t.Certs),
			},
		},
		{
			// 第二十四轮 T2：扫描器告警节流的**持久化**状态。
			//
			// 为什么要落库：节流窗口（每节点每 6 小时最多一条）必须跨**控制面重启**
			// 保持，否则每次重启都会重新告警一次；同时下一次告警的时刻需要可观测。
			Version: 5,
			Name:    "node_sweep_state",
			Up: []string{
				fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
    node_id       text        NOT NULL,
    event         text        NOT NULL,
    last_emit_at  timestamptz NOT NULL,
    PRIMARY KEY (node_id, event)
)`, t.SweepState),
			},
			Down: []string{
				fmt.Sprintf(`DROP TABLE IF EXISTS %s`, t.SweepState),
			},
		},
	}
}

// Migrator 迁移执行器。
type Migrator struct {
	pool   *pgxpool.Pool
	tables Tables
}

// New 构建迁移执行器（校验表名，fail-closed）。
func New(pool *pgxpool.Pool, tables Tables) (*Migrator, error) {
	if pool == nil {
		return nil, errors.New("nodemigrate：连接池为空")
	}
	if tables.Nodes == "" {
		tables = DefaultTables()
	}
	for _, t := range []string{tables.Nodes, tables.Tokens, tables.Revocations,
		tables.Certs, tables.SweepState} {
		if !tablePattern.MatchString(t) {
			return nil, fmt.Errorf("%w：%q", ErrBadTable, t)
		}
	}
	return &Migrator{pool: pool, tables: tables}, nil
}

// EnsureLedger 建迁移记录表（仅可观测性，幂等）。
func (m *Migrator) EnsureLedger(ctx context.Context) error {
	_, err := m.pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS test_node_schema_migrations (
    version     integer     PRIMARY KEY,
    name        text        NOT NULL,
    applied_at  timestamptz NOT NULL DEFAULT now()
)`)
	if err != nil {
		return fmt.Errorf("nodemigrate：建迁移记录表失败：%w", err)
	}
	return nil
}

// Up 执行全部迁移（前进）；返回本次应用的版本号。
func (m *Migrator) Up(ctx context.Context) ([]int, error) {
	if err := m.EnsureLedger(ctx); err != nil {
		return nil, err
	}
	var applied []int
	for _, mig := range All(m.tables) {
		for _, stmt := range mig.Up {
			if _, err := m.pool.Exec(ctx, stmt); err != nil {
				return applied, fmt.Errorf("nodemigrate：迁移 %d(%s) 前进失败：%w",
					mig.Version, mig.Name, err)
			}
		}
		if _, err := m.pool.Exec(ctx,
			`INSERT INTO test_node_schema_migrations (version, name) VALUES ($1,$2)
             ON CONFLICT (version) DO NOTHING`, mig.Version, mig.Name); err != nil {
			return applied, err
		}
		applied = append(applied, mig.Version)
	}
	return applied, nil
}

// Down 回滚全部迁移（**逆序**执行 Down）。
//
// 幂等且**不要求记录表存在**：真实场景里"第二十二轮的旧 schema"根本没有
// test_node_schema_migrations 表，此时 Down 必须能正常执行（向旧 schema 前进/回退
// 是部署脚本的常见动作）。记录表的清理用 IF EXISTS，避免依赖它存在。
func (m *Migrator) Down(ctx context.Context) error {
	migs := All(m.tables)
	for i := len(migs) - 1; i >= 0; i-- {
		for _, stmt := range migs[i].Down {
			if _, err := m.pool.Exec(ctx, stmt); err != nil {
				return fmt.Errorf("nodemigrate：迁移 %d(%s) 回滚失败：%w",
					migs[i].Version, migs[i].Name, err)
			}
		}
	}
	if _, err := m.pool.Exec(ctx,
		`DELETE FROM test_node_schema_migrations WHERE true`); err != nil {
		// 记录表不存在（旧 schema）视为正常：Down 只负责结构回退。
		if !isUndefinedTable(err) {
			return err
		}
	}
	return nil
}

// isUndefinedTable 判定 pgx 错误是否为"表不存在"（SQLSTATE 42P01）。
func isUndefinedTable(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "42P01"
	}
	return false
}

// TableExists 判定表是否存在（测试断言用）。
func (m *Migrator) TableExists(ctx context.Context, name string) (bool, error) {
	return m.ColumnExists(ctx, name, "")
}

// ColumnExists 判定某表的某列是否存在（name 为空则只判定表）。
func (m *Migrator) ColumnExists(ctx context.Context, table, column string) (bool, error) {
	if !tablePattern.MatchString(table) {
		return false, fmt.Errorf("%w：%q", ErrBadTable, table)
	}
	var n int
	var err error
	if column == "" {
		err = m.pool.QueryRow(ctx,
			`SELECT count(*) FROM information_schema.tables
             WHERE table_schema = current_schema() AND table_name = $1`, table).Scan(&n)
	} else {
		err = m.pool.QueryRow(ctx,
			`SELECT count(*) FROM information_schema.columns
             WHERE table_schema = current_schema() AND table_name = $1 AND column_name = $2`,
			table, column).Scan(&n)
	}
	if err != nil {
		return false, fmt.Errorf("nodemigrate：查询结构失败：%w", err)
	}
	return n > 0, nil
}
