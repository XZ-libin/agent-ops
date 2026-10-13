package testdb

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// RunSchema 每轮测试的独立 schema（第十四轮 H5）。
//
// 规则（第二十四轮 R1c 修订）：
//   - 集成测试使用 schema 名 `test_run_<时间戳后缀>`；
//   - 测试结束时**无论通过与否**都删除该 schema；
//   - 删除前断言 schema 名以 `test_run_` 开头，绝不触碰 public 模式中的任何表；
//   - 失败现场**不再以 DB schema 形式保留**：schema 名与失败原因写入测试日志
//     （第二十三轮之前的"失败保留"策略会让任何失败必然打破 `make residual-check`，
//     使该门禁在有失败时永远无法通过——见 ADR-023 §4）。
//
// 实现方式：新建 schema 后，连接串追加 `search_path=<schema>`，
// 被测代码建的表（test_* 前缀）全部落在该 schema 内，public 不再增长。
type RunSchema struct {
	name string
	dsn  string
	pool *pgxpool.Pool
}

// RunSchemaPrefix 每轮独立 schema 的强制前缀（删除前校验）。
const RunSchemaPrefix = "test_run_"

// NewRunSchema 创建每轮独立 schema 与连接池（search_path 指向该 schema）。
// 库名校验（Validate）在此复用：非 agent_ops_test 一律拒绝。
func NewRunSchema(t *testing.T) *RunSchema {
	t.Helper()
	base, err := Resolve()
	if err != nil {
		t.Fatalf("测试数据库校验失败（fail closed）：%v", err)
	}
	name := fmt.Sprintf("%s%d", RunSchemaPrefix, time.Now().UnixNano())

	admin, err := pgxpool.New(context.Background(), base)
	if err != nil {
		t.Skipf("PostgreSQL 不可用，跳过用例（原因：%v）。", err)
		return nil
	}
	pingCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := admin.Ping(pingCtx); err != nil {
		admin.Close()
		t.Skipf("PostgreSQL 不可达，跳过用例（原因：%v）。", err)
		return nil
	}
	// schema 名由代码生成（非外部输入），仍做一次前缀校验。
	if !strings.HasPrefix(name, RunSchemaPrefix) {
		admin.Close()
		t.Fatalf("内部错误：schema 名 %q 缺少前缀 %q", name, RunSchemaPrefix)
	}
	if _, err := admin.Exec(context.Background(), fmt.Sprintf("CREATE SCHEMA %s", quoteIdent(name))); err != nil {
		admin.Close()
		t.Fatalf("创建测试 schema 失败：%v", err)
	}
	// 新 schema 默认不授予其他角色任何权限：审计存储的 Append 会
	// `SET LOCAL ROLE audit_writer` 后写表，缺少 USAGE 会表现为
	// "relation does not exist"（角色看不到该 schema）。此处显式授予。
	for _, stmt := range []string{
		`DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'audit_writer') THEN
    CREATE ROLE audit_writer NOLOGIN;
  END IF;
END $$;`,
		fmt.Sprintf("GRANT USAGE ON SCHEMA %s TO audit_writer", quoteIdent(name)),
	} {
		if _, err := admin.Exec(context.Background(), stmt); err != nil {
			admin.Close()
			t.Fatalf("测试 schema 授权失败：%v", err)
		}
	}
	admin.Close()

	dsn := withSearchPath(base, name)
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("连接测试 schema 失败：%v", err)
	}

	rs := &RunSchema{name: name, dsn: dsn, pool: pool}
	t.Cleanup(func() {
		pool.Close()
		// R1c：失败路径同样删除（清理是单一路径 CleanupRunSchema，便于测试覆盖）。
		if err := CleanupRunSchema(context.Background(), base, name, t.Failed(), t.Logf); err != nil {
			t.Errorf("[H5] 删除测试 schema 失败：%v", err)
		}
	})
	return rs
}

// CleanupRunSchema 删除指定 run schema（**唯一**清理入口，通过/失败都走这里）。
//
// failed 为 true 表示调用方处于失败路径：仍然删除，但把"失败"与 schema 名写入日志，
// 使现场证据留在测试输出里而不是留在数据库里。
// 删除前强制校验前缀：非 test_run_ 前缀（含 public）一律拒绝，fail-closed。
func CleanupRunSchema(ctx context.Context, baseDSN, name string, failed bool, logf func(string, ...any)) error {
	if err := ValidateSchemaName(name); err != nil {
		return err
	}
	admin, err := pgxpool.New(ctx, baseDSN)
	if err != nil {
		return err
	}
	defer admin.Close()
	if _, err := admin.Exec(ctx, fmt.Sprintf("DROP SCHEMA %s CASCADE", quoteIdent(name))); err != nil {
		return err
	}
	state := "通过"
	if failed {
		state = "失败（现场证据转入本日志，schema 不保留）"
	}
	if logf != nil {
		logf("[H5] 测试%s，已删除 schema %s", state, name)
	}
	return nil
}

// Name 返回 schema 名。
func (r *RunSchema) Name() string { return r.name }

// DSN 返回 search_path 指向本 schema 的连接串。
func (r *RunSchema) DSN() string { return r.dsn }

// Pool 返回本 schema 的连接池。
func (r *RunSchema) Pool() *pgxpool.Pool { return r.pool }

// ValidateSchemaName 校验 schema 名必须以 test_run_ 开头
// （删除前的安全闸门：非该前缀一律拒绝，防止误删 public 等）。
func ValidateSchemaName(name string) error {
	if !strings.HasPrefix(name, RunSchemaPrefix) {
		return fmt.Errorf("testdb：拒绝操作 schema %q（必须以 %q 开头；public 等模式不可触碰）",
			name, RunSchemaPrefix)
	}
	if name == RunSchemaPrefix {
		return fmt.Errorf("testdb：schema 名 %q 不合法（缺少时间戳后缀）", name)
	}
	return nil
}

// withSearchPath 在连接串后追加 search_path 参数。
func withSearchPath(dsn, schema string) string {
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + "search_path=" + schema
}

// quoteIdent 最小化标识符引用（schema 名由代码生成：小写字母数字下划线）。
func quoteIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}
