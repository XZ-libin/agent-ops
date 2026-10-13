package testdb

// R1d（第二十四轮）：清理必须在**失败路径**也执行。
//
// 根因（R1c）：第十四轮 H5 的策略是"测试失败时保留 schema 供事后排查"
// （runschema.go 旧 t.Cleanup 分支）。而 `make residual-check` 门禁断言
// `test_run_*` schema 为 0——两者互斥：**任何一个用例失败都必然打破残留门禁**。
// 本轮把策略改为"通过/失败都删除"，失败现场以日志形式保留。
//
// 本用例真实创建 schema，再以 failed=true 调用唯一清理入口 CleanupRunSchema
// （t.Cleanup 在测试失败时传入的正是同一个值），断言 schema 已消失；
// 同时断言 public / 非前缀名一律拒绝——防止"为了清理"而误删非测试对象。

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// adminPool 连接测试库**基线 DSN**（不带 search_path，用于操作 pg_namespace）。
// PostgreSQL 不可达时 skip 并返回 nil（与 NewRunSchema 的 skip 口径一致）。
func adminPool(t *testing.T) (string, *pgxpool.Pool) {
	t.Helper()
	base, err := Resolve()
	if err != nil {
		t.Fatalf("测试库 DSN 校验失败：%v", err)
	}
	pool, err := pgxpool.New(context.Background(), base)
	if err != nil {
		t.Fatalf("连接测试库失败：%v", err)
	}
	pingCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		t.Skipf("PostgreSQL 不可达，跳过用例（原因：%v）。", err)
		return "", nil
	}
	t.Cleanup(pool.Close)
	return base, pool
}

// schemaExists 查询 schema 是否存在。
func schemaExists(ctx context.Context, pool *pgxpool.Pool, name string) (bool, error) {
	var n int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM pg_namespace WHERE nspname = $1`, name).Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}

func TestCleanupRunsOnFailure(t *testing.T) {
	base, pool := adminPool(t)
	if pool == nil {
		return
	}
	ctx := context.Background()
	name := fmt.Sprintf("%s%d", RunSchemaPrefix, time.Now().UnixNano())
	if _, err := pool.Exec(ctx, fmt.Sprintf("CREATE SCHEMA %s", quoteIdent(name))); err != nil {
		t.Fatalf("创建测试 schema 失败：%v", err)
	}
	// 兜底：本用例自身出错时也不留残留（仍走前缀校验闸门）。
	t.Cleanup(func() {
		if ok, _ := schemaExists(context.Background(), pool, name); ok {
			if err := CleanupRunSchema(context.Background(), base, name, true, t.Logf); err != nil {
				t.Errorf("兜底清理失败：%v", err)
			}
		}
	})

	if ok, err := schemaExists(ctx, pool, name); err != nil || !ok {
		t.Fatalf("前置条件：schema %s 应存在（存在=%v 错误=%v）", name, ok, err)
	}

	var logged []string
	logf := func(format string, args ...any) {
		logged = append(logged, fmt.Sprintf(format, args...))
	}
	// —— 失败路径：failed=true 必须**照样删除** ——
	if err := CleanupRunSchema(ctx, base, name, true, logf); err != nil {
		t.Fatalf("失败路径也必须删除 schema：%v", err)
	}
	if ok, err := schemaExists(ctx, pool, name); err != nil || ok {
		t.Fatalf("[R1d] schema 应已删除（存在=%v 错误=%v）", ok, err)
	}
	if len(logged) != 1 || !strings.Contains(logged[0], "失败") {
		t.Fatalf("[R1d] 失败路径应写一条含\"失败\"的日志，实际 %v", logged)
	}

	// —— fail-closed：非 run 前缀一律拒绝，public 必须安然无恙 ——
	for _, bad := range []string{"public", "information_schema", "test_approvals", "test_run_", ""} {
		if err := CleanupRunSchema(ctx, base, bad, true, nil); err == nil {
			t.Fatalf("[R1d] schema 名 %q 必须被清理闸门拒绝", bad)
		}
	}
	if ok, err := schemaExists(ctx, pool, "public"); err != nil || !ok {
		t.Fatalf("[R1d] public 必须仍然存在（存在=%v 错误=%v）", ok, err)
	}
	t.Logf("[R1d] 失败路径清理验证通过：schema 已删除、日志留证、public 与非前缀名拒绝")
}
