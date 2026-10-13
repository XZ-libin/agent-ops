package testdb

// R3c（第二十四轮）：public 模式的表数量**只防增长，不清理历史残留**。
//
// 事实（R0/R3b 实测）：agent_ops_test.public 有 75 张表 =
//   - 3 张生产命名表：approvals、audit_events、idempotency_keys；
//   - 72 张历史残留表：test_audit_events_* / test_approvals_*，其表名时间戳
//     全部落在 2026-10-12 ~ 10-13 01:00（第十四轮 H5 之前，当时测试直接用基线
//     DSN 在 public 建表）。H5 引入 NewRunSchema（search_path=test_run_*）后，
//     第二十四轮两次全量 `go test ./...` 之后 public 计数保持 75，未再增长。
//
// 硬性约束 3：**不删除** public 中的任何表（含这 72 张历史残留）。
// 因此本守卫只做一件事：把"不得再增长"变成可执行断言。超出基线即失败，
// 并列出全部 public 表名与体积，供人工识别新增者。

import (
	"context"
	"testing"
	"time"
)

// publicTableBaseline public 表数基线（第二十四轮 R0 实测快照值）。
const publicTableBaseline = 75

func TestPublicTableCountDoesNotGrow(t *testing.T) {
	_, pool := adminPool(t)
	if pool == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var n int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM pg_tables WHERE schemaname = 'public'`).Scan(&n); err != nil {
		t.Fatalf("查询 public 表数失败：%v", err)
	}
	if n > publicTableBaseline {
		rows, err := pool.Query(ctx, `SELECT tablename,
			pg_size_pretty(pg_total_relation_size('public.' || quote_ident(tablename)))
		  FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename`)
		if err != nil {
			t.Fatalf("列出 public 表失败：%v", err)
		}
		defer rows.Close()
		for rows.Next() {
			var name, size string
			if err := rows.Scan(&name, &size); err != nil {
				t.Fatalf("读取表名失败：%v", err)
			}
			t.Logf("[R3] public.%s (%s)", name, size)
		}
		t.Fatalf("[R3] public 表数 %d 超过基线 %d：新测试表必须建在当前 run schema 内"+
			"（用 testdb.NewRunSchema，禁止直接用基线 DSN 建表）", n, publicTableBaseline)
	}
	if n != publicTableBaseline {
		t.Logf("[R3] public 表数 %d（低于基线 %d：说明有人清理了历史残留，"+
			"本轮并未授权删除 public 表，请核对）", n, publicTableBaseline)
	}
	t.Logf("[R3] public 表数=%d，与基线一致（未增长；守卫只阻止新增，不删除历史残留）", n)
}
