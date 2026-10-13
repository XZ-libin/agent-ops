package nodesvc

// 迁移测试（第二十三轮 T3/T4）：验证新增列在**已存在的 schema** 上前进与回滚。
//
// 覆盖：
//   - Up：三组迁移全部应用后，目标列存在，且旧数据被正确回填；
//   - Down：逆序回滚后列被移除（可重复执行，幂等）；
//   - 幂等：Up 连续执行两次不报错；
//   - 表名守卫：非 test_ 前缀被拒绝。

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/ORG/agent-ops/internal/nodemigrate"
)

// TestMigrationUpDownVerified（T3/T4）迁移 Up 与 Down 均已验证。
func TestMigrationUpDownVerified(t *testing.T) {
	e := newEnv(t)
	if e == nil {
		return
	}
	ctx := context.Background()
	nodes, tokens, revocations := e.store.Tables()

	mig, err := nodemigrate.New(e.pool, nodemigrate.Tables{
		Nodes: nodes, Tokens: tokens, Revocations: revocations,
		Certs:      "test_node_certs",
		SweepState: "test_node_sweep_state",
	})
	if err != nil {
		t.Fatal(err)
	}

	// ① Up：全部迁移前进。注意本环境的建表已包含新列（CREATE TABLE 与迁移同步），
	//    因此这里先 Down 一次模拟"第二十二轮的旧 schema"，再 Up 验证前进。
	if err := mig.Down(ctx); err != nil {
		t.Fatalf("Down（模拟旧 schema）失败：%v", err)
	}
	// 回滚后：三组新列都应不存在。
	for _, col := range []string{"pending_superseded_serial", "boot_session_id", "session_sent_at"} {
		ok, err := mig.ColumnExists(ctx, nodes, col)
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			t.Fatalf("Down 后列 %s.%s 应不存在", nodes, col)
		}
	}
	if ok, err := mig.ColumnExists(ctx, tokens, "reissued_for_node_id"); err != nil || ok {
		t.Fatalf("Down 后列 %s.reissued_for_node_id 应不存在（ok=%v err=%v）", tokens, ok, err)
	}
	if ok, err := mig.ColumnExists(ctx, revocations, "reason"); err != nil || !ok {
		// reason 列本身是第二十二轮就有的；迁移 1 只加 CHECK 约束，因此列应始终存在。
		t.Fatalf("reason 列应始终存在（ok=%v err=%v）", ok, err)
	}

	// ② Up：重新前进。
	applied, err := mig.Up(ctx)
	if err != nil {
		t.Fatalf("Up 失败：%v", err)
	}
	if len(applied) != 5 {
		t.Fatalf("应有 5 条迁移被应用（第二十三轮 3 条 + 第二十四轮证书状态机表 004 + 扫描状态表 005），实际 %v", applied)
	}
	for _, col := range []string{"pending_superseded_serial", "boot_session_id", "session_sent_at"} {
		ok, err := mig.ColumnExists(ctx, nodes, col)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Fatalf("Up 后应存在列 %s.%s", nodes, col)
		}
	}
	if ok, err := mig.ColumnExists(ctx, tokens, "reissued_for_node_id"); err != nil || !ok {
		t.Fatalf("Up 后应存在列 %s.reissued_for_node_id（ok=%v err=%v）", tokens, ok, err)
	}

	// ③ 幂等：Up 重复执行不报错。
	if _, err := mig.Up(ctx); err != nil {
		t.Fatalf("Up 应幂等（重复执行不报错）：%v", err)
	}
	// ④ 幂等：Down 重复执行不报错。
	if err := mig.Down(ctx); err != nil {
		t.Fatalf("Down 应幂等：%v", err)
	}
	if err := mig.Down(ctx); err != nil {
		t.Fatalf("Down 二次执行应幂等：%v", err)
	}
	// 回到已迁移状态，便于后续用例（本 schema 在用例结束时删除，但仍保持一致性）。
	if _, err := mig.Up(ctx); err != nil {
		t.Fatal(err)
	}

	// ⑤ 迁移记录表存在（可观测性）。
	if ok, err := mig.TableExists(ctx, "test_node_schema_migrations"); err != nil || !ok {
		t.Fatalf("迁移记录表应存在（ok=%v err=%v）", ok, err)
	}
	t.Logf("[迁移] Up 应用 %v；Down 移除三组新列；Up/Down 均可重复执行（幂等）；记录表存在", applied)
}

// TestMigrationReasonBackfill（T3）迁移 1 把历史空 reason 回填为 revoked。
func TestMigrationReasonBackfill(t *testing.T) {
	e := newEnv(t)
	if e == nil {
		return
	}
	ctx := context.Background()
	nodes, tokens, revocations := e.store.Tables()
	mig, err := nodemigrate.New(e.pool, nodemigrate.Tables{
		Nodes: nodes, Tokens: tokens, Revocations: revocations,
		Certs:      "test_node_certs",
		SweepState: "test_node_sweep_state",
	})
	if err != nil {
		t.Fatal(err)
	}
	// 先回滚掉 CHECK 约束，插入一行空 reason 的"历史数据"。
	if err := mig.Down(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := e.pool.Exec(ctx, fmt.Sprintf(
		`INSERT INTO %s (serial, node_id, revoked_at, reason) VALUES ($1,$2,now(),'')`,
		revocations), "legacy-serial", "nod_01M4RHFDJ0LEGACY00000000"); err != nil {
		t.Fatalf("插入历史行失败：%v", err)
	}
	// Up 应回填为 revoked 并加上 CHECK 约束。
	if _, err := mig.Up(ctx); err != nil {
		t.Fatalf("Up 失败：%v", err)
	}
	reason, found, err := e.store.RevocationReason(ctx, "legacy-serial")
	if err != nil || !found {
		t.Fatalf("历史行应存在：found=%v err=%v", found, err)
	}
	if reason != RevokeReason {
		t.Fatalf("历史空 reason 应回填为 %q，实际 %q", RevokeReason, reason)
	}
	// CHECK 约束生效：非法 reason 必须被数据库拒绝。
	if _, err := e.pool.Exec(ctx, fmt.Sprintf(
		`INSERT INTO %s (serial, node_id, revoked_at, reason) VALUES ($1,$2,now(),$3)`,
		revocations), "bad-serial", "nod_01M4RHFDJ0LEGACY00000001", "not-a-reason"); err == nil {
		t.Fatal("非法 reason 必须被 CHECK 约束拒绝")
	}
	t.Log("[迁移] 历史空 reason 回填为 revoked；CHECK 约束拒绝非法取值")
}

// TestMigrationRejectsNonTestTables（迁移）表名守卫：非 test_ 前缀被拒绝。
func TestMigrationRejectsNonTestTables(t *testing.T) {
	e := newEnv(t)
	if e == nil {
		return
	}
	for _, bad := range []string{"nodes", "prod_nodes", "test_BAD", "test-"} {
		if _, err := nodemigrate.New(e.pool, nodemigrate.Tables{
			Nodes: bad, Tokens: "test_t", Revocations: "test_r",
			Certs: "test_c", SweepState: "test_s",
		}); !errors.Is(err, nodemigrate.ErrBadTable) {
			t.Fatalf("表名 %q 应被拒绝（ErrBadTable），实际 %v", bad, err)
		}
	}
	// 合法名通过。
	if _, err := nodemigrate.New(e.pool, nodemigrate.DefaultTables()); err != nil {
		t.Fatalf("默认表名应被接受：%v", err)
	}
	t.Log("[迁移] 非 test_ 前缀表名一律拒绝（prod_nodes / nodes / test-BAD 等）")
}
