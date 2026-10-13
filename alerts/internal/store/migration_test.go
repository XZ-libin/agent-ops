package store

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/XZ-libin/agent-ops/internal/testdb"
)

// repoRoot 从当前目录向上寻找仓库根（含 go.work）。
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.work")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("未找到仓库根（含 go.work）：%s", dir)
		}
		dir = parent
	}
}

// readMigration 读取迁移脚本内容。
func readMigration(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(repoRoot(t), "deploy", "migrations", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取迁移脚本失败：%v", err)
	}
	return string(data)
}

// oldAlertsDDL 旧结构（迁移前）：id 主键 + received_at，每次告警一行。
const oldAlertsDDL = `CREATE TABLE test_alerts (
    id          bigserial   PRIMARY KEY,
    source      text        NOT NULL,
    severity    text        NOT NULL CHECK (severity IN ('info','warning','critical')),
    asset_id    text        NOT NULL,
    fingerprint text        NOT NULL,
    summary     text        NOT NULL DEFAULT '',
    received_at timestamptz NOT NULL,
    count       bigint      NOT NULL DEFAULT 1,
    first_seen  timestamptz NOT NULL,
    last_seen   timestamptz NOT NULL
);`

// TestMigration0002FingerprintPK（R4 / 第十七轮 P2 无损版）
// 在独立 run schema 中用**含重复 fingerprint 的旧数据**验证 0002 上下行脚本：
//   - up：先备份（行数等于旧表行数），再聚合（每个 fingerprint 一行，count 求和）；
//   - 重复执行 up：因备份表已存在而失败；
//   - down：从备份原样恢复，逐行逐列与原始数据相等。
//
// 迁移只在 run schema 中执行，**不得作用于 public 模式**。
func TestMigration0002FingerprintPK(t *testing.T) {
	rs := testdb.NewRunSchema(t)
	if rs == nil {
		return
	}
	ctx := context.Background()
	pool := rs.Pool()
	t.Logf("[H5] 迁移测试 schema：%s（迁移脚本只在 search_path 内执行）", rs.Name())

	var publicAlertsBefore int64
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM pg_tables WHERE schemaname='public' AND tablename IN ('test_alerts','test_alerts_pre_0002')`).Scan(&publicAlertsBefore); err != nil {
		t.Fatal(err)
	}

	// 1) 旧结构 + 含重复 fingerprint 的旧数据。
	if _, err := pool.Exec(ctx, oldAlertsDDL); err != nil {
		t.Fatalf("建立旧结构失败：%v", err)
	}
	base := time.Unix(1791825000, 0)
	type row struct {
		fp      string
		count   int64
		at      time.Time
		summary string
	}
	old := []row{
		{"fp-a", 1, base, "第一次"},
		{"fp-a", 3, base.Add(6 * time.Minute), "第三次"},
		{"fp-a", 2, base.Add(3 * time.Minute), "第二次"},
		{"fp-b", 1, base.Add(1 * time.Minute), "b1"},
		{"fp-b", 4, base.Add(8 * time.Minute), "b2"},
	}
	for _, r := range old {
		if _, err := pool.Exec(ctx, `INSERT INTO test_alerts
(source, severity, asset_id, fingerprint, summary, received_at, count, first_seen, last_seen)
VALUES ('test-source-a','warning','ast_itest',$1,$2,$3,$4,$3,$3)`,
			r.fp, r.summary, r.at, r.count); err != nil {
			t.Fatal(err)
		}
	}
	var oldRows int64
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM test_alerts`).Scan(&oldRows); err != nil {
		t.Fatal(err)
	}
	if oldRows != int64(len(old)) {
		t.Fatalf("旧数据行数应为 %d，实际 %d", len(old), oldRows)
	}
	// 快照旧数据（逐行逐列，用于 down 后比对）。
	snapshot := map[int64]string{}
	srows, err := pool.Query(ctx, `SELECT id, source||'|'||severity||'|'||asset_id||'|'||fingerprint||'|'||summary
  ||'|'||received_at::text||'|'||count::text||'|'||first_seen::text||'|'||last_seen::text
FROM test_alerts ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	for srows.Next() {
		var id int64
		var line string
		if err := srows.Scan(&id, &line); err != nil {
			t.Fatal(err)
		}
		snapshot[id] = line
	}
	srows.Close()
	t.Logf("[记录] 旧数据：%d 行（fp-a 3 行、fp-b 2 行，含重复 fingerprint）", oldRows)

	// 2) 执行 up：先备份（行数 == 旧表行数），再聚合。
	if _, err := pool.Exec(ctx, readMigration(t, "0002_alerts_fingerprint_pk.up.sql")); err != nil {
		t.Fatalf("up 脚本执行失败：%v", err)
	}
	var backupRows int64
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM test_alerts_pre_0002`).Scan(&backupRows); err != nil {
		t.Fatalf("备份表不存在或不可读：%v", err)
	}
	if backupRows != oldRows {
		t.Fatalf("up 后备份表行数应等于旧表行数（%d），实际 %d", oldRows, backupRows)
	}
	var upRows int64
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM test_alerts`).Scan(&upRows); err != nil {
		t.Fatal(err)
	}
	if upRows != 2 {
		t.Fatalf("up 后每个 fingerprint 应保留一行（2 行），实际 %d", upRows)
	}
	counts := map[string]int64{}
	rows, err := pool.Query(ctx, `SELECT fingerprint, count FROM test_alerts ORDER BY fingerprint`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var fp string
		var c int64
		if err := rows.Scan(&fp, &c); err != nil {
			t.Fatal(err)
		}
		counts[fp] = c
	}
	rows.Close()
	if counts["fp-a"] != 6 || counts["fp-b"] != 5 {
		t.Fatalf("count 应为旧行之和（fp-a=6 fp-b=5），实际 %v", counts)
	}
	var pkCol string
	if err := pool.QueryRow(ctx, `
SELECT a.attname FROM pg_index i
JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
WHERE i.indrelid = 'test_alerts'::regclass AND i.indisprimary`).Scan(&pkCol); err != nil {
		t.Fatal(err)
	}
	if pkCol != "fingerprint" {
		t.Fatalf("主键应为 fingerprint，实际 %q", pkCol)
	}
	t.Logf("[记录] up 后：备份 %d 行（=旧表行数），聚合后 %d 行（fp-a count=6、fp-b count=5），主键=%s",
		backupRows, upRows, pkCol)

	// 3) 重复执行 up：备份表已存在 → 必须失败（不覆盖备份）。
	if _, err := pool.Exec(ctx, readMigration(t, "0002_alerts_fingerprint_pk.up.sql")); err == nil {
		t.Fatal("备份表已存在时重复执行 up 必须失败")
	} else if !strings.Contains(err.Error(), "备份表") {
		t.Fatalf("失败原因应说明备份表已存在：%v", err)
	}
	var backupRowsAfter int64
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM test_alerts_pre_0002`).Scan(&backupRowsAfter); err != nil {
		t.Fatal(err)
	}
	if backupRowsAfter != backupRows {
		t.Fatalf("重复执行 up 不得改动备份表：%d → %d", backupRows, backupRowsAfter)
	}
	t.Logf("[断言] 重复执行 up 被拒绝，备份表未被覆盖（仍 %d 行）", backupRowsAfter)

	// 4) 执行 down：从备份原样恢复，逐行逐列与旧数据相等；备份表被删除。
	if _, err := pool.Exec(ctx, readMigration(t, "0002_alerts_fingerprint_pk.down.sql")); err != nil {
		t.Fatalf("down 脚本执行失败：%v", err)
	}
	restored := map[int64]string{}
	rrows, err := pool.Query(ctx, `SELECT id, source||'|'||severity||'|'||asset_id||'|'||fingerprint||'|'||summary
  ||'|'||received_at::text||'|'||count::text||'|'||first_seen::text||'|'||last_seen::text
FROM test_alerts ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	for rrows.Next() {
		var id int64
		var line string
		if err := rrows.Scan(&id, &line); err != nil {
			t.Fatal(err)
		}
		restored[id] = line
	}
	rrows.Close()
	if len(restored) != len(snapshot) {
		t.Fatalf("down 后行数应与原始数据一致（%d），实际 %d", len(snapshot), len(restored))
	}
	for id, want := range snapshot {
		got, ok := restored[id]
		if !ok {
			t.Fatalf("down 后缺少 id=%d 的行", id)
		}
		if got != want {
			t.Fatalf("down 后 id=%d 的行与原始数据不一致：\n原始 %s\n恢复 %s", id, want, got)
		}
	}
	if err := pool.QueryRow(ctx, `
SELECT a.attname FROM pg_index i
JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
WHERE i.indrelid = 'test_alerts'::regclass AND i.indisprimary`).Scan(&pkCol); err != nil {
		t.Fatal(err)
	}
	if pkCol != "id" {
		t.Fatalf("down 后主键应回到 id，实际 %q", pkCol)
	}
	// 备份表在恢复后删除。
	var backupLeft int64
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM pg_tables WHERE schemaname = current_schema() AND tablename='test_alerts_pre_0002'`).Scan(&backupLeft); err != nil {
		t.Fatal(err)
	}
	if backupLeft != 0 {
		t.Fatal("down 后备份表应被删除")
	}
	t.Logf("[记录] down 后：%d 行逐行逐列与原始数据相等，主键=%s，备份表已删除", len(restored), pkCol)

	// 5) 迁移只作用于 run schema：public 中相关表数量未变。
	var publicAlertsAfter int64
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM pg_tables WHERE schemaname='public' AND tablename IN ('test_alerts','test_alerts_pre_0002')`).Scan(&publicAlertsAfter); err != nil {
		t.Fatal(err)
	}
	if publicAlertsAfter != publicAlertsBefore {
		t.Fatalf("迁移不得作用于 public：%d → %d", publicAlertsBefore, publicAlertsAfter)
	}
	t.Log("[断言] 迁移只在 run schema 内执行，public 未被触碰")
}

// TestMigrationDownRequiresBackup 备份表缺失时 down 必须失败（不静默损坏数据）。
func TestMigrationDownRequiresBackup(t *testing.T) {
	rs := testdb.NewRunSchema(t)
	if rs == nil {
		return
	}
	ctx := context.Background()
	if _, err := rs.Pool().Exec(ctx, oldAlertsDDL); err != nil {
		t.Fatal(err)
	}
	if _, err := rs.Pool().Exec(ctx, readMigration(t, "0002_alerts_fingerprint_pk.down.sql")); err == nil {
		t.Fatal("无备份表时 down 必须失败")
	} else if !strings.Contains(err.Error(), "备份表") {
		t.Fatalf("失败原因应说明缺少备份表：%v", err)
	}
	// 原表仍在（未被误删）。
	var n int64
	if err := rs.Pool().QueryRow(ctx, `SELECT count(*) FROM test_alerts`).Scan(&n); err != nil {
		t.Fatalf("down 失败时不得删除原表：%v", err)
	}
}

// TestMigrationScriptsAreSchemaRelative 迁移脚本必须使用未限定表名
// （否则无法在 run schema 中验证、且可能误伤 public）。
func TestMigrationScriptsAreSchemaRelative(t *testing.T) {
	for _, name := range []string{
		"0002_alerts_fingerprint_pk.up.sql",
		"0002_alerts_fingerprint_pk.down.sql",
	} {
		script := readMigration(t, name)
		for _, bad := range []string{"public.", "DROP SCHEMA", "CREATE SCHEMA"} {
			if contains(script, bad) {
				t.Fatalf("迁移脚本 %s 不得包含 %q（必须作用于 search_path 指向的 schema）", name, bad)
			}
		}
	}
}

// contains 判定子串（避免额外依赖）。
func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

// indexOf 返回子串首次出现位置（-1 表示不存在）。
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
