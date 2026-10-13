package redrive

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ORG/agent-ops/internal/testdb"
)

// newTestRedriver 建立真实 PG 重投环境（独立 run schema），并造一条 dead 事件。
func newTestRedriver(t *testing.T) (*Redriver, int64) {
	t.Helper()
	rs := testdb.NewRunSchema(t)
	if rs == nil {
		return nil, 0
	}
	ctx := context.Background()
	// outbox 表（结构同 store；本测试直接建表以独立验证重投）。
	if _, err := rs.Pool().Exec(ctx, `CREATE TABLE IF NOT EXISTS test_outbox (
    id          bigserial   PRIMARY KEY,
    event_type  text        NOT NULL,
    payload     jsonb       NOT NULL,
    status      text        NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','consumed','dead')),
    attempts    integer     NOT NULL DEFAULT 0,
    next_attempt_at timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now(),
    consumed_at timestamptz
);`); err != nil {
		t.Fatalf("建 outbox 表失败：%v", err)
	}
	r, err := New(Config{Pool: rs.Pool(), Now: func() time.Time { return time.Unix(1791825000, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.EnsureSchema(ctx); err != nil {
		t.Fatalf("建重投日志表失败：%v", err)
	}
	// 造一条 dead 事件（模拟消费者第 5 次失败后）。
	var id int64
	if err := rs.Pool().QueryRow(ctx, `INSERT INTO test_outbox
(event_type, payload, status, attempts, next_attempt_at)
VALUES ('alert.received','{"fingerprint":"fp-1"}','dead',5,NULL) RETURNING id`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	t.Logf("[H5] schema：%s，dead 事件 id=%d", rs.Name(), id)
	return r, id
}

// TestRedriveRejections（P3）每一条拒绝条件各一个用例：均不修改任何数据。
func TestRedriveRejections(t *testing.T) {
	r, id := newTestRedriver(t)
	if r == nil {
		return
	}
	ctx := context.Background()

	// 造一条非 dead 事件（pending）用于"状态不是 dead"用例。
	var pendingID int64
	if err := r.pool.QueryRow(ctx, `INSERT INTO test_outbox
(event_type, payload, status, attempts) VALUES ('alert.received','{}','pending',1) RETURNING id`).Scan(&pendingID); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name     string
		eventID  int64
		operator string
		confirm  bool
		mode     string
		want     error
	}{
		{"缺 confirm", id, "ops-alice", false, "test", ErrConfirmRequired},
		{"缺 operator", id, "", true, "test", ErrOperatorRequired},
		{"operator 全空白", id, "   ", true, "test", ErrOperatorRequired},
		{"mode 不是 test", id, "ops-alice", true, "prod", ErrTestModeOnly},
		{"mode 为空", id, "ops-alice", true, "", ErrTestModeOnly},
		{"事件不存在", id + 9999, "ops-alice", true, "test", ErrEventNotFound},
		{"事件状态不是 dead", pendingID, "ops-alice", true, "test", ErrNotDead},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := r.Redrive(ctx, tc.eventID, tc.operator, tc.confirm, tc.mode)
			if !errors.Is(err, tc.want) {
				t.Fatalf("应返回 %v，实际 %v", tc.want, err)
			}
			// 拒绝时不得写日志、不得改状态。
			if n, _ := r.LogCount(ctx); n != 0 {
				t.Fatalf("拒绝时不得写重投日志：%d", n)
			}
			var status string
			var attempts int
			qerr := r.pool.QueryRow(ctx,
				`SELECT status, attempts FROM test_outbox WHERE id=$1`, tc.eventID).Scan(&status, &attempts)
			if errors.Is(qerr, pgx.ErrNoRows) {
				return // 事件本就不存在：无需校验状态
			}
			if qerr != nil {
				t.Fatal(qerr)
			}
			if tc.eventID == pendingID {
				if status != "pending" || attempts != 1 {
					t.Fatalf("拒绝时不得修改事件：status=%s attempts=%d", status, attempts)
				}
			} else {
				if status != "dead" || attempts != 5 {
					t.Fatalf("拒绝时不得修改 dead 事件：status=%s attempts=%d", status, attempts)
				}
			}
		})
	}
}

// TestRedriveSuccessWritesExactlyOneLog（P3 成功用例）
// 成功重投：事件置回 pending、attempts 归零，重投日志恰好新增一行。
func TestRedriveSuccessWritesExactlyOneLog(t *testing.T) {
	r, id := newTestRedriver(t)
	if r == nil {
		return
	}
	ctx := context.Background()

	before, err := r.LogCount(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Redrive(ctx, id, "ops-alice", true, "test"); err != nil {
		t.Fatalf("合法重投应成功：%v", err)
	}
	after, err := r.LogCount(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if after != before+1 {
		t.Fatalf("重投日志应恰好新增一行：%d → %d", before, after)
	}
	var status string
	var attempts int
	var nextAt *time.Time
	if err := r.pool.QueryRow(ctx,
		`SELECT status, attempts, next_attempt_at FROM test_outbox WHERE id=$1`, id).Scan(&status, &attempts, &nextAt); err != nil {
		t.Fatal(err)
	}
	if status != "pending" {
		t.Fatalf("重投后状态应为 pending，实际 %q", status)
	}
	if attempts != 0 {
		t.Fatalf("重投后 attempts 应归零，实际 %d", attempts)
	}
	if nextAt != nil {
		t.Fatalf("重投后应清空退避时间，实际 %v", nextAt)
	}
	// 日志内容：event_id / operator / 原状态 / 时间戳。
	var logEventID int64
	var operator, prev string
	var at time.Time
	if err := r.pool.QueryRow(ctx,
		`SELECT event_id, operator, previous_status, created_at FROM test_redrive_log ORDER BY id DESC LIMIT 1`).
		Scan(&logEventID, &operator, &prev, &at); err != nil {
		t.Fatal(err)
	}
	if logEventID != id || operator != "ops-alice" || prev != "dead" || at.IsZero() {
		t.Fatalf("日志内容不符：event_id=%d operator=%s prev=%s at=%v", logEventID, operator, prev, at)
	}
	t.Logf("[断言] 重投成功：status=pending attempts=0，日志恰好 +1 行（event_id=%d operator=%s prev=%s）",
		logEventID, operator, prev)

	// 再次重投同一事件：状态已非 dead → 拒绝，日志不再新增。
	if err := r.Redrive(ctx, id, "ops-bob", true, "test"); !errors.Is(err, ErrNotDead) {
		t.Fatalf("已重投的事件再次重投应被拒绝：%v", err)
	}
	if n, _ := r.LogCount(ctx); n != after {
		t.Fatalf("被拒绝的重投不得写日志：%d → %d", after, n)
	}
}

// TestRedriveTableNameGuard 表名必须是 test_ 前缀。
func TestRedriveTableNameGuard(t *testing.T) {
	rs := testdb.NewRunSchema(t)
	if rs == nil {
		return
	}
	for _, bad := range []string{"redrive_log", "public.test_redrive_log", "test_x; DROP TABLE y"} {
		if _, err := New(Config{Pool: rs.Pool(), LogTable: bad}); err == nil {
			t.Fatalf("非法表名必须拒绝：%q", bad)
		}
	}
}
