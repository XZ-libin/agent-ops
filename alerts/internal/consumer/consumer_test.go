package consumer

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ORG/agent-ops/alerts/internal/ingest"
	"github.com/ORG/agent-ops/alerts/internal/store"
	"github.com/ORG/agent-ops/internal/testdb"
)

// testAlert 构造测试告警（明显的测试假值）。
func testAlert(fp string) ingest.Alert {
	return ingest.Alert{
		Source: "test-source-a", Severity: "warning", AssetID: "ast_itest",
		Fingerprint: fp, Summary: "磁盘使用率高",
	}
}

// newTestEnv 建立真实 PG 环境（独立 schema）：store（写 outbox）+ consumer。
func newTestEnv(t *testing.T, cfgFn func(*Config)) (*store.Store, *Consumer) {
	t.Helper()
	rs := testdb.NewRunSchema(t)
	if rs == nil {
		return nil, nil
	}
	ctx := context.Background()
	st, err := store.New(rs.Pool(), store.DefaultAlertsTable, store.DefaultOutboxTable)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.EnsureSchema(ctx); err != nil {
		t.Fatalf("outbox 建表失败（非 skip）：%v", err)
	}
	cfg := Config{Pool: rs.Pool(), Now: func() time.Time { return time.Unix(1791825000, 0) }}
	if cfgFn != nil {
		cfgFn(&cfg)
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.EnsureSchema(ctx); err != nil {
		t.Fatalf("待诊断表建表失败（非 skip）：%v", err)
	}
	t.Logf("[H5] schema：%s", rs.Name())
	return st, c
}

// TestConsumerCreatesOneRequestPerEvent（C1 ①）新事件生成一条待诊断记录，
// 且事件被标记 consumed、记录状态固定 pending。
func TestConsumerCreatesOneRequestPerEvent(t *testing.T) {
	st, c := newTestEnv(t, nil)
	if st == nil || c == nil {
		return
	}
	ctx := context.Background()
	base := time.Unix(1791825000, 0)

	// 两个不同 fingerprint → 两条 outbox 事件。
	for i, fp := range []string{"fp-a", "fp-b"} {
		if _, err := st.Record(ctx, testAlert(fp), ingest.DefaultDedupWindow,
			base.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	pending, err := c.PendingCount(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if pending != 2 {
		t.Fatalf("应有 2 条未消费事件，实际 %d", pending)
	}

	n, err := c.RunOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("应处理 2 条事件，实际 %d", n)
	}
	reqs, err := c.RequestCount(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if reqs != 2 {
		t.Fatalf("应生成 2 条待诊断记录，实际 %d", reqs)
	}
	statuses, err := c.RequestStatuses(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range statuses {
		if s != "pending" {
			t.Fatalf("本轮待诊断记录状态必须固定 pending，实际 %q", s)
		}
	}
	pending, err = c.PendingCount(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if pending != 0 {
		t.Fatalf("处理完成后不应有未消费事件，实际 %d", pending)
	}
	t.Logf("[断言] 2 条事件 → 2 条待诊断记录（pending），事件全部 consumed")
}

// TestConsumerIsIdempotentOnRerun（C1 ②）重复运行消费者不增加行数。
func TestConsumerIsIdempotentOnRerun(t *testing.T) {
	st, c := newTestEnv(t, nil)
	if st == nil || c == nil {
		return
	}
	ctx := context.Background()
	if _, err := st.Record(ctx, testAlert("fp-idem"), ingest.DefaultDedupWindow, time.Unix(1791825000, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	first, err := c.RequestCount(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// 再跑两次（事件已 consumed，不应再被处理）。
	for i := 0; i < 2; i++ {
		n, err := c.RunOnce(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Fatalf("第 %d 次重复运行不应处理任何事件，实际 %d", i+1, n)
		}
	}
	again, err := c.RequestCount(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if again != first {
		t.Fatalf("重复运行不得增加行数：%d → %d", first, again)
	}
	t.Logf("[断言] 重复运行 2 次：待诊断记录仍为 %d 行", again)
}

// TestFailedConsumptionKeepsEventPending（C1 ③）消费失败的事件保持未处理、下次可重试。
func TestFailedConsumptionKeepsEventPending(t *testing.T) {
	base := time.Unix(1791825000, 0)
	current := base
	failing := true
	st, c := newTestEnv(t, func(cfg *Config) {
		cfg.Now = func() time.Time { return current }
		// 注入处理钩子：首次必失败。
		cfg.Process = func(_ context.Context, _ Event) error {
			if failing {
				return errors.New("注入的消费失败（仅测试）")
			}
			return nil
		}
	})
	if st == nil || c == nil {
		return
	}
	ctx := context.Background()
	if _, err := st.Record(ctx, testAlert("fp-retry"), ingest.DefaultDedupWindow, time.Unix(1791825000, 0)); err != nil {
		t.Fatal(err)
	}

	if _, err := c.RunOnce(ctx); err == nil {
		t.Fatal("注入失败时应返回错误")
	}
	pending, err := c.PendingCount(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if pending != 1 {
		t.Fatalf("失败事件必须保持未消费：%d", pending)
	}
	// 失败后进入退避：需把时钟推进到退避之后才能重试。
	current = base.Add(2 * time.Second)
	reqs, err := c.RequestCount(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if reqs != 0 {
		t.Fatalf("失败时不应生成记录：%d", reqs)
	}

	// 修复后重试：事件被处理并标记 consumed。
	failing = false
	n, err := c.RunOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("重试应处理 1 条，实际 %d", n)
	}
	if pending, _ = c.PendingCount(ctx); pending != 0 {
		t.Fatalf("重试后不应有未消费事件：%d", pending)
	}
	t.Log("[断言] 失败事件保持 pending，重试后成功消费")
}

// TestCrashBetweenInsertAndMarkDoesNotDuplicate（C1 ④）
// 模拟"写完待诊断记录但未标记 consumed 即崩溃"：重启后不产生重复记录。
func TestCrashBetweenInsertAndMarkDoesNotDuplicate(t *testing.T) {
	st, c := newTestEnv(t, nil)
	if st == nil || c == nil {
		return
	}
	ctx := context.Background()
	if _, err := st.Record(ctx, testAlert("fp-crash"), ingest.DefaultDedupWindow, time.Unix(1791825000, 0)); err != nil {
		t.Fatal(err)
	}

	// 崩溃模拟：只完成"写待诊断记录"，不做 MarkConsumed。
	events, err := c.pending(ctx, c.batch)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("应读到 1 条未消费事件：%d", len(events))
	}
	if err := c.CreateDiagnosisRequest(ctx, events[0]); err != nil {
		t.Fatal(err)
	}
	// 此时：记录已写、事件仍 pending（模拟崩溃点）。
	if reqs, _ := c.RequestCount(ctx); reqs != 1 {
		t.Fatalf("崩溃点应有 1 条记录：%d", reqs)
	}
	if pending, _ := c.PendingCount(ctx); pending != 1 {
		t.Fatalf("崩溃点事件应仍 pending：%d", pending)
	}

	// 重启消费者 → 重新处理：唯一约束跳过重复写入，只补标记 consumed。
	n, err := c.RunOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("重启应处理 1 条，实际 %d", n)
	}
	reqs, err := c.RequestCount(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if reqs != 1 {
		t.Fatalf("重启后不得产生重复记录：%d", reqs)
	}
	if pending, _ := c.PendingCount(ctx); pending != 0 {
		t.Fatalf("重启后事件应已消费：%d", pending)
	}
	t.Log("[断言] 崩溃重启：记录仍为 1 条，无重复")
}

// TestConsumerTableNameGuard 表名必须是 test_ 前缀（防注入）。
func TestConsumerTableNameGuard(t *testing.T) {
	rs := testdb.NewRunSchema(t)
	if rs == nil {
		return
	}
	for _, bad := range []string{"alerts", "public.test_alerts", "test_x; DROP TABLE y"} {
		if _, err := New(Config{Pool: rs.Pool(), RequestsTable: bad}); err == nil {
			t.Fatalf("非法表名必须拒绝：%q", bad)
		}
	}
	if _, err := New(Config{Pool: rs.Pool()}); err != nil {
		t.Fatalf("默认表名应通过：%v", err)
	}
}

// —— 第十六轮 R3：重试与死信 ——

// TestRetryThenDeadAfterMaxAttempts（R3 ①）连续 4 次失败后仍 pending，
// 第 5 次失败后置 dead。
func TestRetryThenDeadAfterMaxAttempts(t *testing.T) {
	base := time.Unix(1791825000, 0)
	current := base
	st, c := newTestEnv(t, func(cfg *Config) {
		cfg.Now = func() time.Time { return current }
		cfg.Process = func(context.Context, Event) error { return errors.New("注入失败（仅测试）") }
	})
	if st == nil || c == nil {
		return
	}
	ctx := context.Background()
	if _, err := st.Record(ctx, testAlert("fp-dead"), ingest.DefaultDedupWindow, base); err != nil {
		t.Fatal(err)
	}
	events, err := c.pending(ctx, c.batch)
	if err != nil {
		t.Fatal(err)
	}
	id := events[0].ID

	// 第 1..4 次失败：仍 pending，attempts 递增，退避时间按 1/2/4/8s 设置。
	for attempt := 1; attempt <= 4; attempt++ {
		if _, err := c.RunOnce(ctx); err == nil {
			t.Fatalf("第 %d 次失败应返回错误", attempt)
		}
		got, err := c.Attempts(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if got != attempt {
			t.Fatalf("attempts 应为 %d，实际 %d", attempt, got)
		}
		if status, _ := c.Status(ctx, id); status != StatusPending {
			t.Fatalf("第 %d 次失败后仍应为 pending，实际 %q", attempt, status)
		}
		// 退避未到：立即再跑不会再次尝试（attempts 不变）。
		if _, err := c.RunOnce(ctx); err != nil {
			t.Fatalf("退避期内不应尝试（不应报错）：%v", err)
		}
		if again, _ := c.Attempts(ctx, id); again != attempt {
			t.Fatalf("退避期内 attempts 不得变化：%d → %d", attempt, again)
		}
		// 推进到退避之后。
		current = current.Add(Backoff(attempt))
	}

	// 第 5 次失败：置 dead。
	if _, err := c.RunOnce(ctx); err == nil {
		t.Fatal("第 5 次失败应返回错误")
	}
	if status, _ := c.Status(ctx, id); status != StatusDead {
		t.Fatalf("第 5 次失败后应置 dead，实际 %q", status)
	}
	if n, _ := c.DeadCount(ctx); n != 1 {
		t.Fatalf("应有 1 条死信，实际 %d", n)
	}
	t.Log("[断言] 4 次失败保持 pending，第 5 次失败置 dead")
}

// TestBackoffDelaysRetry（R3 ②）退避时间未到时不尝试。
func TestBackoffDelaysRetry(t *testing.T) {
	base := time.Unix(1791825000, 0)
	current := base
	attempted := 0
	st, c := newTestEnv(t, func(cfg *Config) {
		cfg.Now = func() time.Time { return current }
		cfg.Process = func(context.Context, Event) error {
			attempted++
			return errors.New("注入失败（仅测试）")
		}
	})
	if st == nil || c == nil {
		return
	}
	ctx := context.Background()
	if _, err := st.Record(ctx, testAlert("fp-backoff"), ingest.DefaultDedupWindow, base); err != nil {
		t.Fatal(err)
	}
	if _, err := c.RunOnce(ctx); err == nil {
		t.Fatal("首次应失败")
	}
	if attempted != 1 {
		t.Fatalf("首次应尝试 1 次，实际 %d", attempted)
	}
	// 退避 1 秒：0.5 秒后再跑不应尝试。
	current = base.Add(500 * time.Millisecond)
	if _, err := c.RunOnce(ctx); err != nil {
		t.Fatalf("退避期内不应报错：%v", err)
	}
	if attempted != 1 {
		t.Fatalf("退避期内不得再次尝试：%d", attempted)
	}
	// 1 秒后（到点）应再次尝试。
	current = base.Add(1 * time.Second)
	if _, err := c.RunOnce(ctx); err == nil {
		t.Fatal("到点后应再次尝试（失败）")
	}
	if attempted != 2 {
		t.Fatalf("到点后应尝试第 2 次，实际 %d", attempted)
	}
	t.Log("[断言] 退避未到不尝试；到点后重试")
}

// TestDeadEventNotProcessedLater（R3 ③）dead 事件在后续运行中不被处理。
func TestDeadEventNotProcessedLater(t *testing.T) {
	base := time.Unix(1791825000, 0)
	current := base
	attempted := 0
	st, c := newTestEnv(t, func(cfg *Config) {
		cfg.Now = func() time.Time { return current }
		cfg.Process = func(context.Context, Event) error {
			attempted++
			return errors.New("注入失败（仅测试）")
		}
	})
	if st == nil || c == nil {
		return
	}
	ctx := context.Background()
	if _, err := st.Record(ctx, testAlert("fp-dead2"), ingest.DefaultDedupWindow, base); err != nil {
		t.Fatal(err)
	}
	// 连续 5 次失败（每次推进到退避之后）。
	for i := 0; i < MaxAttempts; i++ {
		if _, err := c.RunOnce(ctx); err == nil {
			t.Fatalf("第 %d 次应失败", i+1)
		}
		current = current.Add(8 * time.Second)
	}
	if attempted != MaxAttempts {
		t.Fatalf("应尝试 %d 次，实际 %d", MaxAttempts, attempted)
	}
	// 后续运行：dead 事件不再被处理。
	for i := 0; i < 3; i++ {
		current = current.Add(time.Hour)
		n, err := c.RunOnce(ctx)
		if err != nil {
			t.Fatalf("dead 事件不应再产生错误：%v", err)
		}
		if n != 0 {
			t.Fatalf("dead 事件不得被处理：%d", n)
		}
	}
	if attempted != MaxAttempts {
		t.Fatalf("dead 后不得再尝试：%d", attempted)
	}
	// 死信数据保留。
	if n, _ := c.DeadCount(ctx); n != 1 {
		t.Fatalf("死信数据应保留：%d", n)
	}
	t.Log("[断言] dead 事件不再被处理，数据保留")
}

// TestSuccessDoesNotIncreaseAttempts（R3 ④）成功后 attempts 不再增加。
func TestSuccessDoesNotIncreaseAttempts(t *testing.T) {
	st, c := newTestEnv(t, nil)
	if st == nil || c == nil {
		return
	}
	ctx := context.Background()
	if _, err := st.Record(ctx, testAlert("fp-ok"), ingest.DefaultDedupWindow, time.Unix(1791825000, 0)); err != nil {
		t.Fatal(err)
	}
	events, err := c.pending(ctx, c.batch)
	if err != nil {
		t.Fatal(err)
	}
	id := events[0].ID
	if n, err := c.RunOnce(ctx); err != nil || n != 1 {
		t.Fatalf("首次应成功消费：n=%d err=%v", n, err)
	}
	before, err := c.Attempts(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	// 再跑多次：事件已 consumed，不再被处理，attempts 不变。
	for i := 0; i < 3; i++ {
		if _, err := c.RunOnce(ctx); err != nil {
			t.Fatal(err)
		}
	}
	after, err := c.Attempts(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("成功后 attempts 不得增加：%d → %d", before, after)
	}
	if status, _ := c.Status(ctx, id); status != StatusConsumed {
		t.Fatalf("状态应为 consumed，实际 %q", status)
	}
}

// TestBackoffTable 退避表（1s/2s/4s/8s）与上限。
func TestBackoffTable(t *testing.T) {
	want := map[int]time.Duration{1: time.Second, 2: 2 * time.Second, 3: 4 * time.Second, 4: 8 * time.Second}
	for attempt, d := range want {
		if got := Backoff(attempt); got != d {
			t.Fatalf("Backoff(%d)=%v，期望 %v", attempt, got, d)
		}
	}
	if Backoff(MaxAttempts) != 0 {
		t.Fatal("第 5 次失败不应退避（直接置 dead）")
	}
	if MaxAttempts != 5 {
		t.Fatalf("最大尝试次数应为 5，实际 %d", MaxAttempts)
	}
}
