package store

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/XZ-libin/agent-ops/alerts/internal/ingest"
	"github.com/XZ-libin/agent-ops/internal/testdb"
)

// newTestStore 建立真实 PG 存储（每轮独立 schema；PG 不可用则 skip）。
func newTestStore(t *testing.T) *Store {
	t.Helper()
	rs := testdb.NewRunSchema(t)
	if rs == nil {
		return nil
	}
	s, err := New(rs.Pool(), DefaultAlertsTable, DefaultOutboxTable)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("建表失败（非 skip）：%v", err)
	}
	t.Logf("[H5] schema：%s", rs.Name())
	return s
}

// testAlert 构造测试告警（source 为明显的测试假值）。
func testAlert(fp string) ingest.Alert {
	return ingest.Alert{
		Source: "test-source-a", Severity: "warning", AssetID: "ast_itest",
		Fingerprint: fp, Summary: "磁盘使用率高",
	}
}

// TestDedupUpsertSustained20Minutes（R2 ①）持续 20 分钟的告警：
// test_alerts 行数恒为 1（fingerprint 主键），count 与窗口语义正确。
//
// 精确语义（窗口 5 分钟、边界含等号）：
//
//	t=0 打开窗口（count=1, outbox+1）；t=1..4 count 2..5；
//	t=5/10/15 窗口到期重开（count 重置 1，各 +1 条 outbox）；t=16..19 count 2..5。
//	20 条（t=0..19）后：行数 1、count=4、outbox=4。
func TestDedupUpsertSustained20Minutes(t *testing.T) {
	st := newTestStore(t)
	if st == nil {
		return
	}
	ctx := context.Background()
	base := time.Unix(1791825000, 0)

	// 每分钟一条，持续 20 分钟（t=0..19 共 20 条）。
	for i := 0; i <= 19; i++ {
		now := base.Add(time.Duration(i) * time.Minute)
		if _, err := st.Record(ctx, testAlert("fp-sustained"), ingest.DefaultDedupWindow, now); err != nil {
			t.Fatalf("第 %d 分钟写入失败：%v", i, err)
		}
	}

	alerts, outbox, err := st.Counts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if alerts != 1 {
		t.Fatalf("持续 20 分钟告警应始终只有 1 行（fingerprint 主键），实际 %d", alerts)
	}
	count, err := st.AlertCount(ctx, "fp-sustained")
	if err != nil {
		t.Fatal(err)
	}
	// 窗口 5 分钟：t=0/5/10/15 各打开一次；最后窗口 t=15 起，t=15..19 共 5 条。
	if count != 5 {
		t.Fatalf("最后窗口内计数应为 5，实际 %d", count)
	}
	// 4 个窗口 → 4 条 outbox 事件。
	if outbox != 4 {
		t.Fatalf("20 分钟内应打开 4 个窗口（4 条 outbox），实际 %d", outbox)
	}
	t.Logf("[断言] 持续 20 分钟（20 条）：test_alerts=%d 行，count=%d，outbox=%d 行", alerts, count, outbox)
}

// TestOutboxOnlyOnWindowOpen（R2 ②③）窗口内重复不写 outbox；
// 窗口过期后同一 fingerprint 再次打开窗口并新增一条 outbox。
func TestOutboxOnlyOnWindowOpen(t *testing.T) {
	st := newTestStore(t)
	if st == nil {
		return
	}
	ctx := context.Background()
	base := time.Unix(1791825000, 0)

	// 首次：窗口打开 → outbox 1。
	if _, err := st.Record(ctx, testAlert("fp-window"), ingest.DefaultDedupWindow, base); err != nil {
		t.Fatal(err)
	}
	// 窗口内 3 次重复：outbox 不增加。
	for i := 1; i <= 3; i++ {
		now := base.Add(time.Duration(i) * time.Minute)
		if _, err := st.Record(ctx, testAlert("fp-window"), ingest.DefaultDedupWindow, now); err != nil {
			t.Fatal(err)
		}
	}
	alerts, outbox, err := st.Counts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if alerts != 1 || outbox != 1 {
		t.Fatalf("窗口内重复不得新增行或事件：alerts=%d outbox=%d", alerts, outbox)
	}
	t.Logf("[断言] 窗口内重复：alerts=%d outbox=%d（未新增）", alerts, outbox)

	// 窗口过期（+5 分钟，相对 window_start=base）：重新打开窗口 → outbox 2。
	reopen := base.Add(5 * time.Minute)
	if _, err := st.Record(ctx, testAlert("fp-window"), ingest.DefaultDedupWindow, reopen); err != nil {
		t.Fatal(err)
	}
	alerts2, outbox2, err := st.Counts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if alerts2 != 1 {
		t.Fatalf("窗口重开不得新增行：alerts=%d", alerts2)
	}
	if outbox2 != 2 {
		t.Fatalf("窗口重开应新增一条 outbox：%d", outbox2)
	}
	count, err := st.AlertCount(ctx, "fp-window")
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("窗口重开后计数应重置为 1，实际 %d", count)
	}
	t.Logf("[断言] 窗口重开：alerts=%d outbox=%d count=%d", alerts2, outbox2, count)
}

// TestConcurrentSameFingerprintOpensWindowOnce（R2 ④）
// 并发 10 个相同 fingerprint 请求：只打开一次窗口（outbox 恰好 1 条）、只有 1 行。
func TestConcurrentSameFingerprintOpensWindowOnce(t *testing.T) {
	st := newTestStore(t)
	if st == nil {
		return
	}
	ctx := context.Background()
	now := time.Unix(1791825000, 0)

	const n = 10
	var wg sync.WaitGroup
	errs := make([]error, n)
	decisions := make([]ingest.Decision, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			decisions[i], errs[i] = st.Record(ctx, testAlert("fp-concurrent"), ingest.DefaultDedupWindow, now)
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("并发第 %d 个请求失败：%v", i, err)
		}
	}
	opened := 0
	for _, d := range decisions {
		if !d.Deduplicated {
			opened++
		}
	}
	if opened != 1 {
		t.Fatalf("并发请求应只有 1 个打开窗口，实际 %d", opened)
	}
	alerts, outbox, err := st.Counts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if alerts != 1 || outbox != 1 {
		t.Fatalf("并发应只产生 1 行与 1 条事件：alerts=%d outbox=%d", alerts, outbox)
	}
	count, err := st.AlertCount(ctx, "fp-concurrent")
	if err != nil {
		t.Fatal(err)
	}
	if count != n {
		t.Fatalf("计数应为 %d（含窗口打开那次），实际 %d", n, count)
	}
	t.Logf("[断言] 并发 %d 次：alerts=%d outbox=%d count=%d", n, alerts, outbox, count)
}

// TestRowCountBoundedByFingerprints 行数上限由不同 fingerprint 数量决定。
func TestRowCountBoundedByFingerprints(t *testing.T) {
	st := newTestStore(t)
	if st == nil {
		return
	}
	ctx := context.Background()
	base := time.Unix(1791825000, 0)

	// 3 个 fingerprint 各持续 10 分钟（每分钟一条）。
	for i := 0; i <= 10; i++ {
		now := base.Add(time.Duration(i) * time.Minute)
		for _, fp := range []string{"fp-a", "fp-b", "fp-c"} {
			if _, err := st.Record(ctx, testAlert(fp), ingest.DefaultDedupWindow, now); err != nil {
				t.Fatal(err)
			}
		}
	}
	alerts, _, err := st.Counts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if alerts != 3 {
		t.Fatalf("行数应由 fingerprint 数量决定（3），实际 %d", alerts)
	}
}
