package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/XZ-libin/agent-ops/alerts/internal/ingest"
	"github.com/XZ-libin/agent-ops/alerts/internal/store"
	"github.com/XZ-libin/agent-ops/internal/testdb"
)

// TestIntegrationAlertsIngest 第十四轮 A2 集成测试：
// 真实 PostgreSQL（55432 / agent_ops_test / 独立 schema test_run_<时间戳>）
// + 真实 HTTP 服务器（httptest）发送告警。
//
// 断言：
//  1. 新告警：test_alerts 与 test_outbox 各新增预期行数；
//  2. 重复发送（窗口内）：test_alerts 不增加、计数增加、outbox 不增加；
//  3. 窗口外：新增一行；
//  4. 告警负载中不含请求头中的签名值与密钥。
//
// PostgreSQL 不可用时 skip 并输出原因（按裁决：被跳过的集成测试标记"未验证"）。
func TestIntegrationAlertsIngest(t *testing.T) {
	rs := testdb.NewRunSchema(t)
	if rs == nil {
		return // 已 skip
	}
	ctx := context.Background()

	st, err := store.New(rs.Pool(), store.DefaultAlertsTable, store.DefaultOutboxTable)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.EnsureSchema(ctx); err != nil {
		t.Fatalf("告警建表失败（非 skip）：%v", err)
	}
	t.Logf("[H5] 集成测试 schema：%s", rs.Name())

	// 注入时钟（去重窗口可控）。
	base := time.Unix(1791825000, 0)
	current := base
	now := func() time.Time { return current }

	srv, err := New(Config{Sources: testSources(t), Recorder: st, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	t.Logf("[夹具] 真实 HTTP 服务器已启动：%s", httpSrv.URL)

	post := func(t *testing.T, body string, at time.Time) (*http.Response, string) {
		t.Helper()
		tsStr := fmt.Sprintf("%d", at.Unix())
		req, rerr := http.NewRequest(http.MethodPost, httpSrv.URL+"/v1/alerts", strings.NewReader(body))
		if rerr != nil {
			t.Fatal(rerr)
		}
		req.Header.Set(ingest.HeaderTimestamp, tsStr)
		req.Header.Set(ingest.HeaderSignature, ingest.Sign(testKeyA, tsStr, []byte(body)))
		resp, derr := http.DefaultClient.Do(req)
		if derr != nil {
			t.Fatal(derr)
		}
		defer func() { _ = resp.Body.Close() }()
		raw, _ := io.ReadAll(resp.Body)
		return resp, string(raw)
	}

	alertJSON := func(fp string) string {
		return fmt.Sprintf(`{"source":"test-source-a","severity":"warning","asset_id":"ast_itest","fingerprint":%q,"summary":"磁盘使用率 92%%"}`, fp)
	}

	// 1) 新告警 → alerts 1 行、outbox 1 行。
	resp, out := post(t, alertJSON("fp-itest-1"), current)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("应 202，实际 %d（%s）", resp.StatusCode, out)
	}
	alerts, outbox, err := st.Counts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if alerts != 1 || outbox != 1 {
		t.Fatalf("新告警应各新增 1 行：alerts=%d outbox=%d", alerts, outbox)
	}
	t.Logf("[断言] 新告警写入：test_alerts=%d 行，test_outbox=%d 行", alerts, outbox)

	// 2) 窗口内重复（+1 分钟）→ alerts 不增加、计数 2、outbox 不增加。
	current = base.Add(1 * time.Minute)
	resp, out = post(t, alertJSON("fp-itest-1"), current)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("窗口内应 202，实际 %d（%s）", resp.StatusCode, out)
	}
	var r2 alertResponse
	if err := json.Unmarshal([]byte(out), &r2); err != nil {
		t.Fatal(err)
	}
	if !r2.Deduplicated || r2.Count != 2 {
		t.Fatalf("窗口内应去重且计数为 2：%+v", r2)
	}
	alerts2, outbox2, err := st.Counts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if alerts2 != 1 {
		t.Fatalf("窗口内不得新增 test_alerts 行：%d", alerts2)
	}
	if outbox2 != 1 {
		t.Fatalf("窗口内不得新增 outbox 行：%d", outbox2)
	}
	count, err := st.AlertCount(ctx, "fp-itest-1")
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("计数应为 2，实际 %d", count)
	}
	t.Logf("[断言] 窗口内去重：test_alerts 仍 %d 行，计数=%d，outbox 仍 %d 行", alerts2, count, outbox2)

	// 3) 窗口外（+6 分钟，相对窗口起点）→ 不新增行（fingerprint 主键），
	//    但窗口重开 → outbox 新增一条。
	current = base.Add(6 * time.Minute)
	resp, out = post(t, alertJSON("fp-itest-1"), current)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("窗口外应 202，实际 %d（%s）", resp.StatusCode, out)
	}
	var r3 alertResponse
	if err := json.Unmarshal([]byte(out), &r3); err != nil {
		t.Fatal(err)
	}
	if r3.Deduplicated || r3.Count != 1 {
		t.Fatalf("窗口外应重开窗口（count 重置为 1、非去重）：%+v", r3)
	}
	alerts3, outbox3, err := st.Counts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// R2：行数由 fingerprint 数量决定（仍为 1）；窗口重开写一条 outbox。
	if alerts3 != 1 || outbox3 != 2 {
		t.Fatalf("窗口重开应只新增 outbox：alerts=%d outbox=%d", alerts3, outbox3)
	}
	t.Logf("[断言] 窗口重开：test_alerts=%d 行（未增长），test_outbox=%d 行", alerts3, outbox3)

	// 4) outbox 负载不含签名值与密钥。
	payloads, err := st.OutboxPayloads(ctx, ingest.OutboxEventType)
	if err != nil {
		t.Fatal(err)
	}
	if len(payloads) != 2 {
		t.Fatalf("应有 2 条 alert.received 事件（两个窗口），实际 %d", len(payloads))
	}
	tsStr := fmt.Sprintf("%d", base.Unix())
	sig := ingest.Sign(testKeyA, tsStr, []byte(alertJSON("fp-itest-1")))
	for _, p := range payloads {
		if strings.Contains(p, sig) {
			t.Fatalf("outbox 负载不得包含签名值：%s", p)
		}
		if strings.Contains(p, string(testKeyA)) || strings.Contains(p, string(testKeyB)) {
			t.Fatalf("outbox 负载不得包含签名密钥：%s", p)
		}
		if !strings.Contains(p, ingest.OutboxEventType) && !strings.Contains(p, "fp-itest-1") {
			t.Fatalf("outbox 负载应包含告警内容：%s", p)
		}
	}
	t.Logf("[断言] outbox 负载不含签名与密钥（%d 条）", len(payloads))

	// 5) 签名错误不得写入任何行。
	current = base.Add(10 * time.Minute)
	beforeAlerts, beforeOutbox, _ := st.Counts(ctx)
	badBody := alertJSON("fp-itest-2")
	req, _ := http.NewRequest(http.MethodPost, httpSrv.URL+"/v1/alerts", strings.NewReader(badBody))
	req.Header.Set(ingest.HeaderTimestamp, fmt.Sprintf("%d", current.Unix()))
	req.Header.Set(ingest.HeaderSignature, strings.Repeat("0", 64))
	badResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = badResp.Body.Close()
	if badResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("错误签名应 401，实际 %d", badResp.StatusCode)
	}
	afterAlerts, afterOutbox, _ := st.Counts(ctx)
	if afterAlerts != beforeAlerts || afterOutbox != beforeOutbox {
		t.Fatalf("签名失败不得写入：alerts %d→%d outbox %d→%d",
			beforeAlerts, afterAlerts, beforeOutbox, afterOutbox)
	}
	t.Log("[断言] 签名失败未写入任何行")
}
