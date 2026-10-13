package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/XZ-libin/agent-ops/alerts/internal/ingest"
	"github.com/XZ-libin/agent-ops/alerts/internal/planner"
)

// 仅测试的固定假密钥（明显的测试值，非真实凭据）。
var (
	testKeyA = []byte("test-only-key-source-a")
	testKeyB = []byte("test-only-key-source-b")
)

// testSources 测试用源白名单（source-a / source-b）。
func testSources(t *testing.T) *ingest.SourceSet {
	t.Helper()
	set, err := ingest.NewSourceSet([]string{"test-source-a", "test-source-b"}, func(name string) string {
		switch name {
		case ingest.KeyEnvName("test-source-a"):
			return string(testKeyA)
		case ingest.KeyEnvName("test-source-b"):
			return string(testKeyB)
		case ingest.ProfileName("test-source-a"):
			return "prometheus"
		case ingest.ProfileName("test-source-b"):
			return "docker-monitor"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	return set
}

// fakeRecorder 内存替身（单元测试用；集成测试走真实 PG）。
//
// 替身同样实现**窗口语义**（窗口内计数加一、窗口外新增一行），
// 以便在 HTTP 层验证"窗口与时钟被正确传入"；
// 真实 PG 下的窗口语义由集成测试验证。
type fakeRecorder struct {
	mu       sync.Mutex
	recorded []ingest.Alert
	state    map[string]struct {
		count     int64
		firstSeen time.Time
	}
	fail error
}

func newFakeRecorder() *fakeRecorder {
	return &fakeRecorder{state: map[string]struct {
		count     int64
		firstSeen time.Time
	}{}}
}

func (f *fakeRecorder) Record(_ context.Context, a ingest.Alert, window time.Duration, now time.Time) (ingest.Decision, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return ingest.Decision{}, f.fail
	}
	// 窗口以**首次出现**时刻起算（与 store 的 received_at >= now-window 语义一致）。
	if st, ok := f.state[a.Fingerprint]; ok && now.Before(st.firstSeen.Add(window)) {
		st.count++
		f.state[a.Fingerprint] = st
		return ingest.Decision{Deduplicated: true, ExistingCount: st.count}, nil
	}
	f.state[a.Fingerprint] = struct {
		count     int64
		firstSeen time.Time
	}{count: 1, firstSeen: now}
	f.recorded = append(f.recorded, a)
	return ingest.Decision{Deduplicated: false, ExistingCount: 1}, nil
}

func (f *fakeRecorder) alertCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.recorded)
}

// newTestServer 构建测试服务（注入固定时钟与源白名单）。
func newTestServer(t *testing.T, rec Recorder, now func() time.Time) *Server {
	t.Helper()
	s, err := New(Config{Sources: testSources(t), Recorder: rec, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// newTestServerWithLimiter 构建带指定限流器的测试服务。
// testLimiter 按测试白名单预分配桶的限流器（R2）。
func testLimiter(perMinute, burst int, now func() time.Time) *ingest.Limiter {
	return ingest.NewLimiterForSources([]string{"test-source-a", "test-source-b"}, perMinute, burst, now)
}

func newTestServerWithLimiter(t *testing.T, rec Recorder, now func() time.Time, limiter *ingest.Limiter) *Server {
	t.Helper()
	s, err := New(Config{Sources: testSources(t), Recorder: rec, Now: now, Limiter: limiter})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// sendAlert 发送一条带正确签名（源 A 密钥）的告警。
func sendAlert(t *testing.T, s *Server, ts time.Time, body string) *httptest.ResponseRecorder {
	t.Helper()
	return sendAlertWithKey(t, s, ts, body, testKeyA)
}

// sendAlertWithKey 用指定密钥签名后发送。
func sendAlertWithKey(t *testing.T, s *Server, ts time.Time, body string, key []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/alerts", strings.NewReader(body))
	tsStr := fmt.Sprintf("%d", ts.Unix())
	req.Header.Set(ingest.HeaderTimestamp, tsStr)
	req.Header.Set(ingest.HeaderSignature, ingest.Sign(key, tsStr, []byte(body)))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	return w
}

// alertBody 构造告警 JSON（默认源 test-source-a）。
func alertBody(fingerprint, severity string) string {
	return alertBodyFrom("test-source-a", fingerprint, severity)
}

// alertBodyFrom 构造指定源的告警 JSON。
func alertBodyFrom(source, fingerprint, severity string) string {
	return fmt.Sprintf(`{"source":%q,"severity":%q,"asset_id":"ast_1","fingerprint":%q,"summary":"磁盘使用率高"}`,
		source, severity, fingerprint)
}

// TestSignatureValidPasses 签名正确 → 202 且记录成功。
func TestSignatureValidPasses(t *testing.T) {
	rec := newFakeRecorder()
	now := time.Unix(1791825000, 0)
	s := newTestServer(t, rec, func() time.Time { return now })

	w := sendAlert(t, s, now, alertBody("fp-1", "warning"))
	if w.Code != http.StatusAccepted {
		t.Fatalf("应返回 202，实际 %d（%s）", w.Code, w.Body.String())
	}
	var resp alertResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Status != "recorded" || resp.Count != 1 || resp.Deduplicated {
		t.Fatalf("响应不符：%+v", resp)
	}
	if rec.alertCount() != 1 {
		t.Fatalf("应记录 1 条：%d", rec.alertCount())
	}
}

// TestSignatureFailuresReturn401 签名错误 / 缺失 / 时间戳篡改 → 401。
func TestSignatureFailuresReturn401(t *testing.T) {
	now := time.Unix(1791825000, 0)
	body := alertBody("fp-1", "warning")
	tsStr := fmt.Sprintf("%d", now.Unix())
	good := ingest.Sign(testKeyA, tsStr, []byte(body))

	cases := []struct {
		name      string
		timestamp string
		signature string
		body      string
	}{
		{"签名错误", tsStr, strings.Repeat("a", 64), body},
		{"签名缺失", tsStr, "", body},
		{"时间戳缺失", "", good, body},
		{"时间戳篡改", fmt.Sprintf("%d", now.Unix()+1), good, body},
		{"时间戳非整数", "not-a-number", good, body},
		{"时间戳超窗", fmt.Sprintf("%d", now.Add(-time.Hour).Unix()), ingest.Sign(testKeyA, fmt.Sprintf("%d", now.Add(-time.Hour).Unix()), []byte(body)), body},
		{"请求体被改", tsStr, good, alertBody("fp-2", "warning")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := newFakeRecorder()
			s := newTestServer(t, rec, func() time.Time { return now })
			req := httptest.NewRequest(http.MethodPost, "/v1/alerts", strings.NewReader(tc.body))
			if tc.timestamp != "" {
				req.Header.Set(ingest.HeaderTimestamp, tc.timestamp)
			}
			if tc.signature != "" {
				req.Header.Set(ingest.HeaderSignature, tc.signature)
			}
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, req)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("应返回 401，实际 %d（%s）", w.Code, w.Body.String())
			}
			if rec.alertCount() != 0 {
				t.Fatal("签名失败不得记录任何告警")
			}
		})
	}
}

// TestInvalidSeverityReturns400 severity 非法 → 400。
func TestInvalidSeverityReturns400(t *testing.T) {
	now := time.Unix(1791825000, 0)
	for _, bad := range []string{"", "INFO", "debug", "fatal"} {
		rec := newFakeRecorder()
		s := newTestServer(t, rec, func() time.Time { return now })
		w := sendAlert(t, s, now, alertBody("fp-1", bad))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("severity=%q 应返回 400，实际 %d", bad, w.Code)
		}
		if rec.alertCount() != 0 {
			t.Fatal("非法 severity 不得记录")
		}
	}
}

// TestEmptyFingerprintReturns400 fingerprint 为空 → 400。
func TestEmptyFingerprintReturns400(t *testing.T) {
	now := time.Unix(1791825000, 0)
	rec := newFakeRecorder()
	s := newTestServer(t, rec, func() time.Time { return now })
	body := `{"source":"test-source-a","severity":"info","asset_id":"ast_1","fingerprint":"","summary":"x"}`
	w := sendAlert(t, s, now, body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("空 fingerprint 应返回 400，实际 %d（%s）", w.Code, w.Body.String())
	}
}

// TestOversizedBodyReturns413 请求体超过 64KB → 413。
func TestOversizedBodyReturns413(t *testing.T) {
	now := time.Unix(1791825000, 0)
	rec := newFakeRecorder()
	s := newTestServer(t, rec, func() time.Time { return now })
	big := strings.Repeat("x", int(DefaultMaxBodyBytes)+1024)
	body := fmt.Sprintf(`{"source":"test-source-a","severity":"info","asset_id":"a","fingerprint":"fp","summary":%q}`, big)
	w := sendAlert(t, s, now, body)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("超大请求体应返回 413，实际 %d", w.Code)
	}
	if rec.alertCount() != 0 {
		t.Fatal("超大请求不得记录")
	}
	if DefaultMaxBodyBytes != 64<<10 {
		t.Fatalf("请求体上限应为 64KB，实际 %d", DefaultMaxBodyBytes)
	}
}

// TestDedupWindowBehaviour 去重窗口：窗口内计数加一、窗口外新增一行（注入时钟）。
func TestDedupWindowBehaviour(t *testing.T) {
	rec := newFakeRecorder()
	base := time.Unix(1791825000, 0)
	current := base
	s := newTestServer(t, rec, func() time.Time { return current })

	// 第一条：新增。
	if w := sendAlert(t, s, current, alertBody("fp-1", "warning")); w.Code != http.StatusAccepted {
		t.Fatalf("首次应 202，实际 %d", w.Code)
	}
	if rec.alertCount() != 1 {
		t.Fatalf("应新增 1 行：%d", rec.alertCount())
	}

	// 窗口内（+4 分钟）：计数加一，不新增行。
	current = base.Add(4 * time.Minute)
	w := sendAlert(t, s, current, alertBody("fp-1", "warning"))
	if w.Code != http.StatusAccepted {
		t.Fatalf("窗口内应 202，实际 %d", w.Code)
	}
	var resp alertResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Deduplicated || resp.Count != 2 {
		t.Fatalf("窗口内应去重且计数为 2：%+v", resp)
	}
	if rec.alertCount() != 1 {
		t.Fatalf("窗口内不得新增行：%d", rec.alertCount())
	}

	// 窗口外（+6 分钟，相对第一条）：新增一行。
	current = base.Add(6 * time.Minute)
	w = sendAlert(t, s, current, alertBody("fp-1", "warning"))
	if w.Code != http.StatusAccepted {
		t.Fatalf("窗口外应 202，实际 %d", w.Code)
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Deduplicated || resp.Count != 1 {
		t.Fatalf("窗口外应新增（不去重、计数 1）：%+v", resp)
	}
	if rec.alertCount() != 2 {
		t.Fatalf("窗口外应新增一行：%d", rec.alertCount())
	}
}

// TestReceivedAtInjectedByServer received_at 由服务端注入（请求体中的同名字段被忽略）。
func TestReceivedAtInjectedByServer(t *testing.T) {
	rec := newFakeRecorder()
	now := time.Unix(1791825000, 0)
	s := newTestServer(t, rec, func() time.Time { return now })
	body := `{"source":"test-source-a","severity":"info","asset_id":"a","fingerprint":"fp","summary":"x","received_at":"1999-01-01T00:00:00Z"}`
	if w := sendAlert(t, s, now, body); w.Code != http.StatusAccepted {
		t.Fatalf("应 202，实际 %d", w.Code)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	got := rec.recorded[0].ReceivedAt
	if !got.Equal(now.UTC()) {
		t.Fatalf("received_at 应由服务端注入：%v", got)
	}
}

// TestGetMethodNotAllowed 只接受 POST。
func TestGetMethodNotAllowed(t *testing.T) {
	rec := newFakeRecorder()
	s := newTestServer(t, rec, func() time.Time { return time.Unix(1791825000, 0) })
	req := httptest.NewRequest(http.MethodGet, "/v1/alerts", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET 应返回 405，实际 %d", w.Code)
	}
}

// TestResponsesNeverContainSecretOrSignature 响应中不得出现密钥与签名值。
func TestResponsesNeverContainSecretOrSignature(t *testing.T) {
	now := time.Unix(1791825000, 0)
	rec := newFakeRecorder()
	s := newTestServer(t, rec, func() time.Time { return now })
	tsStr := fmt.Sprintf("%d", now.Unix())
	body := alertBody("fp-1", "warning")
	sig := ingest.Sign(testKeyA, tsStr, []byte(body))

	req := httptest.NewRequest(http.MethodPost, "/v1/alerts", strings.NewReader(body))
	req.Header.Set(ingest.HeaderTimestamp, tsStr)
	req.Header.Set(ingest.HeaderSignature, sig)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)

	out := w.Body.String()
	if bytes.Contains([]byte(out), testKeyA) || strings.Contains(out, sig) {
		t.Fatalf("响应不得包含密钥或签名：%s", out)
	}
}

// —— 第十五轮 R3：源白名单与每源密钥 ——

// TestSourceNotAllowedReturns403（R3 ①）白名单外的源 → 403，不写任何表。
func TestSourceNotAllowedReturns403(t *testing.T) {
	now := time.Unix(1791825000, 0)
	rec := newFakeRecorder()
	s := newTestServer(t, rec, func() time.Time { return now })

	body := alertBodyFrom("unknown-source", "fp-1", "warning")
	w := sendAlertWithKey(t, s, now, body, testKeyA)
	if w.Code != http.StatusForbidden {
		t.Fatalf("白名单外源应返回 403，实际 %d（%s）", w.Code, w.Body.String())
	}
	if rec.alertCount() != 0 {
		t.Fatal("403 不得写入任何表")
	}
	// 403 响应不得泄露密钥。
	if strings.Contains(w.Body.String(), string(testKeyA)) {
		t.Fatal("403 响应不得包含密钥")
	}
}

// TestWrongSourceKeyReturns401（R3 ②）用源 B 的密钥给源 A 的请求签名 → 401。
func TestWrongSourceKeyReturns401(t *testing.T) {
	now := time.Unix(1791825000, 0)
	rec := newFakeRecorder()
	s := newTestServer(t, rec, func() time.Time { return now })

	body := alertBodyFrom("test-source-a", "fp-1", "warning")
	w := sendAlertWithKey(t, s, now, body, testKeyB) // 错密钥
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("错源密钥应返回 401，实际 %d（%s）", w.Code, w.Body.String())
	}
	if rec.alertCount() != 0 {
		t.Fatal("401 不得写入任何表")
	}
	// 用正确密钥应通过（对照）。
	if w2 := sendAlertWithKey(t, s, now, body, testKeyA); w2.Code != http.StatusAccepted {
		t.Fatalf("正确密钥应 202，实际 %d", w2.Code)
	}
}

// TestMissingSourceKeyFailsStartup（R3 ③）缺任一已列出源的密钥 → 拒绝启动。
func TestMissingSourceKeyFailsStartup(t *testing.T) {
	_, err := ingest.NewSourceSet([]string{"test-source-a", "test-source-b"}, func(name string) string {
		switch name {
		case ingest.KeyEnvName("test-source-a"):
			return string(testKeyA)
		case ingest.ProfileName("test-source-a"):
			return "prometheus"
		}
		return "" // 源 B 缺密钥（画像也不声明）
	})
	if err == nil {
		t.Fatal("缺源密钥必须拒绝启动")
	}
	if !strings.Contains(err.Error(), "TEST_SOURCE_B") {
		t.Fatalf("错误信息应指出缺失的环境变量：%v", err)
	}
}

// TestEmptySourceAllowlistFailsStartup（R3 ④）源白名单为空 → 拒绝启动。
func TestEmptySourceAllowlistFailsStartup(t *testing.T) {
	if _, err := ingest.ParseSources(""); err == nil {
		t.Fatal("空源白名单必须报错")
	}
	if _, err := ingest.ParseSources("  ,  ,"); err == nil {
		t.Fatal("全空项的源白名单必须报错")
	}
	if _, err := ingest.NewSourceSet(nil, func(string) string { return "x" }); err == nil {
		t.Fatal("空源白名单必须拒绝启动")
	}
}

// TestKeyEnvNameConvention（R3）密钥环境变量命名：大写、连字符转下划线。
func TestKeyEnvNameConvention(t *testing.T) {
	cases := map[string]string{
		"prometheus":        "AGENT_OPS_ALERT_KEY_PROMETHEUS",
		"alert-manager":     "AGENT_OPS_ALERT_KEY_ALERT_MANAGER",
		"Zabbix-Cloud":      "AGENT_OPS_ALERT_KEY_ZABBIX_CLOUD",
		"  spaced-source  ": "AGENT_OPS_ALERT_KEY_SPACED_SOURCE",
	}
	for in, want := range cases {
		if got := ingest.KeyEnvName(in); got != want {
			t.Fatalf("KeyEnvName(%q)=%q，期望 %q", in, got, want)
		}
	}
}

// —— 第十五轮 R4：速率限制 ——

// TestRateLimitBurstThen429（R4 ①）突发 10 次通过、第 11 次 429（带 Retry-After）。
func TestRateLimitBurstThen429(t *testing.T) {
	now := time.Unix(1791825000, 0)
	rec := newFakeRecorder()
	limiter := testLimiter(60, 10, func() time.Time { return now })
	s := newTestServerWithLimiter(t, rec, func() time.Time { return now }, limiter)

	for i := 0; i < 10; i++ {
		body := alertBodyFrom("test-source-a", fmt.Sprintf("fp-%d", i), "info")
		if w := sendAlert(t, s, now, body); w.Code != http.StatusAccepted {
			t.Fatalf("第 %d 次突发应通过，实际 %d（%s）", i+1, w.Code, w.Body.String())
		}
	}
	// 第 11 次：令牌耗尽 → 429 + Retry-After。
	w := sendAlert(t, s, now, alertBodyFrom("test-source-a", "fp-11", "info"))
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("第 11 次应返回 429，实际 %d", w.Code)
	}
	if ra := w.Header().Get("Retry-After"); ra == "" {
		t.Fatal("429 必须带 Retry-After 头")
	} else if n, err := strconv.Atoi(ra); err != nil || n < 1 {
		t.Fatalf("Retry-After 应为正整数秒，实际 %q", ra)
	}
	if rec.alertCount() != 10 {
		t.Fatalf("429 不得写入任何表：%d", rec.alertCount())
	}
}

// TestRateLimitRefillsOverTime（R4 ②）时钟前进后令牌恢复。
func TestRateLimitRefillsOverTime(t *testing.T) {
	base := time.Unix(1791825000, 0)
	current := base
	rec := newFakeRecorder()
	limiter := testLimiter(60, 10, func() time.Time { return current })
	s := newTestServerWithLimiter(t, rec, func() time.Time { return current }, limiter)

	// 耗尽令牌。
	for i := 0; i < 10; i++ {
		body := alertBodyFrom("test-source-a", fmt.Sprintf("fp-%d", i), "info")
		if w := sendAlert(t, s, current, body); w.Code != http.StatusAccepted {
			t.Fatalf("突发第 %d 次应通过：%d", i+1, w.Code)
		}
	}
	if w := sendAlert(t, s, current, alertBodyFrom("test-source-a", "fp-x", "info")); w.Code != http.StatusTooManyRequests {
		t.Fatalf("令牌耗尽后应 429，实际 %d", w.Code)
	}
	// 前进 1 秒（60/min = 1/s）→ 恢复 1 个令牌。
	current = base.Add(1 * time.Second)
	if w := sendAlert(t, s, current, alertBodyFrom("test-source-a", "fp-y", "info")); w.Code != http.StatusAccepted {
		t.Fatalf("1 秒后应恢复 1 个令牌，实际 %d（%s）", w.Code, w.Body.String())
	}
	// 立即再发：令牌再次耗尽。
	if w := sendAlert(t, s, current, alertBodyFrom("test-source-a", "fp-z", "info")); w.Code != http.StatusTooManyRequests {
		t.Fatalf("再次应 429，实际 %d", w.Code)
	}
}

// TestRateLimitIsPerSource（R4）限流按源独立分桶。
func TestRateLimitIsPerSource(t *testing.T) {
	now := time.Unix(1791825000, 0)
	rec := newFakeRecorder()
	limiter := testLimiter(60, 2, func() time.Time { return now })
	s := newTestServerWithLimiter(t, rec, func() time.Time { return now }, limiter)

	for i := 0; i < 2; i++ {
		if w := sendAlertWithKey(t, s, now, alertBodyFrom("test-source-a", fmt.Sprintf("a-%d", i), "info"), testKeyA); w.Code != http.StatusAccepted {
			t.Fatalf("源 A 第 %d 次应通过：%d", i+1, w.Code)
		}
	}
	if w := sendAlertWithKey(t, s, now, alertBodyFrom("test-source-a", "a-x", "info"), testKeyA); w.Code != http.StatusTooManyRequests {
		t.Fatalf("源 A 应 429，实际 %d", w.Code)
	}
	// 源 B 独立桶：仍可放行。
	if w := sendAlertWithKey(t, s, now, alertBodyFrom("test-source-b", "b-1", "info"), testKeyB); w.Code != http.StatusAccepted {
		t.Fatalf("源 B 应独立放行，实际 %d（%s）", w.Code, w.Body.String())
	}
}

// TestRateLimit429WritesNothing（R4 ③）429 响应不写入任何表。
func TestRateLimit429WritesNothing(t *testing.T) {
	now := time.Unix(1791825000, 0)
	rec := newFakeRecorder()
	limiter := testLimiter(60, 1, func() time.Time { return now })
	s := newTestServerWithLimiter(t, rec, func() time.Time { return now }, limiter)

	if w := sendAlert(t, s, now, alertBody("fp-1", "info")); w.Code != http.StatusAccepted {
		t.Fatalf("首次应通过：%d", w.Code)
	}
	before := rec.alertCount()
	w := sendAlert(t, s, now, alertBody("fp-2", "info"))
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("应 429，实际 %d", w.Code)
	}
	if rec.alertCount() != before {
		t.Fatal("429 不得写入任何表")
	}
}

// —— 第十六轮 R1/R2：请求处理顺序与桶表有界 ——

// TestNonWhitelistedSourceDoesNotAllocateBucket（R1 ①）
// 不在白名单中的 source 不分配桶（桶表大小不变）。
func TestNonWhitelistedSourceDoesNotAllocateBucket(t *testing.T) {
	now := time.Unix(1791825000, 0)
	rec := newFakeRecorder()
	limiter := testLimiter(60, 10, func() time.Time { return now })
	s := newTestServerWithLimiter(t, rec, func() time.Time { return now }, limiter)

	before := limiter.BucketCount()
	for i := 0; i < 50; i++ {
		body := alertBodyFrom(fmt.Sprintf("rogue-source-%d", i), "fp-1", "info")
		if w := sendAlertWithKey(t, s, now, body, testKeyA); w.Code != http.StatusForbidden {
			t.Fatalf("白名单外源应 403，实际 %d", w.Code)
		}
	}
	if after := limiter.BucketCount(); after != before {
		t.Fatalf("白名单外源不得分配桶：%d → %d", before, after)
	}
	if rec.alertCount() != 0 {
		t.Fatal("403 不得写入任何表")
	}
}

// TestBadSignatureDoesNotConsumeTokens（R1 ②）
// 对合法源发送 1000 条签名错误的请求后，合法请求仍能获得完整的突发令牌。
func TestBadSignatureDoesNotConsumeTokens(t *testing.T) {
	now := time.Unix(1791825000, 0)
	rec := newFakeRecorder()
	limiter := testLimiter(60, 10, func() time.Time { return now })
	s := newTestServerWithLimiter(t, rec, func() time.Time { return now }, limiter)

	// 1000 条签名错误（用源 B 的密钥给源 A 签名）。
	for i := 0; i < 1000; i++ {
		body := alertBodyFrom("test-source-a", fmt.Sprintf("fp-bad-%d", i), "info")
		if w := sendAlertWithKey(t, s, now, body, testKeyB); w.Code != http.StatusUnauthorized {
			t.Fatalf("签名错误应 401，实际 %d", w.Code)
		}
	}
	// 合法请求仍应有完整的 10 个突发令牌。
	for i := 0; i < 10; i++ {
		body := alertBodyFrom("test-source-a", fmt.Sprintf("fp-ok-%d", i), "info")
		if w := sendAlert(t, s, now, body); w.Code != http.StatusAccepted {
			t.Fatalf("第 %d 个合法请求应通过（令牌未被伪造请求消耗），实际 %d", i+1, w.Code)
		}
	}
	// 第 11 个合法请求应 429（突发已耗尽）。
	if w := sendAlert(t, s, now, alertBodyFrom("test-source-a", "fp-ok-11", "info")); w.Code != http.StatusTooManyRequests {
		t.Fatalf("突发耗尽后应 429，实际 %d", w.Code)
	}
	if rec.alertCount() != 10 {
		t.Fatalf("只有 10 个合法请求应被记录：%d", rec.alertCount())
	}
}

// TestBucketTableBoundedByWhitelist（R2）桶表大小 = 白名单长度，运行期不新增键。
func TestBucketTableBoundedByWhitelist(t *testing.T) {
	now := time.Unix(1791825000, 0)
	rec := newFakeRecorder()
	limiter := testLimiter(60, 10, func() time.Time { return now })
	s := newTestServerWithLimiter(t, rec, func() time.Time { return now }, limiter)

	// 启动时：桶表长度 = 白名单长度（2）。
	if got := limiter.BucketCount(); got != 2 {
		t.Fatalf("启动时桶表长度应等于白名单长度 2，实际 %d", got)
	}
	// 任意数量未授权 source 后长度不变。
	for i := 0; i < 200; i++ {
		body := alertBodyFrom(fmt.Sprintf("unknown-%d", i), "fp", "info")
		_ = sendAlertWithKey(t, s, now, body, testKeyA)
	}
	// 合法源请求（含超限）后长度仍不变。
	for i := 0; i < 20; i++ {
		body := alertBodyFrom("test-source-b", fmt.Sprintf("fp-b-%d", i), "info")
		_ = sendAlertWithKey(t, s, now, body, testKeyB)
	}
	if got := limiter.BucketCount(); got != 2 {
		t.Fatalf("运行期桶表不得新增键：%d", got)
	}
}

// TestLimiterPreallocationUnit（R2 单元）NewLimiterForSources 预分配与去重。
func TestLimiterPreallocationUnit(t *testing.T) {
	now := func() time.Time { return time.Unix(1791825000, 0) }
	l := ingest.NewLimiterForSources([]string{"a", "B", " a ", "", "c"}, 60, 10, now)
	if got := l.BucketCount(); got != 3 {
		t.Fatalf("去重后应预分配 3 个桶（a/b/c），实际 %d", got)
	}
	// 未预分配的源：不建桶（known=false；调用方本应先经白名单拒绝）。
	allowed, _, known := l.Allow("zzz")
	if known {
		t.Fatalf("未预分配源不得有桶：known=%v allowed=%v", known, allowed)
	}
	if got := l.BucketCount(); got != 3 {
		t.Fatalf("未预分配源不得建桶：%d", got)
	}
	// 已预分配源：大小写不敏感命中同一桶。
	if _, _, known := l.Allow("A"); !known {
		t.Fatal("已预分配源应命中桶（大小写不敏感）")
	}
}

// —— 第十七轮 P1：源画像 ——

// TestProfileMissingFailsStartup（P1 ①）缺画像 → 拒绝启动。
func TestProfileMissingFailsStartup(t *testing.T) {
	_, err := ingest.NewSourceSet([]string{"test-source-a"}, func(name string) string {
		if name == ingest.KeyEnvName("test-source-a") {
			return string(testKeyA)
		}
		return "" // 画像缺失
	})
	if err == nil {
		t.Fatal("缺画像必须拒绝启动")
	}
	if !strings.Contains(err.Error(), "PROFILE_TEST_SOURCE_A") {
		t.Fatalf("错误信息应指出缺失的画像环境变量：%v", err)
	}
}

// TestProfileUnknownFailsStartup（P1 ②）画像未知 → 拒绝启动。
func TestProfileUnknownFailsStartup(t *testing.T) {
	_, err := ingest.NewSourceSet([]string{"test-source-a"}, func(name string) string {
		switch name {
		case ingest.KeyEnvName("test-source-a"):
			return string(testKeyA)
		case ingest.ProfileName("test-source-a"):
			return "grafana" // 未知画像
		}
		return ""
	})
	if err == nil {
		t.Fatal("未知画像必须拒绝启动")
	}
	if !strings.Contains(err.Error(), "grafana") {
		t.Fatalf("错误信息应指出未知画像：%v", err)
	}
	// 已知画像集合与命名规则。
	if len(ingest.KnownProfiles) != 4 {
		t.Fatalf("画像集合应为 4 个：%v", ingest.KnownProfiles)
	}
	for _, p := range []string{"prometheus", "alertmanager", "docker-monitor", "node-exporter"} {
		if !ingest.KnownProfile(p) {
			t.Fatalf("%s 应为已知画像", p)
		}
	}
	if ingest.KnownProfile("grafana") || ingest.KnownProfile("") {
		t.Fatal("未知/空画像不得通过")
	}
	if got := ingest.ProfileName("alert-manager"); got != "AGENT_OPS_ALERT_PROFILE_ALERT_MANAGER" {
		t.Fatalf("画像环境变量命名不符：%s", got)
	}
}

// TestProfileResolverAndSameProfileSamePlan（P1 ③）
// 两个不同 source 声明同一画像时，规划结果相同。
func TestProfileResolverAndSameProfileSamePlan(t *testing.T) {
	set, err := ingest.NewSourceSet([]string{"src-alpha", "src-beta"}, func(name string) string {
		switch name {
		case ingest.KeyEnvName("src-alpha"):
			return "test-only-key-alpha"
		case ingest.KeyEnvName("src-beta"):
			return "test-only-key-beta"
		case ingest.ProfileName("src-alpha"), ingest.ProfileName("src-beta"):
			return "prometheus" // 同一画像
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	if set.ProfileFor("src-alpha") != "prometheus" || set.ProfileFor("src-beta") != "prometheus" {
		t.Fatalf("画像解析不符：%v", set.Profiles())
	}
	// 规划结果相同（按画像匹配）。
	planA := planner.PlanFor(set.ProfileFor("src-alpha"), "critical")
	planB := planner.PlanFor(set.ProfileFor("src-beta"), "critical")
	if planA.RuleID != planB.RuleID || len(planA.Capabilities) != len(planB.Capabilities) {
		t.Fatalf("同画像应产生相同计划：%+v vs %+v", planA, planB)
	}
	if planA.RuleID != "R-001" {
		t.Fatalf("prometheus×critical 应命中 R-001，实际 %s", planA.RuleID)
	}
}
