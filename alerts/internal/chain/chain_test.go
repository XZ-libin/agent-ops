// Package chain 是完整链路的集成测试包（第十六轮 R6）：
// 告警入站 → outbox → 消费者 → 待诊断请求 → 规划器 → 计划表。
//
// 全链路使用真实 PostgreSQL（55432 / agent_ops_test / 每个用例独立 run schema）
// 与真实 HTTP 服务器；不连接任何告警源、适配器或资产。
package chain

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/XZ-libin/agent-ops/alerts/internal/consumer"
	"github.com/XZ-libin/agent-ops/alerts/internal/httpapi"
	"github.com/XZ-libin/agent-ops/alerts/internal/ingest"
	"github.com/XZ-libin/agent-ops/alerts/internal/planner"
	"github.com/XZ-libin/agent-ops/alerts/internal/store"
	"github.com/XZ-libin/agent-ops/internal/testdb"
)

// 仅测试的固定假密钥（明显的测试值，非真实凭据）。
const (
	testKeyPrometheus = "test-only-key-prometheus"
	testKeySourceA    = "test-only-key-source-a"
	testKeyDocker     = "test-only-key-docker"
	testKeyK8s        = "test-only-key-k8s"
)

// chainEnv 完整链路环境。
type chainEnv struct {
	store    *store.Store
	consumer *consumer.Consumer
	planner  *planner.Planner
	pool     *pgxpool.Pool
	schema   *testdb.RunSchema
	baseURL  string
	now      func() time.Time
}

// newChainEnv 建立完整链路（真实 PG + 真实 HTTP 服务器）。
func newChainEnv(t *testing.T) *chainEnv {
	t.Helper()
	rs := testdb.NewRunSchema(t)
	if rs == nil {
		return nil
	}
	ctx := context.Background()
	pool := rs.Pool()
	t.Logf("[H5] 链路测试 schema：%s", rs.Name())

	st, err := store.New(pool, store.DefaultAlertsTable, store.DefaultOutboxTable)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.EnsureSchema(ctx); err != nil {
		t.Fatalf("outbox 建表失败（非 skip）：%v", err)
	}
	base := time.Unix(1791825000, 0)
	current := base
	now := func() time.Time { return current }
	_ = current

	cons, err := consumer.New(consumer.Config{Pool: pool, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if err := cons.EnsureSchema(ctx); err != nil {
		t.Fatalf("待诊断请求表建表失败（非 skip）：%v", err)
	}
	pl, err := planner.New(planner.Config{Pool: pool, Now: now,
		Profiles: map[string]string{
			"prometheus":    "prometheus",
			"test-source-a": "node-exporter",
			"docker-src":    "docker-monitor",
			"k8s-src":       "alertmanager",
		}})
	if err != nil {
		t.Fatal(err)
	}
	if err := pl.EnsureSchema(ctx); err != nil {
		t.Fatalf("计划表建表失败（非 skip）：%v", err)
	}

	// 源白名单（仅测试假密钥）。
	sources, err := ingest.NewSourceSet([]string{"prometheus", "test-source-a", "docker-src", "k8s-src"}, func(name string) string {
		switch name {
		case ingest.KeyEnvName("prometheus"):
			return testKeyPrometheus
		case ingest.KeyEnvName("test-source-a"):
			return testKeySourceA
		case ingest.KeyEnvName("docker-src"):
			return testKeyDocker
		case ingest.KeyEnvName("k8s-src"):
			return testKeyK8s
		case ingest.ProfileName("prometheus"):
			return "prometheus"
		case ingest.ProfileName("test-source-a"):
			return "node-exporter"
		case ingest.ProfileName("docker-src"):
			return "docker-monitor"
		case ingest.ProfileName("k8s-src"):
			return "alertmanager"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := httpapi.New(httpapi.Config{Sources: sources, Recorder: st, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	return &chainEnv{store: st, consumer: cons, planner: pl, pool: pool, schema: rs,
		baseURL: httpSrv.URL, now: now}
}

// postAlert 通过真实 HTTP 发送一条告警（返回状态码与响应体）。
func (e *chainEnv) postAlert(t *testing.T, source, severity, fingerprint, key string, at time.Time) (int, string) {
	t.Helper()
	body := fmt.Sprintf(`{"source":%q,"severity":%q,"asset_id":"ast_chain","fingerprint":%q,"summary":"链路测试"}`,
		source, severity, fingerprint)
	tsStr := fmt.Sprintf("%d", at.Unix())
	req, err := http.NewRequest(http.MethodPost, e.baseURL+"/v1/alerts", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(ingest.HeaderTimestamp, tsStr)
	req.Header.Set(ingest.HeaderSignature, ingest.Sign([]byte(key), tsStr, []byte(body)))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw)
}

// counts 汇总链路各步行数。
type counts struct {
	alerts   int64
	outbox   int64
	requests int64
	plans    int64
}

// snapshot 读取链路各步行数。
func (e *chainEnv) snapshot(t *testing.T) counts {
	t.Helper()
	ctx := context.Background()
	alerts, outbox, err := e.store.Counts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	reqs, err := e.consumer.RequestCount(ctx)
	if err != nil {
		t.Fatal(err)
	}
	plans, err := e.planner.PlanCount(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return counts{alerts: alerts, outbox: outbox, requests: reqs, plans: plans}
}

// TestFullChainAlertToPlan（R6）完整链路：
// 告警入站 → outbox → 消费者 → 待诊断请求 → 规划器 → 计划表，逐步断言行数。
func TestFullChainAlertToPlan(t *testing.T) {
	env := newChainEnv(t)
	if env == nil {
		return
	}
	ctx := context.Background()
	base := time.Unix(1791825000, 0)

	// 0) 初始：全链路为空。
	if got := env.snapshot(t); got != (counts{}) {
		t.Fatalf("初始应为空：%+v", got)
	}

	// 1) 入站：一条 critical 告警（prometheus）→ alerts 1 行、outbox 1 行。
	code, body := env.postAlert(t, "prometheus", "critical", "fp-chain-1", testKeyPrometheus, base)
	if code != http.StatusAccepted {
		t.Fatalf("入站应 202，实际 %d（%s）", code, body)
	}
	got := env.snapshot(t)
	if got.alerts != 1 || got.outbox != 1 {
		t.Fatalf("入站后应 alerts=1 outbox=1，实际 %+v", got)
	}
	t.Logf("[链路] ① 入站：alerts=%d outbox=%d", got.alerts, got.outbox)

	// 2) 消费者：outbox → 待诊断请求。
	n, err := env.consumer.RunOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("消费者应处理 1 条事件，实际 %d", n)
	}
	got = env.snapshot(t)
	if got.requests != 1 {
		t.Fatalf("消费者后应有 1 条待诊断请求，实际 %+v", got)
	}
	if pending, _ := env.consumer.PendingCount(ctx); pending != 0 {
		t.Fatalf("outbox 应已消费：pending=%d", pending)
	}
	t.Logf("[链路] ② 消费者：requests=%d（outbox 全部 consumed）", got.requests)

	// 3) 规划器：请求 → 计划（R-001，3 个只读能力）。
	n, err = env.planner.RunOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("规划器应生成 1 条计划，实际 %d", n)
	}
	got = env.snapshot(t)
	if got.plans != 1 {
		t.Fatalf("应有 1 条计划，实际 %+v", got)
	}
	plans, err := env.planner.Plans(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if plans[0].RuleID != "R-001" || len(plans[0].Capabilities) != 3 || plans[0].Status != planner.StatusPlanned ||
		plans[0].Profile != "prometheus" {
		t.Fatalf("计划内容不符：%+v", plans[0])
	}
	t.Logf("[链路] ③ 规划器：plans=%d rule=%s caps=%v status=%s",
		got.plans, plans[0].RuleID, plans[0].Capabilities, plans[0].Status)

	// 4) 窗口内重复告警：alerts 不增长（fingerprint 主键）、outbox 不增长。
	code, _ = env.postAlert(t, "prometheus", "critical", "fp-chain-1", testKeyPrometheus, base.Add(time.Minute))
	if code != http.StatusAccepted {
		t.Fatalf("窗口内重复应 202，实际 %d", code)
	}
	got = env.snapshot(t)
	if got.alerts != 1 || got.outbox != 1 {
		t.Fatalf("窗口内重复不得新增行：%+v", got)
	}
	count, err := env.store.AlertCount(ctx, "fp-chain-1")
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("窗口内重复应计数为 2，实际 %d", count)
	}
	// 消费者/规划器再跑：无新事件、无新计划。
	if n, _ := env.consumer.RunOnce(ctx); n != 0 {
		t.Fatalf("无新事件时消费者不应处理：%d", n)
	}
	if n, _ := env.planner.RunOnce(ctx); n != 0 {
		t.Fatalf("无新请求时规划器不应新增：%d", n)
	}
	t.Logf("[链路] ④ 窗口内重复：alerts=%d count=%d outbox=%d（均未增长）", got.alerts, count, got.outbox)

	// 5) 第二个 fingerprint（无匹配规则）→ 全链路各步 +1，计划 reason=no_rule。
	code, _ = env.postAlert(t, "test-source-a", "warning", "fp-chain-2", testKeySourceA, base.Add(2*time.Minute))
	if code != http.StatusAccepted {
		t.Fatalf("第二条告警应 202，实际 %d", code)
	}
	if n, err := env.consumer.RunOnce(ctx); err != nil || n != 1 {
		t.Fatalf("消费者应处理 1 条：n=%d err=%v", n, err)
	}
	if n, err := env.planner.RunOnce(ctx); err != nil || n != 1 {
		t.Fatalf("规划器应新增 1 条：n=%d err=%v", n, err)
	}
	got = env.snapshot(t)
	if got.alerts != 2 || got.outbox != 2 || got.requests != 2 || got.plans != 2 {
		t.Fatalf("链路各步应各为 2：%+v", got)
	}
	plans, err = env.planner.Plans(ctx)
	if err != nil {
		t.Fatal(err)
	}
	last := plans[len(plans)-1]
	if last.Reason != planner.ReasonNoRule || len(last.Capabilities) != 0 || last.Status != planner.StatusNoRule {
		t.Fatalf("第二条应为 no_rule 计划：%+v", last)
	}
	t.Logf("[链路] ⑤ 第二条（无匹配规则）：alerts=%d outbox=%d requests=%d plans=%d（reason=%s）",
		got.alerts, got.outbox, got.requests, got.plans, last.Reason)

	// 6) 幂等复跑：消费者与规划器均不新增。
	for i := 0; i < 2; i++ {
		if n, _ := env.consumer.RunOnce(ctx); n != 0 {
			t.Fatalf("复跑消费者不应处理：%d", n)
		}
		if n, _ := env.planner.RunOnce(ctx); n != 0 {
			t.Fatalf("复跑规划器不应新增：%d", n)
		}
	}
	if got2 := env.snapshot(t); got2 != got {
		t.Fatalf("复跑不得改变行数：%+v → %+v", got, got2)
	}
	t.Log("[链路] ⑥ 幂等复跑：行数不变")
}

// TestChainRejectsNonWhitelistedSource（R1 在链路中的体现）
// 白名单外源在链路第一步即 403，全链路不产生任何行。
func TestChainRejectsNonWhitelistedSource(t *testing.T) {
	env := newChainEnv(t)
	if env == nil {
		return
	}
	base := time.Unix(1791825000, 0)
	code, _ := env.postAlert(t, "unknown-source", "critical", "fp-x", testKeySourceA, base)
	if code != http.StatusForbidden {
		t.Fatalf("白名单外源应 403，实际 %d", code)
	}
	if got := env.snapshot(t); got != (counts{}) {
		t.Fatalf("被拒请求不得产生任何行：%+v", got)
	}
	t.Log("[断言] 白名单外源：403 且全链路 0 行")
}

// TestChainSignatureFailureProducesNothing 签名失败在链路第二步即 401，
// 全链路不产生任何行。
func TestChainSignatureFailureProducesNothing(t *testing.T) {
	env := newChainEnv(t)
	if env == nil {
		return
	}
	base := time.Unix(1791825000, 0)
	code, _ := env.postAlert(t, "prometheus", "critical", "fp-x", testKeySourceA /* 错密钥 */, base)
	if code != http.StatusUnauthorized {
		t.Fatalf("签名错误应 401，实际 %d", code)
	}
	if got := env.snapshot(t); got != (counts{}) {
		t.Fatalf("签名失败不得产生任何行：%+v", got)
	}
	t.Log("[断言] 签名失败：401 且全链路 0 行")
}
