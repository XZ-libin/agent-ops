package planner

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/XZ-libin/agent-ops/internal/testdb"
)

// —— 仓库定位与清单解析 ——

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
			t.Fatalf("未找到仓库根：%s", dir)
		}
		dir = parent
	}
}

// manifestCapability 适配器清单中的能力声明（本测试所需字段）。
type manifestCapability struct {
	Name        string `yaml:"name"`
	RiskTier    string `yaml:"risk_tier"`
	Destructive bool   `yaml:"destructive"`
}

// adapterCapabilities 读取 adapters/*/manifest.yaml，返回 能力名 → (tier, destructive)。
func adapterCapabilities(t *testing.T) map[string]manifestCapability {
	t.Helper()
	root := repoRoot(t)
	matches, err := filepath.Glob(filepath.Join(root, "adapters", "*", "manifest.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) == 0 {
		t.Fatal("未找到任何适配器清单（adapters/*/manifest.yaml）")
	}
	out := map[string]manifestCapability{}
	for _, path := range matches {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var mf struct {
			Capabilities []manifestCapability `yaml:"capabilities"`
		}
		if err := yaml.Unmarshal(data, &mf); err != nil {
			t.Fatalf("解析清单 %s 失败：%v", path, err)
		}
		for _, c := range mf.Capabilities {
			out[c.Name] = c
		}
	}
	return out
}

// TestRuleCapabilitiesExistInAdapters（R5 ①）规则表中每个能力名都存在于
// adapters/*/manifest.yaml，且 tier 为 read_only。
func TestRuleCapabilitiesExistInAdapters(t *testing.T) {
	caps := adapterCapabilities(t)
	for _, rule := range Rules {
		if len(rule.Capabilities) == 0 {
			t.Fatalf("规则 %s 的能力列表不得为空", rule.ID)
		}
		for _, name := range rule.Capabilities {
			decl, ok := caps[name]
			if !ok {
				t.Fatalf("规则 %s 引用了不存在于适配器清单的能力：%s", rule.ID, name)
			}
			if decl.RiskTier != "read_only" {
				t.Fatalf("规则 %s 的能力 %s tier 应为 read_only，实际 %q", rule.ID, name, decl.RiskTier)
			}
		}
	}
	t.Logf("规则表能力校验通过：%d 条规则，%d 个不同能力", len(Rules), len(Capabilities()))
}

// TestRuleTableHasNoDestructiveCapabilities（R5 ②）
// 规则表中不存在 destructive 或非 read_only 的能力（table-driven）。
func TestRuleTableHasNoDestructiveCapabilities(t *testing.T) {
	caps := adapterCapabilities(t)
	for _, name := range Capabilities() {
		name := name
		t.Run(name, func(t *testing.T) {
			decl, ok := caps[name]
			if !ok {
				t.Fatalf("能力 %s 不在任何适配器清单中", name)
			}
			if decl.Destructive {
				t.Fatalf("能力 %s 标记为 destructive，不得出现在诊断计划中", name)
			}
			if decl.RiskTier != "read_only" {
				t.Fatalf("能力 %s 非 read_only（%q），不得出现在诊断计划中", name, decl.RiskTier)
			}
		})
	}
}

// TestPlannerDoesNotImportAdapters（R5 ③）仓库级检查：
// alerts/internal/planner 中不得 import 任何 adapters/* 包。
func TestPlannerDoesNotImportAdapters(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	importRe := regexp.MustCompile(`"([^"]*adapters/[^"]*)"`)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		data, err := os.ReadFile(e.Name())
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range importRe.FindAllStringSubmatch(string(data), -1) {
			t.Fatalf("规划器不得 import 适配器包：%s → %s", e.Name(), m[1])
		}
	}
	// 同时确认规划器源码中不出现执行类关键字（防御性检查）。
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		data, _ := os.ReadFile(e.Name())
		for _, bad := range []string{"exec.Command", "ssh.New", "docker.NewClient", "kubernetes.NewClient"} {
			if strings.Contains(string(data), bad) {
				t.Fatalf("规划器源码不得出现执行调用 %q：%s", bad, e.Name())
			}
		}
	}
}

// TestPlanForTableDriven 纯函数规则匹配（含大小写与空白归一化）。
func TestPlanForTableDriven(t *testing.T) {
	cases := []struct {
		profile, severity string
		wantRule          string
		wantCaps          int
		wantReason        string
	}{
		{"prometheus", "critical", "R-001", 3, ""},
		{"prometheus", "warning", "R-002", 2, ""},
		{"  PROMETHEUS  ", " Critical ", "R-001", 3, ""},
		{"alertmanager", "critical", "R-003", 3, ""},
		{"docker-monitor", "warning", "R-006", 2, ""},
		{"node-exporter", "critical", "R-007", 3, ""},
		{"prometheus", "info", "", 0, ReasonNoRule},
		{"unknown-profile", "critical", "", 0, ReasonNoRule},
		{"", "", "", 0, ReasonNoProfile},
	}
	for _, tc := range cases {
		got := PlanFor(tc.profile, tc.severity)
		if got.RuleID != tc.wantRule || len(got.Capabilities) != tc.wantCaps || got.Reason != tc.wantReason {
			t.Fatalf("PlanFor(%q,%q)=%+v，期望 rule=%q caps=%d reason=%q",
				tc.profile, tc.severity, got, tc.wantRule, tc.wantCaps, tc.wantReason)
		}
	}
}

// —— 计划表（真实 PG，独立 run schema） ——

// newTestPlanner 建立真实 PG 规划器（含待诊断请求表）。
func newTestPlanner(t *testing.T) (*Planner, *testdb.RunSchema) {
	t.Helper()
	rs := testdb.NewRunSchema(t)
	if rs == nil {
		return nil, nil
	}
	ctx := context.Background()
	// 待诊断请求表（结构同消费者；本测试直接建表以便独立验证规划器）。
	if _, err := rs.Pool().Exec(ctx, `CREATE TABLE IF NOT EXISTS test_diagnosis_requests (
    id         bigserial   PRIMARY KEY,
    event_id   bigint      NOT NULL UNIQUE,
    fingerprint text       NOT NULL DEFAULT '',
    source     text        NOT NULL DEFAULT '',
    severity   text        NOT NULL DEFAULT '',
    asset_id   text        NOT NULL DEFAULT '',
    status     text        NOT NULL DEFAULT 'pending',
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);`); err != nil {
		t.Fatalf("建待诊断请求表失败：%v", err)
	}
	p, err := New(Config{Pool: rs.Pool(), Now: func() time.Time { return time.Unix(1791825000, 0) },
		Profiles: map[string]string{"prometheus": "prometheus", "docker-monitor": "docker-monitor",
			"test-source-a": "node-exporter"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.EnsureSchema(ctx); err != nil {
		t.Fatalf("建计划表失败：%v", err)
	}
	t.Logf("[H5] schema：%s", rs.Name())
	return p, rs
}

// insertRequest 插入一条 pending 待诊断请求。
func insertRequest(t *testing.T, p *Planner, eventID int64, source, severity string) {
	t.Helper()
	_, err := p.pool.Exec(context.Background(), `INSERT INTO test_diagnosis_requests
(event_id, fingerprint, source, severity, asset_id, status, created_at, updated_at)
VALUES ($1,$2,$3,$4,'ast_itest','pending',now(),now())`,
		eventID, "fp-"+source, source, severity)
	if err != nil {
		t.Fatal(err)
	}
}

// TestPlannerRunOnceAndIdempotent（R5 ④）重复规划只生成一行。
func TestPlannerRunOnceAndIdempotent(t *testing.T) {
	p, _ := newTestPlanner(t)
	if p == nil {
		return
	}
	ctx := context.Background()
	insertRequest(t, p, 1, "prometheus", "critical")
	insertRequest(t, p, 2, "docker-monitor", "warning")

	n, err := p.RunOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("应新增 2 条计划，实际 %d", n)
	}
	// 重复运行：不新增。
	for i := 0; i < 3; i++ {
		again, err := p.RunOnce(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if again != 0 {
			t.Fatalf("重复规划不得新增行：%d", again)
		}
	}
	count, err := p.PlanCount(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("计划表应有 2 行，实际 %d", count)
	}
	plans, err := p.Plans(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, pl := range plans {
		if pl.Status != StatusPlanned {
			t.Fatalf("本轮计划状态必须固定 planned，实际 %q", pl.Status)
		}
	}
	if plans[0].RuleID != "R-001" || len(plans[0].Capabilities) != 3 {
		t.Fatalf("event 1 应命中 R-001 且 3 个能力：%+v", plans[0])
	}
	t.Logf("[断言] 首次规划 2 行；重复规划 3 次均为 0 新增；状态固定 planned")
}

// TestPlannerNoRule（R5 ⑤ / P1 ④）无匹配规则时**状态**为 no_rule（能力列表为空）。
func TestPlannerNoRule(t *testing.T) {
	p, _ := newTestPlanner(t)
	if p == nil {
		return
	}
	ctx := context.Background()
	insertRequest(t, p, 10, "test-source-a", "warning") // node-exporter 画像 × warning 无规则

	n, err := p.RunOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("应生成 1 条 no_rule 计划，实际 %d", n)
	}
	plans, err := p.Plans(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(plans) != 1 {
		t.Fatalf("应有 1 条计划：%d", len(plans))
	}
	got := plans[0]
	if got.Status != StatusNoRule {
		t.Fatalf("无匹配规则时状态应为 no_rule，实际 %q", got.Status)
	}
	if got.RuleID != "" {
		t.Fatalf("无匹配规则时规则编号应为空，实际 %q", got.RuleID)
	}
	if len(got.Capabilities) != 0 {
		t.Fatalf("无匹配规则时能力列表应为空，实际 %v", got.Capabilities)
	}
	if got.Reason != ReasonNoRule {
		t.Fatalf("无匹配规则时原因应为 %q，实际 %q", ReasonNoRule, got.Reason)
	}
	t.Log("[断言] 无匹配规则 → status=no_rule + 空能力 + reason=no_rule")
}

// TestPlannerTableNameGuard 表名必须是 test_ 前缀。
func TestPlannerTableNameGuard(t *testing.T) {
	rs := testdb.NewRunSchema(t)
	if rs == nil {
		return
	}
	for _, bad := range []string{"plans", "public.test_diagnosis_plans", "test_x; DROP TABLE y"} {
		if _, err := New(Config{Pool: rs.Pool(), PlansTable: bad}); err == nil {
			t.Fatalf("非法表名必须拒绝：%q", bad)
		}
	}
	if _, err := New(Config{Pool: rs.Pool()}); err != nil {
		t.Fatalf("默认表名应通过：%v", err)
	}
}
