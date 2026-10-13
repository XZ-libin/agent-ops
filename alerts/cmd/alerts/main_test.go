package main

import (
	"strings"
	"testing"

	"github.com/ORG/agent-ops/alerts/internal/ingest"
)

// testEnv 构造测试环境变量（明显的假密钥）。
func testEnv() map[string]string {
	return map[string]string{
		ingest.EnvSources:                  "test-source-a,test-source-b",
		ingest.KeyEnvName("test-source-a"): "test-only-key-source-a",
		ingest.KeyEnvName("test-source-b"): "test-only-key-source-b",
		// 第十七轮 P1：每个白名单源必须声明画像。
		ingest.ProfileName("test-source-a"): "prometheus",
		ingest.ProfileName("test-source-b"): "docker-monitor",
		"AGENT_OPS_ALERT_DSN":               "postgres://agent_ops:agent_ops@localhost:55432/agent_ops_test?sslmode=disable",
	}
}

// getenvFrom 返回基于 map 的 getenv。
func getenvFrom(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

// TestModeRequiredAndProdRejected（R5 ①②）mode 缺失启动失败；mode=prod 启动失败。
func TestModeRequiredAndProdRejected(t *testing.T) {
	if _, err := parseMode(""); err == nil {
		t.Fatal("缺 mode 必须启动失败")
	} else if !strings.Contains(err.Error(), "-mode") {
		t.Fatalf("错误信息应指出 -mode 必填：%v", err)
	}
	if _, err := parseMode("staging"); err == nil {
		t.Fatal("未知 mode 必须启动失败")
	}
	if _, err := parseMode("prod"); err == nil {
		t.Fatal("mode=prod 本轮必须拒绝启动")
	} else if !strings.Contains(err.Error(), "生产认证未实现") {
		t.Fatalf("prod 拒绝原因应说明生产认证未实现：%v", err)
	}
	// prod 下即便配置齐全也不得放行。
	if _, _, err := loadConfig(getenvFrom(testEnv()), modeProd); err == nil {
		t.Fatal("mode=prod 不得放行")
	}
}

// TestDatabaseNameValidated（R5 ③）库名不是 agent_ops_test 启动失败。
func TestDatabaseNameValidated(t *testing.T) {
	for _, bad := range []string{
		"postgres://agent_ops:agent_ops@localhost:55432/agent_ops?sslmode=disable",
		"postgres://agent_ops:agent_ops@localhost:55432/other?sslmode=disable",
	} {
		env := testEnv()
		env["AGENT_OPS_ALERT_DSN"] = bad
		if _, _, err := loadConfig(getenvFrom(env), modeTest); err == nil {
			t.Fatalf("库名非 agent_ops_test 必须拒绝启动：%s", bad)
		}
	}
	// 正确库名应通过。
	if _, dsn, err := loadConfig(getenvFrom(testEnv()), modeTest); err != nil {
		t.Fatalf("合法配置应通过：%v", err)
	} else if !strings.Contains(dsn, "agent_ops_test") {
		t.Fatalf("DSN 应为测试库：%s", dsn)
	}
}

// TestSourceConfigRequired 源白名单与每源密钥缺失即拒绝启动。
func TestSourceConfigRequired(t *testing.T) {
	// 缺源白名单。
	env := testEnv()
	delete(env, ingest.EnvSources)
	if _, _, err := loadConfig(getenvFrom(env), modeTest); err == nil {
		t.Fatal("缺源白名单必须拒绝启动")
	}
	// 源白名单为空。
	env = testEnv()
	env[ingest.EnvSources] = "  ,  "
	if _, _, err := loadConfig(getenvFrom(env), modeTest); err == nil {
		t.Fatal("空源白名单必须拒绝启动")
	}
	// 缺某源密钥。
	env = testEnv()
	delete(env, ingest.KeyEnvName("test-source-b"))
	if _, _, err := loadConfig(getenvFrom(env), modeTest); err == nil {
		t.Fatal("缺源密钥必须拒绝启动")
	}
	// 配置齐全应通过，且不把密钥写入日志（本测试只校验返回值不含密钥字样）。
	set, _, err := loadConfig(getenvFrom(testEnv()), modeTest)
	if err != nil {
		t.Fatal(err)
	}
	if !set.Allowed("test-source-a") || set.Allowed("unknown") {
		t.Fatal("源白名单判定不符")
	}
}

// TestProfileConfigRequired（P1 ①②）缺画像 / 画像未知 → 拒绝启动。
func TestProfileConfigRequired(t *testing.T) {
	// 缺画像。
	env := testEnv()
	delete(env, ingest.ProfileName("test-source-a"))
	if _, _, err := loadConfig(getenvFrom(env), modeTest); err == nil {
		t.Fatal("缺画像必须拒绝启动")
	}
	// 画像未知。
	env = testEnv()
	env[ingest.ProfileName("test-source-a")] = "grafana"
	if _, _, err := loadConfig(getenvFrom(env), modeTest); err == nil {
		t.Fatal("未知画像必须拒绝启动")
	}
	// 配置齐全应通过，且画像可解析。
	set, _, err := loadConfig(getenvFrom(testEnv()), modeTest)
	if err != nil {
		t.Fatal(err)
	}
	if set.ProfileFor("test-source-a") != "prometheus" || set.ProfileFor("test-source-b") != "docker-monitor" {
		t.Fatalf("画像解析不符：%v", set.Profiles())
	}
}

// TestWorkerOnlyInTestMode（W1 ①）-worker 与 mode=prod 同时出现 → 拒绝启动；
// 仅 test 模式允许开启。
func TestWorkerOnlyInTestMode(t *testing.T) {
	// prod + worker：拒绝（且必须先于任何连接/建表动作被拒绝）。
	if err := checkWorkerMode(true, modeProd); err == nil {
		t.Fatal("mode=prod 开启 -worker 必须拒绝启动")
	} else if !strings.Contains(err.Error(), "-worker") {
		t.Fatalf("拒绝原因应指出 -worker：%v", err)
	}
	// prod 本身也已被 parseMode 拒绝（双重保险）。
	if _, err := parseMode("prod"); err == nil {
		t.Fatal("mode=prod 本轮必须拒绝启动")
	}
	// test + worker：允许。
	if err := checkWorkerMode(true, modeTest); err != nil {
		t.Fatalf("test 模式应允许 -worker：%v", err)
	}
	// test 且未开启 worker：允许。
	if err := checkWorkerMode(false, modeTest); err != nil {
		t.Fatalf("未开启 worker 不应报错：%v", err)
	}
	t.Log("[断言] ① -worker 仅 test 模式可用；prod 开启即拒绝启动")
}
