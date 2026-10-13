package testdb

import (
	"strings"
	"testing"
)

// TestValidateRejectsNonTestDatabase 库名校验（H2）：非 agent_ops_test 一律拒绝，
// 防止测试误连默认库（默认库里曾出现生产命名表，违反约束）。
func TestValidateRejectsNonTestDatabase(t *testing.T) {
	if err := Validate(DefaultDSN); err != nil {
		t.Fatalf("默认测试 DSN 应通过：%v", err)
	}
	if err := Validate("postgres://agent_ops:agent_ops@localhost:55432/agent_ops?sslmode=disable"); err == nil {
		t.Fatal("默认库 agent_ops 必须被拒绝")
	}
	if err := Validate("postgres://agent_ops:agent_ops@localhost:55432/other?sslmode=disable"); err == nil {
		t.Fatal("其他库名必须被拒绝")
	}
	if err := Validate("not-a-dsn"); err == nil {
		t.Fatal("无法解析的连接串必须被拒绝")
	}
}

// TestResolveRejectsWrongDatabase Resolve 在库名错误时返回错误（不返回可用 DSN）。
// 说明：环境变量由调用方设置，本用例只覆盖默认路径与解析路径。
func TestResolveRejectsWrongDatabase(t *testing.T) {
	t.Setenv(EnvDSN, "postgres://agent_ops:agent_ops@localhost:55432/agent_ops?sslmode=disable")
	if _, err := Resolve(); err == nil {
		t.Fatal("环境变量指向默认库时应拒绝")
	}
	t.Setenv(EnvDSN, "")
	dsn, err := Resolve()
	if err != nil {
		t.Fatalf("默认路径应可用：%v", err)
	}
	if !strings.Contains(dsn, "/"+TestDatabase+"?") {
		t.Fatalf("默认 DSN 应指向 %s：%s", TestDatabase, dsn)
	}
}

// TestValidateSchemaNameRejectsNonRunPrefix（H5）schema 名校验：
// 非 test_run_ 前缀一律拒绝（删除前的安全闸门，public 不可触碰）。
func TestValidateSchemaNameRejectsNonRunPrefix(t *testing.T) {
	bad := []string{"public", "agent_ops_test", "test_approvals", "test_run_", "", "Test_Run_1", "pg_temp"}
	for _, name := range bad {
		if err := ValidateSchemaName(name); err == nil {
			t.Fatalf("schema 名 %q 必须被拒绝", name)
		}
	}
	good := []string{"test_run_1", "test_run_1791824288901869000"}
	for _, name := range good {
		if err := ValidateSchemaName(name); err != nil {
			t.Fatalf("schema 名 %q 应通过：%v", name, err)
		}
	}
}

// TestRunSchemaPrefixIsEnforced 前缀常量与校验函数一致。
func TestRunSchemaPrefixIsEnforced(t *testing.T) {
	if RunSchemaPrefix != "test_run_" {
		t.Fatalf("每轮 schema 前缀应为 test_run_，实际 %q", RunSchemaPrefix)
	}
	if err := ValidateSchemaName(RunSchemaPrefix + "x"); err != nil {
		t.Fatalf("带后缀的名字应通过：%v", err)
	}
}
