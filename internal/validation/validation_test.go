package validation

import "testing"

// TestValidCapabilityName 能力名称规则（第五轮修正的安全语义，钉死行为）。
func TestValidCapabilityName(t *testing.T) {
	valid := []string{
		"diagnose.slow_query",
		"restart.service",
		"a",
		"a.b.c_1",
		"diagnose.disk_usage",
	}
	invalid := []string{
		"",                 // 空
		"Volume.Delete",    // 大写（大小写绕过被第五轮修正封堵）
		"a b",              // 空白
		"a..b",             // 空分段
		".a",               // 前导点
		"a.",               // 尾随点
		"诊断.查询",            // Unicode
		"a-b",              // 连字符
		"a/b",              // 斜杠
		"restart\tservice", // 制表符
	}
	for _, name := range valid {
		if !ValidCapabilityName(name) {
			t.Errorf("应合法：%q", name)
		}
	}
	for _, name := range invalid {
		if ValidCapabilityName(name) {
			t.Errorf("应拒绝：%q", name)
		}
	}
}

// TestValidUnitName systemd unit 名称规则（第七轮 linux 适配器语义，钉死行为）。
func TestValidUnitName(t *testing.T) {
	valid := []string{"nginx", "nginx@1", "my-app_1.service", "a.b-c"}
	invalid := []string{"", "../etc/passwd", "a b", "a;b", "a/b", "a|b", "a&b"}
	for _, u := range valid {
		if !ValidUnitName(u) {
			t.Errorf("应合法：%q", u)
		}
	}
	for _, u := range invalid {
		if ValidUnitName(u) {
			t.Errorf("应拒绝：%q", u)
		}
	}
}

// TestValidShellToken 单条 argv 元素无 shell 语义判定。
func TestValidShellToken(t *testing.T) {
	valid := []string{"-r", "-P", "-m", "/etc/os-release", "/proc/loadavg", "is-active", "nginx", "a=b:c"}
	invalid := []string{"", "a b", "a;b", "a&b", "a|b", "a`b", "a$b", "a<b", "a>b", `a"b`, `a'b`, "a\nb", "a\\b"}
	for _, s := range valid {
		if !ValidShellToken(s) {
			t.Errorf("应合法：%q", s)
		}
	}
	for _, s := range invalid {
		if ValidShellToken(s) {
			t.Errorf("应拒绝：%q", s)
		}
	}
}

// TestValidAbsUnixPath 绝对路径规则。
func TestValidAbsUnixPath(t *testing.T) {
	valid := []string{"/", "/var/log", "/etc/nginx/nginx.conf", "/data/app-v1.2/run"}
	invalid := []string{"", "var/log", "/../etc", "/a/../b", "/a b", "/a;b", "//", "/."}
	for _, p := range valid {
		if !ValidAbsUnixPath(p) {
			t.Errorf("应合法：%q", p)
		}
	}
	for _, p := range invalid {
		if ValidAbsUnixPath(p) {
			t.Errorf("应拒绝：%q", p)
		}
	}
}
