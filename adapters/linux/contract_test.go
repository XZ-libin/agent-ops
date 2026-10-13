package linux

import (
	"context"
	"strings"
	"testing"
	"time"

	contractv1 "github.com/ORG/agent-ops/contract/gen/go/agent_ops/contract/v1"

	"github.com/ORG/agent-ops/internal/validation"
)

// allowedCommands 适配器允许的固定只读命令集合（契约测试白名单）。
var allowedCommands = map[string]bool{
	"uname":     true,
	"cat":       true,
	"df":        true,
	"free":      true,
	"systemctl": true,
}

// forbiddenArgPattern 命令参数中禁止出现的 shell 危险字符（argv 形式下不允许任何 shell 语义）。
func hasForbiddenChars(s string) bool {
	return strings.ContainsAny(s, ";&|`$<>'\"\\") || strings.Contains(s, "..") || strings.Contains(s, " ")
}

// TestCommandWhitelist 契约测试：适配器发出的每一条命令都必须在允许集合内，
// 且 systemctl 的 unit 参数通过白名单正则；任何 argv 元素不含 shell 危险字符。
func TestCommandWhitelist(t *testing.T) {
	r := newFakeRunner()
	r.setOutput([]string{"uname", "-r"}, "6.1.0\n")
	r.setOutput([]string{"cat", "/etc/os-release"}, "NAME=\"Debian\"\n")
	r.setOutput([]string{"df", "-P"}, "/dev/sda1 100000 50000 50000 50% /")
	r.setOutput([]string{"free", "-m"}, "Mem: 16000 8000 7999 1 100 7900")
	r.setOutput([]string{"cat", "/proc/loadavg"}, "1.00 1.20 1.30 3/456 12345")
	r.setOutput([]string{"systemctl", "is-active", "nginx"}, "active\n")

	a := testAdapter(t, r)
	ctx := context.Background()
	target := &contractv1.AssetTarget{AssetId: "ast_01HX"}
	instance := &contractv1.Instance{Id: "ast_01HX/linux"}

	if _, err := a.Discover(ctx, target); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Health(ctx, instance); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{"disk_usage", "memory_pressure", "load_average", "service_state:nginx"} {
		if _, err := a.Diagnose(ctx, instance, q); err != nil {
			t.Fatal(err)
		}
	}

	calls := r.snapshotCalls()
	if len(calls) == 0 {
		t.Fatal("未记录到任何命令调用")
	}
	if len(calls) != 8 {
		t.Fatalf("命令调用数应为 8（2 discover + 2 health + 4 diagnose），got %d", len(calls))
	}

	used := map[string]bool{}
	for _, call := range calls {
		bin := call[0]
		if !allowedCommands[bin] {
			t.Fatalf("命令 %q 不在允许集合内：%v", bin, call)
		}
		used[bin] = true
		for _, arg := range call[1:] {
			if hasForbiddenChars(arg) {
				t.Fatalf("参数含 shell 危险字符：%q（命令 %v）", arg, call)
			}
		}
		if bin == "systemctl" {
			if len(call) != 3 || call[1] != "is-active" || !validation.ValidUnitName(call[2]) {
				t.Fatalf("systemctl 调用形状/unit 校验不符：%v", call)
			}
		}
	}

	// 契约测试输出：白名单检查结果可见。
	t.Logf("命令白名单检查通过：允许集合 %v，实际使用 %v", mapKeys(allowedCommands), mapKeys(used))
}

func mapKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestContextTimeoutSafe 契约测试：context 超时后适配器安全返回（不 panic、不长时间阻塞）。
func TestContextTimeoutSafe(t *testing.T) {
	r := newFakeRunner()
	r.blockCtx = true
	a := testAdapter(t, r)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := a.Health(ctx, &contractv1.Instance{Id: "i1"})
	if err == nil {
		t.Fatal("context 超时应返回错误")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("超时返回耗时过长：%v", elapsed)
	}
}

// TestUndeclaredCapabilityRejected 契约测试：未声明能力被拒绝。
func TestUndeclaredCapabilityRejected(t *testing.T) {
	a := testAdapter(t, newFakeRunner())
	_, err := a.Execute(context.Background(),
		&contractv1.Action{Capability: "volume.delete_all"},
		&contractv1.AuthZ{AuthorizationId: "a1"})
	if err == nil {
		t.Fatal("未声明能力必须被拒绝")
	}
}

// TestNoCredentialMarkersInCommands 契约测试：命令与参数中不出现任何凭据字样。
func TestNoCredentialMarkersInCommands(t *testing.T) {
	r := newFakeRunner()
	r.setOutput([]string{"df", "-P"}, "/dev/sda1 100000 50000 50000 50% /")
	r.setOutput([]string{"cat", "/proc/loadavg"}, "1.00 1.20 1.30 3/456 12345")
	a := testAdapter(t, r)

	if _, err := a.Health(context.Background(), &contractv1.Instance{Id: "i1"}); err != nil {
		t.Fatal(err)
	}
	markers := []string{"password", "secret", "token", "PRIVATE KEY", "ssh"}
	for _, call := range r.snapshotCalls() {
		for _, arg := range call {
			for _, m := range markers {
				if strings.Contains(strings.ToLower(arg), m) {
					t.Fatalf("命令中出现凭据字样 %q：%v", m, call)
				}
			}
		}
	}
}
