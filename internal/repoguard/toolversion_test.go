package repoguard

// T2c（第二十五轮）：CI 常量与 docs/tooling.md 登记版本必须一致。
//
// 为什么要这条守卫：登记表的用途是"外部二进制先登记后使用"（硬性约束 5）。
// 一旦 `ci.yml` 里的 `GO_VERSION` / `KUBECTL_VERSION` 与 `docs/tooling.md` 登记的版本
// 漂移，CI 就会下载一个**没有登记、没有校验值**的版本——`sha256sum -c` 会从
// tooling.md 取到一个对应不上产品的哈希，要么误报失败，要么（更糟）取到空值。
// 本守卫只读文件、**不执行任何二进制**。

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/ORG/agent-ops/internal/toolpin"
)

// ciPlatform CI runner 的平台（`runs-on: ubuntu-latest` → linux/amd64）。
const ciPlatform = "linux/amd64"

// ciVersionConstants ci.yml 顶部 env 里的工具版本常量 → 登记表中的工具名。
var ciVersionConstants = []struct{ envKey, tool string }{
	{"GO_VERSION", "go"},
	{"KUBECTL_VERSION", "kubectl"},
	{"BUF_VERSION", "buf"},
	{"KIND_VERSION", "kind"},
}

// envValuePattern 匹配 `  GO_VERSION: "1.27.2"` 形式（引号可选）。
var envValuePattern = regexp.MustCompile(`(?m)^\s+([A-Z0-9_]+VERSION):\s*"?([^"\n]+?)"?\s*$`)

func TestToolVersionMatchesRegistered(t *testing.T) {
	path := filepath.Join(repoRoot(t), ciWorkflowPath)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取 CI 配置失败：%v", err)
	}
	found := map[string]string{}
	for _, m := range envValuePattern.FindAllStringSubmatch(string(raw), -1) {
		found[m[1]] = strings.TrimSpace(m[2])
	}

	var mismatches, missingConst []string
	checked := 0
	for _, c := range ciVersionConstants {
		ciVal, ok := found[c.envKey]
		if !ok {
			missingConst = append(missingConst, c.envKey)
			continue
		}
		regVal, err := toolpin.RegisteredVersionOn(c.tool, ciPlatform)
		if err != nil {
			t.Errorf("[T2c] %s 在 docs/tooling.md 中解析不出登记版本（ci.yml 用的是 %s=%s）：%v",
				c.tool, c.envKey, ciVal, err)
			continue
		}
		checked++
		if regVal != ciVal {
			mismatches = append(mismatches,
				c.tool+": ci.yml "+c.envKey+"="+ciVal+" 但 docs/tooling.md 登记 "+regVal)
		}
	}
	if len(missingConst) > 0 {
		t.Fatalf("[T2c] ci.yml 的 env 块缺少版本常量 %v（工具链版本必须固定且可核对）", missingConst)
	}
	if len(mismatches) > 0 {
		t.Fatalf("[T2c] CI 常量与登记表不一致：%v\n"+
			"要么同步 ci.yml，要么在 docs/tooling.md 登记新平台产物并实测校验", mismatches)
	}
	if checked != len(ciVersionConstants) {
		t.Fatalf("[T2c] 应核对 %d 项，实际 %d 项", len(ciVersionConstants), checked)
	}
	t.Logf("[T2c] %d 项一致：%s", checked, strings.Join([]string{
		"go=" + found["GO_VERSION"],
		"kubectl=" + found["KUBECTL_VERSION"],
		"buf=" + found["BUF_VERSION"],
		"kind=" + found["KIND_VERSION"],
	}, " "))
}
