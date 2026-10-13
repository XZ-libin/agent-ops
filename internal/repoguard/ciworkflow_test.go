// CI 配置守卫（第二十轮 C1）：把"门禁不可被绕过"从约定变成**可执行断言**。
//
// 检查对象：.github/workflows/*.yml
//
//	① 不得出现 "continue on error"（连字符形式）绕过开关；
//	② residual-check job 不得使用 if 表达式跳过；
//	③ 四个独立 job 必须存在：gen-check / build / test / residual-check；
//	④ residual-check 必须真正执行 `make residual-check`；
//	⑤ 工具链版本必须固定（不得出现 go-version: "1.x" 这类浮动主版本）。
//
// 为什么放在 repoguard：本包是仓库级守卫的归属地（HTTP 边界 + 仓库结构约束），
// CI 门禁配置属于同一类"不许被静默放宽"的仓库级约束。
package repoguard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ciWorkflowPath 待检查的 workflow 文件（相对仓库根）。
const ciWorkflowPath = ".github/workflows/ci.yml"

// requiredCIJobs C1 要求的独立 job 名称。
//
// 第二十一轮裁决 1 修订：原"四个独立 job"改为**三个**——残留检查合并进 `test` job
// （GitHub 托管 runner 每个 job 环境全新，独立 job 看不到 test 的残留，形同虚设）。
// 详见 ADR-020 §1。
var requiredCIJobs = []string{"gen-check", "build", "test"}

// forbiddenCIJobs 不得再出现的独立 job（防回归：残留检查必须留在 test job 内）。
var forbiddenCIJobs = []string{"residual-check"}

// forbiddenCIKeys CI 配置中禁止出现的键/片段（连字符形式，避免被注释误伤：
// 本文件自身不写出完整字面量，按片段拼接）。
var forbiddenCIKeys = []string{
	"continue" + "-on-error",
}

// TestCIConfigGuards CI 配置守卫（C1）。
func TestCIConfigGuards(t *testing.T) {
	root := repoRoot(t)
	path := filepath.Join(root, ciWorkflowPath)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取 CI 配置失败（%s）：%v", ciWorkflowPath, err)
	}
	text := string(raw)

	// ① 禁用键。
	for _, key := range forbiddenCIKeys {
		if strings.Contains(text, key) {
			t.Errorf("[C1] CI 配置不得出现 %q（门禁不得被绕过）", key)
		}
	}

	// ③ 独立 job 必须齐备，且不得再出现独立的 residual-check job（防回归）。
	var missing []string
	for _, job := range requiredCIJobs {
		if !strings.Contains(text, "\n  "+job+":") {
			missing = append(missing, job)
		}
	}
	if len(missing) > 0 {
		t.Errorf("[C1] 缺少独立 job：%v（要求 %v）", missing, requiredCIJobs)
	}
	for _, job := range forbiddenCIJobs {
		if strings.Contains(text, "\n  "+job+":") {
			t.Errorf("[C1] 不得存在独立的 %q job：残留检查必须留在 test job 内"+
				"（独立 job 在托管 runner 上看不到 test 的残留，见 ADR-020 §1）", job)
		}
	}

	// ④ 残留检查必须真跑，且必须在 **test job 内部**（同 runner 才能看到真实遗留）。
	if !strings.Contains(text, "run: make residual-check") {
		t.Error("[C1] 必须执行 `make residual-check`")
	}
	if block := jobBlock(text, "test"); block != "" {
		if !strings.Contains(block, "run: make residual-check") {
			t.Error("[C1] `make residual-check` 必须在 test job 内执行（同一 runner 才能检出本次测试的残留）")
		}
		// ② 残留检查步骤不得用 if 跳过。
		for _, line := range strings.Split(block, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "if:") || strings.HasPrefix(trimmed, "if :") {
				t.Errorf("[C1] 残留检查所在 job 不得使用 if 跳过：%q", trimmed)
			}
		}
	} else {
		t.Error("[C1] 未能定位 test job 块")
	}

	// ⑤ 工具链版本必须固定到补丁版本（禁止 "1.27" 这类浮动写法）。
	if strings.Contains(text, `go-version: "1.27"`) || strings.Contains(text, "go-version: '1.27'") {
		t.Error("[C1] go-version 必须固定到补丁版本（如 1.27.2），不得使用浮动主版本")
	}
	if !strings.Contains(text, `go-version: ${{ env.GO_VERSION }}`) {
		t.Error("[C1] go-version 应统一引用 env.GO_VERSION（单一来源）")
	}

	t.Logf("[C1] CI 配置守卫通过：%d 个独立 job（%v）、无绕过开关、残留检查在 test job 内真跑、工具链版本固定",
		len(requiredCIJobs), requiredCIJobs)
}

// jobBlock 截取某个 job 的 YAML 文本块（从 "  <name>:" 到下一个同级 job 或文件尾）。
func jobBlock(text, job string) string {
	marker := "\n  " + job + ":"
	i := strings.Index(text, marker)
	if i < 0 {
		return ""
	}
	rest := text[i+1:]
	// 找下一个顶层 job（缩进恰好两个空格且以 ":" 结尾的行）。
	lines := strings.Split(rest, "\n")
	var out []string
	for idx, line := range lines {
		if idx > 0 && len(line) > 2 && !strings.HasPrefix(line, " ") && strings.HasSuffix(strings.TrimSpace(line), ":") {
			break
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

// repoRoot 从当前目录向上寻找含 go.work 的仓库根。
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, serr := os.Stat(filepath.Join(dir, "go.work")); serr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("未找到仓库根（含 go.work）：%s", dir)
		}
		dir = parent
	}
}
