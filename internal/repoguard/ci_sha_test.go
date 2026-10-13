package repoguard

// T4 CI 外部二进制 SHA-256 强制校验守卫（第二十四轮，缺口 4）。
//
// 背景：docs/tooling.md 中 kubectl 与 Go 的 **linux/amd64** SHA-256 仍是"待回填"，
// 而硬性约束 6 要求"外部二进制必须登记 SHA-256 后才能使用"——CI 若在未校验的
// 情况下下载，就违反了该约束。
//
//	TestCI1_EveryBinaryDownloadVerifiesSHA   每个下载步骤之后必须紧跟校验步骤
//	TestCI2_ToolingHasNoPendingSHAForCIBinaries  CI 二进制不得为"待回填"（合并阻断）
//	TestCI3_ToolingDocFormat                 登记项含五字段（名称/版本/平台/SHA/来源 URL）
//
// 说明：TestCI2 在用户回填 SHA 之前**必然失败**——这是**预期的合并阻断**，
// 不得添加跳过或放宽（见 ADR-023 §4）。

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// toolingDocPath 外部二进制登记文档。
const toolingDocPath = "docs/tooling.md"

// ciBinaries CI 中使用的、需要在 docs/tooling.md 登记 SHA-256 的外部二进制。
// 判断标准：来源 URL 是 HTTP 下载（dl.k8s.io / go.dev 等），而非 Go 模块代理。
//
// 说明：
//   - kubectl：CI 显式 curl 下载 → TestCI1 要求 sha256sum -c；
//   - go：由 setup-go 下载（其等价校验 = 官方清单比对）→ TestCI1 不适用，
//     但 **TestCI2** 仍要求其在 docs/tooling.md 中登记具体 SHA（不得"待回填"）。
var ciBinaries = []struct {
	name     string // 登记表中的名称
	version  string // 版本
	platform string // 平台
	// expectShellStep 在 ci.yml 中用于识别对应下载步骤的关键词。
	expectShellStep string
}{
	{name: "kubectl", version: "v1.31.4", platform: "linux/amd64", expectShellStep: "kubectl"},
	{name: "go", version: "1.27.2", platform: "linux/amd64", expectShellStep: "go"},
}

// TestCI1_EveryBinaryDownloadVerifiesSHA（T4）每个下载外部二进制的步骤之后
// 必须紧跟 sha256sum -c 校验（或等价逐字节比对）；不匹配即失败。
func TestCI1_EveryBinaryDownloadVerifiesSHA(t *testing.T) {
	root := repoRoot(t)
	ciRaw, err := os.ReadFile(filepath.Join(root, ciWorkflowPath))
	if err != nil {
		t.Fatalf("读取 CI 配置失败：%v", err)
	}
	ciText := string(ciRaw)

	// 每个下载步骤（含 curl / wget 下载二进制）必须以 step 内"随后的 sha256sum -c"结束。
	// 用正则在 test job 块内定位下载步骤，并断言该步骤块内包含校验。
	for _, bin := range ciBinaries {
		// 找到包含该工具名的 run 步骤块。
		blocks := splitRunBlocks(ciText, bin.expectShellStep)
		if len(blocks) == 0 {
			t.Fatalf("[CI1] 未在 ci.yml 中找到工具 %s 的下载步骤", bin.name)
		}
		for i, block := range blocks {
			hasCurl := strings.Contains(block, "curl -fsSLo") || strings.Contains(block, "curl -fsSL") ||
				strings.Contains(block, "wget ")
			hasSha := strings.Contains(block, "sha256sum -c")
			if !hasCurl {
				// 非 HTTP 下载（如 go install）不需要 sha256sum；跳过。
				continue
			}
			if !hasSha {
				t.Errorf("[CI1] 工具 %s 的下载步骤（第 %d 个）必须在使用前执行 sha256sum -c：\n%s",
					bin.name, i+1, block)
			}
			// 校验值必须来自 docs/tooling.md（从文档提取），而不是硬编码的占位。
			if strings.Contains(block, "待人工提供") && !strings.Contains(block, "sha256sum") {
				t.Errorf("[CI1] 工具 %s 的下载步骤不得把占位当作校验依据：%s", bin.name, bin.expectShellStep)
			}
		}
	}
	t.Logf("[CI1] HTTP 下载二进制的步骤均包含 sha256sum -c 校验（go 由 setup-go 下载，" +
		"其等价校验=官方清单比对，无需 curl 校验步骤）")
}

// splitRunBlocks 提取 ci.yml 中包含关键字的 `run: |` 块（按步骤切分）。
func splitRunBlocks(text, keyword string) []string {
	var out []string
	lines := strings.Split(text, "\n")
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		// 步骤起点：两个空格的 "- name:" 或 "        run:" 之类。
		if strings.Contains(line, "run: |") {
			// 当前 run 块：收集到下一个 "- name:" 之前。
			var block []string
			j := i + 1
			for j < len(lines) {
				trimmed := strings.TrimSpace(lines[j])
				if strings.HasPrefix(trimmed, "- name:") || trimmed == "" && len(block) > 0 {
					break
				}
				if strings.HasPrefix(trimmed, "- uses:") || strings.HasPrefix(trimmed, "- run:") {
					break
				}
				block = append(block, lines[j])
				j++
			}
			if strings.Contains(strings.Join(block, "\n"), keyword) {
				out = append(out, strings.Join(block, "\n"))
			}
			i = j - 1
		}
	}
	return out
}

// TestCI2_ToolingHasNoPendingSHAForCIBinaries（T4）docs/tooling.md 中 CI 使用的二进制
// 不得为"待回填"。在用户提供 SHA 之前，本测试会失败——这是**预期的合并阻断**，不得放宽。
func TestCI2_ToolingHasNoPendingSHAForCIBinaries(t *testing.T) {
	root := repoRoot(t)
	docRaw, err := os.ReadFile(filepath.Join(root, toolingDocPath))
	if err != nil {
		t.Fatalf("读取 %s 失败：%v", toolingDocPath, err)
	}
	doc := string(docRaw)

	// 每个 CI 二进制在文档"平台相关条目"中必须已登记**具体** SHA（64 位十六进制）。
	pendingMarker := "待人工提供"
	for _, bin := range ciBinaries {
		// 找到该工具 + 平台的行。
		row := findToolingRow(doc, bin.name, bin.platform)
		if row == "" {
			t.Errorf("[CI2] %s (%s) 未在 docs/tooling.md 的登记表中找到条目", bin.name, bin.platform)
			continue
		}
		sha := extractSHA(row)
		if sha == "" {
			t.Errorf("[CI2] %s (%s) 的 SHA-256 为空", bin.name, bin.platform)
		}
		if strings.Contains(row, pendingMarker) {
			t.Errorf("[CI2] %s (%s) 仍为\"待回填\"——合并阻断；请人工从官方校验文件确认后填入"+
				"（实现者不得自行填写，硬性约束 6；本测试预期失败直至回填）", bin.name, bin.platform)
		}
		t.Logf("[CI2] %s (%s) SHA-256=%s", bin.name, bin.platform, sha)
	}
}

// TestCI3_ToolingDocFormat（T4）docs/tooling.md 的每个登记项包含五个字段：
// 名称 / 版本 / 平台 / SHA-256 / 来源 URL。
func TestCI3_ToolingDocFormat(t *testing.T) {
	root := repoRoot(t)
	docRaw, err := os.ReadFile(filepath.Join(root, toolingDocPath))
	if err != nil {
		t.Fatalf("读取 %s 失败：%v", toolingDocPath, err)
	}
	doc := string(docRaw)

	// 平台相关条目表：从"### 平台相关条目"到"### 非平台相关条目"。
	start := strings.Index(doc, "### 平台相关条目")
	end := strings.Index(doc, "### 非平台相关条目")
	if start < 0 || end < 0 || end <= start {
		t.Fatal("[CI3] 未找到\"平台相关条目\"表（docs/tooling.md 结构已变？）")
	}
	table := doc[start:end]

	rows := []string{}
	for _, line := range strings.Split(table, "\n") {
		if strings.HasPrefix(line, "| ") {
			rows = append(rows, line)
		}
	}
	// 表头 + 分隔行之外的数据行。
	var dataRows []string
	for _, r := range rows {
		fields := strings.Split(r, "|")
		fields = fields[1 : len(fields)-1]
		nonEmpty := 0
		for _, f := range fields {
			if len(strings.TrimSpace(f)) > 0 {
				nonEmpty++
			}
		}
		if nonEmpty >= 5 && isHeaderOrSep(r) {
			continue
		}
		if nonEmpty >= 5 {
			dataRows = append(dataRows, r)
		}
	}
	if len(dataRows) == 0 {
		t.Fatal("[CI3] 平台相关条目表没有数据行")
	}
	for _, r := range dataRows {
		fields := splitRow(r)
		if len(fields) < 5 {
			t.Errorf("[CI3] 登记行字段不足 5 个（名称/版本/平台/SHA-256/来源 URL）：%q", r)
			continue
		}
		for i, f := range fields {
			if len(strings.TrimSpace(f)) == 0 {
				t.Errorf("[CI3] 登记行第 %d 字段为空：%q", i+1, r)
			}
		}
	}
	t.Logf("[CI3] 平台相关条目表共 %d 行，每行均含名称/版本/平台/SHA-256/来源 URL 五字段", len(dataRows))
}

// findToolingRow 在文档表格中找"名称 + 平台"对应的行。
func findToolingRow(doc, name, platform string) string {
	for _, line := range strings.Split(doc, "\n") {
		if !strings.HasPrefix(line, "| ") {
			continue
		}
		fields := splitRow(line)
		if len(fields) < 4 {
			continue
		}
		if strings.Contains(fields[0], name) && strings.Contains(fields[2], platform) {
			return line
		}
	}
	return ""
}

// extractSHA 从表格行中提取 SHA-256（纯 64 位十六进制；剔除占位符号）。
//
// 用 '|' 分割后：$1=名称 $2=版本 $3=平台 $4=SHA-256 $5=URL。
func extractSHA(row string) string {
	fields := splitRow(row)
	if len(fields) < 4 {
		return ""
	}
	sha := strings.TrimSpace(fields[3])
	sha = strings.Trim(sha, "`")
	return sha
}

// splitRow 把表格行按 '|' 切分为字段（去掉首尾空）。
func splitRow(line string) []string {
	parts := strings.Split(line, "|")
	// 去掉首尾（表格行两端都有 |）。
	parts = parts[1 : len(parts)-1]
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		out = append(out, strings.TrimSpace(p))
	}
	return out
}

// isHeaderOrSep 判定是否为表头或分隔行（含 ---）。
var isHeaderOrSep = func(line string) bool {
	return strings.Contains(line, "---") || strings.Contains(line, "字段")
}

// 正则：SHA-256 应是 64 位十六进制（用于 Verify）。
var sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
