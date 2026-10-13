// Package toolpin 把测试使用的外部命令行工具钉到 docs/tooling.md 登记的版本（第二十五轮 T2）。
//
// 为什么要它：本机 PATH 上的 kubectl 是 Docker Desktop 自带的 **v1.36.1**，而登记
// （并在 CI 中下载+校验）的是 **v1.31.4**。此前测试的定位方式是"优先 PATH"，
// 等价于**静默使用未登记版本**——测试结论对应的二进制与被保护的产物不是同一个。
//
// 规则（硬性约束 5 + T2b）：
//  1. 期望版本只能来自 `docs/tooling.md` 的登记表（按当前 GOOS/GOARCH 选平台行）；
//  2. 二进制来源按优先级：环境变量 `AGENT_OPS_KUBECTL_BIN`（显式路径）→
//     仓库内 `.tools/kubectl`（gitignore，放置已实测校验的产物）→ PATH；
//  3. 候选存在后**必须**验证 `version --client` 的 gitVersion 与登记一致；
//     不一致、找不到、解析不出 → 返回错误，由调用方 t.Fatal 明确报错，
//     **绝不退回到其他版本**，也不静默 skip。
package toolpin

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

// ToolingDocRelPath 登记表相对仓库根的路径。
const ToolingDocRelPath = "docs/tooling.md"

// KubectlBinEnv 显式指定 kubectl 路径的环境变量（优先级最高）。
const KubectlBinEnv = "AGENT_OPS_KUBECTL_BIN"

// ToolsDirName 仓库内放置"已登记并实测"的二进制的目录（.gitignore 忽略）。
const ToolsDirName = ".tools"

// ErrNotRegistered 登记表里找不到该工具的版本。
var ErrNotRegistered = errors.New("toolpin：docs/tooling.md 中未登记该工具版本")

// RepoRoot 从当前工作目录向上查找含 `docs/tooling.md` 的目录。
func RepoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for i := 0; i < 12; i++ {
		if _, err := os.Stat(filepath.Join(dir, ToolingDocRelPath)); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", fmt.Errorf("toolpin：未找到仓库根（向上 12 层未见 %s）", ToolingDocRelPath)
}

// registeredRow 登记表中一条工具记录的解析结果。
type registeredRow struct {
	name     string
	version  string
	platform string // 空 = 该行没有平台列（如"CI 使用的工具链"表）
}

// loadRows 解析 docs/tooling.md 中所有 markdown 表格行。
//
// 识别方式：以 `|` 开头、跳过分隔行（`---`）与表头行（第一个单元格为"名称"）。
// 若某行第 4 个单元格形如 `linux/amd64`，则视为"平台相关条目"表并记录平台；
// 否则视为通用登记表（版本在第 2 个单元格）。
func loadRows() ([]registeredRow, error) {
	root, err := RepoRoot()
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(filepath.Join(root, ToolingDocRelPath))
	if err != nil {
		return nil, err
	}
	var rows []registeredRow
	for _, line := range strings.Split(string(raw), "\n") {
		t := strings.TrimSpace(line)
		if !strings.HasPrefix(t, "|") {
			continue
		}
		cells := strings.Split(t, "|")
		if len(cells) < 4 {
			continue
		}
		name := normalize(cells[1])
		if name == "" || name == "名称" || strings.HasPrefix(name, "--") ||
			strings.Contains(name, "---") {
			continue
		}
		version := normalize(cells[2])
		if !looksLikeVersion(version) {
			// 非版本行（例如"使用但不由本项目下载"表：第二列是安装路径或说明文字）。
			continue
		}
		platform := ""
		if len(cells) >= 4 {
			p := normalize(cells[3])
			if isPlatform(p) {
				platform = p
			}
		}
		rows = append(rows, registeredRow{name: name, version: version, platform: platform})
	}
	return rows, nil
}

// versionPattern 认得 v1.31.4 / 1.27.2 / v0.30.0 这类版本号，
// 但**不认**路径或描述性文本（登记表之外还有"环境自带"表，其第二列是路径）。
var versionPattern = regexp.MustCompile(`^v?[0-9]+(\.[0-9]+)+([a-zA-Z0-9.+-]*)$`)

// looksLikeVersion 判断单元格是否是版本号形态。
func looksLikeVersion(s string) bool { return versionPattern.MatchString(s) }

// normalize 去掉表格单元格里常见的装饰：空白、反引号、粗体星号，以及尾部括注。
func normalize(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "`", "")
	s = strings.ReplaceAll(s, "*", "")
	// "v1.31.4 (darwin/arm64)" → "v1.31.4"
	if i := strings.IndexByte(s, ' '); i > 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// isPlatform 判断形如 linux/amd64、darwin/arm64（可带中文括注）。
func isPlatform(s string) bool {
	slash := strings.IndexByte(s, '/')
	if slash <= 0 {
		return false
	}
	osName := s[:slash]
	return osName == "linux" || osName == "darwin" || osName == "windows"
}

// RegisteredVersion 返回登记表中该工具在当前平台（GOOS/GOARCH）的版本。
func RegisteredVersion(name string) (string, error) {
	return RegisteredVersionOn(name, runtime.GOOS+"/"+runtime.GOARCH)
}

// RegisteredVersionOn 返回该工具在**指定平台**（如 `linux/amd64`）的登记版本。
//
// 只读文件，不执行任何二进制——供守卫测试比对 CI 侧常量使用。
// 优先取平台行；没有匹配平台的行时退回取该工具的任一无平台记录，
// 但要求同一工具的多条记录**版本一致**（不一致即报错，防止登记表自相矛盾）。
func RegisteredVersionOn(name, platform string) (string, error) {
	rows, err := loadRows()
	if err != nil {
		return "", err
	}
	want := platform
	var platHit, anyHit string
	seen := map[string]bool{}
	for _, r := range rows {
		if r.name != name {
			continue
		}
		if r.version == "" {
			continue
		}
		seen[r.version] = true
		if r.platform != "" {
			if r.platform == want || strings.HasPrefix(r.platform, want) {
				platHit = r.version
			}
			continue
		}
		if anyHit == "" {
			anyHit = r.version
		}
	}
	if len(seen) == 0 {
		return "", fmt.Errorf("%w：%s（平台 %s）", ErrNotRegistered, name, want)
	}
	if len(seen) > 1 {
		var vs []string
		for v := range seen {
			vs = append(vs, v)
		}
		return "", fmt.Errorf("toolpin：%s 在 docs/tooling.md 中登记了多个版本 %v（登记表自相矛盾）",
			name, vs)
	}
	if platHit != "" {
		return platHit, nil
	}
	if anyHit != "" {
		return anyHit, nil
	}
	// 只有其他平台的平台行：本机没有登记行 → 明确失败。
	return "", fmt.Errorf("%w：%s 平台 %s（登记表只有其它平台的行）", ErrNotRegistered, name, want)
}

// cand 一个候选二进制来源。
type cand struct{ src, path string }

// buildCandidates 按优先级列出候选：显式 env → 仓库 .tools/kubectl → PATH。
func buildCandidates() []cand {
	root, _ := RepoRoot() // 允许为空：此时只用 env 与 PATH
	var cands []cand
	if v := strings.TrimSpace(os.Getenv(KubectlBinEnv)); v != "" {
		cands = append(cands, cand{KubectlBinEnv, v})
	}
	if root != "" {
		cands = append(cands, cand{ToolsDirName + "/kubectl", filepath.Join(root, ToolsDirName, "kubectl")})
	}
	if p, e := exec.LookPath("kubectl"); e == nil {
		cands = append(cands, cand{"PATH", p})
	}
	return cands
}

// resolveKubectl 在候选中找出**版本与登记一致**的 kubectl。
//
// 版本不符即刻失败并返回空路径——绝不跳到下一个候选（那是"静默退回其他版本"）。
// 仅"该候选不存在/不可执行"才继续下一个来源。
func resolveKubectl(want string, cands []cand) (string, string, error) {
	var tried []string
	for _, c := range cands {
		if c.path == "" {
			continue
		}
		if _, e := os.Stat(c.path); e != nil {
			tried = append(tried, fmt.Sprintf("%s=%s（不存在）", c.src, c.path))
			continue
		}
		got, e := ClientGitVersion(c.path)
		if e != nil {
			tried = append(tried, fmt.Sprintf("%s=%s（%v）", c.src, c.path, e))
			continue
		}
		if got != want {
			return "", "", fmt.Errorf(
				"toolpin：kubectl 版本与登记不一致——登记 %s（docs/tooling.md），实际 %s（来源 %s：%s）。"+
					"禁止使用未登记版本：请设 %s 指向 %s，或把该版本放到 %s/kubectl",
				want, got, c.src, c.path, KubectlBinEnv, want, ToolsDirName)
		}
		return c.path, want, nil
	}
	return "", "", fmt.Errorf(
		"toolpin：找不到登记版本（%s）的 kubectl；已尝试：%v。"+
			"请设 %s 指向该版本，或把校验过的产物放到 %s/kubectl（参见 docs/tooling.md）",
		want, tried, KubectlBinEnv, ToolsDirName)
}

// PinnedKubectl 返回**版本与登记一致**的 kubectl 路径与版本。
//
// 失败情形都返回错误（由调用方 t.Fatal）：没有可用候选、候选不可执行、
// gitVersion 与登记不符。绝不返回"另一个版本"的路径。
func PinnedKubectl() (string, string, error) {
	want, err := RegisteredVersion("kubectl")
	if err != nil {
		return "", "", err
	}
	return resolveKubectl(want, buildCandidates())
}

// ClientGitVersion 执行 `<bin> version --client -o json` 取 gitVersion。
//
// kubectl 的输出是**嵌套**结构：`{"clientVersion":{"gitVersion":"v1.31.4",…},…}`，
// 顶层没有 gitVersion（实测 v1.31.4 与 v1.36.1 均如此）。为兼容其它工具，
// 先看 clientVersion，再退回顶层。
func ClientGitVersion(bin string) (string, error) {
	out, err := exec.Command(bin, "version", "--client", "-o", "json").Output()
	if err != nil {
		return "", fmt.Errorf("执行 %s version --client 失败：%w", bin, err)
	}
	var v struct {
		ClientVersion struct {
			GitVersion string `json:"gitVersion"`
		} `json:"clientVersion"`
		GitVersion string `json:"gitVersion"`
	}
	if err := json.Unmarshal(out, &v); err != nil {
		return "", fmt.Errorf("解析 %s 的 JSON 版本输出失败：%w", bin, err)
	}
	got := strings.TrimSpace(v.ClientVersion.GitVersion)
	if got == "" {
		got = strings.TrimSpace(v.GitVersion)
	}
	if got == "" {
		return "", fmt.Errorf("%s 未输出 gitVersion（输出 %q）", bin, strings.TrimSpace(string(out)))
	}
	return got, nil
}
