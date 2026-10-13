package repoguard

// 第二十六轮 T4：模块路径守卫（两条，只收紧不放宽）。
//
// 背景：本仓库长期用占位符组织名（`github.com/<ORG>/...`）作为 Go 模块路径。
// 决定（2026-10-13）：模块路径 = 仓库真实位置 `github.com/XZ-libin/agent-ops`。
// 占位符一旦残留，会出现"本地能编译、别人 clone 下来 import 解析不到"的裂缝，
// 而且 `go.mod` 里的模块名与远端仓库不一致时，任何外部消费方都会踩空。
//
// 两条守卫的分工：
//  1. TestModulePathIsRepositoryPath —— 正向：每个 go.mod 的 module 行都必须落在
//     真实仓库路径下（顺带证明根模块存在，防止 walk 空转导致"零命中=通过"的假阳性）；
//  2. TestNoOrgPlaceholderOutsideDocs —— 反向：可编译/可构建的文本里不得再出现占位符。
//
// 二者都只做文件扫描，不执行任何二进制、不联网。

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// modulePathPrefix 模块路径前缀（= 仓库真实位置）。
const modulePathPrefix = "github.com/XZ-libin/agent-ops"

// orgPlaceholder 历史占位符路径前缀（不得出现在代码/构建文件里）。
//
// 用拼接构造：本文件自身也在扫描范围内，写成字面量会立即命中自己的守卫
// （先例见 ciworkflow_test.go 的 forbiddenCIKeys —— 禁用键同样用拼接表达）。
var orgPlaceholder = "github.com/" + "ORG"

// walkSkipDirs 扫描时跳过的目录（非源码或体量巨大）。
var walkSkipDirs = map[string]bool{
	".git": true, ".workbuddy-ai": true, "node_modules": true,
	".venv": true, "__pycache__": true, ".gen-check": true, ".tools": true,
}

// moduleLine 解析 go.mod 的 module 行。
func moduleLine(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	for _, ln := range strings.Split(string(raw), "\n") {
		ln = strings.TrimSpace(ln)
		if strings.HasPrefix(ln, "module ") {
			return strings.TrimSpace(strings.TrimPrefix(ln, "module")), nil
		}
	}
	return "", nil
}

func TestModulePathIsRepositoryPath(t *testing.T) {
	root := repoRoot(t)
	var mods []string
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if walkSkipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() == "go.mod" {
			mods = append(mods, p)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("遍历 go.mod 失败：%v", err)
	}
	// 防"零命中即通过"：go.work 声明了 7 个模块（含根模块 `.`）。
	if len(mods) < 7 {
		t.Fatalf("只找到 %d 个 go.mod（go.work 声明 7 个模块），守卫实际没在校验什么", len(mods))
	}
	var bad []string
	for _, p := range mods {
		line, err := moduleLine(p)
		if err != nil {
			t.Fatalf("读取 %s 失败：%v", p, err)
		}
		if line == "" {
			bad = append(bad, filepath.Base(filepath.Dir(p))+"/go.mod: 没有 module 行")
			continue
		}
		if line != modulePathPrefix && !strings.HasPrefix(line, modulePathPrefix+"/") {
			bad = append(bad, relTo(root, p)+": module = "+line)
		}
	}
	if len(bad) > 0 {
		t.Fatalf("[模块路径] 以下 go.mod 不在真实仓库路径 %s 下：%v", modulePathPrefix, bad)
	}
	// 根模块必须正好等于仓库路径（`.`）。
	rootLine, err := moduleLine(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatalf("读取根 go.mod 失败：%v", err)
	}
	if rootLine != modulePathPrefix {
		t.Fatalf("根模块应为 %s，实际 %s", modulePathPrefix, rootLine)
	}
	t.Logf("[模块路径] %d 个 go.mod 全部以 %s 为前缀，根模块 = %s",
		len(mods), modulePathPrefix, rootLine)
}

// scanExts T4 反向守卫覆盖的文件类型（可编译/可构建的文本）。
var scanExts = map[string]bool{
	".go": true, ".proto": true, ".mod": true, ".work": true,
	".sh": true, ".yaml": true, ".yml": true,
}

func TestNoOrgPlaceholderOutsideDocs(t *testing.T) {
	root := repoRoot(t)
	var hits []string
	checked := 0
	byExt := map[string]int{}
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// 排除**仓库根的 docs/**：历史 ADR 与运维文档是当时的决策记录，
			// 本轮明文规定不得改写（硬性约束 12）。里面的占位符组织名是叙述性引用，
			// 不是可解析的导入路径，改了反而破坏 ADR 的时间线价值。
			// 只按仓库根相对路径判定，避免任意层级的同名目录被顺手跳过。
			if walkSkipDirs[d.Name()] {
				return filepath.SkipDir
			}
			if r, _ := filepath.Rel(root, p); filepath.ToSlash(r) == "docs" {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		ok := scanExts[filepath.Ext(name)]
		if !ok && (name == "Makefile" || strings.HasPrefix(name, "makefile")) {
			ok = true
		}
		if !ok {
			return nil
		}
		raw, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		checked++
		byExt[filepath.Ext(name)]++
		if i := strings.Index(string(raw), orgPlaceholder); i >= 0 {
			first := strings.Count(string(raw[:i]), "\n") + 1
			hits = append(hits, relTo(root, p)+":"+strconv.Itoa(first))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("扫描失败：%v", err)
	}
	// 覆盖面自证（防"扫了个空就说通过"）：第二十六轮实测扫描面约 199 个文件，
	// 构成为 .go 173、.yaml/.yml 10、.proto 7、go.mod 7、go.work 1、Makefile 1。
	// 断言按**类别下限**而非总数上限，删文件不会误伤，但任何一类整体消失一定会失败。
	if byExt[".mod"] != 7 {
		t.Fatalf("[占位符] 扫到 %d 个 go.mod，应为 7 个（go.work 声明的模块数）", byExt[".mod"])
	}
	if byExt[".proto"] < 7 {
		t.Fatalf("[占位符] 只扫到 %d 个 .proto，覆盖面异常", byExt[".proto"])
	}
	if byExt[".go"] < 150 {
		t.Fatalf("[占位符] 只扫到 %d 个 .go，覆盖面异常（约 173 个）", byExt[".go"])
	}
	if checked < 190 {
		t.Fatalf("[占位符] 只扫描了 %d 个文件，覆盖面异常（守卫可能失效）", checked)
	}
	if len(hits) > 0 {
		t.Fatalf("[占位符] %d 个文件仍含 %s（docs/ 之外的可编译文本一律不允许）：%v",
			len(hits), orgPlaceholder, hits)
	}
	t.Logf("[占位符] 已扫描 %d 个可编译/构建文件（.go %d、.proto %d、.mod %d、.yaml %d），无占位符残留"+
		"（docs/ 按约束 12 排除）", checked, byExt[".go"], byExt[".proto"], byExt[".mod"],
		byExt[".yaml"]+byExt[".yml"])
}

// relTo 相对仓库根的路径（日志可读性）。
func relTo(root, p string) string {
	rel, err := filepath.Rel(root, p)
	if err != nil {
		return p
	}
	return filepath.ToSlash(rel)
}
