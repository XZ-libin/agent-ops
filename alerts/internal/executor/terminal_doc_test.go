package executor

// 终态运维文档一致性测试（第二十轮 O4）。
//
// 目的：把 docs/ops/terminal-states.md 与**代码中的终态常量**绑在一起——
// 文档漏写一个终态、或写了代码里不存在的终态，测试即失败。
// 这样"语义切换（partial / not_executed）后文档没跟着改"不会静默发生。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// terminalStatesDoc 运维文档相对仓库根的路径。
const terminalStatesDoc = "docs/ops/terminal-states.md"

// TestTerminalStatesDocMatchesCode（O4）文档必须覆盖且仅覆盖代码里的终态。
func TestTerminalStatesDocMatchesCode(t *testing.T) {
	doc := readTerminalDoc(t)
	states := TerminalPlanStates()
	if len(states) == 0 {
		t.Fatal("TerminalPlanStates() 不得为空")
	}

	// ① 每个终态必须在文档中出现（以行内代码 `state` 形式）。
	for _, st := range states {
		if !strings.Contains(doc, "`"+st+"`") {
			t.Errorf("[O4] 文档缺少终态 %q（`%s`）", st, st)
		}
	}

	// ② 文档不得把中间态当成终态（终态表里不得出现 running / planned / no_rule）。
	terminalTable := sectionBetween(doc, "## 1. 终态一览", "### 非终态")
	if terminalTable == "" {
		t.Fatal("未能在文档中定位『终态一览』表")
	}
	for _, nonTerminal := range []string{PlanRunning, "planned", "no_rule"} {
		if strings.Contains(terminalTable, "`"+nonTerminal+"`") {
			t.Errorf("[O4] 终态表不得包含非终态 %q", nonTerminal)
		}
	}

	// ③ 文档不得声称代码中不存在的终态（例如旧的四态集合里的写法）。
	known := map[string]bool{}
	for _, st := range states {
		known[st] = true
	}
	for _, legacy := range []string{"succeeded", "skipped", "aborted", "cancelled"} {
		if strings.Contains(doc, "`"+legacy+"`") {
			t.Errorf("[O4] 文档出现代码中不存在的终态 %q", legacy)
		}
	}

	// ④ 每个终态在文档中必须有含义说明（PlanStateMeanings 的关键词需可对齐）。
	meanings := PlanStateMeanings()
	if len(meanings) != len(states) {
		t.Errorf("[O4] PlanStateMeanings 覆盖 %d 个终态，TerminalPlanStates 有 %d 个",
			len(meanings), len(states))
	}
	for _, st := range states {
		if strings.TrimSpace(meanings[st]) == "" {
			t.Errorf("[O4] 终态 %q 缺少含义说明", st)
		}
	}

	// ⑤ 文档必须包含告警条件与监控项清单（O4 的交付要求）。
	for _, must := range []string{"建议的告警条件", "需要同步更新的监控项", "interrupted", "no_cluster_configured"} {
		if !strings.Contains(doc, must) {
			t.Errorf("[O4] 文档缺少必需内容：%q", must)
		}
	}

	t.Logf("[O4] 文档与代码终态一致：%v（含义说明 %d 条，含告警条件与监控项清单）",
		states, len(meanings))
}

// TestTerminalStatesDocDistinguishesPartialAndNotExecuted（O4 核心）：
// 文档必须明确区分 partial（部分成功）与 not_executed（一个都没执行）——
// 这是第十九轮语义切换的下游口径要点。
func TestTerminalStatesDocDistinguishesPartialAndNotExecuted(t *testing.T) {
	doc := readTerminalDoc(t)
	for _, must := range []string{
		"部分成功",      // partial 的语义
		"一个能力都没有执行", // not_executed 的语义
		"非终态",       // running / planned / no_rule 的说明（非终态）
	} {
		if !strings.Contains(doc, must) {
			t.Errorf("[O4] 文档必须写明 %q", must)
		}
	}
	// 拆分说明必须存在（否则读者会把 not_executed 读成 partial）。
	if !strings.Contains(doc, "ADR-018") {
		t.Error("[O4] 文档必须引用 ADR-018（partial / not_executed 拆分依据）")
	}
	t.Log("[O4] 文档明确区分 partial（部分成功）与 not_executed（一个都没执行），并引用 ADR-018")
}

// readTerminalDoc 读取运维文档（从当前目录向上找到仓库根）。
func readTerminalDoc(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		cand := filepath.Join(dir, terminalStatesDoc)
		if _, serr := os.Stat(cand); serr == nil {
			raw, rerr := os.ReadFile(cand)
			if rerr != nil {
				t.Fatalf("读取 %s 失败：%v", cand, rerr)
			}
			return string(raw)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("未找到运维文档 %s（从 %s 向上查找）", terminalStatesDoc, dir)
		}
		dir = parent
	}
}

// sectionBetween 取 start 与 end 之间的文本（不含两端标记）；找不到返回空串。
func sectionBetween(doc, start, end string) string {
	i := strings.Index(doc, start)
	if i < 0 {
		return ""
	}
	rest := doc[i+len(start):]
	j := strings.Index(rest, end)
	if j < 0 {
		return rest
	}
	return rest[:j]
}
