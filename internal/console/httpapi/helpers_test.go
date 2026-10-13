package httpapi

// C4 辅助：仓库根定位、静态解析、OpenAPI/proto 读取、断言小工具。
// 这些都在**同一份测试文件集**里，不新增生产代码。

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/XZ-libin/agent-ops/internal/console"
)

// repoRootFrom 向上找到含 go.work 的目录（仓库根）。
func repoRootFrom(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 12; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.work")); err == nil {
			return dir
		}
		up := filepath.Dir(dir)
		if up == dir {
			break
		}
		dir = up
	}
	t.Fatal("未找到仓库根（go.work）")
	return ""
}

// findRouteLits 找出所有**路由登记**：
//   - `[]Route{ {Method: …}, … }` 的省略写法（元素 CompositeLit 的 Type 为 nil）；
//   - 显式 `Route{…}` 写法；
//   - 零值 `Route{}`（无字段）视为"未登记"，不参与判定。
func findRouteLits(f *ast.File) []*ast.CompositeLit {
	var out []*ast.CompositeLit
	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		if isRouteArray(lit) {
			for _, elt := range lit.Elts {
				if inner, ok := elt.(*ast.CompositeLit); ok && len(inner.Elts) > 0 {
					out = append(out, inner)
				}
			}
			return true
		}
		if isRouteType(lit.Type) && len(lit.Elts) > 0 {
			out = append(out, lit)
		}
		return true
	})
	return out
}

func isRouteArray(lit *ast.CompositeLit) bool {
	arr, ok := lit.Type.(*ast.ArrayType)
	if !ok {
		return false
	}
	return isRouteType(arr.Elt)
}

func isRouteType(e ast.Expr) bool {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name == "Route"
	case *ast.SelectorExpr:
		return t.Sel.Name == "Route"
	}
	return false
}

// findCompositeLits 找出 `Type{...}` 形式的组合字面量（含字段名省略的情况）。
func findCompositeLits(f *ast.File, typeName string) []*ast.CompositeLit {
	var out []*ast.CompositeLit
	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		switch sel := lit.Type.(type) {
		case *ast.Ident:
			if sel.Name == typeName {
				out = append(out, lit)
			}
		case *ast.SelectorExpr:
			if sel.Sel.Name == typeName {
				out = append(out, lit)
			}
		}
		return true
	})
	return out
}

func keyName(e ast.Expr) string {
	if id, ok := e.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}

func unquote(lit string) (string, bool) {
	v, err := strconv.Unquote(lit)
	return v, err == nil
}

// —— OpenAPI ——

type openAPISchema struct {
	Properties map[string]any `yaml:"properties"`
}

type openAPIDoc struct {
	Paths      map[string]map[string]any `yaml:"paths"`
	Components struct {
		Schemas map[string]openAPISchema `yaml:"schemas"`
	} `yaml:"components"`
}

func openAPIPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRootFrom(t), "openapi", "console.yaml")
}

func loadOpenAPI(t *testing.T) openAPIDoc {
	t.Helper()
	raw, err := os.ReadFile(openAPIPath(t))
	if err != nil {
		t.Fatalf("读取 openapi/console.yaml 失败：%v", err)
	}
	var doc openAPIDoc
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("解析 OpenAPI 失败：%v", err)
	}
	if len(doc.Paths) == 0 || len(doc.Components.Schemas) == 0 {
		t.Fatal("OpenAPI 解析结果为空（结构或守卫假设不符）")
	}
	return doc
}

// —— proto 文本解析 ——

// parseProtoMessages 从 .proto 里抽取 message 名 → 字段名列表（顺序保留）。
//
// 只处理本仓库契约的实际写法：`名字 = 编号;` 与 `map<..,..> 名字 = 编号;`，
// 忽略注释与 enum（enum 由 VerifyReason 单独覆盖）。
func parseProtoMessages(t *testing.T, path string) map[string][]string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取 proto 失败：%v", err)
	}
	out := map[string][]string{}
	var current string
	for _, line := range strings.Split(string(raw), "\n") {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "//") || trim == "" {
			continue
		}
		if strings.HasPrefix(trim, "message ") {
			name := strings.TrimSuffix(strings.Fields(trim)[1], "{")
			current = name
			out[name] = nil
			continue
		}
		if trim == "}" {
			current = ""
			continue
		}
		if current == "" || !strings.Contains(trim, "=") {
			continue
		}
		left := strings.TrimSpace(strings.SplitN(trim, "=", 2)[0])
		if left == "" || strings.HasPrefix(left, "reserved") || strings.HasPrefix(left, "option") {
			continue
		}
		fields := strings.Fields(left)
		name := fields[len(fields)-1]
		if !strings.Contains(name, ">") { // 排除 `map<k,v>` 这种以 > 结尾的左段
			out[current] = append(out[current], name)
			continue
		}
		// `map<string, string> payload` → 取 > 之后的最后一个 token
		after := left[strings.LastIndex(left, ">")+1:]
		after = strings.TrimSpace(after)
		if after != "" {
			out[current] = append(out[current], after)
		}
	}
	for name, fields := range out {
		if len(fields) == 0 {
			t.Errorf("proto 消息 %s 没有解析到字段", name)
		}
	}
	return out
}

func keysOf(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sortStrings(out)
	return out
}

func keysOf2(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sortStrings(out)
	return out
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// —— SQL 小工具（仅测试夹具使用）——

func quote(ident string) string { return `"` + strings.ReplaceAll(ident, `"`, `""`) + `"` }

func auditSeqSequence(table string) string { return table + "_seq_seq" }

func firstLine(stmt string) string {
	one := strings.TrimSpace(strings.Split(stmt, "\n")[0])
	if len(one) > 80 {
		return one[:80]
	}
	return one
}

// —— HTTP 断言小工具 ——

func assertEnvelope(t *testing.T, body, wantCode string) {
	t.Helper()
	var env struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(body), &env); err != nil {
		t.Fatalf("错误信封解析失败：%v（body=%s）", err, body)
	}
	if env.Error.Code != wantCode {
		t.Errorf("错误码应为 %s，实际 %s（body=%s）", wantCode, env.Error.Code, body)
	}
	// message 必须取自固定文本表，不能是内部错误串。
	found := false
	for _, fixed := range errorMessages {
		if env.Error.Message == fixed {
			found = true
		}
	}
	if !found {
		t.Errorf("message 不在固定文本表内：%q", env.Error.Message)
	}
}

// assertNoReasonLeak 401 响应不得透露失败细节。
func assertNoReasonLeak(t *testing.T, body string) {
	t.Helper()
	low := strings.ToLower(body)
	for _, leak := range []string{"expired", "kid", "issuer", "audience", "signature", "alg",
		"rsa", "token", "sub ", "subject"} {
		if strings.Contains(low, leak) {
			t.Fatalf("401 响应泄露了失败细节 %q：%s", leak, body)
		}
	}
	assertEnvelope(t, body, "unauthorized")
}

func allowedPayloadKey(k string) bool {
	for _, keys := range console.PayloadAllowlist {
		for _, want := range keys {
			if k == want {
				return true
			}
		}
	}
	return false
}

// mintValidExpired 造一个"已过期"的合法签名令牌（配合注入时钟，不用 sleep）。
func mintValidExpired(t *testing.T, k testKeys, clock *fakeClock) string {
	t.Helper()
	return "Bearer " + mint(t, k, "RS256", k.kid, map[string]any{
		"iss": fmt.Sprint(testIssuer), "aud": testAud, "sub": "operator-a",
		"exp": clock.Now().Add(-2 * time.Minute).Unix(),
	})
}
