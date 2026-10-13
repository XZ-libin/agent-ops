// Package repoguard 提供**仓库级**只读守卫（第十三轮 F2 建立，第十四轮 H1 升级为
// AST 判定）。
//
// 两层判定：
//
//	第一层（AST，主判定）：用 go/parser + go/ast 解析全仓非测试 Go 文件的 import
//	  与调用表达式：
//	    - 禁止 net/http、k8s.io/client-go/...、rest 客户端等 HTTP 相关包出现在
//	      允许文件之外；
//	    - 允许文件中禁止"非字面量 URL 拼接"（请求路径必须来自白名单函数或字面量）。
//	第二层（字面量，兜底）：沿用第十三轮的文本扫描，禁止写方法常量/字面量与
//	  越界路径字面量。
//
// 允许文件（唯一出口）：
//
//	adapters/docker/client.go
//	adapters/kubernetes/client.go
package repoguard

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// AllowedHTTPFiles 允许出现后端 HTTP 调用的文件（相对仓库根的斜杠路径）。
var AllowedHTTPFiles = []string{
	"adapters/docker/client.go",
	"adapters/kubernetes/client.go",
	// 第十九轮 A1：OIDC 生产的 JWKS 拉取。该文件只发 GET、不做 URL 拼接，
	// 且只返回公钥集合（不含任何私钥或凭据）。
	"gateway/internal/grpcwire/jwks.go",
}

// AllowedInboundHTTPFiles 允许使用**入站**（服务端）HTTP 符号的文件（第十五轮 R1）。
//
// 入站规则：`http.Server`/`http.ServeMux`/`http.HandleFunc`/`http.Handle`/
// `http.ListenAndServe` 等入站符号只允许出现在下列文件中；
// 其他文件出现入站符号一律失败（fail-closed）。
// 入站允许文件同样受**出站**规则约束：不得出现任何出站调用。
var AllowedInboundHTTPFiles = []string{
	"alerts/internal/httpapi/server.go",
}

// AllowedMethods 白名单文件内允许的 HTTP 方法（只读）。
var AllowedMethods = []string{"GET"}

// ForbiddenHTTPImports 禁止出现在允许文件之外的 HTTP 相关 import 路径
// （前缀匹配）。
var ForbiddenHTTPImports = []string{
	"net/http",
	"net/http/",
	"k8s.io/client-go",
	"k8s.io/apimachinery/pkg/util/net",
	"github.com/go-resty/resty",
	"github.com/hashicorp/go-retryablehttp",
	"gopkg.in/resty",
}

// ForbiddenWriteMethods 全仓禁止出现的写方法**原始字符串字面量**与出站写调用
// （第二层兜底；符号级判定由 AST 层负责，见 outboundHTTPSelectors）。
var ForbiddenWriteMethods = []string{
	`"POST"`, `"PUT"`, `"DELETE"`, `"PATCH"`,
	"http.Post(", "http.PostForm(",
}

// outboundHTTPSelectors 出站 HTTP 调用的符号（AST 层）：
// 出现在允许文件之外即违规——即使某个包只是"顺手"发一个请求。
var outboundHTTPSelectors = []string{
	"http.NewRequest", "http.NewRequestWithContext", "http.Client",
	"http.Transport", "http.DefaultClient", "http.Get",
	"http.Head", "http.Post", "http.PostForm", "http.Do",
	"clientcmd", "rest.Config", "rest.RESTClient", "kubernetes.NewForConfig",
}

// serverHTTPSelectors 入站（服务端）HTTP 符号：仅这些用法时，
// 非允许文件可以 import net/http（本仓库的告警入口需要监听 HTTP）。
//
// 说明（第十四轮）：H1 裁决的字面表述为"net/http 不得出现在允许文件之外"，
// 但 A1 要求新增 HTTP 接收端点——两者冲突。此处按"出站/入站"细分：
// 出站调用一律禁止在允许文件之外出现；入站服务端用法放行。
// 该细分已作为待确认项写入报告与 ADR-013。
var serverHTTPSelectors = []string{
	"http.Server", "http.Handler", "http.HandlerFunc", "http.NewServeMux",
	"http.ListenAndServe", "http.ResponseWriter", "http.Error",
	"http.Status", "http.Request", "http.MethodPost", "http.MethodGet",
}

// inboundHTTPSelectors 入站**端点注册/监听**符号（第十五轮 R1 明确列举）：
// 只允许出现在 AllowedInboundHTTPFiles 中——这些符号才真正把端口暴露出去。
var inboundHTTPSelectors = []string{
	"http.Server", "http.ServeMux", "http.NewServeMux",
	"http.HandleFunc", "http.Handle", "http.ListenAndServe",
}

// ForbiddenPathLiterals 全仓禁止出现的写/敏感路径字面量
// （Docker 与 Kubernetes 两侧的越界端点）。
// 一律使用**带引号**的形式，避免与注释中的说明文字、以及
// internal/exec 这类合法导入路径产生误报。
var ForbiddenPathLiterals = []string{
	`"/containers/create"`,
	`"/containers/start"`,
	`"/containers/stop"`,
	`"/containers/kill"`,
	`"/containers/restart"`,
	`"/containers/exec"`,
	`"/exec"`,
	`"/images/create"`,
	`"/build"`,
	`"/secrets"`,
	`"/services"`,
	`"/nodes"`,
	`"/api/v1/secrets"`,
	`"serviceaccounts"`,
	`"portforward"`,
	`"pods/log"`,
	`"pods/exec"`,
}

// ExemptFiles 守卫定义文件自身（包含被禁字面量清单），不参与字面量扫描。
var ExemptFiles = []string{
	"internal/repoguard/repoguard.go",
}

// Violation 一条守卫违规。
type Violation struct {
	File   string // 相对仓库根路径
	Layer  string // AST / 字面量
	Kind   string // 违规类型
	Detail string // 具体内容
}

func (v Violation) String() string {
	return fmt.Sprintf("[%s] %s：%s（%s）", v.Layer, v.File, v.Kind, v.Detail)
}

// ScanRepo 扫描仓库（root 为仓库根目录）内的全部非测试 Go 文件。
func ScanRepo(root string) ([]Violation, error) {
	allowed := make(map[string]bool, len(AllowedHTTPFiles))
	for _, f := range AllowedHTTPFiles {
		allowed[f] = true
	}
	exempt := make(map[string]bool, len(ExemptFiles))
	for _, f := range ExemptFiles {
		exempt[f] = true
	}
	inboundAllowed := make(map[string]bool, len(AllowedInboundHTTPFiles))
	for _, f := range AllowedInboundHTTPFiles {
		inboundAllowed[f] = true
	}

	var violations []Violation
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", ".workbuddy-ai", "node_modules", ".gen-check", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		if strings.HasPrefix(rel, "contract/gen/") {
			return nil // 生成代码不参与扫描
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		if exempt[rel] {
			return nil
		}

		// 第一层：AST 判定（import 与 URL 拼接）。
		astViolations, aerr := scanAST(rel, data, allowed[rel], inboundAllowed[rel])
		if aerr != nil {
			return fmt.Errorf("repoguard：解析 %s 失败：%w", rel, aerr)
		}
		violations = append(violations, astViolations...)

		// 第二层：字面量兜底。
		violations = append(violations, scanLiterals(rel, string(data))...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(violations, func(i, j int) bool {
		if violations[i].File != violations[j].File {
			return violations[i].File < violations[j].File
		}
		return violations[i].Detail < violations[j].Detail
	})
	return violations, nil
}

// scanAST 对单个文件做 AST 判定。
func scanAST(rel string, data []byte, isAllowed, isInboundAllowed bool) ([]Violation, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, rel, data, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	var violations []Violation

	// 收集文件内的 selector（pkg.Symbol）用法。
	selectors := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); ok {
			selectors[id.Name+"."+sel.Sel.Name] = true
		}
		return true
	})

	// 1) import 判定。
	for _, imp := range f.Imports {
		p, uerr := strconv.Unquote(imp.Path.Value)
		if uerr != nil {
			continue
		}
		if !IsHTTPImport(p) {
			continue
		}
		if isAllowed {
			continue
		}
		// 非出站允许文件：出站调用一律违规。
		if hasOutboundHTTP(selectors) {
			violations = append(violations, Violation{
				File: rel, Layer: "AST", Kind: "非白名单文件出现出站 HTTP 调用",
				Detail: p + "（" + firstOutbound(selectors) + "）",
			})
			continue
		}
		// 入站符号：只允许出现在登记过的入站允许文件（R1）。
		if hasInboundHTTP(selectors) {
			if !isInboundAllowed {
				violations = append(violations, Violation{
					File: rel, Layer: "AST", Kind: "未登记文件出现入站 HTTP 符号",
					Detail: p + "（" + firstInbound(selectors) + "）",
				})
			}
			continue
		}
		if !hasServerHTTP(selectors) {
			// 既非入站也非出站：无法判定用途 → fail-closed 拒绝。
			violations = append(violations, Violation{
				File: rel, Layer: "AST", Kind: "非白名单文件 import 了 HTTP 相关包且用途不明",
				Detail: p,
			})
		}
	}

	// 2) 允许文件内：禁止"非字面量 URL 拼接"，且方法参数只能是 GET。
	if isAllowed {
		violations = append(violations, scanURLConcatenation(fset, rel, f)...)
		violations = append(violations, scanRequestMethods(fset, rel, f)...)
	}
	return violations, nil
}

// hasOutboundHTTP 判定 selector 集合是否含出站 HTTP 调用。
func hasOutboundHTTP(selectors map[string]bool) bool {
	for _, sym := range outboundHTTPSelectors {
		for sel := range selectors {
			if sel == sym || strings.HasPrefix(sel, sym+".") || strings.HasPrefix(sel, sym) {
				return true
			}
		}
	}
	return false
}

// firstOutbound 返回首个命中的出站符号（用于错误详情）。
func firstOutbound(selectors map[string]bool) string {
	for _, sym := range outboundHTTPSelectors {
		for sel := range selectors {
			if strings.HasPrefix(sel, sym) {
				return sel
			}
		}
	}
	return ""
}

// hasInboundHTTP 判定 selector 集合是否含入站端点注册/监听符号。
func hasInboundHTTP(selectors map[string]bool) bool {
	for _, sym := range inboundHTTPSelectors {
		for sel := range selectors {
			if sel == sym || strings.HasPrefix(sel, sym+".") {
				return true
			}
		}
	}
	return false
}

// firstInbound 返回首个命中的入站符号（用于错误详情）。
func firstInbound(selectors map[string]bool) string {
	for _, sym := range inboundHTTPSelectors {
		for sel := range selectors {
			if sel == sym || strings.HasPrefix(sel, sym+".") {
				return sel
			}
		}
	}
	return ""
}

// hasServerHTTP 判定 selector 集合是否含入站（服务端）HTTP 用法。
func hasServerHTTP(selectors map[string]bool) bool {
	for _, sym := range serverHTTPSelectors {
		for sel := range selectors {
			if strings.HasPrefix(sel, sym) {
				return true
			}
		}
	}
	return false
}

// scanRequestMethods 检查允许文件内的请求方法：只允许 GET。
// 判定 http.NewRequest / http.NewRequestWithContext 的方法实参，
// 以及 http.Post / http.PostForm 等出站写调用。
func scanRequestMethods(fset *token.FileSet, rel string, f *ast.File) []Violation {
	var violations []Violation
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok || id.Name != "http" {
			return true
		}
		switch sel.Sel.Name {
		case "Post", "PostForm":
			violations = append(violations, Violation{
				File: rel, Layer: "AST", Kind: "允许文件内出现非 GET 调用",
				Detail: fmt.Sprintf("%s:%d http.%s", rel, fset.Position(call.Pos()).Line, sel.Sel.Name),
			})
		case "NewRequest", "NewRequestWithContext":
			idx := 0
			if sel.Sel.Name == "NewRequestWithContext" {
				idx = 1
			}
			if len(call.Args) <= idx {
				return true
			}
			if !isGetMethod(call.Args[idx]) {
				violations = append(violations, Violation{
					File: rel, Layer: "AST", Kind: "允许文件内出现非 GET 方法",
					Detail: fmt.Sprintf("%s:%d", rel, fset.Position(call.Pos()).Line),
				})
			}
		}
		return true
	})
	return violations
}

// isGetMethod 判定方法实参是否为 GET（http.MethodGet 或字面量 "GET"）。
func isGetMethod(e ast.Expr) bool {
	switch v := e.(type) {
	case *ast.SelectorExpr:
		return v.Sel.Name == "MethodGet"
	case *ast.BasicLit:
		if v.Kind == token.STRING {
			s, err := strconv.Unquote(v.Value)
			return err == nil && s == "GET"
		}
	}
	return false
}

// IsHTTPImport 判定 import 路径是否为 HTTP 相关包（前缀匹配）。
func IsHTTPImport(p string) bool {
	for _, f := range ForbiddenHTTPImports {
		if p == f || strings.HasPrefix(p, f) {
			return true
		}
	}
	return false
}

// scanURLConcatenation 检查允许文件中的字符串拼接：
// 请求路径必须来自白名单函数或字面量，禁止"路径字面量片段 + 非字面量"的混合拼接
// （变量拼接可以绕过白名单判定）。
func scanURLConcatenation(fset *token.FileSet, rel string, f *ast.File) []Violation {
	var violations []Violation
	ast.Inspect(f, func(n ast.Node) bool {
		bin, ok := n.(*ast.BinaryExpr)
		if !ok || bin.Op != token.ADD {
			return true
		}
		hasPathLiteral, hasNonLiteral := false, false
		ast.Inspect(bin, func(inner ast.Node) bool {
			switch v := inner.(type) {
			case *ast.BasicLit:
				if v.Kind == token.STRING {
					if s, uerr := strconv.Unquote(v.Value); uerr == nil && strings.HasPrefix(s, "/") {
						hasPathLiteral = true
					}
				}
			case *ast.Ident, *ast.CallExpr, *ast.SelectorExpr, *ast.IndexExpr:
				hasNonLiteral = true
			}
			return true
		})
		if hasPathLiteral && hasNonLiteral {
			violations = append(violations, Violation{
				File: rel, Layer: "AST", Kind: "允许文件中出现非字面量 URL 拼接",
				Detail: fmt.Sprintf("%s:%d", rel, fset.Position(bin.Pos()).Line),
			})
		}
		return true
	})
	return violations
}

// scanLiterals 第二层：文本字面量兜底扫描。
func scanLiterals(rel, content string) []Violation {
	var violations []Violation
	for _, bad := range ForbiddenWriteMethods {
		if strings.Contains(content, bad) {
			violations = append(violations, Violation{
				File: rel, Layer: "字面量", Kind: "禁止的写方法", Detail: bad,
			})
		}
	}
	for _, bad := range ForbiddenPathLiterals {
		if strings.Contains(content, bad) {
			violations = append(violations, Violation{
				File: rel, Layer: "字面量", Kind: "禁止的路径字面量", Detail: bad,
			})
		}
	}
	return violations
}

// ScanFileForMethods 校验单个白名单文件只使用允许的方法（GET）。
func ScanFileForMethods(path string) ([]Violation, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var violations []Violation
	for _, bad := range ForbiddenWriteMethods {
		if strings.Contains(string(data), bad) {
			violations = append(violations, Violation{
				File: filepath.ToSlash(path), Layer: "字面量",
				Kind: "白名单文件内出现写方法", Detail: bad,
			})
		}
	}
	return violations, nil
}

// RepoRoot 从 start 目录向上寻找仓库根（含 go.work 的目录）。
func RepoRoot(start string) (string, error) {
	dir, err := filepath.Abs(start)
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.work")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("repoguard：未找到仓库根（含 go.work 的目录），起点 %s", start)
		}
		dir = parent
	}
}
