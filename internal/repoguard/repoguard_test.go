package repoguard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRepoGuardPassesOnCleanRepo 仓库级守卫（AST 主判定 + 字面量兜底）：
// 扫描全仓非测试 Go 文件，断言无违规。
func TestRepoGuardPassesOnCleanRepo(t *testing.T) {
	root, err := RepoRoot(".")
	if err != nil {
		t.Fatal(err)
	}
	violations, err := ScanRepo(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range violations {
		t.Errorf("守卫违规：%s", v)
	}
	if len(violations) != 0 {
		t.Fatalf("仓库级守卫失败：%d 条违规", len(violations))
	}
	t.Logf("仓库级守卫通过：根目录 %s，允许文件 %v", root, AllowedHTTPFiles)
}

// TestGuardScansBothAdapterPackages 守卫覆盖范围：两个适配器包都在扫描范围内。
func TestGuardScansBothAdapterPackages(t *testing.T) {
	root, err := RepoRoot(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range AllowedHTTPFiles {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(f))); err != nil {
			t.Fatalf("允许文件不存在（守卫覆盖范围与实现不一致）：%s（%v）", f, err)
		}
	}
	for _, dir := range []string{"adapters/docker", "adapters/kubernetes"} {
		entries, err := os.ReadDir(filepath.Join(root, filepath.FromSlash(dir)))
		if err != nil {
			t.Fatalf("适配器目录不可读：%s（%v）", dir, err)
		}
		found := false
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".go") && !strings.HasSuffix(e.Name(), "_test.go") {
				found = true
			}
		}
		if !found {
			t.Fatalf("适配器包 %s 没有非测试 Go 文件（守卫覆盖不到）", dir)
		}
	}
}

// TestIsHTTPImport HTTP import 判定（前缀匹配）。
func TestIsHTTPImport(t *testing.T) {
	yes := []string{"net/http", "net/http/httptest", "k8s.io/client-go/rest", "k8s.io/client-go/kubernetes"}
	for _, p := range yes {
		if !IsHTTPImport(p) {
			t.Errorf("%s 应判为 HTTP 相关 import", p)
		}
	}
	no := []string{"net/url", "net", "encoding/json", "context", "go/ast"}
	for _, p := range no {
		if IsHTTPImport(p) {
			t.Errorf("%s 不应判为 HTTP 相关 import", p)
		}
	}
}

// TestASTGuardRejectsFixtureViolations 夹具验证 AST 守卫**本身有效**：
// 非白名单文件 import net/http、使用变量拼接路径等必须报错。
func TestASTGuardRejectsFixtureViolations(t *testing.T) {
	cases := []struct {
		name     string
		file     string
		content  string
		wantKind string
		wantLaye string
	}{
		{
			name: "非白名单文件出现出站 HTTP 调用（net/http）",
			file: "somepkg/rogue.go",
			content: `package somepkg

import "net/http"

func rogue() *http.Client { return &http.Client{} }
`,
			wantKind: "非白名单文件出现出站 HTTP 调用",
			wantLaye: "AST",
		},
		{
			name: "非白名单文件出现出站 HTTP 调用（client-go rest）",
			file: "somepkg/k8sclient.go",
			content: `package somepkg

import "k8s.io/client-go/rest"

func cfg() *rest.Config { return &rest.Config{} }
`,
			wantKind: "非白名单文件出现出站 HTTP 调用",
			wantLaye: "AST",
		},
		{
			name: "允许文件中变量拼接 URL",
			file: "adapters/docker/client.go",
			content: `package docker

import (
	"fmt"
	"net/http"
)

func (c *Client) bad(id string) (*http.Request, error) {
	path := "/containers/" + id + "/json"
	return http.NewRequest(http.MethodGet, path, nil)
}

var _ = fmt.Sprintf
`,
			wantKind: "允许文件中出现非字面量 URL 拼接",
			wantLaye: "AST",
		},
		{
			name: "字面量层兜底：写方法",
			file: "somepkg/write.go",
			content: `package somepkg

const m = "POST"
`,
			wantKind: "禁止的写方法",
			wantLaye: "字面量",
		},
		{
			name: "字面量层兜底：越界路径",
			file: "somepkg/paths.go",
			content: `package somepkg

const createPath = "/containers/create"
`,
			wantKind: "禁止的路径字面量",
			wantLaye: "字面量",
		},
		{
			name: "字面量层兜底：secrets 路径",
			file: "somepkg/k8s.go",
			content: `package somepkg

const secretsPath = "/api/v1/secrets"
`,
			wantKind: "禁止的路径字面量",
			wantLaye: "字面量",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "go.work"), []byte("go 1.27\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, filepath.FromSlash(tc.file))
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(tc.content), 0o644); err != nil {
				t.Fatal(err)
			}

			violations, err := ScanRepo(root)
			if err != nil {
				t.Fatal(err)
			}
			if len(violations) == 0 {
				t.Fatal("守卫必须报出违规（夹具证明守卫本身有效）")
			}
			hit := false
			for _, v := range violations {
				if v.Kind == tc.wantKind && v.Layer == tc.wantLaye {
					hit = true
				}
			}
			if !hit {
				t.Fatalf("应报出 [%s] %q 类型违规，实际 %v", tc.wantLaye, tc.wantKind, violations)
			}
		})
	}
}

// TestGuardAllowsWhitelistedFileWithWhitelistPathBuilder 允许文件使用白名单
// 路径构造函数（fmt.Sprintf）时不报错——守卫不误报合法实现。
func TestGuardAllowsWhitelistedFileWithWhitelistPathBuilder(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.work"), []byte("go 1.27\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "adapters", "docker")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	content := `package docker

import (
	"fmt"
	"net/http"
)

// containerInspectPath 白名单路径构造函数（唯一路径来源）。
func containerInspectPath(id string) string {
	return fmt.Sprintf("/containers/%s/json", id)
}

func (c *Client) get(id string) (*http.Request, error) {
	return http.NewRequest(http.MethodGet, containerInspectPath(id), nil)
}
`
	if err := os.WriteFile(filepath.Join(dir, "client.go"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	violations, err := ScanRepo(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(violations) != 0 {
		t.Fatalf("白名单文件的白名单路径构造函数不应报错：%v", violations)
	}
}

// TestAllowedFilesUseGETOnly 允许文件内只允许 GET（字面量层定向检查）。
func TestAllowedFilesUseGETOnly(t *testing.T) {
	root, err := RepoRoot(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range AllowedHTTPFiles {
		violations, err := ScanFileForMethods(filepath.Join(root, filepath.FromSlash(f)))
		if err != nil {
			t.Fatal(err)
		}
		if len(violations) != 0 {
			t.Fatalf("允许文件 %s 出现写方法：%v", f, violations)
		}
	}
}

// TestAllowedFilesUsePathBuilders 允许文件不得直接拼接路径：
// 定向检查两个客户端文件的 AST（与全仓扫描同一判定）。
func TestAllowedFilesUsePathBuilders(t *testing.T) {
	root, err := RepoRoot(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range AllowedHTTPFiles {
		path := filepath.Join(root, filepath.FromSlash(f))
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		violations, err := scanAST(f, data, true, false)
		if err != nil {
			t.Fatal(err)
		}
		if len(violations) != 0 {
			t.Fatalf("允许文件 %s 不得出现 URL 拼接：%v", f, violations)
		}
	}
}

// TestASTGuardAllowsInboundHTTPServer 入站（服务端）HTTP 用法放行：
// 本仓库的告警入口需要监听 HTTP；出站调用仍被禁止（见下一条用例）。
// 说明：H1 裁决字面表述与 A1 冲突，此处按"出站/入站"细分，已作为待确认项上报。
func TestASTGuardAllowsInboundHTTPServer(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.work"), []byte("go 1.27\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "alerts", "internal", "httpapi")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	content := `package httpapi

import (
	"net/http"
)

// 仅入站：监听与处理请求，不构造任何出站请求。
func Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/alerts", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "只接受 POST", http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	})
	return mux
}
`
	if err := os.WriteFile(filepath.Join(dir, "server.go"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	violations, err := ScanRepo(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(violations) != 0 {
		t.Fatalf("仅入站的服务端用法不应报错：%v", violations)
	}
}

// TestASTGuardRejectsInboundFileWithOutboundCall 同一入站文件里夹带出站调用必须失败
// （"顺手发个请求"是典型绕过路径）。
func TestASTGuardRejectsInboundFileWithOutboundCall(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.work"), []byte("go 1.27\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "alerts", "internal", "httpapi")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	content := `package httpapi

import (
	"net/http"
)

func Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/x", func(w http.ResponseWriter, _ *http.Request) {
		resp, _ := http.Get("http://example.invalid/")
		_ = resp
	})
	return mux
}
`
	if err := os.WriteFile(filepath.Join(dir, "server.go"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	violations, err := ScanRepo(root)
	if err != nil {
		t.Fatal(err)
	}
	hit := false
	for _, v := range violations {
		if v.Kind == "非白名单文件出现出站 HTTP 调用" {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("入站文件中的出站调用必须被拒绝：%v", violations)
	}
}

// TestASTGuardRejectsNonGETInAllowedFile 允许文件内出现非 GET 方法必须失败
// （AST 层检查方法实参，强于字面量匹配）。
func TestASTGuardRejectsNonGETInAllowedFile(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.work"), []byte("go 1.27\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "adapters", "docker")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	content := `package docker

import (
	"net/http"
)

func (c *Client) del(url string) (*http.Request, error) {
	return http.NewRequest(http.MethodDelete, url, nil)
}
`
	if err := os.WriteFile(filepath.Join(dir, "client.go"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	violations, err := ScanRepo(root)
	if err != nil {
		t.Fatal(err)
	}
	hit := false
	for _, v := range violations {
		if v.Kind == "允许文件内出现非 GET 方法" {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("允许文件内的非 GET 方法必须被拒绝：%v", violations)
	}
}

// —— 第十五轮 R1：入站允许文件登记 ——

// TestInboundAllowlistIsExplicit 入站允许列表必须显式登记且只含告警入口的 HTTP 层。
func TestInboundAllowlistIsExplicit(t *testing.T) {
	want := []string{"alerts/internal/httpapi/server.go"}
	if len(AllowedInboundHTTPFiles) != len(want) {
		t.Fatalf("入站允许列表应恰好 %d 项，实际 %v", len(want), AllowedInboundHTTPFiles)
	}
	for i, f := range want {
		if AllowedInboundHTTPFiles[i] != f {
			t.Fatalf("入站允许列表第 %d 项应为 %s，实际 %s", i, f, AllowedInboundHTTPFiles[i])
		}
	}
	// 入站允许文件必须真实存在（登记与实现一致）。
	root, err := RepoRoot(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range AllowedInboundHTTPFiles {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(f))); err != nil {
			t.Fatalf("入站允许文件不存在：%s（%v）", f, err)
		}
	}
}

// TestInboundSymbolsRejectedInUnregisteredFile（R1 ①）
// 入站符号出现在未登记文件中必须失败。
func TestInboundSymbolsRejectedInUnregisteredFile(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.work"), []byte("go 1.27\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "somepkg")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	content := `package somepkg

import (
	"net/http"
)

// 未登记文件里偷偷起一个监听端口：必须被守卫拒绝。
func Serve() {
	srv := &http.Server{Addr: ":9999"}
	_ = srv
	http.HandleFunc("/x", func(_ http.ResponseWriter, _ *http.Request) {})
	_ = http.ListenAndServe(":9999", nil)
}
`
	if err := os.WriteFile(filepath.Join(dir, "rogue_server.go"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	violations, err := ScanRepo(root)
	if err != nil {
		t.Fatal(err)
	}
	hit := false
	for _, v := range violations {
		if v.Kind == "未登记文件出现入站 HTTP 符号" {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("未登记文件的入站符号必须被拒绝：%v", violations)
	}
}

// TestInboundSymbolsAllowedInRegisteredFile（R1 ②）
// 入站允许文件中的入站符号通过。
func TestInboundSymbolsAllowedInRegisteredFile(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.work"), []byte("go 1.27\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "alerts", "internal", "httpapi")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	content := `package httpapi

import (
	"net/http"
)

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/alerts", s.handleAlert)
	return mux
}

func Listen(addr string, h http.Handler) error {
	srv := &http.Server{Addr: addr, Handler: h}
	return srv.ListenAndServe()
}
`
	if err := os.WriteFile(filepath.Join(dir, "server.go"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	violations, err := ScanRepo(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(violations) != 0 {
		t.Fatalf("入站允许文件的入站符号应通过：%v", violations)
	}
}

// TestOutboundSymbolsRejectedInInboundAllowedFile（R1 ③）
// 入站允许文件中出现出站符号必须失败。
func TestOutboundSymbolsRejectedInInboundAllowedFile(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.work"), []byte("go 1.27\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "alerts", "internal", "httpapi")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	content := `package httpapi

import (
	"net/http"
)

func Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/x", func(w http.ResponseWriter, _ *http.Request) {
		resp, _ := http.Get("http://example.invalid/")
		_ = resp
	})
	return mux
}
`
	if err := os.WriteFile(filepath.Join(dir, "server.go"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	violations, err := ScanRepo(root)
	if err != nil {
		t.Fatal(err)
	}
	hit := false
	for _, v := range violations {
		if v.Kind == "非白名单文件出现出站 HTTP 调用" {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("入站允许文件中的出站符号必须被拒绝：%v", violations)
	}
}
