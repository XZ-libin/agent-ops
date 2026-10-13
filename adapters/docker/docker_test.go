package docker

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	contractv1 "github.com/ORG/agent-ops/contract/gen/go/agent_ops/contract/v1"

	"github.com/ORG/agent-ops/internal/validation"
)

// —— 测试辅助 ——

// newFakeDaemon 启动一个假的 Docker Engine API（仅测试用，不接触真实守护进程）。
// handler 收到的每个请求都会记录到 seen 中，便于断言"只发 GET 白名单端点"。
func newFakeDaemon(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *[]string) {
	t.Helper()
	seen := &[]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*seen = append(*seen, r.Method+" "+r.URL.Path)
		handler(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, seen
}

// testAdapter 用假守护进程构建适配器。
func testAdapter(t *testing.T, srv *httptest.Server, opts ...Option) *Adapter {
	t.Helper()
	a, err := New(Config{Endpoint: srv.URL, Mode: ModeTest}, opts...)
	if err != nil {
		t.Fatalf("构建适配器失败：%v", err)
	}
	return a
}

// —— D1/D2：端点白名单 ——

// TestAllowedEndpointWhitelist 白名单：仅允许五个只读 GET 端点（含容器 inspect），
// 其余路径与方法一律拒绝。
func TestAllowedEndpointWhitelist(t *testing.T) {
	allowed := []struct{ method, path string }{
		{http.MethodGet, "/version"},
		{http.MethodGet, "/info"},
		{http.MethodGet, "/containers/json"},
		{http.MethodGet, "/containers/abc123/json"},
		{http.MethodGet, "/containers/2b3c4d5e6f7890abcdef/json"},
		{http.MethodGet, "/images/json"},
	}
	for _, c := range allowed {
		if err := AllowedEndpoint(c.method, c.path); err != nil {
			t.Errorf("白名单端点应放行：%s %s → %v", c.method, c.path, err)
		}
	}

	denied := []struct {
		method, path string
		reason       string
	}{
		{http.MethodPost, "/containers/create", "创建容器（写）"},
		{http.MethodPost, "/containers/abc123/start", "启动容器（写）"},
		{http.MethodPost, "/containers/abc123/stop", "停止容器（写）"},
		{http.MethodDelete, "/containers/abc123", "删除容器（写）"},
		{http.MethodDelete, "/images/abc", "删除镜像（写）"},
		{http.MethodPut, "/containers/abc123/archive", "写路径"},
		{http.MethodPatch, "/containers/abc123", "写路径"},
		{http.MethodGet, "/containers/abc123/start", "启动（GET 亦不允许）"},
		{http.MethodGet, "/containers/create", "创建（GET 亦不允许）"},
		{http.MethodGet, "/containers/abc123/logs", "未列入白名单"},
		{http.MethodGet, "/containers/abc123/top", "未列入白名单"},
		{http.MethodGet, "/secrets", "未列入白名单"},
		{http.MethodGet, "/services", "未列入白名单"},
		{http.MethodGet, "/nodes", "未列入白名单"},
		{http.MethodGet, "/_ping", "未列入白名单"},
		{http.MethodGet, "/containers/../secrets/json", "路径穿越"},
		{http.MethodGet, "/containers/abc123/json/extra", "额外路径段"},
		{http.MethodGet, "/containers/abc/../json", "路径穿越"},
		{http.MethodGet, "/images/create", "写端点"},
	}
	for _, c := range denied {
		err := AllowedEndpoint(c.method, c.path)
		if err == nil {
			t.Errorf("非白名单端点必须拒绝：%s %s（%s）", c.method, c.path, c.reason)
			continue
		}
		if c.method == http.MethodGet {
			if !errors.Is(err, ErrEndpointNotAllowed) {
				t.Errorf("%s 应报 ErrEndpointNotAllowed，实际 %v", c.path, err)
			}
			continue
		}
		if !errors.Is(err, ErrWriteMethodForbidden) {
			t.Errorf("%s %s 应报 ErrWriteMethodForbidden，实际 %v", c.method, c.path, err)
		}
	}
}

// TestAdapterNeverSendsWriteMethods 客户端只发 GET 白名单端点：
// 断言假守护进程观察到的全部请求方法均为 GET 且路径在白名单内。
func TestAdapterNeverSendsWriteMethods(t *testing.T) {
	srv, seen := newFakeDaemon(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/version":
			_, _ = w.Write([]byte(`{"Version":"29.0.0","ApiVersion":"1.45","Os":"linux","Arch":"arm64"}`))
		case "/info":
			_, _ = w.Write([]byte(`{"Containers":1,"Images":2}`))
		case "/containers/json":
			_, _ = w.Write([]byte(`[{"Id":"abc","Labels":{"agent-ops.test":"true"},"State":"running"}]`))
		case "/containers/abc/json":
			_, _ = w.Write([]byte(`{"Id":"abc","Config":{"Labels":{"agent-ops.test":"true"},"Env":["A=1"]},"State":{"Status":"running"}}`))
		case "/images/json":
			_, _ = w.Write([]byte(`[{"Id":"img1","Labels":{"agent-ops.test":"true"}}]`))
		default:
			t.Errorf("客户端请求了白名单之外的端点：%s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	a := testAdapter(t, srv)
	ctx := context.Background()

	if _, err := a.Discover(ctx, &contractv1.AssetTarget{AssetId: "ast_d1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Health(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Diagnose(ctx, nil, QuestionInfo); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Diagnose(ctx, nil, QuestionContainerList); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Diagnose(ctx, nil, QuestionContainerStatusPrefix+"abc"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Diagnose(ctx, nil, QuestionImageList); err != nil {
		t.Fatal(err)
	}
	for _, got := range *seen {
		if !strings.HasPrefix(got, "GET ") {
			t.Fatalf("只读适配器不得发送非 GET 请求：%s", got)
		}
		if err := AllowedEndpoint(strings.SplitN(got, " ", 2)[0], strings.SplitN(got, " ", 2)[1]); err != nil {
			t.Fatalf("请求端点不在白名单内：%s（%v）", got, err)
		}
	}
}

// TestSourceContainsNoWriteMethods 源码守卫（硬性约束 4）：
// 适配器非测试源码中不得出现任何写方法常量或调用。
func TestSourceContainsNoWriteMethods(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	forbidden := []string{
		"http.MethodPost", "http.MethodPut", "http.MethodDelete", "http.MethodPatch",
		`"POST"`, `"PUT"`, `"DELETE"`, `"PATCH"`,
		"NewRequestWithContext(ctx, \"POST\"", "http.Post(", "http.NewRequest(\"POST\"",
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(".", name))
		if err != nil {
			t.Fatal(err)
		}
		for _, bad := range forbidden {
			if strings.Contains(string(data), bad) {
				t.Fatalf("源码 %s 中不得出现写方法 %q（Docker 只允许白名单 GET）", name, bad)
			}
		}
	}
}

// —— D1/D2：屏蔽规则 ——

// TestMaskContainerInspectMasksEnvMountsLabels 屏蔽三类字段：
// Config.Env、Mounts 宿主机路径、Labels 凭据类键。
func TestMaskContainerInspectMasksEnvMountsLabels(t *testing.T) {
	raw := map[string]any{
		"Id": "abc123",
		"Config": map[string]any{
			"Env": []any{"PATH=/usr/bin", "DB_PASSWORD=supersecret", "TOKEN=abc"},
			"Labels": map[string]any{
				"agent-ops.test":    "true",
				"com.example.owner": "ops",
				"secret.api":        "s3cr3t",
				"TOKEN_MAIN":        "tok-123",
				"PasswordHint":      "hunter2",
			},
		},
		"Mounts": []any{
			map[string]any{
				"Type":        "bind",
				"Source":      "/Users/x/private/data",
				"Destination": "/data",
			},
		},
		"HostConfig": map[string]any{
			"Binds": []any{"/Users/x/private/data:/data"},
		},
		"State": map[string]any{"Status": "running"},
	}
	masked, paths := MaskContainerInspect(raw)

	cfg := masked["Config"].(map[string]any)
	if _, has := cfg["Env"]; has {
		t.Fatal("Config.Env 必须被屏蔽")
	}
	labels := cfg["Labels"].(map[string]any)
	if _, has := labels["secret.api"]; has {
		t.Fatal("secret.* 标签必须被屏蔽")
	}
	if _, has := labels["TOKEN_MAIN"]; has {
		t.Fatal("TOKEN_* 标签必须被屏蔽（大小写不敏感）")
	}
	if _, has := labels["PasswordHint"]; has {
		t.Fatal("Password* 标签必须被屏蔽（大小写不敏感）")
	}
	if labels["agent-ops.test"] != "true" || labels["com.example.owner"] != "ops" {
		t.Fatalf("非凭据标签必须保留：%v", labels)
	}
	mount := masked["Mounts"].([]any)[0].(map[string]any)
	if _, has := mount["Source"]; has {
		t.Fatal("Mounts[*].Source（宿主机路径）必须被屏蔽")
	}
	if mount["Destination"] != "/data" {
		t.Fatalf("容器内路径应保留：%v", mount)
	}
	if _, has := masked["HostConfig"].(map[string]any)["Binds"]; has {
		t.Fatal("HostConfig.Binds（宿主机路径）必须被屏蔽")
	}
	// 屏蔽是"删除 + 记录路径"，原数据不被修改。
	if _, has := raw["Config"].(map[string]any)["Env"]; !has {
		t.Fatal("屏蔽不得修改入参")
	}
	joined := strings.Join(paths, ",")
	for _, want := range []string{"Config.Env", "Mounts[0].Source", "HostConfig.Binds", "Config.Labels.secret.api"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("屏蔽路径应包含 %s，实际 %v", want, paths)
		}
	}
	// 屏蔽后的值不得出现凭据原文。
	blob := marshalIndent(masked)
	for _, secret := range []string{"supersecret", "s3cr3t", "tok-123", "hunter2", "/Users/x/private/data"} {
		if strings.Contains(blob, secret) {
			t.Fatalf("屏蔽结果泄露敏感值 %q：%s", secret, blob)
		}
	}
}

// TestWhitelistInfoReturnsOnlyListedFields /info 白名单（第十三轮 F1）：
// 只返回明确列出的字段，其余一律不返回；注入未知敏感字段与白名单外普通字段
// 都必须不出现。
func TestWhitelistInfoReturnsOnlyListedFields(t *testing.T) {
	raw := map[string]any{
		// 白名单内（应保留）
		"ServerVersion":     "29.8.2",
		"OperatingSystem":   "Docker Desktop",
		"Architecture":      "aarch64",
		"NCPU":              8,
		"MemTotal":          int64(8 << 30),
		"Containers":        3,
		"ContainersRunning": 1,
		"ContainersPaused":  0,
		"ContainersStopped": 2,
		"Images":            7,
		"KernelVersion":     "6.10.0",
		// 白名单外：已知敏感字段（原删除式屏蔽覆盖）
		"Swarm": map[string]any{
			"LocalNodeState": "active",
			"NodeID":         "node-xyz",
			"NodeAddr":       "10.0.0.5",
		},
		"Name":     "prod-host-01",
		"NodeID":   "node-xyz",
		"NodeAddr": "10.0.0.5",
		// 白名单外：普通字段（也必须不出现）
		"Driver":         "overlay2",
		"LoggingDriver":  "json-file",
		"RegistryConfig": map[string]any{"InsecureRegistryCIDRs": []any{"127.0.0.0/8"}},
		"Runtimes":       map[string]any{"runc": map[string]any{"path": "runc"}},
	}
	out, dropped := WhitelistInfo(raw)

	want := []string{
		"ServerVersion", "OperatingSystem", "Architecture", "NCPU", "MemTotal",
		"Containers", "ContainersRunning", "ContainersPaused", "ContainersStopped",
		"Images", "KernelVersion",
	}
	if len(out) != len(want) {
		t.Fatalf("只应返回 %d 个白名单字段，实际 %d 个：%v", len(want), len(out), out)
	}
	for _, k := range want {
		if _, has := out[k]; !has {
			t.Fatalf("白名单字段 %s 必须保留", k)
		}
	}
	// 未知敏感字段与白名单外普通字段都不得出现。
	for _, k := range []string{"Swarm", "Name", "NodeID", "NodeAddr", "Driver", "LoggingDriver", "RegistryConfig", "Runtimes"} {
		if _, has := out[k]; has {
			t.Fatalf("白名单外字段 %s 不得返回", k)
		}
	}
	blob := marshalIndent(out)
	for _, secret := range []string{"node-xyz", "10.0.0.5", "prod-host-01", "overlay2", "json-file"} {
		if strings.Contains(blob, secret) {
			t.Fatalf("白名单输出泄露 %q：%s", secret, blob)
		}
	}
	// 被裁剪字段清单应完整记录。
	if len(dropped) != 8 {
		t.Fatalf("应记录 8 个被裁剪字段，实际 %v", dropped)
	}
	// 原数据不被修改。
	if _, has := raw["Swarm"]; !has {
		t.Fatal("白名单裁剪不得修改入参")
	}
}

// TestInfoEndpointWhitelistedOverHTTP /info 经客户端后同样只返回白名单字段。
func TestInfoEndpointWhitelistedOverHTTP(t *testing.T) {
	srv, _ := newFakeDaemon(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{
			"ServerVersion":"29.8.2","OperatingSystem":"Docker Desktop","Architecture":"aarch64",
			"NCPU":8,"MemTotal":8589934592,"Containers":3,"ContainersRunning":1,
			"ContainersPaused":0,"ContainersStopped":2,"Images":7,"KernelVersion":"6.10.0",
			"Swarm":{"NodeAddr":"10.0.0.5"},"Name":"prod-host-01","Driver":"overlay2"
		}`))
	})
	a := testAdapter(t, srv)
	info, dropped, err := a.client.Info(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, has := info["Swarm"]; has {
		t.Fatal("Swarm 不得出现")
	}
	if _, has := info["Driver"]; has {
		t.Fatal("白名单外普通字段不得出现")
	}
	if info["ServerVersion"] != "29.8.2" || info["KernelVersion"] != "6.10.0" {
		t.Fatalf("白名单字段值不符：%v", info)
	}
	if len(dropped) != 3 {
		t.Fatalf("应裁剪 3 个字段，实际 %v", dropped)
	}
}

// —— F3：生产模式连接守卫 ——

// TestProdModeRejectsUnixSocket prod + unix socket 启动失败（错误说明原因）。
func TestProdModeRejectsUnixSocket(t *testing.T) {
	_, err := NewClient(Config{
		Endpoint:      "unix:///var/run/docker.sock",
		Mode:          ModeProd,
		ReadOnlyProxy: true, // 即便声明了代理，unix socket 仍拒绝
	})
	if !errors.Is(err, ErrProdUnixSocketForbidden) {
		t.Fatalf("prod + unix socket 必须拒绝：%v", err)
	}
	if err == nil || !strings.Contains(err.Error(), "只读代理") {
		t.Fatalf("错误信息应说明必须经只读代理：%v", err)
	}
}

// TestProdModeRequiresProxyDeclaration prod + TCP 未声明只读代理 → 启动失败。
func TestProdModeRequiresProxyDeclaration(t *testing.T) {
	_, err := NewClient(Config{Endpoint: "tcp://127.0.0.1:2375", Mode: ModeProd})
	if !errors.Is(err, ErrProdProxyNotDeclared) {
		t.Fatalf("prod + TCP 未声明代理必须拒绝：%v", err)
	}
}

// TestProdModeAllowsDeclaredProxy prod + TCP + 显式声明只读代理 → 通过配置校验。
func TestProdModeAllowsDeclaredProxy(t *testing.T) {
	c, err := NewClient(Config{
		Endpoint:      "tcp://docker-socket-proxy:2375",
		Mode:          ModeProd,
		ReadOnlyProxy: true,
	})
	if err != nil {
		t.Fatalf("prod + 声明只读代理应通过：%v", err)
	}
	if c == nil {
		t.Fatal("客户端应构建成功")
	}
}

// TestTestModeAllowsUnixSocket test 模式允许 unix socket。
func TestTestModeAllowsUnixSocket(t *testing.T) {
	if _, err := NewClient(Config{Endpoint: "unix:///var/run/docker.sock", Mode: ModeTest}); err != nil {
		t.Fatalf("test 模式 unix socket 应允许：%v", err)
	}
}

// TestParseModeRequiresExplicitValue 模式必须显式指定。
func TestParseModeRequiresExplicitValue(t *testing.T) {
	if _, err := ParseMode(""); err == nil {
		t.Fatal("空模式必须拒绝")
	}
	if _, err := ParseMode("staging"); err == nil {
		t.Fatal("未知模式必须拒绝")
	}
	if m, err := ParseMode("prod"); err != nil || m != ModeProd {
		t.Fatalf("prod 应解析成功：%v %v", m, err)
	}
}

// TestMaskLabelsPrefixRule 标签凭据前缀规则（secret/token/password，大小写不敏感）。
func TestMaskLabelsPrefixRule(t *testing.T) {
	in := map[string]any{
		"agent-ops.test": "true",
		"secret":         "a",
		"Secret.x":       "b",
		"token":          "c",
		"Tokens":         "d",
		"password":       "e",
		"PasswordHint":   "f",
		"keepme":         "g",
		"not-secret":     "h",
	}
	out, masked := MaskLabels(in)
	if len(masked) != 6 {
		t.Fatalf("应屏蔽 6 个凭据类键，实际 %v", masked)
	}
	for _, k := range []string{"secret", "Secret.x", "token", "Tokens", "password", "PasswordHint"} {
		if _, has := out[k]; has {
			t.Fatalf("%s 必须被屏蔽", k)
		}
	}
	if out["agent-ops.test"] != "true" || out["keepme"] != "g" || out["not-secret"] != "h" {
		t.Fatalf("非凭据键必须保留：%v", out)
	}
}

// —— D1/D2：标签过滤与空列表报错 ——

// TestListContainersAppliesLabelFilterAndDropsUnlabelled 列表只返回带测试标签的
// 容器；即使守护进程返回无标签对象，也不会被带出。
func TestListContainersAppliesLabelFilterAndDropsUnlabelled(t *testing.T) {
	var gotFilters string
	srv, _ := newFakeDaemon(t, func(w http.ResponseWriter, r *http.Request) {
		gotFilters = r.URL.Query().Get("filters")
		_, _ = w.Write([]byte(`[
			{"Id":"aaa","Labels":{"agent-ops.test":"true"},"State":"running"},
			{"Id":"bbb","Labels":{"other":"1"},"State":"running"},
			{"Id":"ccc","Labels":{"agent-ops.test":"false"},"State":"running"}
		]`))
	})
	a := testAdapter(t, srv)
	items, err := a.client.ListContainers(context.Background())
	if err != nil {
		t.Fatalf("应返回标签过滤后的列表：%v", err)
	}
	if len(items) != 1 || items[0]["Id"] != "aaa" {
		t.Fatalf("只应返回带 agent-ops.test=true 的容器：%v", items)
	}
	if !strings.Contains(gotFilters, TestLabel+"=true") {
		t.Fatalf("必须向守护进程下发标签过滤条件，实际 %q", gotFilters)
	}
}

// TestListContainersEmptyReturnsExplicitError 过滤后为空 → 明确报错（不静默）。
func TestListContainersEmptyReturnsExplicitError(t *testing.T) {
	srv, _ := newFakeDaemon(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[]`))
	})
	a := testAdapter(t, srv)
	if _, err := a.client.ListContainers(context.Background()); !errors.Is(err, ErrNoLabelledObjects) {
		t.Fatalf("空列表应明确报错：%v", err)
	}
	if _, err := a.client.ListImages(context.Background()); !errors.Is(err, ErrNoLabelledObjects) {
		t.Fatalf("空镜像列表应明确报错：%v", err)
	}
	// 经适配器接口（Diagnose）同样报错，而不是返回"0 个"的成功结论。
	if _, err := a.Diagnose(context.Background(), nil, QuestionContainerList); !errors.Is(err, ErrNoLabelledObjects) {
		t.Fatalf("Diagnose 列表应明确报错：%v", err)
	}
}

// TestInspectRejectsUnlabelledContainer 只允许 inspect 带测试标签的容器。
func TestInspectRejectsUnlabelledContainer(t *testing.T) {
	srv, _ := newFakeDaemon(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"Id":"bbb","Config":{"Labels":{"other":"1"}},"State":{"Status":"running"}}`))
	})
	a := testAdapter(t, srv)
	if _, _, err := a.client.InspectContainer(context.Background(), "bbb"); !errors.Is(err, ErrNoLabelledObjects) {
		t.Fatalf("无测试标签的容器不得 inspect：%v", err)
	}
}

// —— D1/D2：超时与响应体上限 ——

// TestRequestTimeout 请求超时（默认 10s，可配）。
func TestRequestTimeout(t *testing.T) {
	srv, _ := newFakeDaemon(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(500 * time.Millisecond):
			_, _ = w.Write([]byte(`{}`))
		case <-r.Context().Done():
		}
	})
	a := testAdapter(t, srv, WithTimeout(50*time.Millisecond))
	if a.timeout != 50*time.Millisecond {
		t.Fatalf("超时配置未生效：%v", a.timeout)
	}
	start := time.Now()
	if _, err := a.client.Version(context.Background()); err == nil {
		t.Fatal("超时请求应报错")
	}
	if elapsed := time.Since(start); elapsed > 400*time.Millisecond {
		t.Fatalf("应在超时时长内返回：%v", elapsed)
	}
	if DefaultTimeout != 10*time.Second {
		t.Fatalf("默认超时应为 10 秒，实际 %v", DefaultTimeout)
	}
}

// TestResponseBodyLimit 响应体上限（默认 1MB，可配）。
func TestResponseBodyLimit(t *testing.T) {
	big := strings.Repeat("x", 4096)
	srv, _ := newFakeDaemon(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"Blob":"` + big + `"}`))
	})
	a := testAdapter(t, srv, WithMaxBodyBytes(1024))
	if _, err := a.client.Version(context.Background()); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("超过响应体上限应报错：%v", err)
	}
	if DefaultMaxBodyBytes != 1<<20 {
		t.Fatalf("默认上限应为 1MB，实际 %d", DefaultMaxBodyBytes)
	}
}

// —— D1/D2：只读语义（Execute/PlanRollback）与清单 ——

// TestExecuteRejectsReadOnlyCapabilities Execute 对只读能力直接拒绝并提示走
// Diagnose/Health；PlanRollback 返回 ErrNoRollbackNeeded。
func TestExecuteRejectsReadOnlyCapabilities(t *testing.T) {
	srv, seen := newFakeDaemon(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	})
	a := testAdapter(t, srv)
	ctx := context.Background()

	for _, capName := range []string{
		"docker.version", "docker.info", "docker.container.list",
		"docker.container.inspect_status", "docker.image.list",
	} {
		_, err := a.Execute(ctx, &contractv1.Action{Capability: capName}, &contractv1.AuthZ{AuthorizationId: "az1"})
		if !errors.Is(err, ErrReadOnlyHint) {
			t.Fatalf("%s 应被拒绝并提示走 Diagnose/Health：%v", capName, err)
		}
	}
	// 未声明能力同样拒绝。
	if _, err := a.Execute(ctx, &contractv1.Action{Capability: "docker.container.start"}, nil); err == nil {
		t.Fatal("未声明能力必须拒绝")
	}
	if _, err := a.PlanRollback(ctx, &contractv1.ActionRecord{}); !errors.Is(err, ErrNoRollbackNeeded) {
		t.Fatalf("只读适配器回滚计划应返回 ErrNoRollbackNeeded：%v", err)
	}
	if len(*seen) != 0 {
		t.Fatalf("Execute/PlanRollback 不得发起任何 Docker 请求：%v", *seen)
	}
}

// TestManifestIsReadOnlyOnly 清单：五个只读能力、全部 rollbackable=false、
// destructive=false、超时为正。
func TestManifestIsReadOnlyOnly(t *testing.T) {
	srv, _ := newFakeDaemon(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	})
	a := testAdapter(t, srv)
	m := a.Manifest()
	if m == nil || len(m.Capabilities) != 5 {
		t.Fatalf("应声明 5 个能力：%+v", m)
	}
	want := map[string]bool{
		"docker.version": true, "docker.info": true, "docker.container.list": true,
		"docker.container.inspect_status": true, "docker.image.list": true,
	}
	for _, c := range m.Capabilities {
		if !want[c.Name] {
			t.Fatalf("未预期的能力：%s", c.Name)
		}
		delete(want, c.Name)
		if c.RiskTier != contractv1.RiskTier_RISK_TIER_READ_ONLY {
			t.Fatalf("%s 必须为 read_only：%v", c.Name, c.RiskTier)
		}
		if c.Rollbackable || c.Destructive {
			t.Fatalf("%s 不得声明 rollbackable/destructive", c.Name)
		}
		if c.Timeout == nil || c.Timeout.AsDuration() <= 0 {
			t.Fatalf("%s 必须声明正超时（H6）", c.Name)
		}
		if !validation.ValidCapabilityName(c.Name) {
			t.Fatalf("%s 名称不合法", c.Name)
		}
	}
	if len(want) != 0 {
		t.Fatalf("缺少能力声明：%v", want)
	}
}

// TestDiagnoseRejectsFreeText 自由文本与非法容器 ID 一律拒绝。
func TestDiagnoseRejectsFreeText(t *testing.T) {
	srv, _ := newFakeDaemon(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	})
	a := testAdapter(t, srv)
	for _, q := range []string{"rm -rf /", "list all containers", "container_status:", "container_status:../../etc/passwd"} {
		if _, err := a.Diagnose(context.Background(), nil, q); err == nil {
			t.Fatalf("非法诊断问题必须拒绝：%q", q)
		}
	}
}

// TestEndpointConfigValidation 连接方式校验（fail-closed）。
func TestEndpointConfigValidation(t *testing.T) {
	for _, ep := range []string{"", "ftp://host", "unix://"} {
		if _, err := NewClient(Config{Endpoint: ep, Mode: ModeTest}); err == nil {
			t.Fatalf("非法连接方式必须拒绝：%q", ep)
		}
	}
	if _, err := NewClient(Config{Endpoint: "unix:///var/run/docker.sock", Mode: ModeTest}); err != nil {
		t.Fatalf("test 模式 unix socket 应可用：%v", err)
	}
	if _, err := NewClient(Config{Endpoint: "tcp://127.0.0.1:2375", Mode: ModeTest}); err != nil {
		t.Fatalf("test 模式 tcp 应可用：%v", err)
	}
	// 模式必须显式指定。
	if _, err := NewClient(Config{Endpoint: "tcp://127.0.0.1:2375"}); err == nil {
		t.Fatal("未指定运行模式必须拒绝")
	}
}

// TestContextCancellationSafe 上下文取消安全：取消后调用不 panic、返回错误。
func TestContextCancellationSafe(t *testing.T) {
	srv, _ := newFakeDaemon(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(200 * time.Millisecond):
			_, _ = w.Write([]byte(`{}`))
		case <-r.Context().Done():
		}
	})
	a := testAdapter(t, srv)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.client.Version(ctx); err == nil {
		t.Fatal("已取消的上下文应返回错误")
	}
	if _, err := a.Discover(ctx, &contractv1.AssetTarget{AssetId: "ast"}); err == nil {
		t.Fatal("已取消的上下文 Discover 应返回错误")
	}
	if _, err := a.Health(ctx, nil); err != nil {
		t.Fatalf("Health 应把不可达映射为 unhealthy 而非报错：%v", err)
	}
}

// TestGatewayDoesNotWireDockerAdapter D3：本轮不接入网关执行路径——
// 网关侧源码不得导入 adapters/docker。
func TestGatewayDoesNotWireDockerAdapter(t *testing.T) {
	root := filepath.Join("..", "..", "gateway")
	if _, err := os.Stat(root); err != nil {
		t.Skipf("skip：未找到网关目录（%v）。", err)
	}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		if strings.Contains(string(data), "agent-ops/adapters/docker") {
			t.Errorf("D3：本轮不接入网关，网关源码不得导入 docker 适配器：%s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
