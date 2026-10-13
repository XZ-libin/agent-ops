package docker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// —— 端点白名单（第十二轮 D1）——
//
// 只允许以下 GET 端点；其余路径与方法在客户端内部一律拒绝。
// 白名单是"客户端唯一出口"的守门人：本包不存在绕过它的请求路径。
const (
	// PathVersion 引擎版本。
	PathVersion = "/version"
	// PathInfo 引擎信息（输出经 MaskInfo 屏蔽）。
	PathInfo = "/info"
	// PathContainers 容器列表（强制按测试标签过滤）。
	PathContainers = "/containers/json"
	// PathImages 镜像列表（强制按测试标签过滤）。
	PathImages = "/images/json"
)

// containerInspectPath 生成容器 inspect 路径（/containers/{id}/json）。
//
// 第十四轮 H1：请求路径必须由白名单路径构造函数生成，调用点不得做字符串拼接
// （仓库级 AST 守卫会拒绝"路径字面量 + 变量"的拼接）。
func containerInspectPath(id string) string {
	return fmt.Sprintf("/containers/%s/json", id)
}

// containerInspectPattern 容器 inspect 端点：/containers/{id}/json。
// id 只允许 Docker 的容器 ID/名称字符集（十六进制、字母、数字、_ . -），
// 杜绝路径穿越与额外路径段。
var containerInspectPattern = regexp.MustCompile(`^/containers/[A-Za-z0-9][A-Za-z0-9_.-]{0,127}/json$`)

// 客户端错误。
var (
	// ErrEndpointNotAllowed 请求不在白名单内（路径或方法）。
	ErrEndpointNotAllowed = errors.New("docker：端点不在只读白名单内，已拒绝")
	// ErrWriteMethodForbidden 写方法（POST/PUT/DELETE/PATCH）一律禁止。
	ErrWriteMethodForbidden = errors.New("docker：只读适配器禁止任何写方法（POST/PUT/DELETE/PATCH）")
	// ErrResponseTooLarge 响应体超过上限。
	ErrResponseTooLarge = errors.New("docker：响应体超过上限")
	// ErrNoLabelledObjects 过滤后为空：明确报错而非静默返回空列表。
	ErrNoLabelledObjects = errors.New("docker：未发现带 agent-ops.test=true 标签的对象（生产模式下列表为空，明确报错而非静默）")
	// ErrBadEndpoint 连接方式非法。
	ErrBadEndpoint = errors.New("docker：连接方式非法（支持 unix:///path 或 tcp://host:port）")
	// ErrProdUnixSocketForbidden 生产模式禁止直接使用 Docker unix socket
	// （第十三轮 F3：socket 等价 root 权限，必须经只读代理）。
	ErrProdUnixSocketForbidden = errors.New(
		"docker：mode=prod 禁止直接使用 Docker unix socket（socket 等价 root 权限）；" +
			"生产必须经只读代理（docker-socket-proxy，仅开放 GET 端点）的 TCP 地址接入")
	// ErrProdProxyNotDeclared 生产模式使用 TCP 但未显式声明为只读代理。
	ErrProdProxyNotDeclared = errors.New(
		"docker：mode=prod 使用 TCP 时必须显式声明 ReadOnlyProxy=true（确认对端是仅开放 GET 的只读代理）")
)

// Mode 运行模式（第十三轮 F3）。
type Mode string

const (
	// ModeTest 测试模式：允许 unix socket 直连与 TCP。
	ModeTest Mode = "test"
	// ModeProd 生产模式：只接受显式声明为只读代理的 TCP 地址。
	ModeProd Mode = "prod"
)

// ParseMode 解析运行模式（必须显式指定，空串即错误）。
func ParseMode(s string) (Mode, error) {
	switch Mode(strings.TrimSpace(s)) {
	case ModeTest:
		return ModeTest, nil
	case ModeProd:
		return ModeProd, nil
	case "":
		return "", errors.New("docker：必须显式指定运行模式（Mode=test|prod），不得依赖默认值")
	}
	return "", fmt.Errorf("docker：未知运行模式 %q（仅接受 test / prod）", s)
}

// 默认上限（第十二轮 D1，工程默认）。
const (
	// DefaultTimeout 单请求超时（工程默认 10 秒）。
	DefaultTimeout = 10 * time.Second
	// DefaultMaxBodyBytes 响应体上限（工程默认 1MB）。
	DefaultMaxBodyBytes int64 = 1 << 20
	// TestLabel 测试对象标签：只有带该标签的容器/镜像才可被列出或 inspect。
	TestLabel = "agent-ops.test"
	// testLabelFilter 传给 Engine API 的标签过滤表达式。
	testLabelFilter = `{"label":["` + TestLabel + `=true"]}`
)

// Config 客户端配置。
type Config struct {
	// Endpoint 连接方式：unix:///var/run/docker.sock 或 tcp://127.0.0.1:2375。
	Endpoint string
	// Mode 运行模式（第十三轮 F3，必填）：test 允许 unix socket；
	// prod 只接受显式声明为只读代理的 TCP 地址。
	Mode Mode
	// ReadOnlyProxy 显式声明"对端是仅开放 GET 端点的只读代理"
	// （如 docker-socket-proxy）。mode=prod 时必须为 true，否则拒绝启动。
	ReadOnlyProxy bool
	// Timeout 单请求超时（<=0 用 DefaultTimeout）。
	Timeout time.Duration
	// MaxBodyBytes 响应体上限（<=0 用 DefaultMaxBodyBytes）。
	MaxBodyBytes int64
}

// Client 最小只读 Docker Engine API 客户端。
// 唯一出口是 get：所有请求都经白名单校验，且**只使用 GET**。
type Client struct {
	http    *http.Client
	base    string
	maxBody int64
}

// NewClient 构建只读客户端；endpoint 与运行模式的组合非法直接拒绝（fail-closed）。
//
// 第十三轮 F3 连接守卫：
//   - mode=test：允许 unix socket 与 TCP；
//   - mode=prod：**只**接受 TCP 且必须显式声明 ReadOnlyProxy=true；
//     直接使用 unix socket（等价 root 权限）一律拒绝启动，错误信息说明原因。
func NewClient(cfg Config) (*Client, error) {
	mode, err := ParseMode(string(cfg.Mode))
	if err != nil {
		return nil, err
	}
	cfg.Mode = mode
	if strings.TrimSpace(cfg.Endpoint) == "" {
		return nil, ErrBadEndpoint
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	maxBody := cfg.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = DefaultMaxBodyBytes
	}

	u, err := url.Parse(cfg.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("%w：%v", ErrBadEndpoint, err)
	}
	// F3：生产模式的连接守卫（先于任何网络动作，fail-closed）。
	if cfg.Mode == ModeProd {
		if u.Scheme != "tcp" && u.Scheme != "http" {
			return nil, fmt.Errorf("%w（当前 endpoint=%s）", ErrProdUnixSocketForbidden, cfg.Endpoint)
		}
		if !cfg.ReadOnlyProxy {
			return nil, fmt.Errorf("%w（当前 endpoint=%s）", ErrProdProxyNotDeclared, cfg.Endpoint)
		}
	}
	transport := &http.Transport{}
	var base string
	switch u.Scheme {
	case "unix":
		socket := u.Path
		if socket == "" {
			return nil, ErrBadEndpoint
		}
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		}
		base = "http://docker" // unix socket 下主机名无意义
	case "tcp", "http":
		if u.Host == "" {
			return nil, ErrBadEndpoint
		}
		base = "http://" + u.Host
	default:
		return nil, fmt.Errorf("%w：不支持的 scheme %q", ErrBadEndpoint, u.Scheme)
	}

	return &Client{
		http:    &http.Client{Transport: transport, Timeout: timeout},
		base:    base,
		maxBody: maxBody,
	}, nil
}

// AllowedEndpoint 判定 method+path 是否在白名单内（导出以便单测与审计核对）。
// 只允许 GET，且路径必须命中白名单；其余一律拒绝。
func AllowedEndpoint(method, path string) error {
	if method != http.MethodGet {
		return fmt.Errorf("%w：method=%s", ErrWriteMethodForbidden, method)
	}
	if path == PathVersion || path == PathInfo || path == PathContainers || path == PathImages {
		return nil
	}
	if containerInspectPattern.MatchString(path) {
		return nil
	}
	return fmt.Errorf("%w：path=%s", ErrEndpointNotAllowed, path)
}

// get 唯一的请求出口：先过白名单，再发 GET，最后做响应体上限检查。
// query 只接受调用方内部构造的固定值（本包不向外部暴露任意 query）。
func (c *Client) get(ctx context.Context, path string, query url.Values) ([]byte, error) {
	if err := AllowedEndpoint(http.MethodGet, path); err != nil {
		return nil, err
	}
	u := c.base + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	// 响应体上限：多读 1 字节即可判定超限（不把超限内容读进内存）。
	body, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBody+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > c.maxBody {
		return nil, fmt.Errorf("%w（上限 %d 字节）", ErrResponseTooLarge, c.maxBody)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("docker：%s 返回状态 %d", path, resp.StatusCode)
	}
	return body, nil
}

// getJSON 读取 JSON 对象。
func (c *Client) getJSON(ctx context.Context, path string, query url.Values) (map[string]any, error) {
	body, err := c.get(ctx, path, query)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("docker：%s 响应不是合法 JSON：%w", path, err)
	}
	return out, nil
}

// getJSONArray 读取 JSON 数组。
func (c *Client) getJSONArray(ctx context.Context, path string, query url.Values) ([]map[string]any, error) {
	body, err := c.get(ctx, path, query)
	if err != nil {
		return nil, err
	}
	var out []map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("docker：%s 响应不是合法 JSON 数组：%w", path, err)
	}
	return out, nil
}

// Version 读取引擎版本（无敏感字段，不需屏蔽）。
func (c *Client) Version(ctx context.Context) (map[string]any, error) {
	return c.getJSON(ctx, PathVersion, nil)
}

// Info 读取引擎信息：按**白名单**裁剪（第十三轮 F1），只返回明确列出的字段，
// 其余一律不返回（不做删除式屏蔽）。第二个返回值是被裁剪掉的字段名列表。
func (c *Client) Info(ctx context.Context) (map[string]any, []string, error) {
	raw, err := c.getJSON(ctx, PathInfo, nil)
	if err != nil {
		return nil, nil, err
	}
	whitelisted, dropped := WhitelistInfo(raw)
	return whitelisted, dropped, nil
}

// ListContainers 列出带测试标签的容器（强制标签过滤 + 逐项复核）。
// 过滤后为空 → ErrNoLabelledObjects（明确报错，不静默返回空列表）。
func (c *Client) ListContainers(ctx context.Context) ([]map[string]any, error) {
	q := url.Values{}
	q.Set("all", "1")
	q.Set("filters", testLabelFilter)
	raw, err := c.getJSONArray(ctx, PathContainers, q)
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(raw))
	for _, item := range raw {
		// 复核：即使守护进程未按过滤器生效，也不返回无标签对象。
		if !hasTestLabel(item["Labels"]) {
			continue
		}
		masked, _ := MaskContainerSummary(item)
		out = append(out, masked)
	}
	if len(out) == 0 {
		return nil, ErrNoLabelledObjects
	}
	return out, nil
}

// InspectContainer 读取指定容器详情（经 MaskContainerInspect 屏蔽）。
// 只允许对带测试标签的容器 inspect：无标签即拒绝（不返回任何内容）。
func (c *Client) InspectContainer(ctx context.Context, id string) (map[string]any, []string, error) {
	if strings.TrimSpace(id) == "" {
		return nil, nil, errors.New("docker：容器 ID 为空")
	}
	path := containerInspectPath(id)
	raw, err := c.getJSON(ctx, path, nil)
	if err != nil {
		return nil, nil, err
	}
	if !hasTestLabelInConfig(raw) {
		return nil, nil, fmt.Errorf("%w：容器 %s 未带测试标签", ErrNoLabelledObjects, id)
	}
	masked, paths := MaskContainerInspect(raw)
	return masked, paths, nil
}

// ListImages 列出带测试标签的镜像（强制标签过滤 + 逐项复核）。
// 过滤后为空 → ErrNoLabelledObjects。
func (c *Client) ListImages(ctx context.Context) ([]map[string]any, error) {
	q := url.Values{}
	q.Set("all", "0")
	q.Set("filters", testLabelFilter)
	raw, err := c.getJSONArray(ctx, PathImages, q)
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(raw))
	for _, item := range raw {
		if !hasTestLabel(item["Labels"]) {
			continue
		}
		masked, _ := MaskImageSummary(item)
		out = append(out, masked)
	}
	if len(out) == 0 {
		return nil, ErrNoLabelledObjects
	}
	return out, nil
}

// hasTestLabel 判定 Labels 是否含 agent-ops.test=true。
func hasTestLabel(v any) bool {
	labels, ok := v.(map[string]any)
	if !ok {
		return false
	}
	val, ok := labels[TestLabel]
	if !ok {
		return false
	}
	s, ok := val.(string)
	return ok && s == "true"
}

// hasTestLabelInConfig 容器 inspect 结果中标签位于 Config.Labels。
func hasTestLabelInConfig(raw map[string]any) bool {
	cfg, ok := raw["Config"].(map[string]any)
	if !ok {
		return false
	}
	return hasTestLabel(cfg["Labels"])
}
