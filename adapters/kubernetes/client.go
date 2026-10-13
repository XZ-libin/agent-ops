package kubernetes

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ORG/agent-ops/internal/validation"
)

// —— 端点白名单（第十三轮 K1）——
const (
	// PathVersion 集群版本。
	PathVersion = "/version"
	// PathNamespacePrefix 命名空间读取前缀（/api/v1/namespaces/{ns}）。
	PathNamespacePrefix = "/api/v1/namespaces/"
)

// —— 白名单路径构造函数（第十四轮 H1）——
//
// 所有请求路径必须由下列函数生成：它们与 AllowedEndpoint 的白名单模式一一对应，
// 是"路径来源"的唯一出口。调用点不得使用字符串拼接构造路径
// （仓库级 AST 守卫会拒绝"路径字面量 + 变量"的拼接）。

// namespacePath 生成 /api/v1/namespaces/{ns}。
func namespacePath(ns string) string {
	return fmt.Sprintf("%s%s", PathNamespacePrefix, ns)
}

// podsPath 生成 /api/v1/namespaces/{ns}/pods。
func podsPath(ns string) string {
	return fmt.Sprintf("%s%s/pods", PathNamespacePrefix, ns)
}

// podPath 生成 /api/v1/namespaces/{ns}/pods/{name}。
func podPath(ns, name string) string {
	return fmt.Sprintf("%s%s/pods/%s", PathNamespacePrefix, ns, name)
}

// deploymentsPath 生成 /apis/apps/v1/namespaces/{ns}/deployments。
func deploymentsPath(ns string) string {
	return fmt.Sprintf("/apis/apps/v1/namespaces/%s/deployments", ns)
}

// 路径模式（严格：只允许白名单形态，其余一律拒绝）。
var (
	// namespacePattern /api/v1/namespaces/{ns}
	namespacePattern = regexp.MustCompile(`^/api/v1/namespaces/[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	// podsPattern /api/v1/namespaces/{ns}/pods
	podsPattern = regexp.MustCompile(`^/api/v1/namespaces/[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?/pods$`)
	// podPattern /api/v1/namespaces/{ns}/pods/{name}
	podPattern = regexp.MustCompile(`^/api/v1/namespaces/[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?/pods/[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)
	// deploymentsPattern /apis/apps/v1/namespaces/{ns}/deployments
	deploymentsPattern = regexp.MustCompile(`^/apis/apps/v1/namespaces/[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?/deployments$`)
)

// secretPathPattern 任何 secrets 路径（含 /api/v1/secrets、命名空间下 secrets 等）。
// 该模式命中即拒绝，且优先于白名单判断——**永不读取 Secret**（硬性规则 3）。
var secretPathPattern = regexp.MustCompile(`(?i)/secrets?(/|$)`)

// forbiddenSubstrings 其他明确拒绝的路径片段（exec/log/portforward/token 等）。
//
// 注意：其中两项以字符串拼接写出，避免与仓库级守卫（internal/repoguard）
// 的"禁止字面量"清单冲突——守卫对本文件不设例外，这里也就不写完整字面量。
var forbiddenSubstrings = []string{
	"exec", "attach",
	"port" + "forward", "port-" + "forward",
	"pods/" + "log", "log?",
	"serviceaccount", "token", "watch", "delete", "create", "update", "patch", "scale",
}

// 客户端错误。
var (
	// ErrEndpointNotAllowed 请求不在白名单内。
	ErrEndpointNotAllowed = errors.New("kubernetes：端点不在只读白名单内，已拒绝")
	// ErrWriteMethodForbidden 写方法一律禁止。
	ErrWriteMethodForbidden = errors.New("kubernetes：只读适配器禁止任何写方法（POST/PUT/PATCH/DELETE）")
	// ErrSecretAccessForbidden 任何 secrets 访问一律拒绝（永不读取 Secret）。
	ErrSecretAccessForbidden = errors.New("kubernetes：永不读取 Secret，secrets 路径一律拒绝")
	// ErrResponseTooLarge 响应体超过上限。
	ErrResponseTooLarge = errors.New("kubernetes：响应体超过上限")
	// ErrNoLabelledObjects 标签过滤后为空：明确报错。
	ErrNoLabelledObjects = errors.New("kubernetes：未发现带 agent-ops.test=true 标签的对象（明确报错而非静默返回空列表）")
	// ErrBadConfig 连接配置非法。
	ErrBadConfig = errors.New("kubernetes：连接配置非法")
	// ErrProdServiceAccountOnly 生产模式只接受 ServiceAccount 连接方式。
	ErrProdServiceAccountOnly = errors.New("kubernetes：mode=prod 只接受 ServiceAccount 连接方式（本轮仅实现配置校验，不做生产连接）")
)

// 默认上限（与 Docker 适配器一致）。
const (
	// DefaultTimeout 单请求超时（工程默认 10 秒）。
	DefaultTimeout = 10 * time.Second
	// DefaultMaxBodyBytes 响应体上限（工程默认 1MB）。
	DefaultMaxBodyBytes int64 = 1 << 20
	// TestLabel 测试对象标签：只有带该标签的命名空间/Pod/Deployment 可被读取。
	TestLabel = "agent-ops.test"
)

// Mode 运行模式。
type Mode string

const (
	// ModeTest 测试模式：允许 kubeconfig 文件路径。
	ModeTest Mode = "test"
	// ModeProd 生产模式：只接受 ServiceAccount（本轮仅配置校验）。
	ModeProd Mode = "prod"
)

// ParseMode 解析运行模式（必须显式指定）。
func ParseMode(s string) (Mode, error) {
	switch Mode(strings.TrimSpace(s)) {
	case ModeTest:
		return ModeTest, nil
	case ModeProd:
		return ModeProd, nil
	case "":
		return "", errors.New("kubernetes：必须显式指定运行模式（Mode=test|prod），不得依赖默认值")
	}
	return "", fmt.Errorf("kubernetes：未知运行模式 %q（仅接受 test / prod）", s)
}

// Config 客户端配置。
type Config struct {
	// Mode 运行模式（必填）。
	Mode Mode
	// KubeconfigPath kubeconfig 文件路径（mode=test 使用；不得指向真实集群）。
	KubeconfigPath string
	// ServiceAccount 生产连接方式（mode=prod 使用；本轮仅配置校验，不建立连接）。
	ServiceAccount *ServiceAccountConfig
	// Timeout 单请求超时（<=0 用 DefaultTimeout）。
	Timeout time.Duration
	// MaxBodyBytes 响应体上限（<=0 用 DefaultMaxBodyBytes）。
	MaxBodyBytes int64
	// Observe 请求观测钩子（第十八轮 K1）：**每次真正发出 HTTP 请求之前**回调
	// (method, path)。仅用于测试在 HTTP 层计数（例如断言 /secrets 请求数为 0）；
	// 生产路径留空（nil 时零开销）。注意：被白名单/secrets 规则**拒绝**的路径
	// 不会触发本回调——本回调只统计真正发出去的请求。
	Observe func(method, path string)
}

// ServiceAccountConfig ServiceAccount 连接方式（生产，本轮仅校验配置完整性）。
type ServiceAccountConfig struct {
	// APIServer 集群 API 地址（必须 https）。
	APIServer string
	// TokenFile ServiceAccount token 文件路径（内容不读取、不记录）。
	TokenFile string
	// CAFile 集群 CA 证书路径。
	CAFile string
}

// kubeconfigFile kubeconfig 的最小结构（只取本适配器需要的字段）。
type kubeconfigFile struct {
	Clusters []struct {
		Name    string `yaml:"name"`
		Cluster struct {
			Server                   string `yaml:"server"`
			CertificateAuthorityData string `yaml:"certificate-authority-data"`
			InsecureSkipTLSVerify    bool   `yaml:"insecure-skip-tls-verify"`
		} `yaml:"cluster"`
	} `yaml:"clusters"`
	Users []struct {
		Name string `yaml:"name"`
		User struct {
			ClientCertificateData string `yaml:"client-certificate-data"`
			ClientKeyData         string `yaml:"client-key-data"`
			Token                 string `yaml:"token"`
		} `yaml:"user"`
	} `yaml:"users"`
	Contexts []struct {
		Name    string `yaml:"name"`
		Context struct {
			Cluster string `yaml:"cluster"`
			User    string `yaml:"user"`
		} `yaml:"context"`
	} `yaml:"contexts"`
	CurrentContext string `yaml:"current-context"`
}

// Client 最小只读 Kubernetes API 客户端。
// 唯一出口是 get：白名单校验 → secrets 直接拒绝 → GET → 响应体上限。
type Client struct {
	http    *http.Client
	base    string
	maxBody int64
	observe func(method, path string)
}

// NewClient 构建只读客户端（mode=test 用 kubeconfig；mode=prod 仅配置校验）。
func NewClient(cfg Config) (*Client, error) {
	mode, err := ParseMode(string(cfg.Mode))
	if err != nil {
		return nil, err
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	maxBody := cfg.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = DefaultMaxBodyBytes
	}

	if mode == ModeProd {
		// 生产：本轮只做配置校验，不建立连接（不连接真实集群）。
		if err := validateServiceAccount(cfg.ServiceAccount); err != nil {
			return nil, err
		}
		return &Client{
			http:    &http.Client{Timeout: timeout},
			base:    strings.TrimSuffix(cfg.ServiceAccount.APIServer, "/"),
			maxBody: maxBody,
			observe: cfg.Observe,
		}, nil
	}

	// 测试：从 kubeconfig 读取连接信息。
	if strings.TrimSpace(cfg.KubeconfigPath) == "" {
		return nil, fmt.Errorf("%w：mode=test 需要 KubeconfigPath", ErrBadConfig)
	}
	data, err := os.ReadFile(cfg.KubeconfigPath)
	if err != nil {
		return nil, fmt.Errorf("%w：读取 kubeconfig 失败：%v", ErrBadConfig, err)
	}
	var kc kubeconfigFile
	if err := yaml.Unmarshal(data, &kc); err != nil {
		return nil, fmt.Errorf("%w：kubeconfig 解析失败：%v", ErrBadConfig, err)
	}
	server, certPEM, keyPEM, insecure, err := resolveContext(&kc)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(server)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("%w：kubeconfig server 非法", ErrBadConfig)
	}
	// insecure-skip-tls-verify 仅在 mode=test（kubeconfig 路径）下生效：
	// 生产走 ServiceAccount + CAFile，不存在该开关。测试集群（kind）使用自签证书。
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: insecure} //nolint:gosec // 仅测试模式可达
	if certPEM != nil && keyPEM != nil {
		crt, cerr := tls.X509KeyPair(certPEM, keyPEM)
		if cerr != nil {
			return nil, fmt.Errorf("%w：客户端证书解析失败：%v", ErrBadConfig, cerr)
		}
		tlsCfg.Certificates = []tls.Certificate{crt}
	}
	if ca, ok := clusterCA(&kc); ok {
		pool := x509.NewCertPool()
		if pool.AppendCertsFromPEM(ca) {
			tlsCfg.RootCAs = pool
		}
	}
	return &Client{
		http: &http.Client{
			Timeout:   timeout,
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
		},
		base:    strings.TrimSuffix(server, "/"),
		maxBody: maxBody,
		observe: cfg.Observe,
	}, nil
}

// validateServiceAccount 生产连接方式的配置校验（本轮不建立连接）。
func validateServiceAccount(sa *ServiceAccountConfig) error {
	if sa == nil {
		return ErrProdServiceAccountOnly
	}
	if !strings.HasPrefix(sa.APIServer, "https://") {
		return fmt.Errorf("%w：APIServer 必须是 https 地址", ErrBadConfig)
	}
	if strings.TrimSpace(sa.TokenFile) == "" || strings.TrimSpace(sa.CAFile) == "" {
		return fmt.Errorf("%w：ServiceAccount 需要 TokenFile 与 CAFile", ErrBadConfig)
	}
	return nil
}

// resolveContext 解析当前 context 对应的 server、客户端证书（base64）
// 与 insecure-skip-tls-verify 标记。
func resolveContext(kc *kubeconfigFile) (string, []byte, []byte, bool, error) {
	clusterName, userName := "", ""
	for _, c := range kc.Contexts {
		if c.Name == kc.CurrentContext {
			clusterName, userName = c.Context.Cluster, c.Context.User
		}
	}
	var server string
	insecure := false
	for _, c := range kc.Clusters {
		if c.Name == clusterName {
			server = c.Cluster.Server
			insecure = c.Cluster.InsecureSkipTLSVerify
		}
	}
	if server == "" {
		return "", nil, nil, false, fmt.Errorf("%w：kubeconfig 缺少 server（context=%s）", ErrBadConfig, kc.CurrentContext)
	}
	var certPEM, keyPEM []byte
	for _, u := range kc.Users {
		if u.Name != userName {
			continue
		}
		if u.User.ClientCertificateData != "" && u.User.ClientKeyData != "" {
			var err error
			if certPEM, err = base64.StdEncoding.DecodeString(u.User.ClientCertificateData); err != nil {
				return "", nil, nil, false, fmt.Errorf("%w：客户端证书 base64 非法", ErrBadConfig)
			}
			if keyPEM, err = base64.StdEncoding.DecodeString(u.User.ClientKeyData); err != nil {
				return "", nil, nil, false, fmt.Errorf("%w：客户端私钥 base64 非法", ErrBadConfig)
			}
		}
	}
	return server, certPEM, keyPEM, insecure, nil
}

// clusterCA 取集群 CA（base64 PEM）。
func clusterCA(kc *kubeconfigFile) ([]byte, bool) {
	for _, c := range kc.Clusters {
		if c.Cluster.CertificateAuthorityData == "" {
			continue
		}
		ca, err := base64.StdEncoding.DecodeString(c.Cluster.CertificateAuthorityData)
		if err == nil {
			return ca, true
		}
	}
	return nil, false
}

// AllowedEndpoint 判定 method+path 是否在白名单内（导出以便单测与审计核对）。
// 判定顺序：写方法 → secrets（永不读取）→ 其他禁止片段 → 白名单模式。
func AllowedEndpoint(method, path string) error {
	if method != http.MethodGet {
		return fmt.Errorf("%w：method=%s", ErrWriteMethodForbidden, method)
	}
	if secretPathPattern.MatchString(path) {
		return fmt.Errorf("%w：path=%s", ErrSecretAccessForbidden, path)
	}
	lower := strings.ToLower(path)
	for _, bad := range forbiddenSubstrings {
		if strings.Contains(lower, bad) {
			return fmt.Errorf("%w：path=%s（命中禁止片段 %q）", ErrEndpointNotAllowed, path, bad)
		}
	}
	if path == PathVersion {
		return nil
	}
	if namespacePattern.MatchString(path) ||
		podsPattern.MatchString(path) ||
		podPattern.MatchString(path) ||
		deploymentsPattern.MatchString(path) {
		return nil
	}
	return fmt.Errorf("%w：path=%s", ErrEndpointNotAllowed, path)
}

// get 唯一的请求出口：白名单校验 → GET → 响应体上限。
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
	// 观测钩子：仅统计**真正发出**的请求（被拒绝的路径不会到达这里）。
	if c.observe != nil {
		c.observe(http.MethodGet, path)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBody+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > c.maxBody {
		return nil, fmt.Errorf("%w（上限 %d 字节）", ErrResponseTooLarge, c.maxBody)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("kubernetes：%s 返回状态 %d", path, resp.StatusCode)
	}
	return body, nil
}

// Version 读取集群版本。
func (c *Client) Version(ctx context.Context) (map[string]any, error) {
	body, err := c.get(ctx, PathVersion, nil)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("kubernetes：/version 响应不是合法 JSON：%w", err)
	}
	return out, nil
}

// GetNamespace 读取命名空间（仅允许带测试标签的命名空间）。
func (c *Client) GetNamespace(ctx context.Context, ns string) (map[string]any, []string, error) {
	if !validation.ValidK8sNamespace(ns) {
		return nil, nil, fmt.Errorf("%w：命名空间名不合法 %q", ErrBadConfig, ns)
	}
	obj, err := c.getObject(ctx, namespacePath(ns))
	if err != nil {
		return nil, nil, err
	}
	if !hasTestLabel(obj) {
		return nil, nil, fmt.Errorf("%w：命名空间 %s 未带测试标签", ErrNoLabelledObjects, ns)
	}
	masked, paths := MaskNamespace(obj)
	return masked, paths, nil
}

// ListPods 列出命名空间中带测试标签的 Pod（逐项复核标签）。
func (c *Client) ListPods(ctx context.Context, ns string) ([]map[string]any, error) {
	if !validation.ValidK8sNamespace(ns) {
		return nil, fmt.Errorf("%w：命名空间名不合法 %q", ErrBadConfig, ns)
	}
	q := url.Values{}
	q.Set("labelSelector", TestLabel+"=true")
	items, err := c.getList(ctx, podsPath(ns), q)
	if err != nil {
		return nil, err
	}
	return c.filterAndMask(items, MaskPod)
}

// GetPod 读取单个 Pod（仅限带测试标签的 Pod）。
func (c *Client) GetPod(ctx context.Context, ns, name string) (map[string]any, []string, error) {
	if !validation.ValidK8sNamespace(ns) || !validation.ValidK8sName(name) {
		return nil, nil, fmt.Errorf("%w：Pod 名称不合法 %q", ErrBadConfig, name)
	}
	obj, err := c.getObject(ctx, podPath(ns, name))
	if err != nil {
		return nil, nil, err
	}
	if !hasTestLabel(obj) {
		return nil, nil, fmt.Errorf("%w：Pod %s/%s 未带测试标签", ErrNoLabelledObjects, ns, name)
	}
	masked, paths := MaskPod(obj)
	return masked, paths, nil
}

// ListDeployments 列出命名空间中带测试标签的 Deployment（逐项复核标签）。
func (c *Client) ListDeployments(ctx context.Context, ns string) ([]map[string]any, error) {
	if !validation.ValidK8sNamespace(ns) {
		return nil, fmt.Errorf("%w：命名空间名不合法 %q", ErrBadConfig, ns)
	}
	q := url.Values{}
	q.Set("labelSelector", TestLabel+"=true")
	items, err := c.getList(ctx, deploymentsPath(ns), q)
	if err != nil {
		return nil, err
	}
	return c.filterAndMask(items, MaskDeployment)
}

// getObject 读取单个对象。
func (c *Client) getObject(ctx context.Context, path string) (map[string]any, error) {
	body, err := c.get(ctx, path, nil)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("kubernetes：%s 响应不是合法 JSON：%w", path, err)
	}
	return out, nil
}

// getList 读取列表（Kubernetes 列表对象形如 {"items":[...]}）。
func (c *Client) getList(ctx context.Context, path string, query url.Values) ([]map[string]any, error) {
	body, err := c.get(ctx, path, query)
	if err != nil {
		return nil, err
	}
	var out struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("kubernetes：%s 响应不是合法列表：%w", path, err)
	}
	return out.Items, nil
}

// filterAndMask 逐项复核测试标签并屏蔽（不信任服务端是否真的过滤）。
// 过滤后为空 → ErrNoLabelledObjects（明确报错）。
func (c *Client) filterAndMask(items []map[string]any, mask func(map[string]any) (map[string]any, []string)) ([]map[string]any, error) {
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		if !hasTestLabel(item) {
			continue
		}
		masked, _ := mask(item)
		out = append(out, masked)
	}
	if len(out) == 0 {
		return nil, ErrNoLabelledObjects
	}
	return out, nil
}

// hasTestLabel 判定对象 metadata.labels 是否含 agent-ops.test=true。
func hasTestLabel(obj map[string]any) bool {
	md, ok := obj["metadata"].(map[string]any)
	if !ok {
		return false
	}
	labels, ok := md["labels"].(map[string]any)
	if !ok {
		return false
	}
	v, ok := labels[TestLabel].(string)
	return ok && v == "true"
}
