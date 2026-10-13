// JWKS 密钥集获取（第十九轮 A1）。
//
// 设计约束（仓库级守卫 ADR-013/ADR-014 的 H1）：出站 HTTP 只允许出现在
// `internal/repoguard` 的 AllowedHTTPFiles 登记文件里。因此本文件是
// grpcwire 中**唯一**发起 HTTP 的文件，且：
//   - 只使用 GET 方法（http.MethodGet 常量，不用字面量）；
//   - 不做任何 URL 字符串拼接（URL 由调用方以完整形态提供）；
//   - 响应体大小上限（防内存耗尽）；
//   - 返回体只含公钥（JWKS 中不含私钥），不记录任何敏感值。
//
// 其余 OIDC 逻辑（JWT 解析、签名与声明校验）在 oidc.go，该文件不 import
// 任何 HTTP 包，只依赖 JWKSFetcher 接口。
package grpcwire

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"
)

// JWK 一个 JWK 公钥（只取本实现需要的字段）。
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	// RSA 参数（base64url 大整数）。
	N string `json:"n"`
	E string `json:"e"`
}

// JWKS 公钥集合。
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// MaxJWKSBodyBytes JWKS 响应体上限（工程默认 1MB）。
const MaxJWKSBodyBytes int64 = 1 << 20

// DefaultJWKSTimeout JWKS 请求超时（工程默认 10 秒）。
const DefaultJWKSTimeout = 10 * time.Second

// ParseJWKS 解析 JWKS JSON 并返回 kid → 公钥映射（只接受 RSA 公钥）。
// 重复 kid：保留第一个，后者忽略并报错（fail-closed：不做"最后覆盖"的猜测）。
func ParseJWKS(raw []byte) (map[string]*rsa.PublicKey, error) {
	var set JWKS
	if err := json.Unmarshal(raw, &set); err != nil {
		return nil, fmt.Errorf("grpcwire：JWKS 解析失败：%w", err)
	}
	out := make(map[string]*rsa.PublicKey, len(set.Keys))
	for i, k := range set.Keys {
		if strings.TrimSpace(k.Kid) == "" {
			return nil, fmt.Errorf("grpcwire：JWKS 第 %d 个密钥缺少 kid", i)
		}
		if _, dup := out[k.Kid]; dup {
			return nil, fmt.Errorf("grpcwire：JWKS 中 kid %q 重复", k.Kid)
		}
		pub, err := jwkToRSAPublic(k)
		if err != nil {
			return nil, err
		}
		out[k.Kid] = pub
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("grpcwire：JWKS 不含任何可用公钥")
	}
	return out, nil
}

// jwkToRSAPublic 把 JWK 的 modulus/exponent 转为 RSA 公钥。
// 只接受 kty=RSA 且 alg 为 RS256（缺省 alg 视为 RS256，由 JWK.use=sig 佐证）。
func jwkToRSAPublic(k JWK) (*rsa.PublicKey, error) {
	if !strings.EqualFold(strings.TrimSpace(k.Kty), "RSA") {
		return nil, fmt.Errorf("grpcwire：JWKS 密钥 %q 只支持 RSA（实际 kty=%q）", k.Kid, k.Kty)
	}
	alg := strings.TrimSpace(k.Alg)
	if alg != "" && alg != "RS256" {
		return nil, fmt.Errorf("grpcwire：JWKS 密钥 %q 只支持 RS256（实际 alg=%q）", k.Kid, alg)
	}
	nb, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(k.N, "="))
	if err != nil {
		return nil, fmt.Errorf("grpcwire：JWKS 密钥 %q 的 n 不是合法 base64url：%w", k.Kid, err)
	}
	eb, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(k.E, "="))
	if err != nil {
		return nil, fmt.Errorf("grpcwire：JWKS 密钥 %q 的 e 不是合法 base64url：%w", k.Kid, err)
	}
	n := new(big.Int).SetBytes(nb)
	if n.Sign() <= 0 {
		return nil, fmt.Errorf("grpcwire：JWKS 密钥 %q 的 n 非法", k.Kid)
	}
	e := 0
	for _, b := range eb {
		e = e<<8 | int(b)
	}
	if e <= 0 {
		return nil, fmt.Errorf("grpcwire：JWKS 密钥 %q 的 e 非法", k.Kid)
	}
	return &rsa.PublicKey{N: n, E: e}, nil
}

// JWKSFetcher JWKS 获取器：返回 JWKS JSON 字节。
// 实现方负责传输（HTTP 或本地文件）；oidc.go 只依赖本接口，不引入任何 HTTP 包。
type JWKSFetcher interface {
	JWKS(ctx context.Context) ([]byte, error)
}

// HTTPJWKSFetcher 经（本地）HTTP 拉取 JWKS；URL 必须由调用方完整提供，
// 本类型不做任何拼接（仓库级守卫要求）。
type HTTPJWKSFetcher struct {
	url    string
	client *http.Client
}

// NewHTTPJWKSFetcher 构建 HTTP JWKS 获取器。
func NewHTTPJWKSFetcher(url string, timeout time.Duration) *HTTPJWKSFetcher {
	if timeout <= 0 {
		timeout = DefaultJWKSTimeout
	}
	return &HTTPJWKSFetcher{url: url, client: &http.Client{Timeout: timeout}}
}

// JWKS 拉取 JWKS（GET；响应体上限 MaxJWKSBodyBytes）。
func (f *HTTPJWKSFetcher) JWKS(ctx context.Context) ([]byte, error) {
	if f == nil || strings.TrimSpace(f.url) == "" {
		return nil, fmt.Errorf("grpcwire：JWKS URL 为空")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.url, nil)
	if err != nil {
		return nil, fmt.Errorf("grpcwire：构造 JWKS 请求失败：%w", err)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("grpcwire：拉取 JWKS 失败：%w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("grpcwire：JWKS 端点返回状态 %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxJWKSBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("grpcwire：读取 JWKS 响应失败：%w", err)
	}
	if int64(len(body)) > MaxJWKSBodyBytes {
		return nil, fmt.Errorf("grpcwire：JWKS 响应体超过上限（%d 字节）", MaxJWKSBodyBytes)
	}
	return body, nil
}

// FileJWKSFetcher 从本地文件读取 JWKS（便于离线与环境自举；仅测试/自托管场景）。
type FileJWKSFetcher struct{ path string }

// NewFileJWKSFetcher 构建本地文件 JWKS 获取器。
func NewFileJWKSFetcher(path string) *FileJWKSFetcher { return &FileJWKSFetcher{path: path} }

// JWKS 读取本地 JWKS 文件（同受 MaxJWKSBodyBytes 上限约束）。
func (f *FileJWKSFetcher) JWKS(context.Context) ([]byte, error) {
	if f == nil || strings.TrimSpace(f.path) == "" {
		return nil, fmt.Errorf("grpcwire：JWKS 文件路径为空")
	}
	body, err := os.ReadFile(f.path)
	if err != nil {
		return nil, fmt.Errorf("grpcwire：读取 JWKS 文件失败：%w", err)
	}
	if int64(len(body)) > MaxJWKSBodyBytes {
		return nil, fmt.Errorf("grpcwire：JWKS 文件超过上限（%d 字节）", MaxJWKSBodyBytes)
	}
	return body, nil
}

// 编译期断言：两个获取器都满足接口。
var (
	_ JWKSFetcher = (*HTTPJWKSFetcher)(nil)
	_ JWKSFetcher = (*FileJWKSFetcher)(nil)
)

// ParseRSAPublicKeyPEM 便于测试与自托管场景从 PKIX PEM 构造公钥（仅公钥）。
// 私钥一律不进本函数：仓库中不允许出现 PEM 私钥文件。
func ParseRSAPublicKeyPEM(pem []byte) (*rsa.PublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(pem)
	if err != nil {
		return nil, fmt.Errorf("grpcwire：解析公钥 PEM 失败：%w", err)
	}
	rp, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("grpcwire：PEM 不是 RSA 公钥（实际 %T）", pub)
	}
	return rp, nil
}
