// OIDC 生产认证（第十九轮 A1）：mode=prod 的 gRPC 入口使用 OIDC 访问令牌。
//
// 校验链（顺序固定，任一不过即 UNAUTHENTICATED）：
//
//	① authorization: Bearer <compact JWS>（格式）
//	② JOSE header 的 alg 必须**恰好**是 RS256（拒绝 none / HS* / 其他）
//	③ kid 必须存在，且必须能在 JWKS 中找到对应 RSA 公钥
//	④ RSASSA-PKCS1-v1_5 + SHA-256 签名校验
//	⑤ iss 与 aud **精确匹配**配置值
//	⑥ exp / nbf 经注入时钟校验，允许 ±ClockSkew（默认 60s）偏差
//	⑦ sub 非空 → actor；**永不**接受请求体或自报头里的 actor
//
// 安全约束：
//   - 令牌、密钥、错误细节**不进入日志/错误/审计**（错误只给固定文案，
//     避免凭据探测）；
//   - 只信任 JWKS 里的 RSA 公钥；不支持 JWKS 加密（JWE）；
//   - 本文件不 import 任何 HTTP 包——JWKS 传输由 JWKSFetcher 抽象提供
//     （出站 HTTP 的登记位置见 internal/repoguard.AllowedHTTPFiles）。
//
// mode=test 下仍使用 StaticTokenAuth（ADR-011 / 第十一轮 H3），
// OIDC 在 test 模式可选启用但不替代静态令牌的启动校验。
package grpcwire

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/metadata"
)

// OIDC 相关错误（对外只回固定文案，不泄露细节）。
var (
	// ErrOIDCMissingToken 缺少 Authorization 头或不是 Bearer 形式。
	ErrOIDCMissingToken = errors.New("grpcwire：缺少 OIDC 承载令牌")
	// ErrOIDCMalformedToken 令牌结构不是三段 compact JWS。
	ErrOIDCMalformedToken = errors.New("grpcwire：OIDC 令牌结构非法")
	// ErrOIDCUnsupportedAlg alg 不是 RS256。
	ErrOIDCUnsupportedAlg = errors.New("grpcwire：OIDC 令牌 alg 必须是 RS256")
	// ErrOIDCMissingKid header 缺少 kid。
	ErrOIDCMissingKid = errors.New("grpcwire：OIDC 令牌 header 缺少 kid")
	// ErrOIDCUnknownKey kid 不在 JWKS 中。
	ErrOIDCUnknownKey = errors.New("grpcwire：OIDC 令牌 kid 不在 JWKS 中")
	// ErrOIDCBadSignature 签名校验失败。
	ErrOIDCBadSignature = errors.New("grpcwire：OIDC 令牌签名校验失败")
	// ErrOIDCBadIssuer iss 不匹配。
	ErrOIDCBadIssuer = errors.New("grpcwire：OIDC 令牌 issuer 不匹配")
	// ErrOIDCBadAudience aud 不匹配。
	ErrOIDCBadAudience = errors.New("grpcwire：OIDC 令牌 audience 不匹配")
	// ErrOIDCExpired 已过期（超出时钟偏差）。
	ErrOIDCExpired = errors.New("grpcwire：OIDC 令牌已过期")
	// ErrOIDCMissingExpiry 令牌缺少 exp（O2：fail-closed，一律拒绝）。
	ErrOIDCMissingExpiry = errors.New("grpcwire：OIDC 令牌缺少 exp（必须声明过期时间）")
	// ErrOIDCNotYetValid 尚未生效（超出时钟偏差）。
	ErrOIDCNotYetValid = errors.New("grpcwire：OIDC 令牌尚未生效")
	// ErrOIDCRefreshRateLimited 未知 kid 触发的 JWKS 刷新被限速拒绝（O1）。
	ErrOIDCRefreshRateLimited = errors.New("grpcwire：JWKS 刷新被限速（距上次刷新不足最小间隔），拒绝该令牌且未发起外部请求")
	// ErrOIDCMissingSubject 缺少 sub。
	ErrOIDCMissingSubject = errors.New("grpcwire：OIDC 令牌缺少 subject")
	// ErrOIDCNotConfigured 配置不完整。
	ErrOIDCNotConfigured = errors.New("grpcwire：OIDC 配置不完整")
)

// DefaultClockSkew 允许的时钟偏差（A1 裁决：60 秒）。
const DefaultClockSkew = 60 * time.Second

// DefaultRefreshInterval 未知 kid 触发 JWKS 刷新的最小间隔（第二十轮 O1：30 秒）。
//
// 为什么需要：未知 kid 会触发一次外部 JWKS 请求；若不限速，攻击者可用随机 kid
// 制造大量外部请求（放大攻击 / 打爆 issuer 端点）。因此两次"由未知 kid 触发"
// 的刷新之间必须间隔 ≥ DefaultRefreshInterval。
const DefaultRefreshInterval = 30 * time.Second

// OIDCConfig OIDC 认证配置（mode=prod 使用）。
type OIDCConfig struct {
	// Issuer 期望的 iss（精确匹配）。
	Issuer string
	// Audience 期望的 aud（精确匹配）。
	Audience string
	// ClockSkew 允许的时钟偏差（<=0 用 DefaultClockSkew）。
	ClockSkew time.Duration
	// RefreshInterval 未知 kid 触发 JWKS 刷新的最小间隔（<=0 用
	// DefaultRefreshInterval=30s）。O1 限速，防止随机 kid 放大外部请求。
	RefreshInterval time.Duration
	// Now 注入时钟（测试用）；nil 用 time.Now。
	Now func() time.Time
	// Fetcher JWKS 获取器（必填）。
	Fetcher JWKSFetcher
}

// OIDCAuth OIDC 访问令牌认证（生产）。
type OIDCAuth struct {
	cfg     OIDCConfig
	skew    time.Duration
	fetcher JWKSFetcher
	// refreshInterval 未知 kid 触发刷新的最小间隔（O1）。
	refreshInterval time.Duration

	mu   sync.RWMutex
	keys map[string]*rsa.PublicKey // kid → 公钥（懒加载 + 未知 kid 时刷新）
	// lastRefresh 上一次**真正发起** JWKS 请求的时刻（O1 限速用）。
	lastRefresh time.Time
	// refreshCount 累计真正发起的 JWKS 请求次数（测试与运维核对）。
	refreshCount int
}

// NewOIDCAuth 构建 OIDC 认证；配置不完整即报错（fail-closed）。
func NewOIDCAuth(cfg OIDCConfig) (*OIDCAuth, error) {
	if strings.TrimSpace(cfg.Issuer) == "" || strings.TrimSpace(cfg.Audience) == "" {
		return nil, fmt.Errorf("%w：issuer 与 audience 必填", ErrOIDCNotConfigured)
	}
	if cfg.Fetcher == nil {
		return nil, fmt.Errorf("%w：缺少 JWKS 获取器", ErrOIDCNotConfigured)
	}
	skew := cfg.ClockSkew
	if skew <= 0 {
		skew = DefaultClockSkew
	}
	refreshInterval := cfg.RefreshInterval
	if refreshInterval <= 0 {
		refreshInterval = DefaultRefreshInterval
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	a := &OIDCAuth{
		cfg: cfg, skew: skew, fetcher: cfg.Fetcher,
		refreshInterval: refreshInterval,
		keys:            map[string]*rsa.PublicKey{},
	}
	// 启动即拉取一次 JWKS：配置/网络问题在启动期暴露，而不是首个请求才失败。
	// 注意：这里必须直接 reload，不能用 keysFor("")——空 kid 会被当成"未知 kid"。
	ctx, cancel := context.WithTimeout(context.Background(), DefaultJWKSTimeout)
	defer cancel()
	if err := a.reload(ctx); err != nil {
		return nil, fmt.Errorf("grpcwire：初始化 JWKS 失败：%w", err)
	}
	a.cfg.Now = now
	return a, nil
}

// Authenticate 解析并校验 OIDC 访问令牌，返回 actor（= sub）。
func (a *OIDCAuth) Authenticate(ctx context.Context) (string, error) {
	if a == nil || a.fetcher == nil {
		return "", ErrUnauthenticated
	}
	token, err := bearerToken(ctx)
	if err != nil {
		return "", err
	}
	// alg=none 的令牌签名段为空：先解析 header 判定 alg（给出精确拒绝原因），
	// 再走通用结构校验——这样 "alg=none" 不会被笼统报成"结构非法"。
	if alg, _, ok := peekAlgAndKid(token); ok && alg != "RS256" {
		return "", ErrOIDCUnsupportedAlg
	}
	header, payload, sig, err := splitCompactJWS(token)
	if err != nil {
		return "", err
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(header, &hdr); err != nil {
		return "", fmt.Errorf("%w：header 解析失败", ErrOIDCMalformedToken)
	}
	// ② alg 必须恰好 RS256（拒绝 none / HS* / RS512 等一切其他值）。
	if hdr.Alg != "RS256" {
		return "", ErrOIDCUnsupportedAlg
	}
	if strings.TrimSpace(hdr.Kid) == "" {
		return "", ErrOIDCMissingKid
	}
	// ③ + ④ kid → 公钥 → 签名校验（未知 kid 时刷新一次并重试）。
	key, err := a.keysFor(ctx, hdr.Kid)
	if err != nil || key == nil {
		return "", err
	}
	signingInput := token[:strings.LastIndex(token, ".")]
	if err := verifyRS256(key, signingInput, sig); err != nil {
		return "", err
	}
	// ⑤⑥⑦ 声明校验。
	var cl struct {
		Iss string          `json:"iss"`
		Sub string          `json:"sub"`
		Aud json.RawMessage `json:"aud"`
		Exp int64           `json:"exp"`
		Nbf int64           `json:"nbf"`
	}
	if err := json.Unmarshal(payload, &cl); err != nil {
		return "", fmt.Errorf("%w：payload 解析失败", ErrOIDCMalformedToken)
	}
	now := a.now().UTC()
	if cl.Iss != a.cfg.Issuer {
		return "", ErrOIDCBadIssuer
	}
	if !audienceMatches(cl.Aud, a.cfg.Audience) {
		return "", ErrOIDCBadAudience
	}
	if cl.Exp <= 0 {
		// O2：exp 必填（fail-closed）。缺失或非正数一律拒绝——放宽为"不判定过期"
		// 等于接受永不失效的令牌，不可接受。nbf 仍可选（见下）。
		return "", ErrOIDCMissingExpiry
	}
	if now.After(time.Unix(cl.Exp, 0).Add(a.skew)) {
		return "", ErrOIDCExpired
	}
	// nbf 可选：缺失（0）时不做未生效判定。
	if cl.Nbf > 0 && now.Before(time.Unix(cl.Nbf, 0).Add(-a.skew)) {
		return "", ErrOIDCNotYetValid
	}
	if strings.TrimSpace(cl.Sub) == "" {
		return "", ErrOIDCMissingSubject
	}
	return strings.TrimSpace(cl.Sub), nil
}

func (a *OIDCAuth) now() time.Time {
	if a.cfg.Now != nil {
		return a.cfg.Now()
	}
	return time.Now()
}

// keysFor 取 kid 对应公钥。
//
// 已知 kid：直接命中缓存（**不受限速影响**，O1 ④）。
// 未知 kid：允许触发一次 JWKS 刷新，但两次刷新之间必须间隔 ≥ refreshInterval
// （O1：30 秒）；间隔不足时**直接拒绝且不发起任何外部请求**（防随机 kid 放大）。
func (a *OIDCAuth) keysFor(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	a.mu.RLock()
	key, ok := a.keys[kid]
	a.mu.RUnlock()
	if ok {
		return key, nil
	}
	if !a.allowRefresh() {
		return nil, ErrOIDCRefreshRateLimited
	}
	if err := a.reload(ctx); err != nil {
		return nil, err
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	key, ok = a.keys[kid]
	if !ok {
		return nil, ErrOIDCUnknownKey
	}
	return key, nil
}

// allowRefresh 判定此刻是否允许发起 JWKS 刷新（O1 限速闸门）。
// 允许时**立即**占用本次配额（先占位再请求，避免并发请求同时通过闸门）。
func (a *OIDCAuth) allowRefresh() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.lastRefresh.IsZero() && a.now().Sub(a.lastRefresh) < a.refreshInterval {
		return false
	}
	a.lastRefresh = a.now()
	return true
}

// RefreshCount 返回累计真正发起的 JWKS 请求次数（供测试与运维核对）。
func (a *OIDCAuth) RefreshCount() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.refreshCount
}

// reload 重新拉取并解析 JWKS（替换整个缓存；解析失败保留旧缓存）。
// 注意：本函数**不做限速**（限速在 allowRefresh 中完成），启动期初始化直接调用。
func (a *OIDCAuth) reload(ctx context.Context) error {
	raw, err := a.fetcher.JWKS(ctx)
	a.mu.Lock()
	a.refreshCount++
	a.lastRefresh = a.now()
	a.mu.Unlock()
	if err != nil {
		return fmt.Errorf("%w：%v", ErrUnauthenticated, err)
	}
	keys, err := ParseJWKS(raw)
	if err != nil {
		return err
	}
	a.mu.Lock()
	a.keys = keys
	a.mu.Unlock()
	return nil
}

// KeyCount 返回当前缓存的公钥数（供测试与运维核对）。
func (a *OIDCAuth) KeyCount() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.keys)
}

// bearerToken 从 gRPC metadata 提取 Bearer 令牌。
func bearerToken(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", ErrOIDCMissingToken
	}
	vals := md.Get(MetaAuthorization)
	if len(vals) == 0 {
		return "", ErrOIDCMissingToken
	}
	raw := strings.TrimSpace(vals[0])
	if len(raw) < 7 || !strings.EqualFold(raw[:7], "bearer ") {
		return "", ErrOIDCMissingToken
	}
	token := strings.TrimSpace(raw[7:])
	if token == "" {
		return "", ErrOIDCMissingToken
	}
	return token, nil
}

// peekAlgAndKid 在**不要求签名段存在**的前提下读取 header 的 alg 与 kid。
// 用于在结构校验之前给出精确的 alg 拒绝原因（alg=none 的签名段为空）。
func peekAlgAndKid(token string) (alg, kid string, ok bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" {
		return "", "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", "", false
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(raw, &hdr); err != nil {
		return "", "", false
	}
	return hdr.Alg, hdr.Kid, true
}

// splitCompactJWS 拆成 header / payload / signature（三段，均 base64url 无填充）。
func splitCompactJWS(token string) (header, payload, sig []byte, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return nil, nil, nil, ErrOIDCMalformedToken
	}
	header, err = base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w：header base64 非法", ErrOIDCMalformedToken)
	}
	payload, err = base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w：payload base64 非法", ErrOIDCMalformedToken)
	}
	sig, err = base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w：signature base64 非法", ErrOIDCMalformedToken)
	}
	return header, payload, sig, nil
}

// verifyRS256 RSASSA-PKCS1-v1_5 + SHA-256 校验。
func verifyRS256(key *rsa.PublicKey, signingInput string, sig []byte) error {
	if key == nil {
		return ErrOIDCUnknownKey
	}
	sum := sha256.Sum256([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, sum[:], sig); err != nil {
		return ErrOIDCBadSignature
	}
	return nil
}

// audienceMatches aud 可以是字符串或字符串数组（RFC 7519）；精确匹配任一即通过。
func audienceMatches(raw json.RawMessage, want string) bool {
	if len(raw) == 0 {
		return false
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return single == want
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err != nil {
		return false
	}
	for _, v := range many {
		if v == want {
			return true
		}
	}
	return false
}
