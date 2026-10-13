package console

// 鉴权（ADR-024 §3，沿用 ADR-019 的 OIDC 规则）。
//
// 只用 Go 标准库（crypto/rsa、crypto/sha256、encoding/base64、encoding/json），
// **不引入任何第三方 JWT/JWKS 库**——与 ADR-019 的裁决一致。
//
// 对外失败原因只有一个：ErrAuth。所有细分原因（alg 不对、kid 缺失、过期、
// iss/aud 不符、验签失败）都归并成它，HTTP 层据此返回 401 且**不回显原因**，
// 避免把"你的 token 差在哪一步"告诉攻击者。

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrAuth 唯一的鉴权失败原因（对外不区分细节）。
var ErrAuth = errors.New("console：鉴权失败")

// ErrStaticTokenInProd 生产模式配置静态令牌（启动即失败）。
var ErrStaticTokenInProd = errors.New("console：生产模式拒绝静态令牌，必须使用 OIDC")

// ErrNoKeySource 既没有 JWKS 来源也没有（测试模式的）静态令牌。
var ErrNoKeySource = errors.New("console：缺少鉴权材料（JWKS 来源或测试静态令牌）")

// KeySource 提供 kid → RSA 公钥。
//
// 由调用方注入：测试用合成 JWKS 夹具（运行时生成、仅存内存）；
// 生产由控制层的 JWKS 拉取通道提供（ADR-019 的限速与刷新规则在那一侧实现，
// 本包**不发起任何出站 HTTP**——见 ADR-024 §3 与 repoguard 的出站禁令）。
type KeySource interface {
	// Keys 返回当前可用的 kid → 公钥集合。
	Keys(ctx context.Context) (map[string]*rsa.PublicKey, error)
}

// AuthConfig 鉴权配置。
type AuthConfig struct {
	// Mode 运行模式。
	Mode Mode
	// Issuer 期望的 iss（**精确匹配**，ADR-019）。
	Issuer string
	// Audience 期望的 aud（**精确匹配**）。
	Audience string
	// Skew 时钟偏差容忍（<=0 用 DefaultClockSkew）。
	Skew time.Duration
	// Keys JWKS 来源（nil 且无 StaticToken 时 Validate 失败）。
	Keys KeySource
	// StaticToken **仅测试模式**允许的固定令牌，便于夹具测试；生产模式给它就报错。
	StaticToken string
	// Now 注入时钟（测试用）。
	Now func() time.Time
}

// Validate 校验配置。生产模式带静态令牌 → 启动即失败（硬性要求）。
func (a AuthConfig) Validate() error {
	if a.Mode != ModeTest && a.Mode != ModeProd {
		return fmt.Errorf("%w：%q", ErrBadMode, string(a.Mode))
	}
	if a.Mode == ModeProd && strings.TrimSpace(a.StaticToken) != "" {
		return ErrStaticTokenInProd
	}
	if a.Mode == ModeProd && a.Keys == nil {
		return ErrNoKeySource
	}
	if a.Keys == nil && strings.TrimSpace(a.StaticToken) == "" {
		return ErrNoKeySource
	}
	if a.Mode == ModeProd && (a.Issuer == "" || a.Audience == "") {
		return errors.New("console：生产模式必须配置 iss 与 aud")
	}
	return nil
}

// Verifier 令牌验证器。
type Verifier struct {
	cfg AuthConfig
}

// NewVerifier 构造验证器（先 Validate）。
func NewVerifier(cfg AuthConfig) (*Verifier, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if cfg.Skew <= 0 {
		cfg.Skew = DefaultClockSkew
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Verifier{cfg: cfg}, nil
}

// StaticTokenConfigured 报告是否在用测试静态令牌（供健康检查/文档披露）。
func (v *Verifier) StaticTokenConfigured() bool {
	return strings.TrimSpace(v.cfg.StaticToken) != ""
}

// Authenticate 校验 Authorization 头的值并返回 actor（令牌里的 sub）。
//
// 入参是**头部原值**（本包不碰 net/http，取头的工作在 HTTP 层）。
// 任何一步失败都返回 ErrAuth，不返回细节。
func (v *Verifier) Authenticate(ctx context.Context, authorization string) (string, error) {
	// 严格 scheme：必须是 "Bearer " 前缀（裸令牌不接受）。
	// 这不是吹毛求疵：宽容的解析会让"忘了写 Bearer"的客户端静默工作，
	// 而后在真正需要 scheme 的网关上突然失败。
	const scheme = "Bearer "
	auth := strings.TrimSpace(authorization)
	if !strings.HasPrefix(auth, scheme) {
		return "", ErrAuth
	}
	token := strings.TrimSpace(strings.TrimPrefix(auth, scheme))
	if token == "" {
		return "", ErrAuth
	}
	// 测试模式的静态令牌：常量时间比较，actor 固定为可识别的测试主体。
	if v.StaticTokenConfigured() {
		if subtle.ConstantTimeCompare([]byte(token), []byte(v.cfg.StaticToken)) != 1 {
			return "", ErrAuth
		}
		return "test-console-operator", nil
	}
	if v.cfg.Keys == nil {
		return "", ErrAuth
	}
	claims, err := v.verifyOIDC(ctx, token)
	if err != nil {
		return "", err
	}
	return claims.Subject, nil
}

// jwtClaims 只解析本场景需要的声明。
type jwtClaims struct {
	Issuer   string          `json:"iss"`
	Audience json.RawMessage `json:"aud"`
	Expiry   int64           `json:"exp"`
	IssuedAt int64           `json:"iat"`
	Subject  string          `json:"sub"`
}

// audience 支持 aud 为字符串或字符串数组两种编码（OIDC 都允许）。
func (c jwtClaims) audience() []string {
	raw := strings.TrimSpace(string(c.Audience))
	if raw == "" {
		return nil
	}
	if raw[0] == '[' {
		var list []string
		if err := json.Unmarshal(c.Audience, &list); err != nil {
			return nil
		}
		return list
	}
	var one string
	if err := json.Unmarshal(c.Audience, &one); err != nil {
		return nil
	}
	return []string{one}
}

func (v *Verifier) verifyOIDC(ctx context.Context, token string) (jwtClaims, error) {
	var zero jwtClaims
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return zero, ErrAuth
	}
	headerRaw, err := decodeSegment(parts[0])
	if err != nil {
		return zero, ErrAuth
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerRaw, &header); err != nil {
		return zero, ErrAuth
	}
	// 只接受 RS256：挡掉 alg=none 与 HS256 两类常见混淆攻击。
	if header.Alg != "RS256" || header.Kid == "" {
		return zero, ErrAuth
	}
	payloadRaw, err := decodeSegment(parts[1])
	if err != nil {
		return zero, ErrAuth
	}
	var claims jwtClaims
	if err := json.Unmarshal(payloadRaw, &claims); err != nil {
		return zero, ErrAuth
	}
	sig, err := decodeSegment(parts[2])
	if err != nil {
		return zero, ErrAuth
	}

	keys, kerr := v.cfg.Keys.Keys(ctx)
	if kerr != nil {
		return zero, ErrAuth
	}
	pub, ok := keys[header.Kid]
	if !ok {
		return zero, ErrAuth // kid 必须在 JWKS 中
	}
	signed := parts[0] + "." + parts[1]
	digest := sha256.Sum256([]byte(signed))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		return zero, ErrAuth
	}

	// exp 必填（缺失或为 0 一律拒绝）；偏差窗口容忍。
	if claims.Expiry == 0 {
		return zero, ErrAuth
	}
	now := v.cfg.Now()
	if !now.Before(claims.exp().Add(v.cfg.Skew)) {
		return zero, ErrAuth
	}
	// iss / aud 精确匹配。
	if v.cfg.Issuer != "" && claims.Issuer != v.cfg.Issuer {
		return zero, ErrAuth
	}
	if v.cfg.Audience != "" && !containsExact(claims.audience(), v.cfg.Audience) {
		return zero, ErrAuth
	}
	if strings.TrimSpace(claims.Subject) == "" {
		return zero, ErrAuth
	}
	return claims, nil
}

// exp 把 unix 秒转成 time.Time。
func (c jwtClaims) exp() time.Time { return time.Unix(c.Expiry, 0) }

// decodeSegment base64url（无填充）解码。
func decodeSegment(s string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		// 有些实现会带填充，重试一次带填充的解码。
		pad := s
		if m := len(s) % 4; m != 0 {
			pad += strings.Repeat("=", 4-m)
		}
		raw, err = base64.URLEncoding.DecodeString(pad)
		if err != nil {
			return nil, err
		}
	}
	return raw, nil
}

// containsExact 精确匹配（不做前缀/子串比较）。
func containsExact(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
