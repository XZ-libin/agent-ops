package grpcwire

// OIDC 单元测试（第十九轮 A2）。
//
// 密钥在**运行时生成**（RSA 2048），JWKS 由 httptest 在本地提供；
// 任何私钥/令牌都不落盘、不进仓库（硬性约束 1 与 7）。
//
// 12 个必测用例与 A1 的校验项一一对应：
//
//	① 有效令牌通过，actor = sub
//	② 签名错误被拒绝
//	③ alg=none 被拒绝
//	④ alg=HS256 被拒绝
//	⑤ kid 不在 JWKS 中被拒绝
//	⑥ iss 错误被拒绝
//	⑦ aud 错误被拒绝
//	⑧ 过期令牌被拒绝
//	⑨ 时钟偏差 60 秒内通过、超出被拒绝
//	⑩ mode=prod 下静态令牌启动失败
//	⑪ 请求体/自报 actor 字段被忽略
//	⑫ 生产模式执行请求返回未实现错误，且不写执行记录

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/metadata"
)

// advance 推进注入时钟（O1/O2 的时间相关断言用）。
func (f *testFixture) advance(d time.Duration) { f.now = f.now.Add(d) }

// newIncomingCtx 构造带进站 metadata 的上下文（模拟 gRPC 服务端收到的请求）。
func newIncomingCtx(md map[string][]string) context.Context {
	return metadata.NewIncomingContext(context.Background(), metadata.MD(md))
}

// cryptoSHA256 sha256 的 crypto.Hash 形态（供 rsa.SignPKCS1v15 使用）。
func cryptoSHA256() crypto.Hash { return crypto.SHA256 }

// testFixture 运行时生成的密钥与本地 JWKS。
type testFixture struct {
	priv   *rsa.PrivateKey
	pub    *rsa.PublicKey
	kid    string
	jwks   []byte
	srv    *httptest.Server
	hits   int
	now    time.Time
	issuer string
	aud    string
}

// newTestFixture 生成 RSA 密钥并在本地起 JWKS 端点。
func newTestFixture(t *testing.T) *testFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成 RSA 密钥失败：%v", err)
	}
	f := &testFixture{
		priv: key, pub: &key.PublicKey, kid: "k-r19-1",
		now: time.Unix(1791825000, 0), issuer: "https://issuer.invalid", aud: "agent-ops-gateway",
	}
	jwksRaw, err := buildJWKS(f.kid, &key.PublicKey)
	if err != nil {
		t.Fatalf("构造 JWKS 失败：%v", err)
	}
	f.jwks = jwksRaw
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		f.hits++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(f.jwks)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

// buildJWKS 由 RSA 公钥构造 JWKS JSON（只含公钥参数）。
func buildJWKS(kid string, pub *rsa.PublicKey) ([]byte, error) {
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}) // 65537
	doc := map[string]any{"keys": []map[string]string{{
		"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig", "n": n, "e": e,
	}}}
	return json.Marshal(doc)
}

// newAuth 构建指向本地 JWKS 的 OIDCAuth（时钟固定）。
func (f *testFixture) newAuth(t *testing.T) *OIDCAuth {
	t.Helper()
	a, err := NewOIDCAuth(OIDCConfig{
		Issuer: f.issuer, Audience: f.aud,
		Fetcher: NewHTTPJWKSFetcher(f.srv.URL, 0),
		Now:     func() time.Time { return f.now },
	})
	if err != nil {
		t.Fatalf("构建 OIDCAuth 失败：%v", err)
	}
	return a
}

// authCtx 带 authorization metadata 的上下文。
func authCtx(token string) context.Context {
	md := map[string][]string{MetaAuthorization: {"Bearer " + token}}
	// 借 grpc metadata 的进站上下文构造方式：直接放 incoming md。
	return newIncomingCtx(md)
}

// signToken 用给定算法签发令牌（alg 可为 none/HS256 以测试拒绝路径）。
func (f *testFixture) signToken(t *testing.T, alg, kid string, claims map[string]any) string {
	t.Helper()
	hdr := map[string]any{"alg": alg, "typ": "JWT"}
	if kid != "" {
		hdr["kid"] = kid
	}
	h, err := json.Marshal(hdr)
	if err != nil {
		t.Fatal(err)
	}
	p, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(p)
	var sig []byte
	switch strings.ToUpper(alg) {
	case "NONE":
		sig = nil
	case "HS256":
		mac := sha256.Sum256([]byte("not-a-real-secret"))
		sig = mac[:]
	default: // RS256
		sum := sha256.Sum256([]byte(signingInput))
		sig, err = rsa.SignPKCS1v15(rand.Reader, f.priv, cryptoSHA256(), sum[:])
		if err != nil {
			t.Fatalf("签名失败：%v", err)
		}
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// baseClaims 生成一组合法声明（exp/nbf 相对固定时钟）。
func (f *testFixture) baseClaims() map[string]any {
	return map[string]any{
		"iss": f.issuer, "aud": f.aud, "sub": "operator-alice",
		"iat": f.now.Add(-time.Minute).Unix(),
		"nbf": f.now.Add(-time.Minute).Unix(),
		"exp": f.now.Add(10 * time.Minute).Unix(),
	}
}

// TestOIDCValidTokenAcceptsActorFromSub（A2 ①）有效令牌通过，actor = sub。
func TestOIDCValidTokenAcceptsActorFromSub(t *testing.T) {
	f := newTestFixture(t)
	auth := f.newAuth(t)
	tok := f.signToken(t, "RS256", f.kid, f.baseClaims())

	actor, err := auth.Authenticate(authCtx(tok))
	if err != nil {
		t.Fatalf("有效令牌应通过：%v", err)
	}
	if actor != "operator-alice" {
		t.Fatalf("actor 应取自 sub，实际 %q", actor)
	}
	t.Logf("[A2①] 有效令牌通过，actor=%q（= sub）", actor)
}

// TestOIDCRejectsBadSignature（A2 ②）签名错误被拒绝。
func TestOIDCRejectsBadSignature(t *testing.T) {
	f := newTestFixture(t)
	auth := f.newAuth(t)
	claims := f.baseClaims()
	h, _ := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT", "kid": f.kid})
	p, _ := json.Marshal(claims)
	signingInput := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(p)
	// 篡改 payload：签名与内容不再对应。
	tampered := base64.RawURLEncoding.EncodeToString(h) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"x","sub":"attacker"}`)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte("sig"))

	if _, err := auth.Authenticate(authCtx(tampered)); err == nil {
		t.Fatal("签名错误的令牌必须被拒绝")
	}
	_ = signingInput
	// 同样地：用一个错误密钥签名的令牌也必须被拒绝。
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	sum := sha256.Sum256([]byte(signingInput))
	badSig, _ := rsa.SignPKCS1v15(rand.Reader, other, cryptoSHA256(), sum[:])
	forged := signingInput + "." + base64.RawURLEncoding.EncodeToString(badSig)
	if _, err := auth.Authenticate(authCtx(forged)); err == nil {
		t.Fatal("用其他密钥签名的令牌必须被拒绝")
	}
	t.Log("[A2②] 签名错误（篡改 payload / 伪造签名）均被拒绝")
}

// TestOIDCRejectsAlgNone（A2 ③）alg=none 被拒绝。
func TestOIDCRejectsAlgNone(t *testing.T) {
	f := newTestFixture(t)
	auth := f.newAuth(t)
	tok := f.signToken(t, "none", f.kid, f.baseClaims())
	if _, err := auth.Authenticate(authCtx(tok)); err == nil {
		t.Fatal("alg=none 必须被拒绝")
	} else if !strings.Contains(err.Error(), "RS256") {
		t.Fatalf("拒绝原因应说明 alg 必须是 RS256：%v", err)
	}
	t.Log("[A2③] alg=none 被拒绝（要求 alg 恰好 RS256）")
}

// TestOIDCRejectsHS256（A2 ④）alg=HS256 被拒绝（算法混淆攻击）。
func TestOIDCRejectsHS256(t *testing.T) {
	f := newTestFixture(t)
	auth := f.newAuth(t)
	tok := f.signToken(t, "HS256", f.kid, f.baseClaims())
	if _, err := auth.Authenticate(authCtx(tok)); err == nil {
		t.Fatal("alg=HS256 必须被拒绝")
	} else if !strings.Contains(err.Error(), "RS256") {
		t.Fatalf("拒绝原因应说明 alg 必须是 RS256：%v", err)
	}
	t.Log("[A2④] alg=HS256 被拒绝（算法混淆）")
}

// TestOIDCRejectsUnknownKid（A2 ⑤ + O1）kid 不在 JWKS 中被拒绝。
//
// 注意：未知 kid 触发的刷新受 O1 限速（30 秒），因此这里先把注入时钟推进
// 超过刷新间隔，再断言"确实触发了一次刷新"。
func TestOIDCRejectsUnknownKid(t *testing.T) {
	f := newTestFixture(t)
	auth := f.newAuth(t)
	base := auth.RefreshCount()
	f.advance(31 * time.Second) // 越过 O1 限速窗口
	tok := f.signToken(t, "RS256", "k-not-in-jwks", f.baseClaims())
	if _, err := auth.Authenticate(authCtx(tok)); err == nil {
		t.Fatal("kid 不在 JWKS 中必须被拒绝")
	}
	if auth.RefreshCount() <= base {
		t.Fatal("未知 kid 应触发一次 JWKS 刷新")
	}
	t.Log("[A2⑤] kid 不在 JWKS 中被拒绝（并刷新一次 JWKS 后重试）")
}

// TestOIDCRefreshRateLimit（O1）未知 kid 触发的 JWKS 刷新受 30 秒限速。
//
//	① 距上次刷新 ≥30s 的未知 kid → 触发一次刷新；
//	② 30 秒内的再次未知 kid → **不触发外部请求**且直接拒绝；
//	③ 超过 30 秒后 → 允许再次刷新；
//	④ 已知 kid 的令牌不受限速影响（命中缓存，不刷新）。
func TestOIDCRefreshRateLimit(t *testing.T) {
	f := newTestFixture(t)
	auth := f.newAuth(t)
	if got := auth.RefreshCount(); got != 1 {
		t.Fatalf("启动期应刷新一次，实际 %d", got)
	}
	if auth.refreshInterval != DefaultRefreshInterval {
		t.Fatalf("默认刷新间隔应为 %s，实际 %s", DefaultRefreshInterval, auth.refreshInterval)
	}

	// ① 首次未知 kid（距上次刷新 31s ≥ 30s）→ 触发刷新。
	f.advance(31 * time.Second)
	before := auth.RefreshCount()
	if _, err := auth.Authenticate(authCtx(f.signToken(t, "RS256", "k-unknown-1", f.baseClaims()))); err == nil {
		t.Fatal("未知 kid 必须被拒绝")
	}
	if auth.RefreshCount() != before+1 {
		t.Fatalf("① 首次未知 kid 应触发一次刷新：%d → %d", before, auth.RefreshCount())
	}
	t.Logf("[O1①] 首次未知 kid 触发刷新（RefreshCount=%d）", auth.RefreshCount())

	// ② 30 秒内再次未知 kid → 拒绝且不发起外部请求。
	before = auth.RefreshCount()
	_, err := auth.Authenticate(authCtx(f.signToken(t, "RS256", "k-unknown-2", f.baseClaims())))
	if err == nil {
		t.Fatal("② 限速期内未知 kid 必须被拒绝")
	}
	if !errors.Is(err, ErrOIDCRefreshRateLimited) {
		t.Fatalf("② 应返回限速错误，实际 %v", err)
	}
	if auth.RefreshCount() != before {
		t.Fatalf("② 限速期内不得发起外部请求：%d → %d", before, auth.RefreshCount())
	}
	t.Logf("[O1②] 30 秒内再次未知 kid：拒绝且未发起请求（RefreshCount 保持 %d）", before)

	// ③ 超过 30 秒后允许再次刷新。
	f.advance(31 * time.Second)
	before = auth.RefreshCount()
	if _, err := auth.Authenticate(authCtx(f.signToken(t, "RS256", "k-unknown-3", f.baseClaims()))); err == nil {
		t.Fatal("未知 kid 必须被拒绝")
	}
	if auth.RefreshCount() != before+1 {
		t.Fatalf("③ 超过间隔后应允许再次刷新：%d → %d", before, auth.RefreshCount())
	}
	t.Logf("[O1③] 超过 30 秒后允许再次刷新（RefreshCount=%d）", auth.RefreshCount())

	// ④ 已知 kid 不受限速影响：此刻仍在限速窗口内，但缓存命中 → 通过且不刷新。
	f.advance(time.Second)
	before = auth.RefreshCount()
	actor, err := auth.Authenticate(authCtx(f.signToken(t, "RS256", f.kid, f.baseClaims())))
	if err != nil {
		t.Fatalf("④ 已知 kid 的有效令牌必须通过：%v", err)
	}
	if actor != "operator-alice" {
		t.Fatalf("④ actor 应取自 sub：%q", actor)
	}
	if auth.RefreshCount() != before {
		t.Fatalf("④ 已知 kid 不得触发刷新：%d → %d", before, auth.RefreshCount())
	}
	t.Logf("[O1④] 已知 kid 命中缓存：通过且未刷新（RefreshCount 保持 %d）", before)
}

// TestOIDCRejectsMissingExp（O2 ①）无 exp 的有效签名令牌被拒绝（fail-closed）。
func TestOIDCRejectsMissingExp(t *testing.T) {
	f := newTestFixture(t)
	auth := f.newAuth(t)
	claims := f.baseClaims()
	delete(claims, "exp")
	tok := f.signToken(t, "RS256", f.kid, claims)
	_, err := auth.Authenticate(authCtx(tok))
	if err == nil {
		t.Fatal("缺少 exp 的令牌必须被拒绝（O2 fail-closed）")
	}
	if !errors.Is(err, ErrOIDCMissingExpiry) {
		t.Fatalf("应返回 exp 缺失错误，实际 %v", err)
	}
	t.Log("[O2①] 无 exp 的有效签名令牌被拒绝（ErrOIDCMissingExpiry）")
}

// TestOIDCRejectsNonPositiveExp（O2 ②）exp 为 0 或负数被拒绝。
func TestOIDCRejectsNonPositiveExp(t *testing.T) {
	f := newTestFixture(t)
	auth := f.newAuth(t)
	for _, v := range []int64{0, -1, -1791825000} {
		claims := f.baseClaims()
		claims["exp"] = v
		tok := f.signToken(t, "RS256", f.kid, claims)
		if _, err := auth.Authenticate(authCtx(tok)); err == nil {
			t.Fatalf("exp=%d 必须被拒绝", v)
		} else if !errors.Is(err, ErrOIDCMissingExpiry) {
			t.Fatalf("exp=%d 应返回 exp 缺失/非法错误，实际 %v", v, err)
		}
	}
	t.Log("[O2②] exp=0 / 负数 均被拒绝")
}

// TestOIDCWithoutNbfPassesBeforeExpiry（O2 ③）无 nbf 的令牌在 exp 之前通过。
func TestOIDCWithoutNbfPassesBeforeExpiry(t *testing.T) {
	f := newTestFixture(t)
	auth := f.newAuth(t)
	claims := f.baseClaims()
	delete(claims, "nbf") // nbf 仍可选
	tok := f.signToken(t, "RS256", f.kid, claims)
	actor, err := auth.Authenticate(authCtx(tok))
	if err != nil {
		t.Fatalf("无 nbf 但未过期的令牌应通过：%v", err)
	}
	if actor != "operator-alice" {
		t.Fatalf("actor 应取自 sub：%q", actor)
	}
	t.Log("[O2③] 无 nbf 的令牌在 exp 之前通过（nbf 仍可选）")
}

// TestOIDCRejectsBadIssuer（A2 ⑥）iss 错误被拒绝。
func TestOIDCRejectsBadIssuer(t *testing.T) {
	f := newTestFixture(t)
	auth := f.newAuth(t)
	claims := f.baseClaims()
	claims["iss"] = "https://attacker.invalid"
	tok := f.signToken(t, "RS256", f.kid, claims)
	if _, err := auth.Authenticate(authCtx(tok)); err == nil {
		t.Fatal("iss 不匹配必须被拒绝")
	}
	t.Log("[A2⑥] iss 错误被拒绝（精确匹配）")
}

// TestOIDCRejectsBadAudience（A2 ⑦）aud 错误被拒绝。
func TestOIDCRejectsBadAudience(t *testing.T) {
	f := newTestFixture(t)
	auth := f.newAuth(t)
	for _, bad := range []any{"some-other-service", []string{"some-other-service", "another"}} {
		claims := f.baseClaims()
		claims["aud"] = bad
		tok := f.signToken(t, "RS256", f.kid, claims)
		if _, err := auth.Authenticate(authCtx(tok)); err == nil {
			t.Fatalf("aud=%v 必须被拒绝", bad)
		}
	}
	t.Log("[A2⑦] aud 错误被拒绝（字符串与数组形态都不放行）")
}

// TestOIDCRejectsExpired（A2 ⑧）过期令牌被拒绝。
func TestOIDCRejectsExpired(t *testing.T) {
	f := newTestFixture(t)
	auth := f.newAuth(t)
	claims := f.baseClaims()
	claims["exp"] = f.now.Add(-5 * time.Minute).Unix() // 已过期 5 分钟（超出 60s 偏差）
	tok := f.signToken(t, "RS256", f.kid, claims)
	if _, err := auth.Authenticate(authCtx(tok)); err == nil {
		t.Fatal("过期令牌必须被拒绝")
	}
	t.Log("[A2⑧] 过期令牌被拒绝")
}

// TestOIDCClockSkewWindow（A2 ⑨）60 秒偏差内通过、超出被拒绝。
func TestOIDCClockSkewWindow(t *testing.T) {
	f := newTestFixture(t)
	auth := f.newAuth(t)

	// 偏差内：exp = now - 30s（"刚过期"30 秒 < 60s 偏差）→ 通过。
	inWindow := f.baseClaims()
	inWindow["exp"] = f.now.Add(-30 * time.Second).Unix()
	if actor, err := auth.Authenticate(authCtx(f.signToken(t, "RS256", f.kid, inWindow))); err != nil {
		t.Fatalf("偏差 30s 内的令牌应通过：%v", err)
	} else if actor != "operator-alice" {
		t.Fatalf("actor 应来自 sub：%q", actor)
	}

	// 偏差外：exp = now - 90s（> 60s）→ 拒绝。
	outWindow := f.baseClaims()
	outWindow["exp"] = f.now.Add(-90 * time.Second).Unix()
	if _, err := auth.Authenticate(authCtx(f.signToken(t, "RS256", f.kid, outWindow))); err == nil {
		t.Fatal("超出 60s 偏差的过期令牌必须被拒绝")
	}

	// nbf 同理：偏差内通过、偏差外拒绝。
	nbfIn := f.baseClaims()
	nbfIn["nbf"] = f.now.Add(30 * time.Second).Unix() // 30 秒后才生效，在偏差内
	if _, err := auth.Authenticate(authCtx(f.signToken(t, "RS256", f.kid, nbfIn))); err != nil {
		t.Fatalf("nbf 偏差 30s 内应通过：%v", err)
	}
	nbfOut := f.baseClaims()
	nbfOut["nbf"] = f.now.Add(90 * time.Second).Unix()
	if _, err := auth.Authenticate(authCtx(f.signToken(t, "RS256", f.kid, nbfOut))); err == nil {
		t.Fatal("nbf 超出 60s 偏差必须被拒绝")
	}
	t.Log("[A2⑨] 时钟偏差 ±60s：exp 与 nbf 在窗口内通过、窗口外拒绝")
}

// TestGuardAuthProdRejectsStaticToken（A2 ⑩）mode=prod 下静态令牌启动失败。
func TestGuardAuthProdRejectsStaticToken(t *testing.T) {
	static := NewStaticTokenAuth(map[string]string{"tok": "alice"})
	if err := GuardAuth(ModeProd, static); err == nil {
		t.Fatal("mode=prod 下静态令牌必须拒绝启动")
	} else if !strings.Contains(err.Error(), "静态 token") {
		t.Fatalf("拒绝原因应说明静态 token：%v", err)
	}
	// 未配置任何 token 的静态认证同样拒绝（fail-closed）。
	if err := GuardAuth(ModeProd, NewStaticTokenAuth(nil)); err == nil {
		t.Fatal("prod 下空静态令牌认证也必须拒绝")
	}
	// mode=test 允许静态令牌（本地测试）。
	if err := GuardAuth(ModeTest, static); err != nil {
		t.Fatalf("test 模式应允许静态令牌：%v", err)
	}
	t.Log("[A2⑩] mode=prod 下静态令牌（含空配置）一律拒绝启动；test 模式放行")
}

// TestNoPrivateKeysCommittedInRepo（A2 硬性约束 1）仓库中不得出现任何 PEM 私钥。
//
// 测试密钥在运行时生成、只存在于内存；本用例扫描仓库（跳过 .git / node_modules /
// .workbuddy-ai / 生成目录），任何 PEM 私钥标记或私钥文件名即失败。
func TestNoPrivateKeysCommittedInRepo(t *testing.T) {
	root := repoRootForSecrets(t)
	// 标记按片段拼接，避免本文件自身命中（与 internal/repoguard 的做法一致）。
	begin := "-----BEGIN "
	end := "PRIVATE KEY-----"
	bad := []string{
		begin + end,
		begin + "RSA " + end,
		begin + "EC " + end,
		begin + "OPENSSH " + end,
	}
	skipDirs := map[string]bool{
		".git": true, ".workbuddy-ai": true, "node_modules": true,
		"vendor": true, ".gen-check": true,
	}
	var offenders []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if skipDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		// 私钥文件名本身也不允许（含 .pem/.key 且名字带 key/private）。
		lower := strings.ToLower(info.Name())
		if strings.HasSuffix(lower, ".key") || strings.Contains(lower, "private") && strings.HasSuffix(lower, ".pem") {
			offenders = append(offenders, "私钥文件名："+path)
			return nil
		}
		if info.Size() > 1<<20 {
			return nil // 大文件跳过（二进制/生成产物）
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		for _, marker := range bad {
			if bytesContains(data, marker) {
				offenders = append(offenders, "含 PEM 私钥标记："+path)
				break
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("扫描仓库失败：%v", err)
	}
	if len(offenders) > 0 {
		for _, o := range offenders {
			t.Errorf("[约束 1] %s", o)
		}
		t.Fatalf("仓库中不得出现任何 PEM 私钥（发现 %d 处）", len(offenders))
	}
	t.Log("[A2 约束 1] 仓库内无 PEM 私钥文件/私钥标记（测试密钥仅运行时生成）")
}

// repoRootForSecrets 从当前目录向上寻找含 go.work 的仓库根。
func repoRootForSecrets(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, serr := os.Stat(filepath.Join(dir, "go.work")); serr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("未找到仓库根（含 go.work）：%s", dir)
		}
		dir = parent
	}
}

func bytesContains(b []byte, sub string) bool {
	return strings.Contains(string(b), sub)
}

// 契约消息（SubmitExecuteRequest）里**没有** actor 字段；即使 metadata 里塞了
// 自报身份头，actor 也只能来自认证后的 sub。这里用一个"不同 sub"的有效令牌
// 证明：无论外界怎么暗示 actor，结果始终等于令牌 sub。
func TestOIDCIgnoresSelfReportedActor(t *testing.T) {
	f := newTestFixture(t)
	auth := f.newAuth(t)
	tok := f.signToken(t, "RS256", f.kid, f.baseClaims())
	// 自报身份头（服务端不读取；这里只为证明其无效）。
	ctx := newIncomingCtx(map[string][]string{
		MetaAuthorization: {"Bearer " + tok},
		"x-actor":         {"spoofed-bob"},
		"actor":           {"spoofed-carol"},
	})
	actor, err := auth.Authenticate(ctx)
	if err != nil {
		t.Fatalf("有效令牌应通过：%v", err)
	}
	if actor != "operator-alice" {
		t.Fatalf("actor 必须来自 sub，不得受自报头影响：%q", actor)
	}
	t.Log("[A2⑪] 自报 actor 头被忽略，actor 始终 = 令牌 sub")
}
