package grpcwire

// JWKS 一致性夹具测试（第二十轮 O3）。
//
// 样本位于 testdata/jwks/（合成、只含公开部分，生成过程见该目录 README.md）。
// 本文件用**固定时钟**与**真实文件获取器**跑完整校验路径（解析 + 验签 + 声明校验），
// 覆盖真实 issuer 的常见形态差异：多密钥、kid 轮换、x5c 字段、aud 数组。

import (
	"crypto/rsa"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// 与 gen/main.go 保持一致的夹具常量（合成值，不对应任何真实 issuer）。
const (
	fixtureDir      = "testdata/jwks"
	fixtureIssuer   = "https://fixtures.invalid/issuer"
	fixtureAudience = "agent-ops-gateway"
	fixtureSubject  = "fixture-operator"
	// fixtureNow 固定时钟：位于 nbf(2023) 与 exp(2033) 之间。
	fixtureNowUnix = int64(1791825000)
)

// fixtureAuth 构建指向样本文件的 OIDCAuth（真实文件获取器 + 固定时钟）。
func fixtureAuth(t *testing.T, jwksFile string) *OIDCAuth {
	t.Helper()
	a, err := NewOIDCAuth(OIDCConfig{
		Issuer:   fixtureIssuer,
		Audience: fixtureAudience,
		Fetcher:  NewFileJWKSFetcher(filepath.Join(fixtureDir, jwksFile)),
		Now:      func() time.Time { return time.Unix(fixtureNowUnix, 0) },
	})
	if err != nil {
		t.Fatalf("构建 OIDCAuth（%s）失败：%v", jwksFile, err)
	}
	return a
}

// readFixtureToken 读取样本令牌（去掉首尾空白）。
func readFixtureToken(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(fixtureDir, name))
	if err != nil {
		t.Fatalf("读取样本令牌失败（%s）：%v", name, err)
	}
	tok := strings.TrimSpace(string(raw))
	if tok == "" {
		t.Fatalf("样本令牌为空：%s", name)
	}
	return tok
}

// TestJWKSFixtureMultiKey（O3 ①）多密钥 JWKS：3 个 kid 都可解析，
// 由其中一把密钥签发的令牌验签通过（证明选中的是正确的公钥）。
func TestJWKSFixtureMultiKey(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(fixtureDir, "multi-key.jwks.json"))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := ParseJWKS(raw)
	if err != nil {
		t.Fatalf("多密钥 JWKS 解析失败：%v", err)
	}
	if len(keys) != 3 {
		t.Fatalf("应解析出 3 个公钥，实际 %d", len(keys))
	}
	for _, kid := range []string{"mk-1", "mk-2", "mk-3"} {
		if keys[kid] == nil {
			t.Fatalf("缺少 kid %q（实际 kid 集合 %v）", kid, kidsOf(keys))
		}
	}

	auth := fixtureAuth(t, "multi-key.jwks.json")
	actor, err := auth.Authenticate(authCtx(readFixtureToken(t, "multi-key.token.txt")))
	if err != nil {
		t.Fatalf("由 mk-2 签发的令牌应通过：%v", err)
	}
	if actor != fixtureSubject {
		t.Fatalf("actor 应取自 sub：%q", actor)
	}
	t.Logf("[O3①] 多密钥：解析出 3 个 kid %v；mk-2 签发令牌验签通过，actor=%q",
		kidsOf(keys), actor)
}

// TestJWKSFixtureKidRotation（O3 ②）kid 轮换样本：旧/新 kid 并存，
// 两者的令牌都必须能验签通过（轮换过渡期不中断认证）。
func TestJWKSFixtureKidRotation(t *testing.T) {
	auth := fixtureAuth(t, "kid-rotation.jwks.json")
	if got := auth.KeyCount(); got != 2 {
		t.Fatalf("轮换样本应含 2 个 kid（旧+新），实际 %d", got)
	}
	for _, tc := range []struct{ name, token string }{
		{"旧 kid（rot-old）", "kid-rotation.old.token.txt"},
		{"新 kid（rot-new）", "kid-rotation.new.token.txt"},
	} {
		actor, err := auth.Authenticate(authCtx(readFixtureToken(t, tc.token)))
		if err != nil {
			t.Fatalf("%s 的令牌应通过：%v", tc.name, err)
		}
		if actor != fixtureSubject {
			t.Fatalf("%s：actor 应取自 sub：%q", tc.name, actor)
		}
	}
	t.Logf("[O3②] kid 轮换：旧 kid 与新 kid 并存（共 %d 个），两者令牌均验签通过", auth.KeyCount())
}

// TestJWKSFixtureWithX5C（O3 ③）带 x5c 字段的样本：解析时忽略 x5c，
// 仍取到 RSA 公钥且验签通过。
func TestJWKSFixtureWithX5C(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(fixtureDir, "with-x5c.jwks.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"x5c"`) {
		t.Fatal("样本必须包含 x5c 字段（否则用例失去意义）")
	}
	keys, err := ParseJWKS(raw)
	if err != nil {
		t.Fatalf("含 x5c 的 JWKS 应可解析（忽略 x5c）：%v", err)
	}
	if keys["x5c-1"] == nil {
		t.Fatalf("应解析出 kid=x5c-1，实际 %v", kidsOf(keys))
	}
	auth := fixtureAuth(t, "with-x5c.jwks.json")
	actor, err := auth.Authenticate(authCtx(readFixtureToken(t, "with-x5c.token.txt")))
	if err != nil {
		t.Fatalf("含 x5c 的样本令牌应通过（x5c 不影响校验）：%v", err)
	}
	if actor != fixtureSubject {
		t.Fatalf("actor 应取自 sub：%q", actor)
	}
	t.Logf("[O3③] 带 x5c：解析忽略 x5c 字段，公钥可用、令牌验签通过（actor=%q）", actor)
}

// TestJWKSFixtureAudArray（O3 ④）aud 为数组的令牌样本：
// 数组内含配置的 audience → 通过；不含 → 拒绝。
func TestJWKSFixtureAudArray(t *testing.T) {
	auth := fixtureAuth(t, "aud-array.jwks.json")
	tok := readFixtureToken(t, "aud-array.token.txt")

	// 数组内含 fixtureAudience → 通过。
	actor, err := auth.Authenticate(authCtx(tok))
	if err != nil {
		t.Fatalf("aud 数组内含配置 audience 时应通过：%v", err)
	}
	if actor != fixtureSubject {
		t.Fatalf("actor 应取自 sub：%q", actor)
	}

	// 同一令牌，换一个不匹配的 audience → 必须拒绝（证明 aud 真的被校验）。
	strict, err := NewOIDCAuth(OIDCConfig{
		Issuer: fixtureIssuer, Audience: "not-in-the-array",
		Fetcher: NewFileJWKSFetcher(filepath.Join(fixtureDir, "aud-array.jwks.json")),
		Now:     func() time.Time { return time.Unix(fixtureNowUnix, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := strict.Authenticate(authCtx(tok)); err == nil {
		t.Fatal("aud 数组不含配置 audience 时必须拒绝")
	}
	t.Logf("[O3④] aud 数组：含配置值 → 通过（actor=%q）；不含 → 拒绝", actor)
}

// TestJWKSFixturesContainNoPrivateKeys（O3 硬性约束）testdata 中不得出现私钥字样。
func TestJWKSFixturesContainNoPrivateKeys(t *testing.T) {
	entries, err := os.ReadDir(fixtureDir)
	if err != nil {
		t.Fatalf("读取夹具目录失败：%v", err)
	}
	// 标记按片段拼接，避免本文件自身命中。
	begin := "-----BEGIN "
	end := "PRIVATE KEY-----"
	markers := []string{begin + end, begin + "RSA " + end, begin + "EC " + end, begin + "OPENSSH " + end}

	scanned := 0
	var offenders []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		path := filepath.Join(fixtureDir, e.Name())
		raw, rerr := os.ReadFile(path)
		if rerr != nil {
			t.Fatalf("读取 %s 失败：%v", path, rerr)
		}
		scanned++
		for _, m := range markers {
			if strings.Contains(string(raw), m) {
				offenders = append(offenders, path)
				break
			}
		}
	}
	if len(offenders) > 0 {
		t.Fatalf("testdata 中不得含私钥：%v", offenders)
	}
	if scanned < 9 {
		t.Fatalf("夹具文件数异常（应 ≥9 个样本文件，实际 %d）", scanned)
	}
	t.Logf("[O3 约束] testdata/jwks 共扫描 %d 个样本文件，无 PRIVATE KEY 字样", scanned)
}

// kidsOf 取 kid 集合（日志用，稳定排序）。
func kidsOf(keys map[string]*rsa.PublicKey) []string {
	var out []string
	for k := range keys {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
