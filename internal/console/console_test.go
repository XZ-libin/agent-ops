package console

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// 第二十七轮 C4：控制台的只读边界、投影与鉴权（无数据库依赖的单元层）。
// HTTP 层与真实库的行为在 internal/console/httpapi/server_test.go。

// —— payload 白名单 ——

func TestConsoleAuditPayloadAllowlist(t *testing.T) {
	cases := []struct {
		name   string
		action string
		raw    string
		want   map[string]string
	}{
		{
			name:   "节点事件只留四个键",
			action: "node.cert_renewed",
			raw:    `{"node_id":"nod_1","boot_session_id":"s1","event_kind":"renew","reason_code":"ok","secret_token":"tok-should-drop","pem":"-----BEGIN CERTIFICATE REQUEST-----x"}`,
			want:   map[string]string{"node_id": "nod_1", "boot_session_id": "s1", "event_kind": "renew", "reason_code": "ok"},
		},
		{
			name:   "审批事件只留三个键",
			action: "approval.approved",
			raw:    `{"approval_id":"apv_1","capability":"linux.service.state","status":"approved","raw_request_body":"drop-me"}`,
			want:   map[string]string{"approval_id": "apv_1", "capability": "linux.service.state", "status": "approved"},
		},
		{
			name:   "执行事件只留三个键",
			action: "execution.succeeded",
			raw:    `{"capability":"diagnose.disk_usage","status":"ok","exit_class":"zero","stdout":"huge-blob"}`,
			want:   map[string]string{"capability": "diagnose.disk_usage", "status": "ok", "exit_class": "zero"},
		},
		{
			name:   "诊断事件同样过滤",
			action: "diagnosis.executed",
			raw:    `{"capability":"diagnose.load_average","status":"ok","exit_class":"zero","stderr":"x"}`,
			want:   map[string]string{"capability": "diagnose.load_average", "status": "ok", "exit_class": "zero"},
		},
		{
			name:   "未登记动作一律不回传",
			action: "alert.received",
			raw:    `{"node_id":"nod_1","capability":"x"}`,
			want:   map[string]string{},
		},
		{
			name:   "容器类型值被丢弃",
			action: "node.enrolled",
			raw:    `{"node_id":"nod_1","event_kind":{"nested":"obj"},"reason_code":["array"]}`,
			want:   map[string]string{"node_id": "nod_1"},
		},
		{
			name:   "null 与数字布尔按规则处理",
			action: "node.enrolled",
			raw:    `{"node_id":"nod_1","event_kind":null,"reason_code":"r1","boot_session_id":7}`,
			want:   map[string]string{"node_id": "nod_1", "reason_code": "r1", "boot_session_id": "7"},
		},
		{
			name:   "坏 JSON 不回传原文",
			action: "node.enrolled",
			raw:    `not-json`,
			want:   map[string]string{},
		},
	}
	for _, c := range cases {
		got := ProjectPayload(c.action, []byte(c.raw))
		if len(got) != len(c.want) {
			t.Errorf("%s：期望 %d 个键，实际 %d（%v）", c.name, len(c.want), len(got), got)
		}
		for k, v := range c.want {
			if got[k] != v {
				t.Errorf("%s：键 %s 期望 %q 实际 %q", c.name, k, v, got[k])
			}
		}
		// 任何情况下都不得把原始文本带出去。
		for _, v := range got {
			if strings.Contains(v, "BEGIN CERTIFICATE") || strings.Contains(v, "drop-me") ||
				strings.Contains(v, "huge-blob") || strings.Contains(v, "tok-should-drop") {
				t.Fatalf("%s：投影结果带出了原始内容：%v", c.name, got)
			}
		}
	}
}

// —— 分页边界 ——

func TestConsolePaginationBounds(t *testing.T) {
	// 空值与"只有空白"都视为未提供 → 默认 50（`?limit=` 与 `?limit=%20` 同义）。
	for _, empty := range []string{"", " ", "\t"} {
		if n, err := NormalizeLimit(empty); err != nil || n != DefaultLimit {
			t.Fatalf("limit=%q 应取默认 %d，实际 %d err=%v", empty, DefaultLimit, n, err)
		}
	}
	// 合法边界。
	for _, ok := range []string{"1", "50", "200"} {
		n, err := NormalizeLimit(ok)
		if err != nil || n <= 0 {
			t.Fatalf("limit=%s 应合法，实际 n=%d err=%v", ok, n, err)
		}
	}
	// 非法值一律 ErrBadLimit（HTTP 层映射为 400）。
	for _, bad := range []string{"0", "-1", "201", "99999", "abc", "1.5", "null"} {
		if _, err := NormalizeLimit(bad); !errors.Is(err, ErrBadLimit) {
			t.Errorf("limit=%q 应返回 ErrBadLimit，实际 %v", bad, err)
		}
	}
	// 游标：空=0；负数与非数字拒绝。
	if n, err := NormalizeAfterSeq(""); err != nil || n != 0 {
		t.Fatalf("after_seq 空值应为 0，实际 %d err=%v", n, err)
	}
	for _, bad := range []string{"-1", "x", "1e3"} {
		if _, err := NormalizeAfterSeq(bad); !errors.Is(err, ErrBadLimit) {
			t.Errorf("after_seq=%q 应被拒绝，实际 %v", bad, err)
		}
	}
	t.Logf("[C4] 分页边界：默认 %d / 上限 %d / 超限与负值拒绝", DefaultLimit, MaxLimit)
}

// —— 配置与模式 ——

func TestConsoleConfigFailsClosed(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.Validate(); err == nil {
		t.Fatal("未显式给 Mode 必须失败（与 gateway parseMode 同口径）")
	}
	cfg.Mode = ModeTest
	if err := cfg.Validate(); err != nil {
		t.Fatalf("默认表名 + test 模式应通过：%v", err)
	}
	// 表名必须 test_ 前缀（防注入，生产表名另有待决）。
	for _, bad := range []string{"nodes", "public", "TEST_nodes", "test-a", ""} {
		c := cfg
		c.NodesTable = bad
		if err := c.Validate(); !errors.Is(err, ErrBadTable) {
			t.Errorf("表名 %q 必须被拒绝，实际 %v", bad, err)
		}
	}
	// 模式解析：显式值。
	if m, err := ParseMode(""); err == nil {
		t.Fatalf("空模式必须失败，实际 %q", m)
	}
	for _, ok := range []string{"test", "prod"} {
		if _, err := ParseMode(ok); err != nil {
			t.Errorf("模式 %q 应合法：%v", ok, err)
		}
	}
}

func TestConsoleProdRejectsStaticToken(t *testing.T) {
	// 生产模式 + 静态令牌 → 构造期失败（不是运行期忽略）。
	_, err := NewVerifier(AuthConfig{
		Mode: ModeProd, Issuer: "https://idp.example", Audience: "agent-ops",
		StaticToken: "dev-token",
	})
	if !errors.Is(err, ErrStaticTokenInProd) {
		t.Fatalf("生产模式配置静态令牌必须启动失败，实际 err=%v", err)
	}
	// 生产模式没有 JWKS 来源同样失败（不能退化成"谁都能访问"）。
	if _, err := NewVerifier(AuthConfig{Mode: ModeProd, Issuer: "i", Audience: "a"}); !errors.Is(err, ErrNoKeySource) {
		t.Fatalf("生产模式缺 JWKS 来源必须失败，实际 %v", err)
	}
	// 测试模式允许静态令牌（夹具用）。
	v, err := NewVerifier(AuthConfig{Mode: ModeTest, StaticToken: "dev-token"})
	if err != nil {
		t.Fatalf("测试模式静态令牌应可用：%v", err)
	}
	actor, err := v.Authenticate(context.Background(), "Bearer dev-token")
	if err != nil || actor == "" {
		t.Fatalf("静态令牌鉴权应成功并给出主体，实际 actor=%q err=%v", actor, err)
	}
	if _, err := v.Authenticate(context.Background(), "Bearer wrong"); !errors.Is(err, ErrAuth) {
		t.Fatalf("错误令牌必须只得到 ErrAuth，实际 %v", err)
	}
	t.Log("[C4] 生产模式拒绝静态令牌（ErrStaticTokenInProd），测试模式可用")
}

// —— OIDC 验证（合成密钥，运行时生成、仅存内存）——

type fixtureKeys struct {
	key *rsa.PrivateKey
	kid string
}

func (f fixtureKeys) Keys(context.Context) (map[string]*rsa.PublicKey, error) {
	return map[string]*rsa.PublicKey{f.kid: &f.key.PublicKey}, nil
}

func newFixtureKeys(t *testing.T) fixtureKeys {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return fixtureKeys{key: key, kid: "test-kid-1"}
}

// signJWT 造一个 JWT；alg/kid/exp 等由参数控制，便于构造异常分支。
// signJWT 造一个 JWT；alg/kid/claims 由参数控制，便于构造异常分支。
// 载荷被改动而签名不重算，即为"篡改"分支（见 tamperedPayloadToken）。
func signJWT(t *testing.T, f fixtureKeys, alg, kid string, claims map[string]any, now time.Time) string {
	t.Helper()
	head, _ := json.Marshal(map[string]string{"alg": alg, "typ": "JWT", "kid": kid})
	payload, _ := json.Marshal(claims)
	signing := b64(head) + "." + b64(payload)
	if alg != "RS256" {
		// 非 RS256 分支不需要真签名：验证器应在验签前就拒掉。
		return signing + "." + b64([]byte("not-an-rsa-signature"))
	}
	digest := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + b64(sig)
}

func b64(raw []byte) string { return base64.RawURLEncoding.EncodeToString(raw) }

// tamperedPayloadToken 保留原签名、替换载荷里的 sub（典型的"改 claims 不改签名"攻击）。
func tamperedPayloadToken(t *testing.T, f fixtureKeys, claims map[string]any, now time.Time) string {
	t.Helper()
	token := signJWT(t, f, "RS256", f.kid, claims, now)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("夹具令牌结构异常：%d 段", len(parts))
	}
	evil := map[string]any{}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &evil); err != nil {
		t.Fatal(err)
	}
	evil["sub"] = "operator-elevated"
	body, _ := json.Marshal(evil)
	return parts[0] + "." + b64(body) + "." + parts[2]
}

func TestConsoleAuthRejectsEveryWeakToken(t *testing.T) {
	f := newFixtureKeys(t)
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	v, err := NewVerifier(AuthConfig{
		Mode: ModeTest, Issuer: "https://idp.test", Audience: "agent-ops-console",
		Keys: f, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	good := map[string]any{
		"iss": "https://idp.test", "aud": "agent-ops-console",
		"sub": "operator-a", "exp": now.Add(5 * time.Minute).Unix(),
	}
	if actor, err := v.Authenticate(context.Background(),
		"Bearer "+signJWT(t, f, "RS256", f.kid, good, now)); err != nil || actor != "operator-a" {
		t.Fatalf("合法令牌应通过，实际 actor=%q err=%v", actor, err)
	}

	cases := []struct {
		name  string
		value string
	}{
		{"无令牌", ""},
		{"非 Bearer 前缀", signJWT(t, f, "RS256", f.kid, good, now)},
		{"alg=none", "Bearer " + signJWT(t, f, "none", f.kid, good, now)},
		{"HS256（算法混淆）", "Bearer " + signJWT(t, f, "HS256", f.kid, good, now)},
		{"kid 不在 JWKS", "Bearer " + signJWT(t, f, "RS256", "other-kid", good, now)},
		{"缺少 exp", "Bearer " + signJWT(t, f, "RS256", f.kid,
			map[string]any{"iss": "https://idp.test", "aud": "agent-ops-console", "sub": "operator-a"}, now)},
		{"已过期", "Bearer " + signJWT(t, f, "RS256", f.kid, map[string]any{
			"iss": "https://idp.test", "aud": "agent-ops-console", "sub": "operator-a",
			"exp": now.Add(-3 * time.Minute).Unix()}, now)},
		{"iss 不符", "Bearer " + signJWT(t, f, "RS256", f.kid, map[string]any{
			"iss": "https://attacker", "aud": "agent-ops-console", "sub": "operator-a",
			"exp": now.Add(5 * time.Minute).Unix()}, now)},
		{"aud 不符", "Bearer " + signJWT(t, f, "RS256", f.kid, map[string]any{
			"iss": "https://idp.test", "aud": "other-aud", "sub": "operator-a",
			"exp": now.Add(5 * time.Minute).Unix()}, now)},
		{"aud 为数组但不含期望值", "Bearer " + signJWT(t, f, "RS256", f.kid, map[string]any{
			"iss": "https://idp.test", "aud": []string{"nope"}, "sub": "operator-a",
			"exp": now.Add(5 * time.Minute).Unix()}, now)},
		{"缺 sub", "Bearer " + signJWT(t, f, "RS256", f.kid, map[string]any{
			"iss": "https://idp.test", "aud": "agent-ops-console",
			"exp": now.Add(5 * time.Minute).Unix()}, now)},
		{"被篡改的载荷（签名未重算）", "Bearer " + tamperedPayloadToken(t, f, good, now)},
		{"结构不是三段", "Bearer a.b"},
	}
	for _, c := range cases {
		actor, err := v.Authenticate(context.Background(), c.value)
		if !errors.Is(err, ErrAuth) {
			t.Errorf("%s：必须只得到 ErrAuth，实际 actor=%q err=%v", c.name, actor, err)
		}
		if actor != "" {
			t.Errorf("%s：拒绝时不得返回 actor，实际 %q", c.name, actor)
		}
	}

	// 偏差窗口：过期不超过 60 秒仍可用（DefaultClockSkew），超过即拒。
	nearExpiry := map[string]any{"iss": "https://idp.test", "aud": "agent-ops-console",
		"sub": "operator-a", "exp": now.Add(30 * time.Second).Unix()}
	if _, err := v.Authenticate(context.Background(),
		"Bearer "+signJWT(t, f, "RS256", f.kid, nearExpiry, now)); err != nil {
		t.Fatalf("30 秒内到期应在容忍窗口内：%v", err)
	}
	late := now.Add(90 * time.Second)
	v2, err := NewVerifier(AuthConfig{Mode: ModeTest, Issuer: "https://idp.test",
		Audience: "agent-ops-console", Keys: f, Now: func() time.Time { return late }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v2.Authenticate(context.Background(),
		"Bearer "+signJWT(t, f, "RS256", f.kid, nearExpiry, now)); !errors.Is(err, ErrAuth) {
		t.Fatalf("超出 60 秒容忍窗口必须拒绝，实际 %v", err)
	}
	t.Logf("[C4] 弱令牌与过期令牌全部归并为单一原因（不泄露细节），偏差窗口 %s", DefaultClockSkew)
}
