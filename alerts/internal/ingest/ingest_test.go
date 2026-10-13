package ingest

import (
	"strings"
	"testing"
	"time"
)

// testSecret 仅测试的固定测试密钥（非真实凭据；生产由环境变量注入）。
var testSecret = []byte("itest-secret-not-real")

// TestSignAndVerifyOK 签名正确通过。
func TestSignAndVerifyOK(t *testing.T) {
	body := []byte(`{"source":"prometheus","severity":"warning","fingerprint":"fp-1"}`)
	ts := "1791825000"
	sig := Sign(testSecret, ts, body)
	now := time.Unix(1791825000, 0)
	if err := VerifySignature(testSecret, ts, sig, body, now, DefaultSignatureTolerance); err != nil {
		t.Fatalf("正确签名应通过：%v", err)
	}
}

// TestVerifyRejectsBadSignature 签名错误 / 缺失 / 密钥不符 → 401 语义。
func TestVerifyRejectsBadSignature(t *testing.T) {
	body := []byte(`{"source":"prometheus"}`)
	ts := "1791825000"
	now := time.Unix(1791825000, 0)
	good := Sign(testSecret, ts, body)

	cases := []struct {
		name      string
		secret    []byte
		timestamp string
		signature string
		body      []byte
		want      error
	}{
		{"签名错误", testSecret, ts, strings.Repeat("0", 64), body, ErrSignatureInvalid},
		{"签名缺失", testSecret, ts, "", body, ErrSignatureMissing},
		{"时间戳缺失", testSecret, "", good, body, ErrSignatureMissing},
		{"密钥不符", []byte("other-secret"), ts, good, body, ErrSignatureInvalid},
		{"未配置密钥", nil, ts, good, body, ErrSignatureInvalid},
		{"请求体被改", testSecret, ts, good, []byte(`{"source":"tampered"}`), ErrSignatureInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := VerifySignature(tc.secret, tc.timestamp, tc.signature, tc.body, now, DefaultSignatureTolerance)
			if !errorsIs(err, tc.want) {
				t.Fatalf("应返回 %v，实际 %v", tc.want, err)
			}
		})
	}
}

// TestVerifyRejectsTamperedTimestamp 时间戳篡改（签名失效或超窗）→ 401 语义。
func TestVerifyRejectsTamperedTimestamp(t *testing.T) {
	body := []byte(`{"source":"prometheus"}`)
	ts := "1791825000"
	sig := Sign(testSecret, ts, body)
	now := time.Unix(1791825000, 0)

	// 篡改时间戳但沿用原签名：签名不匹配。
	if err := VerifySignature(testSecret, "1791825001", sig, body, now, DefaultSignatureTolerance); !errorsIs(err, ErrSignatureInvalid) {
		t.Fatalf("篡改时间戳应签名失效：%v", err)
	}
	// 非整数时间戳：视为篡改。
	if err := VerifySignature(testSecret, "not-a-number", sig, body, now, DefaultSignatureTolerance); !errorsIs(err, ErrSignatureInvalid) {
		t.Fatalf("非法时间戳应拒绝：%v", err)
	}
	// 超窗（重放）：时间戳正确签名但过期。
	old := "1791800000"
	oldSig := Sign(testSecret, old, body)
	if err := VerifySignature(testSecret, old, oldSig, body, now, DefaultSignatureTolerance); !errorsIs(err, ErrTimestampStale) {
		t.Fatalf("超窗时间戳应拒绝：%v", err)
	}
}

// TestValidateSeverityWhitelist severity 只接受 info/warning/critical。
func TestValidateSeverityWhitelist(t *testing.T) {
	for _, ok := range []string{"info", "warning", "critical"} {
		if err := Validate(Alert{Source: "s", Severity: ok, AssetID: "a", Fingerprint: "f"}); err != nil {
			t.Fatalf("合法级别 %q 应通过：%v", ok, err)
		}
	}
	for _, bad := range []string{"", "INFO", "debug", "fatal", "warning ", "critical!"} {
		err := Validate(Alert{Source: "s", Severity: bad, AssetID: "a", Fingerprint: "f"})
		if !errorsIs(err, ErrSeverityInvalid) {
			t.Fatalf("非法级别 %q 应被拒绝：%v", bad, err)
		}
	}
}

// TestValidateRequiredFields fingerprint / source / asset_id 为空 → 400 语义。
func TestValidateRequiredFields(t *testing.T) {
	cases := []struct {
		name string
		a    Alert
	}{
		{"fingerprint 为空", Alert{Source: "s", Severity: "info", AssetID: "a"}},
		{"fingerprint 全空白", Alert{Source: "s", Severity: "info", AssetID: "a", Fingerprint: "   "}},
		{"source 为空", Alert{Severity: "info", AssetID: "a", Fingerprint: "f"}},
		{"asset_id 为空", Alert{Source: "s", Severity: "info", Fingerprint: "f"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := Validate(tc.a); !errorsIs(err, ErrFieldMissing) {
				t.Fatalf("应报必填字段缺失：%v", err)
			}
		})
	}
}

// TestLoadSecretFromEnv 密钥从环境变量读取；未配置即拒绝（fail-closed）。
func TestLoadSecretFromEnv(t *testing.T) {
	env := map[string]string{EnvSecret: "itest-secret-not-real"}
	got, err := LoadSecret(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "itest-secret-not-real" {
		t.Fatalf("密钥读取不符：%q", got)
	}
	if _, err := LoadSecret(func(string) string { return "" }); err == nil {
		t.Fatal("未配置密钥必须拒绝（fail-closed）")
	}
}

// TestDefaultWindows 默认窗口常量与裁决一致。
func TestDefaultWindows(t *testing.T) {
	if DefaultDedupWindow != 5*time.Minute {
		t.Fatalf("去重窗口应为 5 分钟，实际 %v", DefaultDedupWindow)
	}
	if OutboxEventType != "alert.received" {
		t.Fatalf("outbox 事件类型应为 alert.received，实际 %q", OutboxEventType)
	}
	if EnvSecret != "AGENT_OPS_ALERT_HMAC_SECRET" {
		t.Fatalf("密钥环境变量名不符：%q", EnvSecret)
	}
}

// errorsIs 本地 errors.Is 包装（避免与命名冲突）。
func errorsIs(err, target error) bool {
	for e := err; e != nil; {
		if e == target {
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := e.(unwrapper)
		if !ok {
			return false
		}
		e = u.Unwrap()
	}
	return false
}
