package executor

import (
	"regexp"
	"strings"
)

// credentialKeyPrefixes 凭据类键名关键字（大小写不敏感）：
// 结果摘要与审计 payload 中命中即掩码（第十七轮 P4 硬性约束 7）。
var credentialKeyPrefixes = []string{"secret", "token", "password", "credential", "passwd", "apikey", "api_key"}

// kvPattern 匹配 key=value / key: value / key="value" 形态的凭据类键值。
var kvPattern = regexp.MustCompile(`(?i)([A-Za-z0-9_.\-]*(?:secret|token|password|credential|passwd|apikey|api_key)[A-Za-z0-9_.\-]*)\s*[:=]\s*("[^"]*"|'[^']*'|\S+)`)

// maskOutput 屏蔽输出中的凭据类键值（保留键名，值替换为 ***）。
func maskOutput(s string) string {
	return kvPattern.ReplaceAllString(s, "${1}=***")
}

// maskOutputs 屏蔽多个输出片段并拼接（供结果摘要使用）。
func maskOutputs(parts []string) string {
	var b strings.Builder
	for i, p := range parts {
		if i > 0 {
			b.WriteString(" | ")
		}
		b.WriteString(maskOutput(p))
	}
	return b.String()
}

// isCredentialKey 判定键名是否凭据类（供测试核对）。
func isCredentialKey(key string) bool {
	lower := strings.ToLower(strings.TrimSpace(key))
	for _, p := range credentialKeyPrefixes {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}
