package console

import (
	"encoding/json"
	"strings"
)

// 审计 payload 的白名单投影（ADR-024 §5）。
//
// 为什么用白名单而不是黑名单：审计 payload 历史上写入过过宽的字段（第十七轮的
// 执行录像输出教训）。黑名单在新字段出现时会**静默放行**；白名单在新键未登记时
// 表现为"控制台看不到这个字段"——可发现、可评审，不会变成泄漏。

// PayloadAllowlist 动作前缀 → 允许回传的键。未登记的前缀**一律不回传任何键**。
var PayloadAllowlist = map[string][]string{
	"node.":      {"node_id", "boot_session_id", "event_kind", "reason_code"},
	"approval.":  {"approval_id", "capability", "status"},
	"diagnosis.": {"capability", "status", "exit_class"},
	"execution.": {"capability", "status", "exit_class"},
}

// allowlistFor 找到动作对应的键集合。
func allowlistFor(action string) []string {
	for prefix, keys := range PayloadAllowlist {
		if strings.HasPrefix(action, prefix) {
			return keys
		}
	}
	return nil
}

// 值级筛查：白名单只挡"键"，挡不住把秘密塞进合法键的值（例如把 PEM 写进
// reason_code）。因此再加三条：PEM/私钥/JWT 特征一律丢弃，超长值丢弃。
// 丢弃是安全侧失败——控制台少一个字段是可发现的（评审能看到），
// 多回传一个凭据是不可发现的。
const maxScalarLen = 256

var secretMarkers = []string{
	"-----BEGIN", "PRIVATE KEY", "PUBLIC KEY", "OPENSSH SSH", "eyJ", // JWT/密钥的 base64 头部
}

// looksLikeSecret 判定值是否携带密钥/PEM/JWT 特征。
func looksLikeSecret(v string) bool {
	if len(v) > maxScalarLen {
		return true
	}
	u := strings.ToUpper(v)
	for _, m := range secretMarkers {
		if strings.Contains(u, strings.ToUpper(m)) {
			return true
		}
	}
	return false
}

// ProjectPayload 把原始 jsonb 投影成"仅白名单键 + 仅标量值"的字符串映射。
//
// 丢弃规则：
//   - 未登记的键（含任何密钥、令牌、PEM、连接串字样的键）；
//   - 值为对象或数组的键（投影只回传标量，避免嵌套结构夹带任意内容）；
//   - null 值；
//   - 解析失败的整个 payload（返回空映射，不回传原始文本）。
func ProjectPayload(action string, raw []byte) map[string]string {
	out := map[string]string{}
	if len(raw) == 0 {
		return out
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return out
	}
	keys := allowlistFor(action)
	if keys == nil {
		return out
	}
	for _, k := range keys {
		v, ok := obj[k]
		if !ok {
			continue
		}
		s, ok := scalarString(v)
		if !ok || looksLikeSecret(s) {
			continue
		}
		out[k] = s
	}
	return out
}

// scalarString 只接受 JSON 标量（字符串 / 数字 / 布尔），其余返回 false。
func scalarString(raw json.RawMessage) (string, bool) {
	t := strings.TrimSpace(string(raw))
	if t == "" || t == "null" {
		return "", false
	}
	switch t[0] {
	case '{', '[':
		return "", false // 容器类型一律丢弃
	case '"':
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return "", false
		}
		return s, true
	}
	if t == "true" || t == "false" {
		return t, true
	}
	// 数字
	if c := t[0]; c == '-' || (c >= '0' && c <= '9') {
		return t, true
	}
	return "", false
}
