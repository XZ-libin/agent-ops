package gateway

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"
	"unicode"

	"google.golang.org/protobuf/encoding/protojson"

	contractv1 "github.com/XZ-libin/agent-ops/contract/gen/go/agent_ops/contract/v1"
)

// —— 幂等键请求内容规范化 ——
// 哈希输入为确定性的 JSON 序列化（结构体字段顺序固定、map 键排序），
// 同一语义请求必然产出同一哈希；任何内容差异（含参数、目标、环境）即不同哈希。

// idemRequestPayload 参与幂等哈希的请求内容（不含凭据：CredentialRef 不参与、
// 也不存储；params 是调用方输入，参与哈希但不写入审计）。
// Key 参与幂等哈希（幂等键是幂等作用域的一部分）；审批哈希不含 Key——
// 见 requestPayload(req, false)：F3 的 pending 去重键是 (actor, request_hash)，
// 同一请求内容换幂等键仍应视为同一待审批事项。
type idemRequestPayload struct {
	Actor        string         `json:"actor"`
	Key          string         `json:"key,omitempty"`
	Capability   string         `json:"capability"`
	Params       map[string]any `json:"params"`
	AssetID      string         `json:"asset_id"`
	Access       string         `json:"access"`
	Environment  string         `json:"environment"`
	ImpactScope  string         `json:"impact_scope"`
	FreezeWindow bool           `json:"freeze_window"`
}

// canonicalRequestBytes 生成请求的规范化字节（见 ADR-009：JSON 键排序、
// 紧凑无空白、不转义 HTML 字符、缺失值 null —— 规则对 TS/Python 客户端同样适用）。
func canonicalRequestBytes(req Request) []byte {
	return canonicalJSON(requestPayload(req, true))
}

// canonicalApprovalBytes 生成审批记录绑定的规范化字节：与幂等字节唯一的区别是
// **不含幂等键**（F3：同一内容换键仍是同一待审批事项）。
func canonicalApprovalBytes(req Request) []byte {
	return canonicalJSON(requestPayload(req, false))
}

// requestPayload 构造请求内容载荷；includeKey 为 false 时省略幂等键。
func requestPayload(req Request, includeKey bool) idemRequestPayload {
	p := idemRequestPayload{
		Actor:        req.Actor,
		Environment:  contractv1.Environment_name[int32(req.Environment)],
		FreezeWindow: req.FreezeWindow,
	}
	if includeKey {
		p.Key = req.IdempotencyKey
	}
	if req.Action != nil {
		p.Capability = req.Action.Capability
		p.ImpactScope = req.Action.ImpactScope
		if req.Action.Params != nil {
			p.Params = req.Action.Params.AsMap()
		}
		if req.Action.Target != nil {
			p.AssetID = req.Action.Target.AssetId
			p.Access = contractv1.AccessKind_name[int32(req.Action.Target.Access)]
		}
	}
	return p
}

// canonicalJSON 产出 ADR-009 规定的规范化 JSON：
//   - 紧凑无空白；结构体字段按声明顺序；map 键按 Unicode 码点升序；
//   - 不转义 < > & 与非 ASCII（json.Encoder.SetEscapeHTML(false)）；
//   - 缺失的可选值为 null，空 map 为 {}，数字取最短往返表示。
func canonicalJSON(v any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		// 输入为纯字符串/数字/布尔/map，不可能失败；防御性兜底。
		panic("gateway canonical json: " + err.Error())
	}
	b := buf.Bytes()
	if n := len(b); n > 0 && b[n-1] == '\n' {
		b = b[:n-1]
	}
	return b
}

// hashRequest 请求内容 sha256（审批记录绑定用；不含幂等键，见 canonicalApprovalBytes）。
// 创建审批与执行期校验两端必须使用同一函数。
func hashRequest(req Request) string {
	sum := sha256.Sum256(canonicalApprovalBytes(req))
	return hex.EncodeToString(sum[:])
}

// —— 幂等已存响应（Response 的持久形态）——
// ActionResult 等 protobuf 消息没有 encoding/json 的 MarshalJSON 实现，
// 显式走 protojson，保证幂等存储（内存/PostgreSQL）两端一致。

// storedResponse 幂等存储中的响应形态。
type storedResponse struct {
	Status     string          `json:"status"`
	Decision   string          `json:"decision,omitempty"`
	ApprovalID string          `json:"approval_id,omitempty"`
	Result     json.RawMessage `json:"result,omitempty"`
	Message    string          `json:"message,omitempty"`
	Reasons    []string        `json:"reasons,omitempty"`
}

// responseToStored 把 Response 转成可持久化形态。
func responseToStored(r *Response) storedResponse {
	s := storedResponse{
		Status:     string(r.Status),
		Decision:   decisionLabel(r.Decision),
		ApprovalID: r.ApprovalID,
		Message:    r.Message,
		Reasons:    r.Reasons,
	}
	if r.Result != nil {
		if b, err := protojson.Marshal(r.Result); err == nil {
			s.Result = b
		}
	}
	return s
}

// storedResponseToResponse 从幂等存储值还原 Response（any → JSON 往返，
// 兼容内存实现与 PostgreSQL 实现的存储差异）。
func storedResponseToResponse(v any) (*Response, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var s storedResponse
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	resp := &Response{
		Status:     Status(s.Status),
		Decision:   decisionFromLabel(s.Decision),
		ApprovalID: s.ApprovalID,
		Message:    s.Message,
		Reasons:    s.Reasons,
	}
	if len(s.Result) > 0 {
		result := &contractv1.ActionResult{}
		if err := protojson.Unmarshal(s.Result, result); err != nil {
			return nil, err
		}
		resp.Result = result
	}
	return resp, nil
}

// —— 错误信息脱敏（约束 11：凭据不得出现在日志、错误、审计 payload 中）——
// 返回给调用方的 Message 统一经 sanitizeError：压缩空白、截断、
// 掩码 key=value 形态的凭据类字段。审计 payload 从不包含错误原文。

// credentialPairPattern 凭据类字段对（password=xxx / token: yyy 等），
// 命中后值替换为 ***（工程默认启发式，待运维确认）。
var credentialPairPattern = regexp.MustCompile(
	`(?i)(password|passwd|pwd|token|secret|credential|api[-_]?key|private[-_]?key)(\s*[=:]\s*)(\S+)`)

// sanitizeError 脱敏错误信息（供响应 Message，不供审计）。
func sanitizeError(err error) string {
	if err == nil {
		return ""
	}
	return Sanitize(err.Error())
}

// Sanitize 脱敏对外文案（凭据形态字段掩码 + 空白压缩 + 截断）：
// gRPC 错误信息、响应 Message 等一切面向调用方的文本统一走这里，
// 确保凭据不会经错误通道外泄（约束 8）。
func Sanitize(msg string) string {
	msg = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, msg)
	msg = strings.Join(strings.Fields(msg), " ")
	if len(msg) > 300 {
		msg = msg[:300] + "…"
	}
	return credentialPairPattern.ReplaceAllString(msg, "${1}${2}***")
}
