// Package ingest 是告警入口的领域逻辑（第十四轮 A1）：
// 请求校验、HMAC-SHA256 签名校验、去重窗口判定与 outbox 事件构造。
//
// 安全边界（ADR-013）：
//   - 签名密钥只从环境变量读取，代码中不硬编码任何真实密钥；
//   - 签名值、密钥不得出现在日志、错误、审计/outbox 负载中（本包不记录二者）；
//   - 本轮不实现诊断：不调用任何适配器、不执行任何命令。
package ingest

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Severity 告警级别（只接受这三个值）。
type Severity string

const (
	// SeverityInfo 提示。
	SeverityInfo Severity = "info"
	// SeverityWarning 警告。
	SeverityWarning Severity = "warning"
	// SeverityCritical 严重。
	SeverityCritical Severity = "critical"
)

// ValidSeverity 判定级别是否合法（**严格**：不做空白/大小写修正，fail-closed）。
func ValidSeverity(s string) bool {
	switch Severity(s) {
	case SeverityInfo, SeverityWarning, SeverityCritical:
		return true
	}
	return false
}

// DefaultDedupWindow 去重窗口（裁决：同一 fingerprint 5 分钟内只写一条）。
const DefaultDedupWindow = 5 * time.Minute

// DefaultSignatureTolerance 签名时间戳容忍窗口（工程默认，待运维确认）：
// 超出该窗口的时间戳视为重放/篡改，返回 401。
const DefaultSignatureTolerance = 5 * time.Minute

// 签名头。
const (
	// HeaderSignature 签名头（hex HMAC-SHA256）。
	HeaderSignature = "X-AgentOps-Signature"
	// HeaderTimestamp 时间戳头（Unix 秒）。
	HeaderTimestamp = "X-AgentOps-Timestamp"
	// EnvSecret 签名密钥的环境变量名（测试用固定测试密钥，生产由运维注入）。
	EnvSecret = "AGENT_OPS_ALERT_HMAC_SECRET"
)

// EnvSources 允许的告警源白名单环境变量（逗号分隔）。
const EnvSources = "AGENT_OPS_ALERT_SOURCES"

// EnvKeyPrefix 每源签名密钥的环境变量前缀：
// AGENT_OPS_ALERT_KEY_<SOURCE>（SOURCE 大写，连字符替换为下划线）。
const EnvKeyPrefix = "AGENT_OPS_ALERT_KEY_"

// EnvProfilePrefix 每源**画像**的环境变量前缀（第十七轮 P1）：
// AGENT_OPS_ALERT_PROFILE_<SOURCE>（命名规则同密钥）。
const EnvProfilePrefix = "AGENT_OPS_ALERT_PROFILE_"

// KnownProfiles 画像取值白名单（限定集合；未知即拒绝启动）。
var KnownProfiles = []string{"prometheus", "alertmanager", "docker-monitor", "node-exporter"}

// ProfileName 返回某源画像的环境变量名。
func ProfileName(source string) string {
	upper := strings.ToUpper(strings.TrimSpace(source))
	upper = strings.ReplaceAll(upper, "-", "_")
	return EnvProfilePrefix + upper
}

// KnownProfile 判定画像是否在已知集合内（大小写不敏感）。
func KnownProfile(profile string) bool {
	p := strings.ToLower(strings.TrimSpace(profile))
	for _, k := range KnownProfiles {
		if p == k {
			return true
		}
	}
	return false
}

// KeyEnvName 返回某源的密钥环境变量名。
func KeyEnvName(source string) string {
	upper := strings.ToUpper(strings.TrimSpace(source))
	upper = strings.ReplaceAll(upper, "-", "_")
	return EnvKeyPrefix + upper
}

// SourceSet 源白名单、每源密钥与每源**画像**（第十五轮 R3；第十七轮 P1 增画像）。
type SourceSet struct {
	// sources 允许的源名称集合（小写比较）。
	sources map[string]bool
	// keys 源 → 签名密钥。
	keys map[string][]byte
	// profiles 源 → 画像（取值限定在 KnownProfiles）。
	profiles map[string]string
}

// ParseSources 解析源白名单（逗号分隔，去空白、去空项；空列表即错误）。
func ParseSources(spec string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, raw := range strings.Split(spec, ",") {
		name := strings.TrimSpace(raw)
		if name == "" {
			continue
		}
		lower := strings.ToLower(name)
		if seen[lower] {
			continue
		}
		seen[lower] = true
		out = append(out, name)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("源白名单为空（%s 必须列出至少一个源）", EnvSources)
	}
	return out, nil
}

// NewSourceSet 构建源白名单、每源密钥与每源画像；任一已列出源缺密钥或
// 缺画像/画像未知即错误（fail-closed，拒绝启动）。
func NewSourceSet(sources []string, getenv func(string) string) (*SourceSet, error) {
	if len(sources) == 0 {
		return nil, errors.New("源白名单为空（fail-closed，拒绝启动）")
	}
	set := &SourceSet{sources: map[string]bool{}, keys: map[string][]byte{}, profiles: map[string]string{}}
	for _, name := range sources {
		lower := strings.ToLower(strings.TrimSpace(name))
		if lower == "" {
			continue
		}
		envName := KeyEnvName(lower)
		key := strings.TrimSpace(getenv(envName))
		if key == "" {
			return nil, fmt.Errorf("源 %q 缺少签名密钥环境变量 %s（fail-closed，拒绝启动）", lower, envName)
		}
		// 画像：必须显式声明且取值已知（第十七轮 P1）。
		profileEnv := ProfileName(lower)
		profile := strings.ToLower(strings.TrimSpace(getenv(profileEnv)))
		if profile == "" {
			return nil, fmt.Errorf("源 %q 缺少画像环境变量 %s（fail-closed，拒绝启动；"+
				"画像取值限定为 %v）", lower, profileEnv, KnownProfiles)
		}
		if !KnownProfile(profile) {
			return nil, fmt.Errorf("源 %q 的画像 %q 未知（fail-closed，拒绝启动；"+
				"画像取值限定为 %v）", lower, profile, KnownProfiles)
		}
		set.sources[lower] = true
		set.keys[lower] = []byte(key)
		set.profiles[lower] = profile
	}
	if len(set.sources) == 0 {
		return nil, errors.New("源白名单为空（fail-closed，拒绝启动）")
	}
	return set, nil
}

// ProfileFor 返回某源的画像（不在白名单返回空串）。
func (s *SourceSet) ProfileFor(source string) string {
	if s == nil {
		return ""
	}
	return s.profiles[strings.ToLower(strings.TrimSpace(source))]
}

// Profiles 返回 源 → 画像 的副本（供规划器按画像匹配）。
func (s *SourceSet) Profiles() map[string]string {
	out := map[string]string{}
	if s == nil {
		return out
	}
	for k, v := range s.profiles {
		out[k] = v
	}
	return out
}

// Allowed 判定源是否在白名单内（大小写不敏感）。
func (s *SourceSet) Allowed(source string) bool {
	if s == nil {
		return false
	}
	return s.sources[strings.ToLower(strings.TrimSpace(source))]
}

// Names 返回白名单中的源名（小写，稳定顺序：字典序）。
// 用于启动时预分配限流桶（第十六轮 R2：桶表大小 = 白名单长度）。
func (s *SourceSet) Names() []string {
	if s == nil {
		return nil
	}
	out := make([]string, 0, len(s.sources))
	for name := range s.sources {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// KeyFor 返回某源的签名密钥（不在白名单返回 nil）。
func (s *SourceSet) KeyFor(source string) []byte {
	if s == nil {
		return nil
	}
	return s.keys[strings.ToLower(strings.TrimSpace(source))]
}

// ErrSourceNotAllowed 源不在白名单 → 403。
var ErrSourceNotAllowed = errors.New("告警源不在白名单中")

// Alert 一条告警（received_at 由服务端注入）。
type Alert struct {
	Source      string    `json:"source"`
	Severity    string    `json:"severity"`
	AssetID     string    `json:"asset_id"`
	Fingerprint string    `json:"fingerprint"`
	Summary     string    `json:"summary"`
	ReceivedAt  time.Time `json:"received_at"`
}

// 领域错误（HTTP 层据此映射状态码）。
var (
	// ErrSignatureMissing 缺少签名头或时间戳头 → 401。
	ErrSignatureMissing = errors.New("缺少签名头或时间戳头")
	// ErrSignatureInvalid 签名不匹配（含时间戳被篡改）→ 401。
	ErrSignatureInvalid = errors.New("签名校验失败")
	// ErrTimestampStale 时间戳超出容忍窗口 → 401。
	ErrTimestampStale = errors.New("时间戳超出容忍窗口")
	// ErrSeverityInvalid 级别非法 → 400。
	ErrSeverityInvalid = errors.New("severity 只接受 info/warning/critical")
	// ErrFieldMissing 必填字段缺失 → 400。
	ErrFieldMissing = errors.New("必填字段缺失")
)

// Validate 校验告警字段（severity 白名单、必填字段）。
func Validate(a Alert) error {
	if !ValidSeverity(a.Severity) {
		return fmt.Errorf("%w（当前 %q）", ErrSeverityInvalid, a.Severity)
	}
	if strings.TrimSpace(a.Fingerprint) == "" {
		return fmt.Errorf("%w：fingerprint", ErrFieldMissing)
	}
	if strings.TrimSpace(a.Source) == "" {
		return fmt.Errorf("%w：source", ErrFieldMissing)
	}
	if strings.TrimSpace(a.AssetID) == "" {
		return fmt.Errorf("%w：asset_id", ErrFieldMissing)
	}
	return nil
}

// Sign 计算签名：hex(HMAC-SHA256(secret, timestamp + "." + body))。
// 供测试与发送方（告警源）复用；时间戳参与签名，篡改时间戳即签名失效。
func Sign(secret []byte, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifySignature 校验签名与时间戳：
//   - 任一头部缺失 → ErrSignatureMissing；
//   - 时间戳非整数 → ErrSignatureInvalid（篡改形态）；
//   - 时间戳与 now 相差超过 tolerance → ErrTimestampStale；
//   - 签名不匹配 → ErrSignatureInvalid。
//
// 比较使用 hmac.Equal（常量时间）。错误信息不回显签名值与密钥。
func VerifySignature(secret []byte, timestamp, signature string, body []byte, now time.Time, tolerance time.Duration) error {
	if strings.TrimSpace(timestamp) == "" || strings.TrimSpace(signature) == "" {
		return ErrSignatureMissing
	}
	if len(secret) == 0 {
		return ErrSignatureInvalid // 未配置密钥：一律拒绝（fail-closed）
	}
	ts, err := strconv.ParseInt(strings.TrimSpace(timestamp), 10, 64)
	if err != nil {
		return ErrSignatureInvalid
	}
	if tolerance <= 0 {
		tolerance = DefaultSignatureTolerance
	}
	drift := now.Sub(time.Unix(ts, 0))
	if drift < 0 {
		drift = -drift
	}
	if drift > tolerance {
		return ErrTimestampStale
	}
	want := Sign(secret, strings.TrimSpace(timestamp), body)
	got := strings.ToLower(strings.TrimSpace(signature))
	if !hmac.Equal([]byte(want), []byte(got)) {
		return ErrSignatureInvalid
	}
	return nil
}

// LoadSecret 从环境变量读取签名密钥（不打印、不回显内容）。
func LoadSecret(getenv func(string) string) ([]byte, error) {
	v := strings.TrimSpace(getenv(EnvSecret))
	if v == "" {
		return nil, fmt.Errorf("未配置签名密钥环境变量 %s（fail-closed，拒绝启动）", EnvSecret)
	}
	return []byte(v), nil
}

// OutboxEvent 写入 outbox 的事件（负载为规范化 JSON，不含签名与密钥）。
type OutboxEvent struct {
	EventType string
	Payload   []byte
}

// OutboxEventType 新告警写入 outbox 的事件类型。
const OutboxEventType = "alert.received"

// Decision 去重判定结果。
type Decision struct {
	// Deduplicated 本次是否命中窗口内的既有告警（true = 计数加一、不新增行）。
	Deduplicated bool
	// ExistingCount 命中时既有行的计数（未命中为 0）。
	ExistingCount int64
}
