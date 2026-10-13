// Package idempotency 实现幂等键（ADR-002 决策 5 / Q10）：
//
//   - 作用域：操作人 + 接口 + key；
//   - 同键同请求内容 → 返回已存的响应；
//   - 同键不同请求内容 → 422（ErrContentConflict）；
//   - 同键仍在处理中 → 409（ErrInProgress）；
//   - 处理中超时（超过 lease_until）→ 状态转为 abandoned，同键返回 409
//     （ErrAbandoned，说明"上一次操作状态未知，已放弃，请使用新的 key 重试"），
//     绝不同 key 重新执行——原操作可能仍在运行；
//   - 有效期默认 24 小时（DefaultTTL，默认值，待运维确认）。
//
// 存储层以 Store 接口抽象，提供内存实现（MemoryStore）与 PostgreSQL 实现
// （PostgresStore）。过期与租约判定统一使用注入的时钟（WithClock），
// 不依赖数据库 now()。过期清理为惰性方式。
// TODO(待决策)：幂等过期清理的调度方式（后台任务）未定。
package idempotency

import (
	"context"
	"errors"
	"time"

	"github.com/XZ-libin/agent-ops/internal/audit"
)

// DefaultTTL 幂等键默认有效期 24 小时（默认值，待运维确认）。
const DefaultTTL = 24 * time.Hour

// DefaultLease 处理中租约默认时长 5 分钟（默认值，待运维确认；
// 对齐"执行类能力超时 300s"候选）。处理超过 lease_until 后判为 abandoned。
const DefaultLease = 5 * time.Minute

// CleanupIntervalDefault 过期清理调度频率：每小时一次（工程默认值，待运维确认）。
// 本模块只提供可调度的 CleanupExpired 入口，调度器本身不实现。
// TODO(待决策)：清理任务的接入点（控制层 cron/外部调度）未定。
const CleanupIntervalDefault = time.Hour

// 错误与 HTTP 状态码的对应关系：
//   - ErrContentConflict → HTTP 422（同键不同请求内容）；
//   - ErrInProgress      → HTTP 409（同键仍在处理中）；
//   - ErrAbandoned       → HTTP 409（上一次操作状态未知，已放弃，请使用新的 key 重试）。
var (
	ErrContentConflict = errors.New("idempotency key 已存在且请求内容不同（HTTP 422）")
	ErrInProgress      = errors.New("idempotency key 正在处理中（HTTP 409）")
	ErrAbandoned       = errors.New("idempotency key 上一次操作状态未知，已放弃，请使用新的 key 重试（HTTP 409）")
	ErrRecordMissing   = errors.New("idempotency key 记录不存在（已过期或被清理）")
)

// Scope 幂等键作用域：操作人 + 接口 + key（三者组合唯一）。
type Scope struct {
	Actor string // 操作人
	API   string // 接口（方法 + 路径，如 "POST /change-plans"）
	Key   string // 调用方携带的 Idempotency-Key
	// Destructive 本次操作的能力是否 destructive（若可知）；
	// 用于 idempotency.abandoned 审计事件载荷，不影响幂等判定。
	Destructive bool
}

// Status 幂等记录状态。
type Status string

const (
	StatusProcessing Status = "processing"
	StatusCompleted  Status = "completed"
	// StatusAbandoned 处理超时后被放弃：原操作状态未知，可能仍在运行；
	// 同 key 不可重新执行，操作者须换新 key 重试。
	StatusAbandoned Status = "abandoned"
)

// Entry 幂等记录。
type Entry struct {
	Scope       Scope
	RequestHash string    // 请求内容的哈希（sha256）
	Status      Status    // processing / completed / abandoned
	Response    any       // 已存响应（completed 后有效）
	CreatedAt   time.Time // 创建时间，用于 TTL 判定
	LeaseUntil  time.Time // 处理中租约期限；超过后转为 abandoned
}

// BeginResult Begin 的返回。
type BeginResult struct {
	Entry *Entry
	// Fresh 为 true 表示本次创建了记录，调用方应执行实际操作；
	// 为 false 表示 Entry 携带已存记录（含已存响应），调用方直接复用。
	Fresh bool
}

// Store 幂等键存储抽象。实现必须保证同一 Scope 的 Begin 判定原子性。
type Store interface {
	// Begin 获取或创建幂等记录：
	//   - 不存在（或已过期）→ 创建 processing 记录，Fresh=true；
	//   - 存在且请求内容相同：
	//   - completed → 返回已存记录（含响应），Fresh=false；
	//   - processing → 返回 ErrInProgress；
	//   - 存在且请求内容不同 → 返回 ErrContentConflict。
	Begin(ctx context.Context, scope Scope, request []byte) (BeginResult, error)
	// Complete 写入响应并置为 completed；记录不存在（如已过期）→ ErrRecordMissing。
	Complete(ctx context.Context, scope Scope, response any) error
}

// Option 配置 Store 实现（MemoryStore 与 PostgresStore 通用）。
type Option func(*storeConfig)

// storeConfig 各实现共用的配置。
type storeConfig struct {
	ttl      time.Duration
	lease    time.Duration
	now      func() time.Time
	recorder audit.Recorder // 可选：abandoned 事件写入审计
}

// WithTTL 覆盖有效期（默认 DefaultTTL）。
func WithTTL(ttl time.Duration) Option { return func(c *storeConfig) { c.ttl = ttl } }

// WithLease 覆盖处理中租约时长（默认 DefaultLease）。
func WithLease(lease time.Duration) Option { return func(c *storeConfig) { c.lease = lease } }

// WithClock 注入时间源（测试用；过期与租约判定统一使用该时钟，不用数据库 now()）。
func WithClock(now func() time.Time) Option { return func(c *storeConfig) { c.now = now } }

// WithAuditRecorder 注入审计写入器：处理超时转 abandoned 时记录
// idempotency.abandoned 事件（不改变 Store 接口签名）。nil 时不记录。
func WithAuditRecorder(r audit.Recorder) Option { return func(c *storeConfig) { c.recorder = r } }

// applyOptions 应用选项，返回带默认值的配置。
func applyOptions(opts ...Option) storeConfig {
	c := storeConfig{ttl: DefaultTTL, lease: DefaultLease, now: time.Now}
	for _, o := range opts {
		o(&c)
	}
	return c
}
