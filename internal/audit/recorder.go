package audit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
)

// PolicyDecision 策略判定事件载荷（policy.decided），
// 决策与等级以枚举字符串形式记录，便于审计阅读与检索。
type PolicyDecision struct {
	Capability string   `json:"capability"`
	Tier       string   `json:"tier"`     // RiskTier.String()
	Decision   string   `json:"decision"` // Decision.String()
	Reasons    []string `json:"reasons"`
}

// IdempotencyAbandoned 幂等键处理超时事件载荷（idempotency.abandoned）。
type IdempotencyAbandoned struct {
	Key         string `json:"key"`
	Actor       string `json:"actor"`
	API         string `json:"api"`
	Destructive bool   `json:"destructive"` // 该能力是否 destructive（若可知）
}

// Recorder 审计事件写入接口（internal 内部使用）。
// *Store 为其实现；policy 与 idempotency 通过本接口接入审计，
// 不改变 policy.Evaluate 与 idempotency.Store 的既有签名。
type Recorder interface {
	RecordPolicyDecision(ctx context.Context, d PolicyDecision) error
	RecordIdempotencyAbandoned(ctx context.Context, d IdempotencyAbandoned) error
}

// 编译期断言：*Store 实现 Recorder。
var _ Recorder = (*Store)(nil)

// RecordPolicyDecision 写入 policy.decided 事件（包括 deny）。
func (s *Store) RecordPolicyDecision(ctx context.Context, d PolicyDecision) error {
	_, err := s.Append(ctx, Event{
		ID:      newEventID(),
		Actor:   "policy",
		Action:  "policy.decided",
		Target:  d.Capability,
		Payload: d,
	})
	return err
}

// RecordIdempotencyAbandoned 写入 idempotency.abandoned 事件。
func (s *Store) RecordIdempotencyAbandoned(ctx context.Context, d IdempotencyAbandoned) error {
	_, err := s.Append(ctx, Event{
		ID:      newEventID(),
		Actor:   d.Actor,
		Action:  "idempotency.abandoned",
		Target:  d.Key,
		Payload: d,
	})
	return err
}

// newEventID 生成本地事件 ID（随机 hex；ULID 类 ID 规范随资产模块统一后替换）。
func newEventID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand 失败属于环境异常，直接暴露。
		panic(err)
	}
	return "evt-" + hex.EncodeToString(b)
}
