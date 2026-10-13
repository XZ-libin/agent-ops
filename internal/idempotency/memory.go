package idempotency

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"

	"github.com/ORG/agent-ops/internal/audit"
)

// MemoryStore 幂等键内存实现。
// 并发安全：Begin/Complete 以互斥锁保证同一 Scope 的判定原子性。
// 时间通过 WithClock 注入（生产默认 time.Now）；过期与租约判定只使用注入时钟。
type MemoryStore struct {
	mu      sync.Mutex
	entries map[memoryKey]Entry
	cfg     storeConfig
}

type memoryKey struct {
	actor string
	api   string
	key   string
}

// NewMemoryStore 创建内存实现。
func NewMemoryStore(opts ...Option) *MemoryStore {
	return &MemoryStore{
		entries: make(map[memoryKey]Entry),
		cfg:     applyOptions(opts...),
	}
}

// Begin 见 Store 接口文档。
func (s *MemoryStore) Begin(ctx context.Context, scope Scope, request []byte) (BeginResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.cfg.now()
	k := memoryKey{actor: scope.Actor, api: scope.API, key: scope.Key}
	h := hashRequest(request)

	if e, ok := s.entries[k]; ok {
		// 过期判定：now >= CreatedAt+ttl 视为过期（边界含等号，与 PostgresStore 一致）。
		if !now.Before(e.CreatedAt.Add(s.cfg.ttl)) {
			delete(s.entries, k)
		} else {
			switch {
			case e.RequestHash != h:
				return BeginResult{}, ErrContentConflict
			case e.Status == StatusCompleted:
				// completed：返回已存记录（含响应）。
				return BeginResult{Entry: &e, Fresh: false}, nil
			case e.Status == StatusAbandoned:
				// 已放弃：绝不同 key 重新执行。
				return BeginResult{}, ErrAbandoned
			case e.Status == StatusProcessing:
				if !now.Before(e.LeaseUntil) {
					// 处理超时：状态转为 abandoned 后返回 409，并记录审计事件。
					e.Status = StatusAbandoned
					s.entries[k] = e
					s.recordAbandoned(ctx, scope)
					return BeginResult{}, ErrAbandoned
				}
				return BeginResult{}, ErrInProgress
			}
		}
	}

	e := Entry{
		Scope:       scope,
		RequestHash: h,
		Status:      StatusProcessing,
		CreatedAt:   now,
		LeaseUntil:  now.Add(s.cfg.lease),
	}
	s.entries[k] = e
	return BeginResult{Entry: &e, Fresh: true}, nil
}

// Complete 见 Store 接口文档。
func (s *MemoryStore) Complete(_ context.Context, scope Scope, response any) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.cfg.now()
	k := memoryKey{actor: scope.Actor, api: scope.API, key: scope.Key}
	e, ok := s.entries[k]
	if !ok || !now.Before(e.CreatedAt.Add(s.cfg.ttl)) {
		return ErrRecordMissing
	}
	e.Status = StatusCompleted
	e.Response = response
	s.entries[k] = e
	return nil
}

// CleanupExpired 清理过期的幂等记录（可调度入口；频率见 CleanupIntervalDefault，
// 工程默认值每小时一次，调度器不实现）。审计记录不清理。返回清理行数。
func (s *MemoryStore) CleanupExpired(_ context.Context) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.cfg.now()
	var n int64
	for k, e := range s.entries {
		if !now.Before(e.CreatedAt.Add(s.cfg.ttl)) {
			delete(s.entries, k)
			n++
		}
	}
	return n, nil
}

// recordAbandoned 写入 idempotency.abandoned 审计事件（未注入 Recorder 时跳过）。
// 记录失败不影响幂等判定语义（由审计链路自身暴露问题）。
func (s *MemoryStore) recordAbandoned(ctx context.Context, scope Scope) {
	if s.cfg.recorder == nil {
		return
	}
	_ = s.cfg.recorder.RecordIdempotencyAbandoned(ctx, audit.IdempotencyAbandoned{
		Key:         scope.Key,
		Actor:       scope.Actor,
		API:         scope.API,
		Destructive: scope.Destructive,
	})
}

// hashRequest 请求内容哈希（sha256 hex）。
func hashRequest(request []byte) string {
	sum := sha256.Sum256(request)
	return hex.EncodeToString(sum[:])
}
