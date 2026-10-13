package ingest

import (
	"strings"
	"sync"
	"time"
)

// 速率限制默认参数（第十五轮 R4，裁决）：每源 60 次/分钟，突发 10。
const (
	// DefaultRateLimitPerMinute 每源每分钟配额。
	DefaultRateLimitPerMinute = 60
	// DefaultRateLimitBurst 每源突发容量（令牌桶容量）。
	DefaultRateLimitBurst = 10
)

// Limiter 每源令牌桶限流器（时钟通过注入控制）。
//
// 语义：每源独立令牌桶，容量 = burst，按 perMinute/60 的速率补充。
// 令牌不足时 Allow 返回 false 与建议的 Retry-After 秒数。
type Limiter struct {
	mu         sync.Mutex
	buckets    map[string]*bucket
	ratePerSec float64
	burst      float64
	now        func() time.Time
}

type bucket struct {
	tokens   float64
	lastFill time.Time
}

// NewLimiter 构建限流器（**不预分配桶**；仅测试用）；perMinute/burst <= 0 用默认值。
//
// 生产路径请用 NewLimiterForSources：桶表在启动时按白名单预分配，
// 运行期间不新增键（第十六轮 R2：桶表大小恒等于白名单长度）。
func NewLimiter(perMinute, burst int, now func() time.Time) *Limiter {
	return NewLimiterForSources(nil, perMinute, burst, now)
}

// NewLimiterForSources 按白名单预分配桶（第十六轮 R2）：
// 桶表大小 = 去重后的白名单长度，运行期间**不新增键**。
// 未预分配的 source 不会被分配桶（Allow 返回 known=false）。
func NewLimiterForSources(sources []string, perMinute, burst int, now func() time.Time) *Limiter {
	if perMinute <= 0 {
		perMinute = DefaultRateLimitPerMinute
	}
	if burst <= 0 {
		burst = DefaultRateLimitBurst
	}
	if now == nil {
		now = time.Now
	}
	l := &Limiter{
		buckets:    map[string]*bucket{},
		ratePerSec: float64(perMinute) / 60.0,
		burst:      float64(burst),
		now:        now,
	}
	for _, src := range sources {
		key := normalizeSource(src)
		if key == "" {
			continue
		}
		if _, exists := l.buckets[key]; exists {
			continue
		}
		l.buckets[key] = &bucket{tokens: l.burst, lastFill: l.now()}
	}
	return l
}

// normalizeSource 源名归一化（小写去空白；桶键唯一来源）。
func normalizeSource(source string) string {
	return strings.ToLower(strings.TrimSpace(source))
}

// BucketCount 返回桶表当前键数（第十六轮 R2：应恒等于白名单长度）。
func (l *Limiter) BucketCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// Allow 尝试为 source 取一个令牌。
//
// 返回 (是否放行, 建议的 Retry-After 秒数；放行时为 0, 该源是否有桶)。
// **不存在的桶不会被创建**（known=false）——调用方必须先做白名单校验（R1 顺序），
// 因此桶表键数在运行期恒定（R2）。
func (l *Limiter) Allow(source string) (allowed bool, retryAfter int, known bool) {
	key := normalizeSource(source)
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	b, ok := l.buckets[key]
	if !ok {
		return true, 0, false // 未预分配：不建桶、不消耗（由白名单负责拒绝）
	}
	// 按经过时间补充令牌。
	elapsed := now.Sub(b.lastFill).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * l.ratePerSec
		if b.tokens > l.burst {
			b.tokens = l.burst
		}
		b.lastFill = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return true, 0, true
	}
	// 令牌不足：计算补满 1 个令牌所需秒数（向上取整，至少 1 秒）。
	need := (1 - b.tokens) / l.ratePerSec
	retry := int(need)
	if float64(retry) < need {
		retry++
	}
	if retry < 1 {
		retry = 1
	}
	return false, retry, true
}
