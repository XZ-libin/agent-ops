package nodeidentity

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"time"
)

// 一次性注册令牌（第二十一轮 N3）。
//
// 设计要点：
//   - 令牌明文**只在生成时返回一次**；控制面只保存其 SHA-256 哈希（`TokenHash`），
//     因此数据库泄露不直接等于令牌泄露；
//   - 有效期 15 分钟（注入时钟判定）；
//   - **用后即失效**：成功注册后立即置为已用；
//   - 校验失败一律返回**同一个**对外错误（`ErrTokenRejected`），不泄露
//     "是哈希不匹配、还是已过期、还是已使用"——具体原因通过 `Outcome` 返回，
//     仅供审计与测试使用（硬性约束 7：错误信息不携带令牌明文）。

// TokenTTL 注册令牌有效期（第二十一轮裁决：15 分钟）。
const TokenTTL = 15 * time.Minute

// tokenBytes 令牌明文的随机字节数（32 字节 → 256 位熵）。
const tokenBytes = 32

// ErrTokenRejected 令牌被拒绝（**对外唯一**的错误，不区分具体原因）。
var ErrTokenRejected = errors.New("nodeidentity：注册令牌无效")

// ErrTokenNotFound 令牌不存在（内部原因，供审计与测试）。
var ErrTokenNotFound = errors.New("nodeidentity：注册令牌不存在")

// ErrTokenExpired 令牌已过期（内部原因，供审计与测试）。
var ErrTokenExpired = errors.New("nodeidentity：注册令牌已过期")

// ErrTokenUsed 令牌已被使用（内部原因，供审计与测试）。
var ErrTokenUsed = errors.New("nodeidentity：注册令牌已被使用")

// TokenHash 令牌的 SHA-256 哈希（固定 32 字节）。
type TokenHash [sha256.Size]byte

// Outcome 令牌校验结果（内部原因；对外一律映射为 ErrTokenRejected）。
type Outcome string

const (
	// OutcomeOK 校验通过（令牌已被标记为已用）。
	OutcomeOK Outcome = "ok"
	// OutcomeNotFound 未找到该令牌哈希。
	OutcomeNotFound Outcome = "not_found"
	// OutcomeExpired 已过期。
	OutcomeExpired Outcome = "expired"
	// OutcomeUsed 已使用。
	OutcomeUsed Outcome = "used"
)

// TokenRecord 控制面保存的令牌记录（**不含明文**）。
type TokenRecord struct {
	// Hash 令牌明文的 SHA-256。
	Hash TokenHash
	// ExpiresAt 到期时刻。
	ExpiresAt time.Time
	// UsedAt 使用时刻；零值表示未使用。
	UsedAt time.Time
	// UsedByNodeID 使用该令牌注册成功的节点身份。
	UsedByNodeID string
}

// GenerateToken 生成一次性注册令牌：返回明文与哈希（明文不落库）。
func GenerateToken(r io.Reader) (plain string, hash TokenHash, err error) {
	if r == nil {
		r = rand.Reader
	}
	buf := make([]byte, tokenBytes)
	if _, err := r.Read(buf); err != nil {
		return "", TokenHash{}, fmt.Errorf("nodeidentity：生成注册令牌失败：%w", err)
	}
	plain = base64.RawURLEncoding.EncodeToString(buf)
	return plain, HashTokenOf(plain), nil
}

// HashTokenOf 计算令牌明文的 SHA-256（恒定时间比较由 CompareTokenHash 负责）。
func HashTokenOf(plain string) TokenHash {
	return sha256.Sum256([]byte(plain))
}

// CompareTokenHash 恒定时间比较两个哈希（防时序侧信道）。
func CompareTokenHash(a, b TokenHash) bool {
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

// NewTokenRecord 构造令牌记录（有效期自 now 起 15 分钟）。
func NewTokenRecord(plain string, now time.Time) TokenRecord {
	return TokenRecord{Hash: HashTokenOf(plain), ExpiresAt: now.UTC().Add(TokenTTL)}
}

// CheckToken 校验令牌（纯函数，不修改记录）。
//
// 校验顺序：存在性 → 已使用 → 已过期。返回对外错误恒为 ErrTokenRejected；
// 具体原因通过 Outcome 返回。
func CheckToken(rec TokenRecord, found bool, plain string, now time.Time) (Outcome, error) {
	if !found {
		return OutcomeNotFound, ErrTokenRejected
	}
	// 哈希比较放在最前：即使记录已过期/已使用，也先确认令牌本身正确，
	// 避免"错误令牌 + 已过期"被误判为过期（不泄露令牌正确性）。
	if !CompareTokenHash(rec.Hash, HashTokenOf(plain)) {
		return OutcomeNotFound, ErrTokenRejected
	}
	if !rec.UsedAt.IsZero() {
		return OutcomeUsed, ErrTokenRejected
	}
	if !now.UTC().Before(rec.ExpiresAt) {
		return OutcomeExpired, ErrTokenRejected
	}
	return OutcomeOK, nil
}

// MarkUsed 返回标记为已用的记录副本（成功注册时调用）。
func MarkUsed(rec TokenRecord, nodeID string, now time.Time) TokenRecord {
	rec.UsedAt = now.UTC()
	rec.UsedByNodeID = nodeID
	return rec
}

// TokenStore 令牌存储抽象。
//
// 本轮只提供内存实现（纯单元部分）；**PostgreSQL 实现待 CI 验证后补**（见报告 TODO）。
type TokenStore interface {
	// Put 保存令牌记录（键为哈希）。
	Put(rec TokenRecord) error
	// Get 按哈希取记录；found=false 表示不存在。
	Get(h TokenHash) (rec TokenRecord, found bool)
}

// MemoryTokenStore 内存令牌存储（仅供单测；进程退出即丢失）。
type MemoryTokenStore struct {
	records map[TokenHash]TokenRecord
}

// NewMemoryTokenStore 构建内存令牌存储。
func NewMemoryTokenStore() *MemoryTokenStore {
	return &MemoryTokenStore{records: map[TokenHash]TokenRecord{}}
}

// Put 保存记录。
func (s *MemoryTokenStore) Put(rec TokenRecord) error {
	if s.records == nil {
		s.records = map[TokenHash]TokenRecord{}
	}
	s.records[rec.Hash] = rec
	return nil
}

// Get 取记录。
func (s *MemoryTokenStore) Get(h TokenHash) (TokenRecord, bool) {
	rec, ok := s.records[h]
	return rec, ok
}

// Enroll 用一次性令牌完成一次注册（纯逻辑编排：校验 → 标记已用 → 返回记录）。
//
// 说明：这里只做"令牌生命周期"部分；证书签发与持久化在调用方（见 ca.go 与报告 TODO）。
func Enroll(store TokenStore, plain string, now time.Time, allocateNodeID func() (string, error)) (TokenRecord, string, error) {
	h := HashTokenOf(plain)
	rec, found := store.Get(h)
	outcome, err := CheckToken(rec, found, plain, now)
	if err != nil {
		return TokenRecord{}, "", err
	}
	if outcome != OutcomeOK {
		return TokenRecord{}, "", ErrTokenRejected
	}
	nodeID, err := allocateNodeID()
	if err != nil {
		return TokenRecord{}, "", err
	}
	used := MarkUsed(rec, nodeID, now)
	if err := store.Put(used); err != nil {
		return TokenRecord{}, "", err
	}
	return used, nodeID, nil
}
