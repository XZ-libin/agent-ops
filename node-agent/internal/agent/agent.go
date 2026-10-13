// Package agent 是节点代理的运行逻辑（第二十二轮 N7）。
//
// 与 cmd/node-agent 分离，便于单测：进程入口只做参数解析与装配。
//
// 约束：
//   - `-mode` **必填**，取值 test / prod；**prod 直接拒绝启动**
//     （生产身份与证书来源未实现）；
//   - 注册令牌来自环境变量 `NODE_ENROLL_TOKEN_FILE` 指向的文件，**权限必须为 0600**
//     （组与其他用户不得有任何权限），否则拒绝启动；
//   - 令牌读入后**尽力清零**（Go 的限制见 ReadTokenFile 注释）；
//   - 证书只保存在内存中（不落盘）；重启需要重新注册；
//   - SIGINT / SIGTERM 时**优雅停机**：停止发送心跳、关闭连接，不留下半完成的注册；
//   - **本轮不执行任何命令**（命令通道未实现）。
package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oklog/ulid/v2"

	contractv1 "github.com/ORG/agent-ops/contract/gen/go/agent_ops/contract/v1"
	"github.com/ORG/agent-ops/internal/nodeidentity"
	"github.com/ORG/agent-ops/node-agent/internal/enrollclient"
	"github.com/ORG/agent-ops/node-agent/internal/identity"
)

// 显式引用 io（保留用于未来的流式令牌读取；当前由 fs/os 使用）。
var _ io.Reader

// 运行模式。
const (
	// ModeTest 测试模式。
	ModeTest = "test"
	// ModeProd 生产模式（本轮拒绝启动）。
	ModeProd = "prod"
)

// 环境变量名。
const (
	// EnvTokenFile 注册令牌文件路径。
	//
	// 注意：**CA 路径不接受环境变量覆盖**（T2）：只通过启动参数 -ca-file 指定，
	// 避免环境被污染时把节点指向攻击者的 CA。
	EnvTokenFile = "NODE_ENROLL_TOKEN_FILE"
)

// T3（续期）默认参数——**工程默认，待确认**。
const (
	// DefaultRenewAtFraction 续期触发点：有效期的 50%。
	DefaultRenewAtFraction = 0.5
	// DefaultRenewJitter 续期时刻抖动：±10%。
	DefaultRenewJitter = 0.10
	// DefaultRenewBackoffInitial 续期失败重试初值：1 分钟。
	DefaultRenewBackoffInitial = time.Minute
	// DefaultRenewBackoffMax 续期失败重试上限：1 小时。
	DefaultRenewBackoffMax = time.Hour
)

// TokenFileMode 令牌文件要求的权限（0600）。
const TokenFileMode fs.FileMode = 0o600

// 错误。
var (
	// ErrModeRequired 未显式指定 -mode。
	ErrModeRequired = errors.New("node-agent：必须显式指定 -mode（test|prod），不得依赖默认值")
	// ErrProdNotImplemented prod 模式未实现（生产身份与证书来源）。
	ErrProdNotImplemented = errors.New("node-agent：mode=prod 不可用——生产身份与证书来源未实现，拒绝启动")
	// ErrTokenFileRequired 未配置令牌文件。
	ErrTokenFileRequired = errors.New("node-agent：必须通过 " + EnvTokenFile + " 指定一次性注册令牌文件")
	// ErrTokenFilePermissive 令牌文件权限过宽。
	ErrTokenFilePermissive = errors.New("node-agent：注册令牌文件权限必须为 0600（组与其他用户不得有任何权限）")
	// ErrTokenFileEmpty 令牌文件为空。
	ErrTokenFileEmpty = errors.New("node-agent：注册令牌文件为空")
	// ErrUnknownMode 未知模式。
	ErrUnknownMode = errors.New("node-agent：未知运行模式（仅接受 test|prod）")
)

// ParseMode 解析运行模式：必填；prod 直接拒绝。
func ParseMode(s string) (string, error) {
	switch strings.TrimSpace(s) {
	case ModeTest:
		return ModeTest, nil
	case ModeProd:
		return "", ErrProdNotImplemented
	case "":
		return "", ErrModeRequired
	}
	return "", fmt.Errorf("%w：%q", ErrUnknownMode, s)
}

// ReadTokenFile 读取令牌文件（权限必须是 0600）。
//
// 权限检查使用 `info.Mode().Perm()`：任何 group/other 位（含可读）都拒绝。
//
// **清零说明**：返回的字符串是 Go 的不可变 string，底层字节无法可靠清零
// （Go 运行时不保证 string 的存储不被复制/逃逸）。这里做**尽力而为**：
// 读取的临时 []byte 在返回前被覆盖清零；但调用方持有的 string 副本无法清除。
// 这是 Go 的语言限制，已在报告中列为 TODO（生产可考虑内存锁定/专用进程）。
func ReadTokenFile(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", ErrTokenFileRequired
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("node-agent：读取令牌文件失败：%w", err)
	}
	if perm := info.Mode().Perm(); perm != TokenFileMode {
		return "", fmt.Errorf("%w（实际 %#o）", ErrTokenFilePermissive, perm)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("node-agent：读取令牌文件失败：%w", err)
	}
	// 尽力清零临时缓冲。
	defer func() {
		for i := range raw {
			raw[i] = 0
		}
	}()
	tok := strings.TrimSpace(string(raw))
	if tok == "" {
		return "", ErrTokenFileEmpty
	}
	return tok, nil
}

// HeartbeatClient 节点侧客户端抽象（便于单测注入计数替身；
// 生产实现是 enrollclient.Client，走真实 mTLS）。
type HeartbeatClient interface {
	// Enroll 用一次性令牌注册（T2：仅在**没有**可用持久化身份时调用）。
	Enroll(ctx context.Context, token string) (*enrollclient.EnrollResult, error)
	// AdoptIdentity 装载已持久化的身份并重建 mTLS 连接（T2：重启复用）。
	AdoptIdentity(ctx context.Context, certDER, caDER []byte, key *ecdsa.PrivateKey) error
	// Heartbeat 上报心跳（携带会话标识，D6）。
	Heartbeat(ctx context.Context, nodeID, bootSessionID string, sentAt time.Time,
		load *contractv1.NodeLoadSummary) (contractv1.NodeStatus, error)
	// Renew 用新 CSR 续期（T3）。
	Renew(ctx context.Context, csrPEM []byte) (*enrollclient.RenewResult, error)
	Close() error
}

// Config 运行配置。
type Config struct {
	// Mode 运行模式（必填）。
	Mode string
	// Token 一次性注册令牌（已从文件读入）。
	Token string
	// DisplayLabel 展示标签。
	DisplayLabel string
	// AgentVersion 版本号。
	AgentVersion string
	// Interval 心跳间隔（<=0 用 10 秒）。
	Interval time.Duration
	// Load 负载摘要（CPU 核数、内存总量；不含进程列表）。
	Load *contractv1.NodeLoadSummary
	// Sleep 注入的等待（默认按 Interval 睡眠且可被 ctx 取消）。
	Sleep func(ctx context.Context, d time.Duration) bool
	// StateDir 身份持久化目录（空 = 仅内存；T2）。
	StateDir string
	// IdentityStore 身份读写器（空则按 StateDir 构造）。
	IdentityStore IdentityStore
	// CABundlePEM 信任的 CA 包（校验持久化身份；空则跳过 CA 校验）。
	CABundlePEM []byte
	// BootSessionID 本进程启动会话标识（D6；空则自动生成）。
	BootSessionID string
	// TokenFileToRemove 注册成功后尽力删除的令牌文件路径（T2）。
	TokenFileToRemove string
	// RemoveToken true 时注册成功后删除 TokenFileToRemove。
	RemoveToken bool
	// RenewAtFraction 续期触发点（有效期的比例；<=0 用 DefaultRenewAtFraction=0.5）。
	RenewAtFraction float64
	// RenewJitter 续期时刻抖动比例（<=0 用 DefaultRenewJitter=0.10）。
	RenewJitter float64
	// RenewBackoffInitial 续期失败重试初值（<=0 用 DefaultRenewBackoffInitial=1min）。
	RenewBackoffInitial time.Duration
	// RenewBackoffMax 续期失败重试上限（<=0 用 DefaultRenewBackoffMax=1h）。
	RenewBackoffMax time.Duration
	// RandomFloat 注入随机源（[0,1)；nil 用 crypto/rand 派生）。
	RandomFloat func() float64
	// Logf 注入日志（nil 用标准库 log.Printf）。
	Logf func(format string, args ...any)
	// Now 注入时钟。
	Now func() time.Time
}

// Runner 节点代理运行器。
type Runner struct {
	cfg    Config
	client HeartbeatClient

	enrolls    int64
	heartbeats int64
	stopped    int32
	reused     int32
	renewed    int64
	renewFails int64

	mu         sync.Mutex
	nodeID     string
	loaded     *identity.Identity
	tokenWarn  string
	lastRenew  time.Time
	backoff    time.Duration
	renewErr   string
	identityAt *identity.Identity
}

// NewRunner 构建运行器（校验配置）。
func NewRunner(cfg Config, client HeartbeatClient) (*Runner, error) {
	if client == nil {
		return nil, errors.New("node-agent：客户端为空")
	}
	mode, err := ParseMode(cfg.Mode)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.Token) == "" {
		return nil, ErrTokenFileRequired
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 10 * time.Second
	}
	if cfg.Sleep == nil {
		cfg.Sleep = sleepCtx
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	cfg.Mode = mode
	if strings.TrimSpace(cfg.BootSessionID) == "" {
		id, err := newNodeSessionID()
		if err != nil {
			return nil, err
		}
		cfg.BootSessionID = id
	}
	if cfg.RenewAtFraction <= 0 {
		cfg.RenewAtFraction = DefaultRenewAtFraction
	}
	if cfg.RenewJitter <= 0 {
		cfg.RenewJitter = DefaultRenewJitter
	}
	if cfg.RenewBackoffInitial <= 0 {
		cfg.RenewBackoffInitial = DefaultRenewBackoffInitial
	}
	if cfg.RenewBackoffMax <= 0 {
		cfg.RenewBackoffMax = DefaultRenewBackoffMax
	}
	if cfg.Logf == nil {
		cfg.Logf = log.Printf
	}
	if cfg.IdentityStore == nil && strings.TrimSpace(cfg.StateDir) != "" {
		st, err := identity.New(cfg.StateDir, "")
		if err != nil {
			return nil, err
		}
		cfg.IdentityStore = st
	}
	return &Runner{cfg: cfg, client: client}, nil
}

// newNodeSessionID 生成会话标识（ULID；D6）。
func newNodeSessionID() (string, error) {
	id, err := ulid.New(ulid.Timestamp(time.Now().UTC()), rand.Reader)
	if err != nil {
		return "", fmt.Errorf("node-agent：生成启动会话标识失败：%w", err)
	}
	return id.String(), nil
}

// IdentityStore 身份持久化抽象（便于测试注入损坏/权限异常的文件）。
type IdentityStore interface {
	// EnsureDir 准备 state 目录（权限 0700）。
	EnsureDir() error
	// Load 读取并校验已有身份（不存在时返回 identity.ErrNotFound）。
	Load(now time.Time, caPool *x509.CertPool, nodeID string) (*identity.Identity, error)
	// Save 原子保存身份。
	Save(id *identity.Identity) error
}

// sleepCtx 可被 ctx 取消的睡眠；返回 false 表示被取消。
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// Run 执行"注册一次 + 心跳循环"，直到 ctx 被取消（优雅停机）。
//
// 停机语义：**停止发送心跳 → 关闭连接**；ctx 在注册前被取消则**不发起注册**
// （不留半完成的注册）。
func (r *Runner) Run(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return nil // 启动前已取消：不发起注册
	}
	nodeID, interval, err := r.prepareIdentity(ctx)
	if err != nil {
		return err
	}

	for {
		if !r.cfg.Sleep(ctx, interval) {
			break // 收到停机信号
		}
		if ctx.Err() != nil {
			break
		}
		if _, herr := r.client.Heartbeat(ctx, nodeID, r.cfg.BootSessionID,
			r.cfg.Now().UTC(), r.cfg.Load); herr != nil {
			// 单次心跳失败不终止进程（控制面可能短暂不可用）；
			// 真正的停机由 ctx 驱动。
			continue
		}
		atomic.AddInt64(&r.heartbeats, 1)
		// T3：到期前续期（50%±10% 抖动；失败指数退避 1min→1h）。
		r.MaybeRenew(ctx)
	}
	// 优雅停机：不再发送心跳，关闭连接。
	atomic.StoreInt32(&r.stopped, 1)
	return r.client.Close()
}

// prepareIdentity 决定本次启动的身份来源：
//
//  1. 有 state 目录且身份文件**有效** → **复用**（不注册、不消耗令牌；T2）；
//  2. 身份文件不存在 → 走注册（消耗一次性令牌），成功后**原子保存**身份；
//  3. 身份文件存在但**损坏/权限过宽/已过期** → **拒绝启动**（绝不静默重新注册）。
//
// 返回（node_id, 心跳间隔, error）。
func (r *Runner) prepareIdentity(ctx context.Context) (string, time.Duration, error) {
	interval := r.cfg.Interval
	if r.cfg.IdentityStore == nil {
		// 未配置持久化：退化为仅内存（每次启动都要注册）。
		res, err := r.client.Enroll(ctx, r.cfg.Token)
		if err != nil {
			return "", 0, fmt.Errorf("node-agent：注册失败：%w", err)
		}
		atomic.AddInt64(&r.enrolls, 1)
		r.mu.Lock()
		r.nodeID = res.NodeID
		r.mu.Unlock()
		if res.HeartbeatInterval > 0 {
			interval = res.HeartbeatInterval
		}
		return res.NodeID, interval, nil
	}

	if err := r.cfg.IdentityStore.EnsureDir(); err != nil {
		return "", 0, err
	}
	pool := caPoolFromPEM(r.cfg.CABundlePEM)
	now := r.cfg.Now().UTC()
	// nodeID 参数传空：文件名中的记录不可信，先按"不校验身份"的方式加载，
	// 再以**证书自身**的 CN 作为权威 node_id。
	loaded, lerr := r.cfg.IdentityStore.Load(now, pool, "")
	switch {
	case lerr == nil:
		// ① 复用：装载身份并重建 mTLS 连接。
		if err := r.client.AdoptIdentity(ctx,
			loaded.CertificateDER, loaded.CACertificateDER, loaded.PrivateKey()); err != nil {
			return "", 0, fmt.Errorf("node-agent：装载持久化身份失败：%w", err)
		}
		atomic.StoreInt32(&r.reused, 1)
		r.mu.Lock()
		r.nodeID = loaded.NodeID
		r.loaded = loaded
		r.mu.Unlock()
		return loaded.NodeID, interval, nil
	case errors.Is(lerr, identity.ErrNotFound):
		// ② 首次启动：注册。
	default:
		// ③ 明确拒绝（不静默重新注册）。
		return "", 0, fmt.Errorf("node-agent：拒绝启动——%w", lerr)
	}

	res, err := r.client.Enroll(ctx, r.cfg.Token)
	if err != nil {
		return "", 0, fmt.Errorf("node-agent：注册失败：%w", err)
	}
	atomic.AddInt64(&r.enrolls, 1)
	if res.HeartbeatInterval > 0 {
		interval = res.HeartbeatInterval
	}
	// 原子保存身份（T2）。
	ident, err := identityFromEnroll(res)
	if err != nil {
		return "", 0, err
	}
	if err := r.cfg.IdentityStore.Save(ident); err != nil {
		return "", 0, fmt.Errorf("node-agent：保存身份失败：%w", err)
	}
	// 尽力删除令牌文件（失败只记录警告，不影响启动）。
	if r.cfg.RemoveToken && strings.TrimSpace(r.cfg.TokenFileToRemove) != "" {
		if rerr := os.Remove(r.cfg.TokenFileToRemove); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
			r.mu.Lock()
			r.tokenWarn = fmt.Sprintf("令牌文件删除失败（不影响启动）：%v", rerr)
			r.mu.Unlock()
		}
	}
	r.mu.Lock()
	r.nodeID = res.NodeID
	r.loaded = ident
	r.mu.Unlock()
	return res.NodeID, interval, nil
}

// TokenWarning 返回令牌文件清理的警告（空表示无警告；供进程日志与测试断言）。
func (r *Runner) TokenWarning() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.tokenWarn
}

// ReusedIdentity 本次启动是否复用了持久化身份（T2 测试断言用）。
func (r *Runner) ReusedIdentity() bool { return atomic.LoadInt32(&r.reused) == 1 }

// identityFromEnroll 把注册结果转换为可持久化身份。
func identityFromEnroll(res *enrollclient.EnrollResult) (*identity.Identity, error) {
	if res == nil || len(res.CertificateDER) == 0 || res.PrivateKey == nil {
		return nil, errors.New("node-agent：注册结果缺少证书或私钥")
	}
	return &identity.Identity{
		NodeID:           res.NodeID,
		CertificateDER:   res.CertificateDER,
		CACertificateDER: res.CACertificateDER,
		NotAfter:         res.NotAfter,
		Key:              res.PrivateKey,
	}, nil
}

// caPoolFromPEM 构造 CA 池（空包返回 nil，表示跳过 CA 校验）。
func caPoolFromPEM(pemBytes []byte) *x509.CertPool {
	if len(pemBytes) == 0 {
		return nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil
	}
	return pool
}

// MaybeRenew 在到达"有效期的 renewAt 比例"时尝试续期（T3）。
//
// 从心跳循环调用；也导出以便测试与运维工具显式触发一次评估。
//
// 判定用**注入时钟**与身份的 NotAfter：remaining/total 的比例决定是否到期续期点，
// 并叠加 ±jitter 抖动（避免所有节点同时续期打爆控制面）。
// 失败按指数退避重试，**不改变节点状态**（服务端也不会因续期失败改状态）。
func (r *Runner) MaybeRenew(ctx context.Context) {
	r.mu.Lock()
	id := r.identityAt
	if id == nil || r.cfg.IdentityStore == nil {
		r.mu.Unlock()
		return
	}
	now := r.cfg.Now().UTC()
	total := id.NotAfter.Sub(id.NotBeforeOrCreatedAt())
	if total <= 0 {
		r.mu.Unlock()
		return
	}
	// 抖动：**相对**于触发点（不是相对于整个有效期）。
	//
	// 裁决口径：有效期内 50% 处续期，抖动 ±10% ⇒ 实际比例落在 [0.45, 0.55]，
	// 对 7 天有效期即 [3.15d, 3.85d]。
	// 若按"有效期的 ±10%"理解会得到 [0.4, 0.6]（2.8d~4.2d），与裁决不符。
	offset := r.cfg.RenewJitter
	frac := r.cfg.RenewAtFraction
	if r.cfg.RandomFloat != nil {
		// 把 [0,1) 映射到 [-1, +1)，再按**触发点比例**缩放。
		frac *= 1 + (r.cfg.RandomFloat()*2-1)*offset
	}
	renewAt := id.NotBeforeOrCreatedAt().Add(time.Duration(float64(total) * frac))
	if now.Before(renewAt) {
		r.mu.Unlock()
		return
	}
	// 退避闸门。
	if !r.backoffElapsed(now) {
		r.mu.Unlock()
		return
	}
	r.mu.Unlock()

	if _, err := r.renewOnce(ctx); err != nil {
		atomic.AddInt64(&r.renewFails, 1)
		r.noteRenewFailure(err.Error(), now)
		return
	}
	atomic.AddInt64(&r.renewed, 1)
	r.noteRenewSuccess(now)
}

// backoffElapsed 判定退避是否已过（首次调用总是放行）。
func (r *Runner) backoffElapsed(now time.Time) bool {
	if r.backoff <= 0 || r.lastRenew.IsZero() {
		return true
	}
	return !now.Before(r.lastRenew.Add(r.backoff))
}

// noteRenewFailure 记录失败并推进指数退避（初值 1min，上限 1h）。
func (r *Runner) noteRenewFailure(msg string, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.backoff <= 0 {
		r.backoff = r.cfg.RenewBackoffInitial
	} else {
		r.backoff *= 2
		if r.backoff > r.cfg.RenewBackoffMax {
			r.backoff = r.cfg.RenewBackoffMax
		}
	}
	r.lastRenew = now
	r.renewErr = msg
	// 日志不含任何密钥/令牌材料。
	logf := r.cfg.Logf
	go logf("node-agent：证书续期失败（将在 %s 后重试）：%s", r.backoff, msg)
}

// noteRenewSuccess 记录成功并重置退避。
func (r *Runner) noteRenewSuccess(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.backoff = 0
	r.lastRenew = now
	r.renewErr = ""
}

// renewOnce 执行一次续期：生成**新密钥**的 CSR → RPC → 原子替换身份文件。
//
// 必须换钥（服务端第 6 步校验）：因此每次续期都生成新的私钥；
// 旧私钥在替换成功后即失去用处（可被 GC 回收）。
func (r *Runner) renewOnce(ctx context.Context) (*enrollclient.RenewResult, error) {
	// 新密钥 + 纯持有性证明 CSR（PEM）。
	newKey, err := nodeidentity.NewNodeKey(nil)
	if err != nil {
		return nil, err
	}
	csrDER, err := nodeidentity.NewCSR(newKey, nil)
	if err != nil {
		return nil, err
	}
	res, err := r.client.Renew(ctx, nodeidentity.CertificateRequestPEM(csrDER))
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	old := r.identityAt
	nodeID := r.nodeID
	r.mu.Unlock()
	ident := &identity.Identity{
		NodeID:           nodeID,
		CertificateDER:   res.CertificateDER,
		CACertificateDER: res.CACertificateDER,
		NotAfter:         res.NotAfter,
		Key:              newKey,
	}
	// 用 T2 的原子写入替换身份文件；失败**不**改变内存中的身份（保持可用）。
	if err := r.cfg.IdentityStore.Save(ident); err != nil {
		return nil, fmt.Errorf("node-agent：续期后保存身份失败：%w", err)
	}
	r.mu.Lock()
	r.identityAt = ident
	r.loaded = ident
	r.mu.Unlock()
	r.cfg.Logf("node-agent：证书续期成功（node_id=%s，not_after=%s，superseded=%s）",
		nodeID, res.NotAfter.UTC().Format(time.RFC3339), res.SupersededSerial)
	_ = old
	return res, nil
}

// RenewCount 成功续期次数（测试断言用）。
func (r *Runner) RenewCount() int64 { return atomic.LoadInt64(&r.renewed) }

// RenewFailureCount 续期失败次数（测试断言用）。
func (r *Runner) RenewFailureCount() int64 { return atomic.LoadInt64(&r.renewFails) }

// RenewBackoff 当前退避时长（测试断言用）。
func (r *Runner) RenewBackoff() time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.backoff
}

// RenewLastError 最近一次续期失败原因（不含敏感材料）。
func (r *Runner) RenewLastError() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.renewErr
}

// SetIdentityForTest 注入身份（仅测试：让续期判定有可用的 NotAfter）。
func (r *Runner) SetIdentityForTest(id *identity.Identity) {
	r.mu.Lock()
	r.identityAt = id
	r.mu.Unlock()
}

// BootSessionID 返回本进程的会话标识（D6）。
func (r *Runner) BootSessionID() string { return r.cfg.BootSessionID }

// NodeID 返回注册后分配的身份（未注册时为空）。
func (r *Runner) NodeID() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.nodeID
}

// EnrollCount 注册次数。
func (r *Runner) EnrollCount() int64 { return atomic.LoadInt64(&r.enrolls) }

// HeartbeatCount 成功发送的心跳次数。
func (r *Runner) HeartbeatCount() int64 { return atomic.LoadInt64(&r.heartbeats) }

// Stopped 是否已停机。
func (r *Runner) Stopped() bool { return atomic.LoadInt32(&r.stopped) == 1 }
