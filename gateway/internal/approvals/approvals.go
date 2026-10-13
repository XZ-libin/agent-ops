// Package approvals 实现变更审批记录存储（第八轮 B 项 + 第九轮扩展 + 第十轮修订，ADR-010）。
//
// 范围：
//   - require_approval 只创建 pending 记录并返回 pending，不执行；
//   - pending → approved / rejected / expired；approved → executing / expired；
//     executing → consumed / abandoned；终态（rejected / expired / consumed /
//     abandoned）不可再迁移；
//   - **先占后执行（第十轮修订，消除 consumed 窗口）**：执行方必须先以原子的
//     CAS（Claim：单条 UPDATE ... WHERE status='approved'，检查影响行数）把审批
//     从 approved 置为 executing，只有抢占成功者才能执行；执行结束后由 Consume
//     （executing → consumed）收口。抢占后未产生终态（进程崩溃 / 幂等跳过）的审批
//     由对账 MarkAbandoned 置 abandoned，**不重放**（需重新提交审批）；
//   - 审批去重（R3，第十轮修订）：去重键由 (actor, idem_key) 改为
//     (actor, request_hash)——同一请求内容即使换了幂等键，也只保留一条 pending
//     记录并返回已有审批 ID；(actor, idem_key) 的「仅 pending」唯一约束保留，
//     用于原子地判定「同键不同内容」冲突（422）；
//   - 四眼原则（第九轮决策，无例外）：Approve 时审批人必须与请求人不同；
//   - 窗口（第九轮决策，工程默认 30 分钟，业务方可调整）：pending 自创建起
//     ExpiresAt 未处理即过期；approved 自 ApprovedAt 起 30 分钟内未执行即作废
//     （置 expired）。两个窗口的判定统一使用注入时钟；
//   - 批准后的自动执行在 gateway 层（本包不含执行逻辑）；
//   - 生产表名未定（试点阶段），测试表必须 test_ 前缀（测试守卫）。
package approvals

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Status 审批记录状态。
type Status string

const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
	StatusRejected Status = "rejected"
	StatusExpired  Status = "expired"
	// StatusConsumed 审批已被执行消费（第九轮：消费后不可再次执行）。
	StatusConsumed Status = "consumed"
	// StatusExecuting 审批已被某次执行抢占（第十轮：approved → executing 的原子 CAS）。
	// 同一审批不可能被抢占两次：抢占失败者不执行、不写执行审计。
	StatusExecuting Status = "executing"
	// StatusAbandoned 抢占后未产生终态（进程崩溃或幂等跳过），由对账标记（第十轮）。
	// abandoned 的审批不可再执行、绝不自动重放：需重新提交审批。
	StatusAbandoned Status = "abandoned"
)

// DefaultApprovalWindow 审批窗口默认值 30 分钟（第九轮决策，工程默认值，
// 业务方可调整）：同时约束「pending 多久未处理即过期」与
// 「approved 多久内必须执行，否则作废」。
const DefaultApprovalWindow = 30 * time.Minute

// 错误。
var (
	// ErrNotFound 记录不存在。
	ErrNotFound = errors.New("审批记录不存在")
	// ErrIllegalTransition 非法状态迁移（终态保护）。
	ErrIllegalTransition = errors.New("非法审批状态迁移")
	// ErrNotApproved 记录当前不是 approved（无法执行）。
	ErrNotApproved = errors.New("审批记录未处于 approved 状态")
	// ErrApprovalVoided approved 超过执行窗口被作废（置 expired）。
	ErrApprovalVoided = errors.New("审批已超 30 分钟执行窗口，已作废（expired）")
	// ErrApproverMustDiffer 四眼原则：审批人必须与请求人不同（无例外）。
	ErrApproverMustDiffer = errors.New("四眼原则：审批人必须与请求人不同")
	// ErrContentConflict 同幂等键（actor+幂等键）的 pending 记录已存在且请求内容
	// 不同（422 语义；第十轮：去重键改为 request_hash，本错误专指「同键不同内容」）。
	ErrContentConflict = errors.New("审批幂等键已存在且请求内容不同（HTTP 422）")
	// ErrNotClaimable 抢占失败：审批已被使用（executing/consumed/abandoned）或状态
	// 不允许（pending/rejected/expired）（第十轮）。
	ErrNotClaimable = errors.New("审批已被使用或已过期，不可抢占执行")
	// ErrNotExecuting 审批未处于 executing 状态（不可消费/放弃）。
	ErrNotExecuting = errors.New("审批未处于 executing 状态（不可消费或放弃）")
	// ErrExecutionLeaseExpired 执行租约已过期（第十一轮 H1）：续期失败，
	// 调用方必须中止执行并交由对账标记 abandoned（不重放、不消费）。
	ErrExecutionLeaseExpired = errors.New("执行租约已过期，不得续期")
)

// AllowedTransitions 允许的状态迁移表（第十轮：先占后执行的两条新边）。
var AllowedTransitions = map[Status][]Status{
	StatusPending:   {StatusApproved, StatusRejected, StatusExpired},
	StatusApproved:  {StatusExecuting, StatusExpired},
	StatusExecuting: {StatusConsumed, StatusAbandoned},
}

// CanTransition 判定 from → to 是否合法。
func CanTransition(from, to Status) bool {
	for _, t := range AllowedTransitions[from] {
		if t == to {
			return true
		}
	}
	return false
}

// Record 一条审批记录。
type Record struct {
	ID             string     // 审批记录 ID（apr_ 前缀 + 随机 hex）
	Actor          string     // 发起操作的执行人/Agent（请求人）
	Capability     string     // 待审批的能力名
	RequestHash    string     // 请求内容哈希（ADR-009；第十轮起为 pending 去重键）
	IdempotencyKey string     // 请求幂等键（同键不同内容的冲突判定键）
	Status         Status     // pending / approved / rejected / expired / executing / consumed / abandoned
	CreatedAt      time.Time  // 创建时间（注入时钟）
	UpdatedAt      time.Time  // 最近状态变更时间（注入时钟）
	ExpiresAt      time.Time  // pending 的过期时间（创建 + 窗口）
	ApprovedAt     *time.Time // approved 时刻（注入时钟）；nil 表示从未批准
	DecidedBy      string     // 审批人/系统；consumed/abandoned 恒为 system
	Reason         string     // 审批意见/过期/作废原因
	// LeaseUntil 执行租约到期时刻（第十一轮 H1）：executing 期间由执行方每
	// renewInterval 续期；对账只把 lease_until 已过期的 executing 记录标为
	// abandoned——未过期的记录一律跳过（可能仍在执行中）。nil 表示无租约
	// （非 executing 状态）。
	LeaseUntil *time.Time
}

// NewRecord 创建 pending 记录所需的输入。
type NewRecord struct {
	Actor          string
	Capability     string
	RequestHash    string
	IdempotencyKey string
	ExpiresAt      time.Time
}

// DefaultLeaseRenewInterval 租约续期间隔（第十二轮 H6：**固定 20 秒**，
// 不再可配）。租约时长按能力超时动态推导，见 LeaseFor。
const DefaultLeaseRenewInterval = 20 * time.Second

// LeaseFor 按能力超时推导执行租约时长（第十二轮 H6，裁决）：
//
//	租约 = 能力超时 + 2 × 续期间隔（20 秒）
//
// 即"最坏情况下连续两次续期失败仍不会误判执行中断"：续期每 20s 一次，
// 只要执行不超过能力超时，租约必然覆盖整个执行窗口。
// 能力超时必须为正（0 或缺失 → 注册期即拒绝），否则租约会退化为
// 2×续期间隔、不满足 ValidateLease 的强约束。
func LeaseFor(capTimeout time.Duration) time.Duration {
	return capTimeout + 2*DefaultLeaseRenewInterval
}

// ValidateLease 启动时强校验（第十二轮 H6）：租约必须**大于**续期间隔的 2 倍，
// 且续期间隔本身必须为正。不满足即拒绝启动/拒绝注册（fail-closed）。
// 与"租约不得小于能力超时"一并由 LeaseFor 构造保证（见其文档）。
func ValidateLease(lease, renew time.Duration) error {
	if renew <= 0 {
		return errors.New("租约续期间隔必须为正")
	}
	if lease <= 2*renew {
		return fmt.Errorf("执行租约（%v）必须大于续期间隔的 2 倍（%v）", lease, 2*renew)
	}
	return nil
}

// Store 审批记录存储抽象。
type Store interface {
	// Create 创建 pending 记录（R3 去重语义见 PostgresStore）。
	Create(ctx context.Context, n NewRecord) (Record, error)
	// Get 读取记录；不存在返回 ErrNotFound。
	Get(ctx context.Context, id string) (Record, error)
	// Approve pending → approved（四眼原则：approver 必须与请求人不同）。
	Approve(ctx context.Context, id, approver, reason string) (Record, error)
	// Reject pending → rejected。
	Reject(ctx context.Context, id, decider, reason string) (Record, error)
	// CheckExecutable approved 且在执行窗口内的记录可执行；超窗作废并报错。
	CheckExecutable(ctx context.Context, id string) (Record, error)
	// Claim 先占后执行（第十轮）：单条 UPDATE ... WHERE status='approved' 的原子 CAS，
	// approved → executing。影响行数为 0 时返回 ErrNotClaimable（已被抢占/已消费/
	// 状态不允许）；approved 已超窗则作废并返回 ErrApprovalVoided。
	// lease 为本次执行的租约时长（第十二轮 H6：由调用方按能力超时经 LeaseFor 推导），
	// 抢占成功时写入 lease_until = now + lease。
	Claim(ctx context.Context, id string, lease time.Duration) (Record, error)
	// Renew 续期执行租约（第十一轮 H1 / 第十二轮 H6）：仅 executing 且租约未过期时
	// 可续期，lease_until = now + lease（lease 必须与 Claim 时一致）。租约已过期
	// 返回 ErrExecutionLeaseExpired（调用方必须中止执行：不重放、不消费，
	// 交由对账标记 abandoned）。
	Renew(ctx context.Context, id string, lease time.Duration) (Record, error)
	// Consume executing → consumed（第十轮：消费只发生在抢占成功之后）。
	// 若 approved 已超过执行窗口，先把记录作废（置 expired）再返回
	// ErrApprovalVoided（不消费）；非 executing 状态返回 ErrNotExecuting。
	Consume(ctx context.Context, id string) (Record, error)
	// MarkAbandoned executing → abandoned（对账用；不重放）。重复调用已 abandoned
	// 的记录视为成功（幂等）；非 executing/abandoned 返回 ErrNotExecuting。
	MarkAbandoned(ctx context.Context, id string) (Record, error)
	// ListExecuting 列出处于 executing 的记录（单实例守卫用：含租约信息）。
	ListExecuting(ctx context.Context) ([]Record, error)
	// ListExpiredExecuting 列出 executing 且 lease_until <= now 的记录
	// （对账用；未过期的记录一律跳过，第十一轮 H1）。
	ListExpiredExecuting(ctx context.Context, now time.Time) ([]Record, error)
	// ExpirePending 把 expires_at <= now 的 pending 批量置 expired，返回行数。
	ExpirePending(ctx context.Context, now time.Time) (int64, error)
	// ExpireApproved 把超过执行窗口的 approved 批量作废（置 expired），返回行数。
	ExpireApproved(ctx context.Context, now time.Time) (int64, error)
}

// Option 配置存储实现。
type Option func(*storeConfig)

type storeConfig struct {
	now    func() time.Time
	window time.Duration
}

// WithClock 注入时间源（测试用；两个窗口的判定统一使用注入时钟）。
func WithClock(now func() time.Time) Option {
	return func(c *storeConfig) { c.now = now }
}

// WithApprovalWindow 覆盖审批窗口（默认 DefaultApprovalWindow=30 分钟，
// 工程默认，业务方可调整）。
func WithApprovalWindow(w time.Duration) Option {
	return func(c *storeConfig) { c.window = w }
}

func applyOptions(opts ...Option) storeConfig {
	c := storeConfig{
		now:    time.Now,
		window: DefaultApprovalWindow,
	}
	for _, o := range opts {
		o(&c)
	}
	return c
}

// identifierPattern 表名必须是合法的小写标识符（仅用于 DDL 拼装，杜绝注入）。
var identifierPattern = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)

// testTablePrefix 测试守卫：测试表必须 test_ 前缀（约束 8）。
const testTablePrefix = "test_"

// validateTable 校验表名；测试模式必须 test_ 前缀。
func validateTable(table string, testGuard bool) error {
	if !identifierPattern.MatchString(table) {
		return errors.New("非法审批表名：" + table)
	}
	if testGuard && !strings.HasPrefix(table, testTablePrefix) {
		return errors.New("审批测试守卫：表名必须以 test_ 开头（当前 " + table + "），拒绝写入")
	}
	return nil
}
