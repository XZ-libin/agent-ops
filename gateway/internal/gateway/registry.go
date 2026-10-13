package gateway

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ORG/agent-ops/gateway/internal/approvals"

	contractv1 "github.com/ORG/agent-ops/contract/gen/go/agent_ops/contract/v1"

	"github.com/ORG/agent-ops/internal/validation"
)

// Handler 已注册能力的具体执行逻辑（由接入方接线，如 internal/linuxwire）。
// 网关保证 Handler 只在以下前提下被调用：策略判定通过（effective 决策为 auto）、
// 幂等检查通过（同键不重复执行）、非 destructive。
type Handler func(ctx context.Context, req Request) (*contractv1.ActionResult, error)

// Registration 一条能力注册：声明（来自适配器清单）+ 执行逻辑。
type Registration struct {
	Decl    *contractv1.Capability
	Handler Handler
}

// Registry 能力注册表：执行路径只能经注册表查找 Handler，
// 不存在任何"按名直呼适配器"的旁路（第八轮目标：执行路径不得绕过策略）。
type Registry struct {
	mu            sync.RWMutex
	byName        map[string]Registration
	allowTestOnly bool // 仅测试注册表允许 test_only 能力（生产注册表拒绝）
}

// NewRegistry 构建生产注册表：test_only=true 的能力在此被拒绝注册
// （第九轮约束 5/6：生产能力目录不包含任何写能力，测试能力在生产不可见）。
func NewRegistry() *Registry {
	return &Registry{byName: make(map[string]Registration)}
}

// NewTestRegistry 构建测试注册表（仅测试）：允许注册 test_only 能力。
func NewTestRegistry() *Registry {
	r := NewRegistry()
	r.allowTestOnly = true
	return r
}

// Register 注册能力：名称必须通过统一校验（internal/validation，D2），
// 必须携带基础风险等级，重复注册直接报错；
// test_only=true 的声明仅测试注册表可加载（fail-closed）。
//
// 第十二轮 H6：能力必须声明**正的超时**（Timeout）。执行租约由能力超时推导
// （租约 = 超时 + 2×续期间隔），超时为 0 或缺失时租约不成立，且无法约束
// "执行不得超过该时长"——一律拒绝注册（fail-closed）。
func (r *Registry) Register(decl *contractv1.Capability, h Handler) error {
	if decl == nil {
		return errors.New("registry：能力声明不能为空")
	}
	if decl.TestOnly && !r.allowTestOnly {
		return fmt.Errorf("registry：能力 %q 标记为 test_only，生产注册表拒绝加载", decl.Name)
	}
	if !validation.ValidCapabilityName(decl.Name) {
		return fmt.Errorf("registry：能力名不合法 %q（名称校验不通过）", decl.Name)
	}
	if decl.RiskTier == contractv1.RiskTier_RISK_TIER_UNSPECIFIED {
		return fmt.Errorf("registry：能力 %q 缺少基础风险等级", decl.Name)
	}
	if decl.Timeout == nil || decl.Timeout.AsDuration() <= 0 {
		return fmt.Errorf("registry：能力 %q 缺少正的执行超时（Timeout 必填：执行租约由它推导，见 approvals.LeaseFor）", decl.Name)
	}
	if h == nil {
		return fmt.Errorf("registry：能力 %q 缺少执行逻辑", decl.Name)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.byName[decl.Name]; dup {
		return fmt.Errorf("registry：能力 %q 重复注册", decl.Name)
	}
	r.byName[decl.Name] = Registration{Decl: decl, Handler: h}
	return nil
}

// Lookup 查找已注册能力。
func (r *Registry) Lookup(name string) (Registration, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	reg, ok := r.byName[name]
	return reg, ok
}

// AllowsTestOnly 报告该注册表是否允许加载 test_only 能力：// 生产注册表（NewRegistry）恒为 false；仅 NewTestRegistry 为 true。
// 执行期复核「test_only 能力不得出现在生产注册表」时使用（第十轮 F1）。
func (r *Registry) AllowsTestOnly() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.allowTestOnly
}

// validateLeasePolicy 启动时强校验（第十二轮 H6）：对每个已注册能力推导执行租约
// （租约 = 能力超时 + 2×续期间隔），要求：
//   - 租约 > 2×续期间隔（等价于能力超时 > 0，注册期已保证）；
//   - 租约 ≥ 能力超时（构造即满足，仍显式断言以防公式被改动）。
//
// 任一项不满足 → 拒绝启动（fail-closed）。
func (r *Registry) validateLeasePolicy(renew time.Duration) error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if renew <= 0 {
		return errors.New("gateway：租约续期间隔必须为正")
	}
	for name, reg := range r.byName {
		timeout := time.Duration(0)
		if reg.Decl != nil && reg.Decl.Timeout != nil {
			timeout = reg.Decl.Timeout.AsDuration()
		}
		lease := approvals.LeaseFor(timeout)
		if err := approvals.ValidateLease(lease, renew); err != nil {
			return fmt.Errorf("gateway：能力 %q 的执行租约不满足强约束：%w", name, err)
		}
		if lease < timeout {
			return fmt.Errorf("gateway：能力 %q 的执行租约（%v）不得小于能力超时（%v）", name, lease, timeout)
		}
	}
	return nil
}

// AssertNoTestOnly 生产启动守卫（第十轮 G2）：注册表中不得存在任何 test_only 能力，
// 存在即返回错误并列出能力名（fail-closed，进程不得带测试能力启动）。
func (r *Registry) AssertNoTestOnly() error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var offenders []string
	for name, reg := range r.byName {
		if reg.Decl != nil && reg.Decl.TestOnly {
			offenders = append(offenders, name)
		}
	}
	if len(offenders) == 0 {
		return nil
	}
	sort.Strings(offenders)
	return fmt.Errorf("registry：生产配置不得加载 test_only 能力（发现 %d 个：%s）",
		len(offenders), strings.Join(offenders, "、"))
}
