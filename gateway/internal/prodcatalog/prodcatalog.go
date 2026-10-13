// Package prodcatalog 加载生产（非测试）能力目录（第十轮 G2）。
//
// 职责：从适配器清单（manifest YAML）读取能力声明并注册进**生产**注册表
// （gateway.NewRegistry：test_only=true 的声明在此被拒绝，见 ADR-010 §5）。
//
// 执行 Handler 现状（TODO，随接入通道批次实现）：资产 → SSH 通道与凭据解析尚未
// 实现，本轮注册的是"未接线"桩——被调用时立即返回错误。桩不绕过任何门控：
// 策略/幂等/审批/审计照常执行，执行结果审计记为 failed（fail-closed）。
package prodcatalog

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"
	"gopkg.in/yaml.v3"

	contractv1 "github.com/XZ-libin/agent-ops/contract/gen/go/agent_ops/contract/v1"

	"github.com/XZ-libin/agent-ops/gateway/internal/gateway"
	"github.com/XZ-libin/agent-ops/internal/validation"
)

// manifestCapability 清单能力声明（本包所需字段）。
type manifestCapability struct {
	Name         string `yaml:"name"`
	RiskTier     string `yaml:"risk_tier"`
	Destructive  bool   `yaml:"destructive"`
	Rollbackable bool   `yaml:"rollbackable"`
	Idempotent   bool   `yaml:"idempotent"`
	TestOnly     bool   `yaml:"test_only"`
	Timeout      string `yaml:"timeout"`
}

type manifestFile struct {
	Name         string               `yaml:"name"`
	Capabilities []manifestCapability `yaml:"capabilities"`
}

// Load 读取清单文件并注册进生产注册表；返回已注册的声明（供调用方核对）。
// 任何声明不合法（名称/等级/超时/test_only）即整体失败（fail-closed，不部分注册）。
func Load(reg *gateway.Registry, path string) ([]*contractv1.Capability, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("prodcatalog：读取清单 %s 失败：%w", path, err)
	}
	caps, err := Parse(data)
	if err != nil {
		return nil, err
	}
	if err := Register(reg, caps); err != nil {
		return nil, err
	}
	return caps, nil
}

// Parse 解析清单字节为能力声明（非法即报错）。
func Parse(data []byte) ([]*contractv1.Capability, error) {
	var mf manifestFile
	if err := yaml.Unmarshal(data, &mf); err != nil {
		return nil, fmt.Errorf("prodcatalog：清单解析失败：%w", err)
	}
	if len(mf.Capabilities) == 0 {
		return nil, fmt.Errorf("prodcatalog：清单 %q 未声明任何能力", mf.Name)
	}
	out := make([]*contractv1.Capability, 0, len(mf.Capabilities))
	for _, c := range mf.Capabilities {
		decl, err := toCapability(c)
		if err != nil {
			return nil, err
		}
		out = append(out, decl)
	}
	return out, nil
}

// Register 把声明注册进注册表（test_only 由生产注册表拒绝）。
func Register(reg *gateway.Registry, caps []*contractv1.Capability) error {
	if reg == nil {
		return fmt.Errorf("prodcatalog：注册表为空")
	}
	for _, decl := range caps {
		if err := reg.Register(decl, unwiredHandler(decl.Name)); err != nil {
			return fmt.Errorf("prodcatalog：%w", err)
		}
	}
	return nil
}

// toCapability 清单条目 → 契约能力声明（名称/等级/超时均校验，fail-closed）。
func toCapability(c manifestCapability) (*contractv1.Capability, error) {
	if !validation.ValidCapabilityName(c.Name) {
		return nil, fmt.Errorf("prodcatalog：能力名不合法 %q", c.Name)
	}
	tier, ok := riskTier(c.RiskTier)
	if !ok {
		return nil, fmt.Errorf("prodcatalog：能力 %q 的风险等级非法/缺失 %q", c.Name, c.RiskTier)
	}
	decl := &contractv1.Capability{
		Name:         c.Name,
		RiskTier:     tier,
		Idempotent:   c.Idempotent,
		Rollbackable: c.Rollbackable,
		Destructive:  c.Destructive,
		TestOnly:     c.TestOnly,
	}
	// 第十二轮 H6：超时必填且为正（执行租约由它推导）。
	if strings.TrimSpace(c.Timeout) == "" {
		return nil, fmt.Errorf("prodcatalog：能力 %q 缺少执行超时（timeout 必填）", c.Name)
	}
	d, err := time.ParseDuration(c.Timeout)
	if err != nil {
		return nil, fmt.Errorf("prodcatalog：能力 %q 超时无法解析 %q：%w", c.Name, c.Timeout, err)
	}
	if d <= 0 {
		return nil, fmt.Errorf("prodcatalog：能力 %q 超时必须为正（当前 %v）", c.Name, d)
	}
	decl.Timeout = durationpb.New(d)
	return decl, nil
}

// riskTier 文本 → 契约风险等级（未指定即报错，fail-closed）。
func riskTier(s string) (contractv1.RiskTier, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "read_only":
		return contractv1.RiskTier_RISK_TIER_READ_ONLY, true
	case "low":
		return contractv1.RiskTier_RISK_TIER_LOW, true
	case "medium":
		return contractv1.RiskTier_RISK_TIER_MEDIUM, true
	case "high":
		return contractv1.RiskTier_RISK_TIER_HIGH, true
	}
	return contractv1.RiskTier_RISK_TIER_UNSPECIFIED, false
}

// unwiredHandler 未接线桩：执行通道（资产 → SSH）实现前的占位。
// 立即返回错误 → 网关写 failed 审计并按失败返回（不绕过任何门控）。
func unwiredHandler(name string) gateway.Handler {
	return func(_ context.Context, _ gateway.Request) (*contractv1.ActionResult, error) {
		return nil, fmt.Errorf("prodcatalog：能力 %s 的执行通道未接线"+
			"（资产→SSH 解析随接入通道批次实现）", name)
	}
}
