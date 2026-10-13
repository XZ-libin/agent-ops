// Package linuxwire 把 Linux 只读适配器的清单能力接线进网关执行注册表。
//
// 路由（第八轮范围：只读 capability 经网关执行以验证链路）：
//
//	diagnose.disk_usage      → 适配器 Diagnose（问题 disk_usage）
//	diagnose.memory_pressure → 适配器 Diagnose（问题 memory_pressure）
//	diagnose.load_average    → 适配器 Diagnose（问题 load_average）
//	diagnose.service_state   → 适配器 Diagnose（问题 service_state:<unit>，
//	                           unit 取请求 params.unit，须过名称校验）
//
// 诊断结论映射为 ActionResult（Outputs 附 conclusion；契约层 Execute 语义
// 留待后续批次完整化——工程默认，见假设清单）。
package linuxwire

import (
	"context"
	"fmt"
	"strings"

	contractv1 "github.com/ORG/agent-ops/contract/gen/go/agent_ops/contract/v1"

	"github.com/ORG/agent-ops/adapters/linux"
	"github.com/ORG/agent-ops/gateway/internal/gateway"
	"github.com/ORG/agent-ops/internal/validation"
)

// Register 把适配器清单中的全部能力注册进网关注册表。
// 任何能力无对应路由/注册失败都返回错误（fail-closed，不部分注册后继续）。
func Register(reg *gateway.Registry, a *linux.Adapter) error {
	m := a.Manifest()
	if m == nil {
		return fmt.Errorf("linuxwire：适配器清单为空")
	}
	for _, c := range m.Capabilities {
		h, err := handlerFor(c.Name, a)
		if err != nil {
			return fmt.Errorf("linuxwire：%w", err)
		}
		if err := reg.Register(c, h); err != nil {
			return fmt.Errorf("linuxwire：%w", err)
		}
	}
	return nil
}

// handlerFor 能力名 → 执行逻辑。只接受清单已知的诊断问题
// （fail-closed：未知问题/写能力在接线期即报错，不部分注册）。
func handlerFor(name string, a *linux.Adapter) (gateway.Handler, error) {
	if !strings.HasPrefix(name, "diagnose.") {
		return nil, fmt.Errorf("能力 %s 无对应路由（本适配器只支持诊断类只读能力）", name)
	}
	question := strings.TrimPrefix(name, "diagnose.")
	switch question {
	case "service_state": // 对应 linux.QuestionServiceStatePrefix 的问题名部分
		return serviceStateHandler(a), nil
	case linux.QuestionDiskUsage, linux.QuestionMemoryPressure, linux.QuestionLoadAverage:
		return diagnoseHandler(a, question), nil
	}
	return nil, fmt.Errorf("能力 %s 无对应路由（未定义的诊断问题）", name)
}

// diagnoseHandler 固定问题的诊断（disk_usage / memory_pressure / load_average）。
func diagnoseHandler(a *linux.Adapter, question string) gateway.Handler {
	return func(ctx context.Context, req gateway.Request) (*contractv1.ActionResult, error) {
		instance, err := resolveInstance(ctx, a, req)
		if err != nil {
			return nil, err
		}
		diag, err := a.Diagnose(ctx, instance, question)
		if err != nil {
			return nil, err
		}
		return toActionResult(diag), nil
	}
}

// serviceStateHandler service_state:<unit>（unit 必须通过名称校验，fail-closed）。
func serviceStateHandler(a *linux.Adapter) gateway.Handler {
	return func(ctx context.Context, req gateway.Request) (*contractv1.ActionResult, error) {
		unit := paramString(req, "unit")
		if !validation.ValidUnitName(unit) {
			return nil, fmt.Errorf("linuxwire：unit 参数不合法（名称校验不通过）：%q", unit)
		}
		instance, err := resolveInstance(ctx, a, req)
		if err != nil {
			return nil, err
		}
		diag, err := a.Diagnose(ctx, instance, linux.QuestionServiceStatePrefix+unit)
		if err != nil {
			return nil, err
		}
		return toActionResult(diag), nil
	}
}

// resolveInstance 通过 Discover 解析目标实例（第一个）。
func resolveInstance(ctx context.Context, a *linux.Adapter, req gateway.Request) (*contractv1.Instance, error) {
	if req.Action == nil || req.Action.Target == nil || strings.TrimSpace(req.Action.Target.AssetId) == "" {
		return nil, fmt.Errorf("linuxwire：目标资产缺失")
	}
	insts, err := a.Discover(ctx, req.Action.Target)
	if err != nil {
		return nil, err
	}
	if len(insts) == 0 {
		return nil, fmt.Errorf("linuxwire：目标上未发现实例")
	}
	return insts[0], nil
}

// paramString 读取 params 中的字符串参数。
func paramString(req gateway.Request, key string) string {
	if req.Action == nil || req.Action.Params == nil {
		return ""
	}
	v, _ := req.Action.Params.AsMap()[key].(string)
	return strings.TrimSpace(v)
}

// toActionResult 诊断报告 → ActionResult（诊断只读能力经网关执行的结果形态）。
func toActionResult(diag *contractv1.DiagnosisReport) *contractv1.ActionResult {
	if diag == nil {
		return &contractv1.ActionResult{Success: false}
	}
	return &contractv1.ActionResult{
		Success: true,
		Outputs: []*contractv1.OutputChunk{
			{Stream: "diagnosis", Content: diag.Conclusion},
		},
	}
}
