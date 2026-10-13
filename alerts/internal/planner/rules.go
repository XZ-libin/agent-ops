// Package planner 是诊断**规划器**（第十六轮 R5）：纯函数 + 计划表。
//
// 职责边界（本轮**只规划、不执行**）：
//   - 输入：一条 pending 的诊断请求（test_diagnosis_requests 及其对应告警）；
//   - 规则表：按告警的 source 与 severity 映射到一组**只读能力**（代码常量）；
//   - 输出：计划记录写入 test_diagnosis_plans（每个请求一行，event_id 唯一），
//     状态固定 planned，含能力名列表与规则编号；
//   - 无匹配规则时：状态仍为 planned、能力列表为空、原因写 no_rule；
//   - **不调用任何适配器、不执行任何能力、不连接任何资产**（第十七轮才执行）。
//
// 规则表约束（由测试强制）：
//   - 每条规则引用的能力必须存在于 adapters/*/manifest.yaml；
//   - 且 tier 必须为 read_only（不得出现 destructive 或非只读能力）。
package planner

import "strings"

// 原因标记。
const (
	// ReasonNoRule 无匹配规则（第十七轮 P1：无匹配时**状态**即为 no_rule）。
	ReasonNoRule = "no_rule"
	// ReasonNoProfile 源未声明画像（防御性；正常路径下启动校验已拒绝）。
	ReasonNoProfile = "no_profile"
	// ReasonDeferredK8s Kubernetes 画像本轮不执行（第十七轮 P4）。
	ReasonDeferredK8s = "kubernetes 画像的诊断执行推迟到后续轮次（本轮只执行 linux 与 docker-monitor）"
)

// 计划状态（第十七轮；第十八轮增 not_executed —— 见 ADR-018）。
const (
	// StatusPlanned 已规划、待执行。
	StatusPlanned = "planned"
	// StatusNoRule 无匹配规则（空计划；**不再用 planned 掩盖**）。
	StatusNoRule = "no_rule"
	// StatusRunning 已被执行器抢占（CAS planned → running）。
	StatusRunning = "running"
	// StatusDone 全部能力执行成功。
	StatusDone = "done"
	// StatusFailed 任一能力执行失败（含 interrupted）。
	StatusFailed = "failed"
	// StatusDeferred 全部能力被推迟（保留状态：当前无产生路径，见 ADR-017）。
	StatusDeferred = "deferred"
	// StatusPartial 至少一个能力被执行，且至少一个能力被拒绝/推迟（无失败）。
	StatusPartial = "partial"
	// StatusNotExecuted 没有任何能力被执行（全部 no_cluster_configured 或 denied）。
	// 第十九轮 F2：与 partial 拆分，避免监控把"集群未配置"误读成"部分成功"。
	StatusNotExecuted = "not_executed"
)

// Rule 一条规划规则：**画像** + severity → 只读能力列表。
//
// 第十七轮 P1：规则按画像匹配（不再按原始 source 名称匹配）——
// 告警源名称只要有一个字符不同就整体失效的问题由此消除；
// 新增同名不同写的告警源时，只需声明相同画像即可复用规则。
type Rule struct {
	// ID 规则编号（写入计划表，便于回溯决策来源）。
	ID string
	// Profile 告警源画像（精确匹配，大小写不敏感；取值见 ingest.KnownProfiles）。
	Profile string
	// Severity 告警级别（精确匹配 info/warning/critical）。
	Severity string
	// Capabilities 计划执行的**只读**能力名（必须存在于适配器清单）。
	Capabilities []string
}

// Rules 规则表（代码常量；**画像**/severity 精确匹配）。
//
// 说明（工程默认，待运维确认）：这里的映射是"最小心智模型"版本——
// 按告警源画像选择对应组件的只读诊断能力，按级别决定诊断深度。
var Rules = []Rule{
	{
		ID: "R-001", Profile: "prometheus", Severity: "critical",
		Capabilities: []string{"diagnose.disk_usage", "diagnose.memory_pressure", "diagnose.load_average"},
	},
	{
		ID: "R-002", Profile: "prometheus", Severity: "warning",
		Capabilities: []string{"diagnose.disk_usage", "diagnose.memory_pressure"},
	},
	{
		ID: "R-003", Profile: "alertmanager", Severity: "critical",
		Capabilities: []string{"k8s.version", "k8s.pod.list", "k8s.deployment.list"},
	},
	{
		ID: "R-004", Profile: "alertmanager", Severity: "warning",
		Capabilities: []string{"k8s.version", "k8s.pod.list"},
	},
	{
		ID: "R-005", Profile: "docker-monitor", Severity: "critical",
		Capabilities: []string{"docker.version", "docker.info", "docker.container.list"},
	},
	{
		ID: "R-006", Profile: "docker-monitor", Severity: "warning",
		Capabilities: []string{"docker.info", "docker.container.list"},
	},
	{
		ID: "R-007", Profile: "node-exporter", Severity: "critical",
		Capabilities: []string{"diagnose.load_average", "diagnose.memory_pressure", "diagnose.disk_usage"},
	},
}

// Plan 一条规划结果。
type Plan struct {
	// RuleID 命中的规则编号；无匹配为空串。
	RuleID string
	// Capabilities 计划执行的只读能力（无匹配时为空）。
	Capabilities []string
	// Reason 无匹配时为 ReasonNoRule，否则为空。
	Reason string
}

// PlanFor 纯函数：按 (**画像**, severity) 生成计划。
// 不访问数据库、不调用适配器、不做任何 I/O。
//
// 无匹配规则时返回 Reason=ReasonNoRule（计划状态由调用方置为 no_rule）。
func PlanFor(profile, severity string) Plan {
	prof := strings.ToLower(strings.TrimSpace(profile))
	sev := strings.ToLower(strings.TrimSpace(severity))
	if prof == "" {
		return Plan{RuleID: "", Capabilities: nil, Reason: ReasonNoProfile}
	}
	for _, r := range Rules {
		if strings.ToLower(r.Profile) != prof || strings.ToLower(r.Severity) != sev {
			continue
		}
		caps := make([]string, len(r.Capabilities))
		copy(caps, r.Capabilities)
		return Plan{RuleID: r.ID, Capabilities: caps}
	}
	return Plan{RuleID: "", Capabilities: nil, Reason: ReasonNoRule}
}

// Capabilities 返回规则表中出现的全部能力名（去重，字典序）。
// 供测试与运维核对"规则表只引用只读能力"。
func Capabilities() []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range Rules {
		for _, c := range r.Capabilities {
			if seen[c] {
				continue
			}
			seen[c] = true
			out = append(out, c)
		}
	}
	sortStrings(out)
	return out
}

// sortStrings 最小化排序（避免额外依赖）。
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
