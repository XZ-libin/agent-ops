// Package linux 是 Linux 主机只读适配器（路线图第一个适配器）。
//
// 它只有读操作，不实现、也不存在任何写操作路径：
//   - Execute 对任何非 read_only 能力返回「只读适配器不执行写操作」；
//   - PlanRollback 恒返回空计划。
//
// 命令约束（安全）：
//   - 只使用固定只读命令集合：uname -r、cat /etc/os-release、cat /proc/loadavg、
//     df -P、free -m、systemctl is-active <unit>；
//   - 命令以 argv 形式传递，禁止拼接 shell 字符串；
//   - systemctl 的 unit 参数必须通过 internal/validation（ValidUnitName）校验，
//     不符合即拒绝（第七轮遗留决策 D2：规则唯一来源为共享包）。
//
// 适配器只依赖共享模块 internal/exec 的 Runner 接口，不直接依赖 ssh 等传输实现
// （第七轮遗留决策 D1）。
package linux

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gopkg.in/yaml.v3"

	"github.com/ORG/agent-ops/contract"
	contractv1 "github.com/ORG/agent-ops/contract/gen/go/agent_ops/contract/v1"
	"github.com/ORG/agent-ops/internal/exec"
	"github.com/ORG/agent-ops/internal/validation"
)

//go:embed manifest.yaml
var manifestYAML []byte

// —— 预定义诊断问题（自由文本一律拒绝）——

const (
	// QuestionDiskUsage 根分区使用率。
	QuestionDiskUsage = "disk_usage"
	// QuestionMemoryPressure 内存压力。
	QuestionMemoryPressure = "memory_pressure"
	// QuestionLoadAverage 1 分钟系统负载。
	QuestionLoadAverage = "load_average"
	// QuestionServiceStatePrefix 服务状态问题前缀：service_state:<unit>，
	// unit 必须通过 validation.ValidUnitName 校验。
	QuestionServiceStatePrefix = "service_state:"
)

// —— 健康阈值（工程默认值，待运维确认）——

const (
	// diskDegradedPercent 根分区使用率超过 90% 判 degraded（工程默认值，待运维确认）。
	diskDegradedPercent = 90.0
	// diskUnhealthyPercent 根分区使用率超过 95% 判 unhealthy（工程默认值，待运维确认）。
	diskUnhealthyPercent = 95.0
	// loadDegradedFactor 1 分钟负载超过 CPU 核数的 2 倍判 degraded（工程默认值，待运维确认）。
	loadDegradedFactor = 2.0
	// defaultCores CPU 核数工程默认值（待运维确认）；调用方可用 WithCores 覆盖，
	// 核数无法从允许命令集合中获取。
	defaultCores = 4
	// runTimeout 单条命令执行超时（与 manifest.yaml 各能力 timeout: 60s 对齐；
	// 双保险之一：网关层还会按能力声明再套一层上下文超时）。
	runTimeout = 60 * time.Second
)

// 适配器错误。
var (
	errWriteDenied    = errors.New("只读适配器不执行写操作")
	errReadOnlyHint   = errors.New("只读适配器不执行写操作（read_only 能力请经 Diagnose/Health 使用）")
	errQuestionReject = errors.New("自由文本诊断问题被拒绝：只接受预定义问题")
	errBadUnit        = errors.New("非法 systemctl unit 名，已拒绝")
	// ErrNoRollbackNeeded 只读操作的回滚计划恒为空，错误文本即理由。
	ErrNoRollbackNeeded = errors.New("只读操作不需要回滚：无副作用，回滚计划为空")
)

// manifestCapability 清单中的能力声明（本适配器所需字段）。
type manifestCapability struct {
	Name        string `yaml:"name"`
	RiskTier    string `yaml:"risk_tier"`
	Destructive bool   `yaml:"destructive"`
	Idempotent  bool   `yaml:"idempotent"`
	Timeout     string `yaml:"timeout"`
}

type manifestFile struct {
	Name              string               `yaml:"name"`
	SupportedVersions []string             `yaml:"supported_versions"`
	AccessMethods     []string             `yaml:"access_methods"`
	Capabilities      []manifestCapability `yaml:"capabilities"`
}

// Option 配置适配器。
type Option func(*Adapter)

// WithCores 覆盖 CPU 核数（负载阈值判定用；默认 defaultCores，待运维确认）。
func WithCores(n int) Option {
	return func(a *Adapter) {
		if n > 0 {
			a.cores = n
		}
	}
}

// Adapter Linux 主机只读适配器。
type Adapter struct {
	runner   exec.Runner
	cores    int
	declared map[string]contractv1.RiskTier // 清单声明的能力 → 等级
	manifest *contractv1.Manifest           // 契约化能力清单（供网关注册/策略评估）
}

// 编译期断言：实现了统一 Adapter 接口。
var _ contract.Adapter = (*Adapter)(nil)

// New 构建适配器并校验内置清单：
// 能力名必须通过名称校验（internal/validation）；风险等级必须为 read_only
// （本适配器不声明写能力）。
func New(runner exec.Runner, opts ...Option) (*Adapter, error) {
	a := &Adapter{
		runner:   runner,
		cores:    defaultCores,
		declared: make(map[string]contractv1.RiskTier),
	}
	for _, o := range opts {
		o(a)
	}

	var mf manifestFile
	if err := yaml.Unmarshal(manifestYAML, &mf); err != nil {
		return nil, fmt.Errorf("linux adapter manifest: %w", err)
	}
	manifest := &contractv1.Manifest{Name: mf.Name, AccessMethods: []contractv1.AccessKind{
		contractv1.AccessKind_ACCESS_SSH,
		contractv1.AccessKind_ACCESS_AGENT,
	}}
	for _, c := range mf.Capabilities {
		if !validation.ValidCapabilityName(c.Name) {
			return nil, fmt.Errorf("linux adapter manifest：能力名不合法 %q（名称校验不通过）", c.Name)
		}
		if c.RiskTier != "read_only" {
			return nil, fmt.Errorf("linux adapter manifest：能力 %q 等级必须是 read_only（只读适配器）", c.Name)
		}
		timeout, err := time.ParseDuration(c.Timeout)
		if err != nil {
			return nil, fmt.Errorf("linux adapter manifest：能力 %q 超时无法解析 %q：%w", c.Name, c.Timeout, err)
		}
		a.declared[c.Name] = contractv1.RiskTier_RISK_TIER_READ_ONLY
		manifest.Capabilities = append(manifest.Capabilities, &contractv1.Capability{
			Name:         c.Name,
			RiskTier:     contractv1.RiskTier_RISK_TIER_READ_ONLY,
			Idempotent:   c.Idempotent,
			Rollbackable: false, // 第九轮 R2：无真实 PlanRollback 实现，一律 false
			Timeout:      durationpb.New(timeout),
			Destructive:  false, // 只读适配器不声明任何破坏性能力
		})
	}
	a.manifest = manifest
	return a, nil
}

// Manifest 返回契约化能力清单（声明式 YAML 的运行时形态），供网关注册与策略评估。
func (a *Adapter) Manifest() *contractv1.Manifest { return a.manifest }

// run 执行一条命令并检查退出码（argv 形式，禁止拼接 shell 字符串；
// 单条命令超时 runTimeout，输出上限/截断由 Runner 保证）。
func (a *Adapter) run(ctx context.Context, argv ...string) (exec.Result, error) {
	res, err := a.runner.Run(ctx, argv, exec.RunOptions{Timeout: runTimeout})
	if err != nil {
		return res, err
	}
	if res.ExitCode != 0 {
		return res, fmt.Errorf("command %q exited %d: %s", argv[0], res.ExitCode, strings.TrimSpace(string(res.Stderr)))
	}
	return res, nil
}

// Discover 返回主机基本信息：内核版本（uname -r）与发行版（cat /etc/os-release）。
func (a *Adapter) Discover(ctx context.Context, target *contractv1.AssetTarget) ([]*contractv1.Instance, error) {
	kernel, err := a.run(ctx, "uname", "-r")
	if err != nil {
		return nil, fmt.Errorf("discover kernel: %w", err)
	}
	osRel, err := a.run(ctx, "cat", "/etc/os-release")
	if err != nil {
		return nil, fmt.Errorf("discover os-release: %w", err)
	}

	inst := &contractv1.Instance{
		Id:      target.AssetId + "/linux",
		Version: strings.TrimSpace(string(kernel.Stdout)),
		AssetId: target.AssetId,
		Extra: []*contractv1.KV{
			{Key: "distro", Value: parseOSRelease(osRel.Stdout)},
		},
	}
	return []*contractv1.Instance{inst}, nil
}

// parseOSRelease 从 /etc/os-release 内容解析发行版名（解析失败返回 unknown）。
func parseOSRelease(b []byte) string {
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "NAME=") {
			return strings.Trim(strings.TrimPrefix(line, "NAME="), `"'`)
		}
	}
	return "unknown"
}

// Health 返回健康状态与关键指标。
// 状态取值：healthy / degraded / unhealthy / unknown。
// 判定规则（工程默认阈值，待运维确认）：
//   - 根分区使用率 >95% → unhealthy；>90% → degraded；
//   - 1 分钟负载 > 2×CPU 核数 → degraded；
//   - 关键指标无法解析时 → unknown。
func (a *Adapter) Health(ctx context.Context, instance *contractv1.Instance) (*contractv1.HealthReport, error) {
	var (
		metrics []*contractv1.Metric
		status  = "healthy"
	)

	df, dfErr := a.run(ctx, "df", "-P")
	if dfErr != nil {
		return nil, fmt.Errorf("health df: %w", dfErr)
	}
	diskPct, diskOK := parseRootUsage(df.Stdout)

	load, loadErr := a.run(ctx, "cat", "/proc/loadavg")
	if loadErr != nil {
		return nil, fmt.Errorf("health loadavg: %w", loadErr)
	}
	load1, loadOK := parseLoad1(load.Stdout)

	if !diskOK && !loadOK {
		status = "unknown"
	}
	if diskOK {
		metrics = append(metrics, &contractv1.Metric{Name: "disk_usage_root_percent", Value: diskPct})
		switch {
		case diskPct > diskUnhealthyPercent:
			status = "unhealthy"
		case diskPct > diskDegradedPercent:
			status = "degraded"
		}
	}
	if loadOK && a.cores > 0 {
		metrics = append(metrics, &contractv1.Metric{Name: "load_1m", Value: load1})
		if status == "healthy" && load1 > loadDegradedFactor*float64(a.cores) {
			status = "degraded"
		}
	}
	// 命令成功但输出无法解析：unknown（保守），命令失败已在上方返回错误。
	if !diskOK {
		status = "unknown"
	}
	if !loadOK {
		status = "unknown"
	}

	return &contractv1.HealthReport{
		Status:      status,
		Metrics:     metrics,
		CollectedAt: timestamppb.New(time.Now()),
	}, nil
}

// parseRootUsage 从 df -P 输出解析根分区（挂载点 /）的 Use%。
func parseRootUsage(out []byte) (float64, bool) {
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		// df -P 行：Filesystem 1024-blocks Used Available Capacity Mounted-on
		if len(fields) >= 6 && fields[5] == "/" {
			pct, err := strconv.ParseFloat(strings.TrimSuffix(fields[4], "%"), 64)
			return pct, err == nil
		}
	}
	return 0, false
}

// parseLoad1 解析 /proc/loadavg 第一个字段（1 分钟负载）。
func parseLoad1(out []byte) (float64, bool) {
	fields := strings.Fields(string(out))
	if len(fields) < 1 {
		return 0, false
	}
	v, err := strconv.ParseFloat(fields[0], 64)
	return v, err == nil
}

// Diagnose 只接受预定义问题，自由文本一律返回错误。
func (a *Adapter) Diagnose(ctx context.Context, instance *contractv1.Instance, question string) (*contractv1.DiagnosisReport, error) {
	switch {
	case question == QuestionDiskUsage:
		res, err := a.run(ctx, "df", "-P")
		if err != nil {
			return nil, err
		}
		pct, ok := parseRootUsage(res.Stdout)
		if !ok {
			return nil, fmt.Errorf("无法解析 df -P 输出")
		}
		return report(question, "df -P", fmt.Sprintf("根分区使用率 %.1f%%", pct)), nil

	case question == QuestionMemoryPressure:
		res, err := a.run(ctx, "free", "-m")
		if err != nil {
			return nil, err
		}
		total, used, ok := parseMem(res.Stdout)
		if !ok {
			return nil, fmt.Errorf("无法解析 free -m 输出")
		}
		return report(question, "free -m", fmt.Sprintf("内存：已用 %dMB / 共 %dMB", used, total)), nil

	case question == QuestionLoadAverage:
		res, err := a.run(ctx, "cat", "/proc/loadavg")
		if err != nil {
			return nil, err
		}
		load1, ok := parseLoad1(res.Stdout)
		if !ok {
			return nil, fmt.Errorf("无法解析 /proc/loadavg 输出")
		}
		return report(question, "cat /proc/loadavg", fmt.Sprintf("1 分钟负载 %.2f", load1)), nil

	case strings.HasPrefix(question, QuestionServiceStatePrefix):
		unit := strings.TrimPrefix(question, QuestionServiceStatePrefix)
		if !validation.ValidUnitName(unit) {
			return nil, fmt.Errorf("%w: %q", errBadUnit, unit)
		}
		// 不符合校验的 unit 不调用任何命令（含合法与否都不伪造结果）。
		res, err := a.run(ctx, "systemctl", "is-active", unit)
		if err != nil {
			return nil, err
		}
		state := strings.TrimSpace(string(res.Stdout))
		return report(question, "systemctl is-active "+unit, fmt.Sprintf("unit %s 状态 %s", unit, state)), nil

	default:
		return nil, errQuestionReject
	}
}

// report 构造诊断报告（证据引用记录所用命令）。
func report(question, command, conclusion string) *contractv1.DiagnosisReport {
	return &contractv1.DiagnosisReport{
		Findings: []*contractv1.Finding{
			{Hypothesis: question, EvidenceRefs: []string{command}, Verdict: "observed"},
		},
		Conclusion: conclusion,
	}
}

// parseMem 解析 free -m 的 Mem 行（total/used）。
func parseMem(out []byte) (int64, int64, bool) {
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.HasPrefix(line, "Mem:") {
			continue
		}
		fields := strings.Fields(line) // Mem: total used free shared buff/cache available
		if len(fields) >= 3 {
			total, err1 := strconv.ParseInt(fields[1], 10, 64)
			used, err2 := strconv.ParseInt(fields[2], 10, 64)
			if err1 == nil && err2 == nil {
				return total, used, true
			}
		}
	}
	return 0, 0, false
}

// Execute 对任何非 read_only 的能力返回错误；本适配器不执行任何写操作。
func (a *Adapter) Execute(ctx context.Context, action *contractv1.Action, authz *contractv1.AuthZ) (*contractv1.ActionResult, error) {
	tier, ok := a.declared[action.Capability]
	if !ok {
		// 未在清单声明的能力一律拒绝（契约要求：未声明的能力不可调用）。
		return nil, fmt.Errorf("%w（能力 %s 未在清单声明，已拒绝）", errWriteDenied, action.Capability)
	}
	if tier != contractv1.RiskTier_RISK_TIER_READ_ONLY {
		return nil, errWriteDenied
	}
	return nil, errReadOnlyHint
}

// PlanRollback 只读能力无任何写副作用：恒返回空计划，理由见 ErrNoRollbackNeeded。
func (a *Adapter) PlanRollback(ctx context.Context, record *contractv1.ActionRecord) ([]*contractv1.Action, error) {
	return []*contractv1.Action{}, ErrNoRollbackNeeded
}
