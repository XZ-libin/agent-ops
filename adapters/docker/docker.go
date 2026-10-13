package docker

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gopkg.in/yaml.v3"

	"github.com/ORG/agent-ops/contract"
	contractv1 "github.com/ORG/agent-ops/contract/gen/go/agent_ops/contract/v1"
	"github.com/ORG/agent-ops/internal/validation"
)

//go:embed manifest.yaml
var manifestYAML []byte

// —— 预定义诊断问题（自由文本一律拒绝）——
const (
	// QuestionVersion 引擎版本。
	QuestionVersion = "version"
	// QuestionInfo 引擎信息（已屏蔽 Swarm 与节点敏感字段）。
	QuestionInfo = "info"
	// QuestionContainerList 容器列表（仅测试标签）。
	QuestionContainerList = "container_list"
	// QuestionImageList 镜像列表（仅测试标签）。
	QuestionImageList = "image_list"
	// QuestionContainerStatusPrefix 容器状态问题前缀：
	// container_status:<id>，id 须通过白名单字符集校验。
	QuestionContainerStatusPrefix = "container_status:"
)

// 适配器错误（与 Linux 适配器同款语义）。
var (
	errWriteDenied = errors.New("只读适配器不执行写操作")
	// ErrReadOnlyHint 只读能力被 Execute 调用时的提示（应走 Diagnose/Health）。
	ErrReadOnlyHint = errors.New("只读适配器不执行写操作（read_only 能力请经 Diagnose/Health 使用）")
	// ErrQuestionRejected 自由文本诊断问题被拒绝：只接受预定义问题。
	ErrQuestionRejected = errors.New("自由文本诊断问题被拒绝：只接受预定义问题")
	// ErrBadContainerID 容器标识不合法（白名单字符集校验不通过）。
	ErrBadContainerID = errors.New("非法容器标识，已拒绝")
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

// WithTimeout 覆盖客户端单请求超时（默认 DefaultTimeout=10s）。
func WithTimeout(d time.Duration) Option {
	return func(a *Adapter) {
		if d > 0 {
			a.timeout = d
		}
	}
}

// WithMaxBodyBytes 覆盖响应体上限（默认 DefaultMaxBodyBytes=1MB）。
func WithMaxBodyBytes(n int64) Option {
	return func(a *Adapter) {
		if n > 0 {
			a.maxBody = n
		}
	}
}

// Adapter Docker 主机只读适配器。
type Adapter struct {
	client   *Client
	timeout  time.Duration
	maxBody  int64
	declared map[string]contractv1.RiskTier // 清单声明的能力 → 等级
	manifest *contractv1.Manifest           // 契约化能力清单（供网关注册/策略评估）
}

// 编译期断言：实现了统一 Adapter 接口。
var _ contract.Adapter = (*Adapter)(nil)

// New 构建适配器并校验内置清单：
// 能力名必须通过名称校验；风险等级必须为 read_only；
// 超时必填且为正（第十二轮 H6：执行租约由能力超时推导）。
func New(cfg Config, opts ...Option) (*Adapter, error) {
	client, err := NewClient(cfg)
	if err != nil {
		return nil, err
	}
	a := &Adapter{
		client:   client,
		timeout:  client.http.Timeout,
		maxBody:  client.maxBody,
		declared: make(map[string]contractv1.RiskTier),
	}
	for _, o := range opts {
		o(a)
	}
	// 选项可能覆盖超时/上限：同步到客户端（客户端是唯一出口）。
	client.http.Timeout = a.timeout
	client.maxBody = a.maxBody

	var mf manifestFile
	if err := yaml.Unmarshal(manifestYAML, &mf); err != nil {
		return nil, fmt.Errorf("docker adapter manifest: %w", err)
	}
	manifest := &contractv1.Manifest{
		Name:          mf.Name,
		AccessMethods: []contractv1.AccessKind{contractv1.AccessKind_ACCESS_DOCKER},
	}
	for _, c := range mf.Capabilities {
		if !validation.ValidCapabilityName(c.Name) {
			return nil, fmt.Errorf("docker adapter manifest：能力名不合法 %q（名称校验不通过）", c.Name)
		}
		if c.RiskTier != "read_only" {
			return nil, fmt.Errorf("docker adapter manifest：能力 %q 等级必须是 read_only（只读适配器）", c.Name)
		}
		if c.Destructive {
			return nil, fmt.Errorf("docker adapter manifest：能力 %q 不得声明 destructive（只读适配器）", c.Name)
		}
		timeout, err := time.ParseDuration(c.Timeout)
		if err != nil {
			return nil, fmt.Errorf("docker adapter manifest：能力 %q 超时无法解析 %q：%w", c.Name, c.Timeout, err)
		}
		if timeout <= 0 {
			return nil, fmt.Errorf("docker adapter manifest：能力 %q 超时必须为正（当前 %v）", c.Name, timeout)
		}
		a.declared[c.Name] = contractv1.RiskTier_RISK_TIER_READ_ONLY
		manifest.Capabilities = append(manifest.Capabilities, &contractv1.Capability{
			Name:         c.Name,
			RiskTier:     contractv1.RiskTier_RISK_TIER_READ_ONLY,
			Idempotent:   c.Idempotent,
			Rollbackable: false, // 只读适配器：无回滚计划
			Timeout:      durationpb.New(timeout),
			Destructive:  false,
		})
	}
	a.manifest = manifest
	return a, nil
}

// Manifest 返回契约化能力清单，供网关注册与策略评估。
func (a *Adapter) Manifest() *contractv1.Manifest { return a.manifest }

// Discover 发现 Docker 守护进程实例与版本（只读：GET /version）。
func (a *Adapter) Discover(ctx context.Context, target *contractv1.AssetTarget) ([]*contractv1.Instance, error) {
	if target == nil {
		return nil, errors.New("docker：目标资产为空")
	}
	ver, err := a.client.Version(ctx)
	if err != nil {
		return nil, fmt.Errorf("docker discover: %w", err)
	}
	extra := []*contractv1.KV{}
	for _, k := range []string{"ApiVersion", "Os", "Arch", "GitCommit"} {
		if v, ok := ver[k].(string); ok && v != "" {
			extra = append(extra, &contractv1.KV{Key: k, Value: v})
		}
	}
	return []*contractv1.Instance{{
		Id:      target.AssetId + "/docker",
		Version: stringValue(ver, "Version"),
		AssetId: target.AssetId,
		Extra:   extra,
	}}, nil
}

// Health 返回守护进程可达性（只读：GET /version）。
func (a *Adapter) Health(ctx context.Context, instance *contractv1.Instance) (*contractv1.HealthReport, error) {
	report := &contractv1.HealthReport{
		Status:      "healthy",
		Metrics:     []*contractv1.Metric{{Name: "reachable", Value: 1}},
		CollectedAt: timestamppb.Now(),
	}
	if _, err := a.client.Version(ctx); err != nil {
		report.Status = "unhealthy"
		report.Metrics = []*contractv1.Metric{{Name: "reachable", Value: 0}}
	}
	if instance != nil {
		report.Metrics = append(report.Metrics, &contractv1.Metric{Name: "instances", Value: 1})
	}
	return report, nil
}

// Diagnose 执行只读排查（只接受预定义问题）。
func (a *Adapter) Diagnose(ctx context.Context, instance *contractv1.Instance, question string) (*contractv1.DiagnosisReport, error) {
	q := strings.TrimSpace(question)
	switch {
	case q == QuestionVersion:
		ver, err := a.client.Version(ctx)
		if err != nil {
			return nil, err
		}
		return report("docker.version", fmt.Sprintf("Docker 引擎版本 %s（API %s，%s/%s）",
			stringValue(ver, "Version"), stringValue(ver, "ApiVersion"),
			stringValue(ver, "Os"), stringValue(ver, "Arch"))), nil

	case q == QuestionInfo:
		info, dropped, err := a.client.Info(ctx)
		if err != nil {
			return nil, err
		}
		return report("docker.info", fmt.Sprintf(
			"Docker 引擎信息：容器 %v 个（运行 %v/暂停 %v/停止 %v）、镜像 %v 个；已按白名单裁剪字段 %d 个",
			info["Containers"], info["ContainersRunning"], info["ContainersPaused"],
			info["ContainersStopped"], info["Images"], len(dropped))), nil

	case q == QuestionContainerList:
		items, err := a.client.ListContainers(ctx)
		if err != nil {
			return nil, err
		}
		names := make([]string, 0, len(items))
		for _, c := range items {
			names = append(names, fmt.Sprintf("%v(%v)", c["Id"], c["State"]))
		}
		return report("docker.container.list", fmt.Sprintf("测试标签容器 %d 个：%s",
			len(items), strings.Join(names, ", "))), nil

	case q == QuestionImageList:
		items, err := a.client.ListImages(ctx)
		if err != nil {
			return nil, err
		}
		names := make([]string, 0, len(items))
		for _, img := range items {
			tags, _ := img["RepoTags"].([]any)
			names = append(names, fmt.Sprintf("%v", tags))
		}
		return report("docker.image.list", fmt.Sprintf("测试标签镜像 %d 个：%s",
			len(items), strings.Join(names, ", "))), nil

	case strings.HasPrefix(q, QuestionContainerStatusPrefix):
		id := strings.TrimSpace(strings.TrimPrefix(q, QuestionContainerStatusPrefix))
		if !validation.ValidContainerID(id) {
			return nil, ErrBadContainerID
		}
		detail, masked, err := a.client.InspectContainer(ctx, id)
		if err != nil {
			return nil, err
		}
		state, _ := detail["State"].(map[string]any)
		return report("docker.container.inspect_status", fmt.Sprintf(
			"容器 %s 状态 %v（运行中 %v，退出码 %v）；已屏蔽字段 %v",
			id, state["Status"], state["Running"], state["ExitCode"], masked)), nil
	}
	return nil, ErrQuestionRejected
}

// Execute 只读适配器不执行任何能力：read_only 能力请走 Diagnose/Health。
func (a *Adapter) Execute(_ context.Context, action *contractv1.Action, _ *contractv1.AuthZ) (*contractv1.ActionResult, error) {
	if action == nil {
		return nil, errWriteDenied
	}
	if _, declared := a.declared[action.Capability]; declared {
		return nil, fmt.Errorf("%w：%s", ErrReadOnlyHint, action.Capability)
	}
	return nil, fmt.Errorf("%w：未声明能力 %s", errWriteDenied, action.Capability)
}

// PlanRollback 只读操作无副作用，回滚计划恒为空。
func (a *Adapter) PlanRollback(_ context.Context, _ *contractv1.ActionRecord) ([]*contractv1.Action, error) {
	return nil, ErrNoRollbackNeeded
}

// report 构造只读诊断结论（结论必须附证据引用，此处以问题名作为证据键）。
func report(question, conclusion string) *contractv1.DiagnosisReport {
	return &contractv1.DiagnosisReport{
		Findings: []*contractv1.Finding{{
			Hypothesis:   question,
			EvidenceRefs: []string{question},
			Verdict:      conclusion,
		}},
		Conclusion: conclusion,
		Confidence: "high",
	}
}

// stringValue 读取 map 中的字符串值（缺失返回空串）。
func stringValue(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

// marshalIndent 供测试与调试输出（不参与业务逻辑）。
func marshalIndent(v any) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(b)
}
