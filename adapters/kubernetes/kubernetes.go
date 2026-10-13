package kubernetes

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
	// QuestionVersion 集群版本。
	QuestionVersion = "version"
	// QuestionPodList 测试标签 Pod 列表：pod_list:<namespace>。
	QuestionPodList = "pod_list:"
	// QuestionPodStatus 单个 Pod 状态：pod_status:<namespace>/<name>。
	QuestionPodStatus = "pod_status:"
	// QuestionDeploymentList 测试标签 Deployment 列表：deployment_list:<namespace>。
	QuestionDeploymentList = "deployment_list:"
	// QuestionNamespaceGet 命名空间信息：namespace_get:<namespace>。
	QuestionNamespaceGet = "namespace_get:"
)

// 适配器错误（与 Docker / Linux 适配器同款语义）。
var (
	errWriteDenied = errors.New("只读适配器不执行写操作")
	// ErrReadOnlyHint 只读能力被 Execute 调用时的提示。
	ErrReadOnlyHint = errors.New("只读适配器不执行写操作（read_only 能力请经 Diagnose/Health 使用）")
	// ErrQuestionRejected 自由文本诊断问题被拒绝。
	ErrQuestionRejected = errors.New("自由文本诊断问题被拒绝：只接受预定义问题")
	// ErrNoRollbackNeeded 只读操作的回滚计划恒为空。
	ErrNoRollbackNeeded = errors.New("只读操作不需要回滚：无副作用，回滚计划为空")
)

// manifestCapability 清单中的能力声明。
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

// Adapter Kubernetes 只读适配器。
type Adapter struct {
	client   *Client
	declared map[string]contractv1.RiskTier
	manifest *contractv1.Manifest
}

// 编译期断言：实现了统一 Adapter 接口。
var _ contract.Adapter = (*Adapter)(nil)

// New 构建适配器并校验内置清单（名称/等级/超时，全部 fail-closed）。
func New(cfg Config, opts ...Option) (*Adapter, error) {
	client, err := NewClient(cfg)
	if err != nil {
		return nil, err
	}
	a := &Adapter{client: client, declared: make(map[string]contractv1.RiskTier)}
	for _, o := range opts {
		o(a)
	}

	var mf manifestFile
	if err := yaml.Unmarshal(manifestYAML, &mf); err != nil {
		return nil, fmt.Errorf("kubernetes adapter manifest: %w", err)
	}
	manifest := &contractv1.Manifest{
		Name:          mf.Name,
		AccessMethods: []contractv1.AccessKind{contractv1.AccessKind_ACCESS_KUBECONFIG},
	}
	for _, c := range mf.Capabilities {
		if !validation.ValidCapabilityName(c.Name) {
			return nil, fmt.Errorf("kubernetes adapter manifest：能力名不合法 %q", c.Name)
		}
		if c.RiskTier != "read_only" {
			return nil, fmt.Errorf("kubernetes adapter manifest：能力 %q 等级必须是 read_only（只读适配器）", c.Name)
		}
		if c.Destructive {
			return nil, fmt.Errorf("kubernetes adapter manifest：能力 %q 不得声明 destructive", c.Name)
		}
		timeout, err := time.ParseDuration(c.Timeout)
		if err != nil {
			return nil, fmt.Errorf("kubernetes adapter manifest：能力 %q 超时无法解析 %q：%w", c.Name, c.Timeout, err)
		}
		if timeout <= 0 {
			return nil, fmt.Errorf("kubernetes adapter manifest：能力 %q 超时必须为正", c.Name)
		}
		a.declared[c.Name] = contractv1.RiskTier_RISK_TIER_READ_ONLY
		manifest.Capabilities = append(manifest.Capabilities, &contractv1.Capability{
			Name:         c.Name,
			RiskTier:     contractv1.RiskTier_RISK_TIER_READ_ONLY,
			Idempotent:   c.Idempotent,
			Rollbackable: false,
			Timeout:      durationpb.New(timeout),
			Destructive:  false,
		})
	}
	a.manifest = manifest
	return a, nil
}

// Option 配置适配器（本轮暂无选项，保留扩展点）。
type Option func(*Adapter)

// Manifest 返回契约化能力清单。
func (a *Adapter) Manifest() *contractv1.Manifest { return a.manifest }

// Discover 发现集群版本（只读：GET /version）。
func (a *Adapter) Discover(ctx context.Context, target *contractv1.AssetTarget) ([]*contractv1.Instance, error) {
	if target == nil {
		return nil, errors.New("kubernetes：目标资产为空")
	}
	ver, err := a.client.Version(ctx)
	if err != nil {
		return nil, fmt.Errorf("kubernetes discover: %w", err)
	}
	extra := []*contractv1.KV{}
	for _, k := range []string{"major", "minor", "gitVersion", "platform"} {
		if v, ok := ver[k].(string); ok && v != "" {
			extra = append(extra, &contractv1.KV{Key: k, Value: v})
		}
	}
	return []*contractv1.Instance{{
		Id:      target.AssetId + "/kubernetes",
		Version: stringValue(ver, "gitVersion"),
		AssetId: target.AssetId,
		Extra:   extra,
	}}, nil
}

// Health 返回 API 可达性（只读：GET /version）。
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

// Diagnose 执行只读排查（只接受预定义问题，自由文本一律拒绝）。
func (a *Adapter) Diagnose(ctx context.Context, _ *contractv1.Instance, question string) (*contractv1.DiagnosisReport, error) {
	q := strings.TrimSpace(question)
	switch {
	case q == QuestionVersion:
		ver, err := a.client.Version(ctx)
		if err != nil {
			return nil, err
		}
		return report("k8s.version", fmt.Sprintf("Kubernetes 集群版本 %s（major %s, minor %s）",
			stringValue(ver, "gitVersion"), stringValue(ver, "major"), stringValue(ver, "minor"))), nil

	case strings.HasPrefix(q, QuestionNamespaceGet):
		ns := strings.TrimSpace(strings.TrimPrefix(q, QuestionNamespaceGet))
		if !validation.ValidK8sNamespace(ns) {
			return nil, fmt.Errorf("%w：命名空间名不合法 %q", ErrQuestionRejected, ns)
		}
		obj, masked, err := a.client.GetNamespace(ctx, ns)
		if err != nil {
			return nil, err
		}
		md, _ := obj["metadata"].(map[string]any)
		return report("k8s.namespace.get", fmt.Sprintf("命名空间 %s 存在（名称 %v，已屏蔽字段 %v）",
			ns, md["name"], masked)), nil

	case strings.HasPrefix(q, QuestionPodList):
		ns := strings.TrimSpace(strings.TrimPrefix(q, QuestionPodList))
		if !validation.ValidK8sNamespace(ns) {
			return nil, fmt.Errorf("%w：命名空间名不合法 %q", ErrQuestionRejected, ns)
		}
		pods, err := a.client.ListPods(ctx, ns)
		if err != nil {
			return nil, err
		}
		names := make([]string, 0, len(pods))
		for _, p := range pods {
			md, _ := p["metadata"].(map[string]any)
			st, _ := p["status"].(map[string]any)
			names = append(names, fmt.Sprintf("%v(%v)", md["name"], st["phase"]))
		}
		return report("k8s.pod.list", fmt.Sprintf("命名空间 %s 的测试标签 Pod %d 个：%s",
			ns, len(pods), strings.Join(names, ", "))), nil

	case strings.HasPrefix(q, QuestionPodStatus):
		nsName := strings.TrimSpace(strings.TrimPrefix(q, QuestionPodStatus))
		ns, name, ok := strings.Cut(nsName, "/")
		if !ok || !validation.ValidK8sNamespace(ns) || !validation.ValidK8sName(name) {
			return nil, fmt.Errorf("%w：Pod 标识非法 %q（应为 <namespace>/<name>）", ErrQuestionRejected, nsName)
		}
		pod, masked, err := a.client.GetPod(ctx, ns, name)
		if err != nil {
			return nil, err
		}
		st, _ := pod["status"].(map[string]any)
		return report("k8s.pod.status", fmt.Sprintf("Pod %s/%s 阶段 %v（已屏蔽字段 %v）",
			ns, name, st["phase"], masked)), nil

	case strings.HasPrefix(q, QuestionDeploymentList):
		ns := strings.TrimSpace(strings.TrimPrefix(q, QuestionDeploymentList))
		if !validation.ValidK8sNamespace(ns) {
			return nil, fmt.Errorf("%w：命名空间名不合法 %q", ErrQuestionRejected, ns)
		}
		deps, err := a.client.ListDeployments(ctx, ns)
		if err != nil {
			return nil, err
		}
		names := make([]string, 0, len(deps))
		for _, d := range deps {
			md, _ := d["metadata"].(map[string]any)
			names = append(names, fmt.Sprintf("%v", md["name"]))
		}
		return report("k8s.deployment.list", fmt.Sprintf("命名空间 %s 的测试标签 Deployment %d 个：%s",
			ns, len(deps), strings.Join(names, ", "))), nil
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

// report 构造只读诊断结论。
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

// stringValue 读取 map 中的字符串值。
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
