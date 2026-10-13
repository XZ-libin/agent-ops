// Package diagcaps 把只读诊断能力（linux / docker / kubernetes）接线为执行器的
// 能力注册表（第十八轮 K1/W1）。
//
// 设计要点：
//   - 这是**唯一**的生产接线路径：cmd/alerts 的 worker 与集成测试都走本包，
//     避免"生产一套、测试一套"；
//   - 只注册**只读**能力（tier=read_only、destructive=false、test_only=false）；
//   - kubernetes 能力标记 RequiresCluster：未配置 kubeconfig 时由执行器记为
//     no_cluster_configured，本包的 Run 不会被调用；
//   - 任何"部分配置"（例如给了 SSH 地址却没给密钥）一律在 Build 阶段报错
//     （fail-closed），不进入运行期。
package diagcaps

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	gossh "golang.org/x/crypto/ssh"

	"github.com/ORG/agent-ops/adapters/docker"
	"github.com/ORG/agent-ops/adapters/kubernetes"
	"github.com/ORG/agent-ops/adapters/linux"
	"github.com/ORG/agent-ops/alerts/internal/executor"
	contractv1 "github.com/ORG/agent-ops/contract/gen/go/agent_ops/contract/v1"
	"github.com/ORG/agent-ops/internal/exec"
	"github.com/ORG/agent-ops/internal/exec/ssh"
)

// 环境变量名（仅测试模式使用；生产接线待运维确认）。
const (
	// EnvAssetID 诊断目标资产 ID。
	EnvAssetID = "AGENT_OPS_DIAG_ASSET_ID"
	// EnvSSHAddr linux 目标主机 host:port。
	EnvSSHAddr = "AGENT_OPS_DIAG_SSH_ADDR"
	// EnvSSHUser linux 目标主机登录用户。
	EnvSSHUser = "AGENT_OPS_DIAG_SSH_USER"
	// EnvSSHKey linux 客户端私钥文件路径（OpenSSH/PEM）。
	EnvSSHKey = "AGENT_OPS_DIAG_SSH_KEY"
	// EnvSSHHostKey 目标主机公钥文件路径（authorized_keys 单行格式）。
	EnvSSHHostKey = "AGENT_OPS_DIAG_SSH_HOST_KEY"
	// EnvDockerEndpoint Docker 守护进程地址（unix:// 或 tcp://）。
	EnvDockerEndpoint = "AGENT_OPS_DIAG_DOCKER_ENDPOINT"
	// EnvKubeconfig kubernetes kubeconfig 路径；未配置即 no_cluster_configured。
	EnvKubeconfig = "AGENT_OPS_K8S_KUBECONFIG"
	// EnvK8sNamespace kubernetes 只读查询的命名空间（测试标签对象所在）。
	EnvK8sNamespace = "AGENT_OPS_K8S_NAMESPACE"
)

// Config 接线配置。
type Config struct {
	// AssetID 诊断目标资产 ID（写入适配器调用参数）。
	AssetID string
	// SSHRunner linux 能力的执行器；为 nil 时按下面的文件路径构建。
	SSHRunner exec.Runner
	// SSHAddr / SSHUser / SSHKeyPath / SSHHostKeyPath 见环境变量说明。
	SSHAddr        string
	SSHUser        string
	SSHKeyPath     string
	SSHHostKeyPath string
	// DockerEndpoint Docker 守护进程地址。
	DockerEndpoint string
	// KubeconfigPath kubeconfig 路径（空 = 未配置集群）。
	KubeconfigPath string
	// K8sNamespace kubernetes 查询命名空间。
	K8sNamespace string
	// K8sObserve kubernetes 请求观测钩子（第十八轮 K1）：每次**真正发出** HTTP
	// 请求前回调 (method, path)。生产留空；测试用于断言 /secrets 请求数为 0。
	K8sObserve func(method, path string)
}

// Result 接线结果。
type Result struct {
	// Caps 能力注册表（能力名 → 注册项）。
	Caps map[string]executor.CapEntry
	// ClusterConfigured 是否配置了集群（KubeconfigPath 非空）。
	ClusterConfigured bool
	// Close 释放接线占用的资源（SSH 连接等）；可为 nil。
	Close func()
}

// FromEnv 从环境读取接线配置（未做完整性校验；Build 负责校验）。
func FromEnv(getenv func(string) string) Config {
	return Config{
		AssetID:        strings.TrimSpace(getenv(EnvAssetID)),
		SSHAddr:        strings.TrimSpace(getenv(EnvSSHAddr)),
		SSHUser:        strings.TrimSpace(getenv(EnvSSHUser)),
		SSHKeyPath:     strings.TrimSpace(getenv(EnvSSHKey)),
		SSHHostKeyPath: strings.TrimSpace(getenv(EnvSSHHostKey)),
		DockerEndpoint: strings.TrimSpace(getenv(EnvDockerEndpoint)),
		KubeconfigPath: strings.TrimSpace(getenv(EnvKubeconfig)),
		K8sNamespace:   strings.TrimSpace(getenv(EnvK8sNamespace)),
	}
}

// readOnlyDecl 只读能力声明（与适配器清单一致）。
func readOnlyDecl(name string) *contractv1.Capability {
	return &contractv1.Capability{
		Name: name, RiskTier: contractv1.RiskTier_RISK_TIER_READ_ONLY,
		Idempotent: true, Rollbackable: false, Destructive: false,
	}
}

// unavailable 构造一个"配置缺失"能力项：被调用即报错（绝不放行、绝不静默成功）。
func unavailable(name, reason string) executor.CapEntry {
	return executor.CapEntry{Decl: readOnlyDecl(name),
		Run: func(context.Context, executor.Request) (executor.Report, error) {
			return executor.Report{}, fmt.Errorf("能力 %s 不可用：%s", name, reason)
		}}
}

// Build 构建能力注册表。任一"部分配置"即报错（fail-closed）。
func Build(cfg Config) (*Result, error) {
	out := &Result{Caps: map[string]executor.CapEntry{}}
	var closers []func()
	closeAll := func() {
		for i := len(closers) - 1; i >= 0; i-- {
			closers[i]()
		}
	}

	// —— linux（prometheus / node-exporter 画像）——
	if err := addLinux(out, cfg, &closers); err != nil {
		closeAll()
		return nil, err
	}
	// —— docker（docker-monitor 画像）——
	if err := addDocker(out, cfg); err != nil {
		closeAll()
		return nil, err
	}
	// —— kubernetes（alertmanager 画像）——
	if err := addKubernetes(out, cfg); err != nil {
		closeAll()
		return nil, err
	}

	out.ClusterConfigured = cfg.KubeconfigPath != ""
	if len(closers) > 0 {
		out.Close = closeAll
	}
	return out, nil
}

// linuxQuestions linux 只读问题（能力名 → 适配器问题）。
var linuxQuestions = map[string]string{
	"diagnose.disk_usage":      linux.QuestionDiskUsage,
	"diagnose.memory_pressure": linux.QuestionMemoryPressure,
	"diagnose.load_average":    linux.QuestionLoadAverage,
}

func addLinux(out *Result, cfg Config, closers *[]func()) error {
	runner := cfg.SSHRunner
	if runner == nil {
		anySet := cfg.SSHAddr != "" || cfg.SSHUser != "" || cfg.SSHKeyPath != "" || cfg.SSHHostKeyPath != ""
		if !anySet {
			for name := range linuxQuestions {
				out.Caps[name] = unavailable(name, "未配置 SSH 目标（AGENT_OPS_DIAG_SSH_*）")
			}
			return nil
		}
		if cfg.SSHAddr == "" || cfg.SSHUser == "" || cfg.SSHKeyPath == "" || cfg.SSHHostKeyPath == "" {
			return errors.New("diagcaps：SSH 配置不完整（Addr/User/Key/HostKey 必须全部提供）")
		}
		signer, err := loadSigner(cfg.SSHKeyPath)
		if err != nil {
			return fmt.Errorf("diagcaps：读取 SSH 私钥失败：%w", err)
		}
		hostKey, err := loadHostKey(cfg.SSHHostKeyPath)
		if err != nil {
			return fmt.Errorf("diagcaps：读取 SSH 主机公钥失败：%w", err)
		}
		r, err := ssh.New(ssh.Options{Addr: cfg.SSHAddr, User: cfg.SSHUser, Signer: signer, HostKey: hostKey})
		if err != nil {
			return fmt.Errorf("diagcaps：构建 SSH Runner 失败：%w", err)
		}
		runner = r
		*closers = append(*closers, func() { _ = r.Close() })
	}
	adapter, err := linux.New(runner)
	if err != nil {
		return fmt.Errorf("diagcaps：构建 linux 适配器失败：%w", err)
	}
	assetID := cfg.AssetID
	if assetID == "" {
		assetID = "diag-target"
	}
	for name, q := range linuxQuestions {
		name, q := name, q
		out.Caps[name] = executor.CapEntry{Decl: readOnlyDecl(name),
			Run: func(ctx context.Context, _ executor.Request) (executor.Report, error) {
				insts, derr := adapter.Discover(ctx, &contractv1.AssetTarget{AssetId: assetID})
				if derr != nil {
					return executor.Report{}, derr
				}
				diag, derr := adapter.Diagnose(ctx, insts[0], q)
				if derr != nil {
					return executor.Report{}, derr
				}
				return executor.Report{Conclusion: diag.Conclusion, Success: true}, nil
			}}
	}
	return nil
}

// dockerQuestions docker 只读问题。
var dockerQuestions = map[string]string{
	"docker.version":        docker.QuestionVersion,
	"docker.info":           docker.QuestionInfo,
	"docker.container.list": docker.QuestionContainerList,
}

func addDocker(out *Result, cfg Config) error {
	if cfg.DockerEndpoint == "" {
		for name := range dockerQuestions {
			out.Caps[name] = unavailable(name, "未配置 Docker 端点（AGENT_OPS_DIAG_DOCKER_ENDPOINT）")
		}
		return nil
	}
	adapter, err := docker.New(docker.Config{Endpoint: cfg.DockerEndpoint, Mode: docker.ModeTest})
	if err != nil {
		return fmt.Errorf("diagcaps：构建 docker 适配器失败：%w", err)
	}
	for name, q := range dockerQuestions {
		name, q := name, q
		out.Caps[name] = executor.CapEntry{Decl: readOnlyDecl(name),
			Run: func(ctx context.Context, _ executor.Request) (executor.Report, error) {
				diag, derr := adapter.Diagnose(ctx, nil, q)
				if derr != nil {
					return executor.Report{}, derr
				}
				return executor.Report{Conclusion: diag.Conclusion, Success: true}, nil
			}}
	}
	return nil
}

func addKubernetes(out *Result, cfg Config) error {
	names := []string{"k8s.version", "k8s.namespace.get", "k8s.pod.list", "k8s.pod.status", "k8s.deployment.list"}
	// 未配置集群：全部标记 RequiresCluster（执行器记为 no_cluster_configured，
	// Run 不会被调用）。
	if cfg.KubeconfigPath == "" {
		for _, name := range names {
			entry := unavailable(name, "未配置集群（"+EnvKubeconfig+" 未设置）")
			entry.RequiresCluster = true
			out.Caps[name] = entry
		}
		return nil
	}
	if cfg.K8sNamespace == "" {
		return errors.New("diagcaps：已配置 kubeconfig 但缺少 " + EnvK8sNamespace + "（kubernetes 只读查询需要命名空间）")
	}
	adapter, err := kubernetes.New(kubernetes.Config{
		Mode: kubernetes.ModeTest, KubeconfigPath: cfg.KubeconfigPath, Observe: cfg.K8sObserve,
	})
	if err != nil {
		return fmt.Errorf("diagcaps：构建 kubernetes 适配器失败：%w", err)
	}
	ns := cfg.K8sNamespace
	questions := map[string]string{
		"k8s.version":         kubernetes.QuestionVersion,
		"k8s.namespace.get":   kubernetes.QuestionNamespaceGet + ns,
		"k8s.pod.list":        kubernetes.QuestionPodList + ns,
		"k8s.deployment.list": kubernetes.QuestionDeploymentList + ns,
	}
	for name, q := range questions {
		name, q := name, q
		out.Caps[name] = executor.CapEntry{Decl: readOnlyDecl(name), RequiresCluster: true,
			Run: func(ctx context.Context, _ executor.Request) (executor.Report, error) {
				diag, derr := adapter.Diagnose(ctx, nil, q)
				if derr != nil {
					return executor.Report{}, derr
				}
				return executor.Report{Conclusion: diag.Conclusion, Success: true}, nil
			}}
	}
	// k8s.pod.status 需要具体 Pod 名：列出测试标签 Pod 后取第一个（真实只读路径）。
	out.Caps["k8s.pod.status"] = executor.CapEntry{Decl: readOnlyDecl("k8s.pod.status"), RequiresCluster: true,
		Run: func(ctx context.Context, _ executor.Request) (executor.Report, error) {
			pods, derr := listPods(ctx, adapter, ns)
			if derr != nil {
				return executor.Report{}, derr
			}
			if len(pods) == 0 {
				return executor.Report{}, errors.New("kubernetes：命名空间 " + ns + " 内没有带测试标签的 Pod")
			}
			diag, derr := adapter.Diagnose(ctx, nil, kubernetes.QuestionPodStatus+pods[0])
			if derr != nil {
				return executor.Report{}, derr
			}
			return executor.Report{Conclusion: diag.Conclusion, Success: true}, nil
		}}
	return nil
}

// listPods 复用适配器的 pod 列表能力并解析出 Pod 名（不额外发请求路径）。
func listPods(ctx context.Context, adapter *kubernetes.Adapter, ns string) ([]string, error) {
	diag, err := adapter.Diagnose(ctx, nil, kubernetes.QuestionPodList+ns)
	if err != nil {
		return nil, err
	}
	// 结论形如："命名空间 ns 的测试标签 Pod 2 个：pod-a(Running), pod-b(Pending)"
	c := diag.Conclusion
	idx := strings.Index(c, "：")
	if idx < 0 {
		return nil, nil
	}
	var names []string
	for _, part := range strings.Split(c[idx+len("："):], ", ") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if i := strings.Index(part, "("); i > 0 {
			part = part[:i]
		}
		names = append(names, part)
	}
	return names, nil
}

// loadSigner 读取 OpenSSH/PEM 私钥文件。
func loadSigner(path string) (gossh.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return gossh.ParsePrivateKey(data)
}

// loadHostKey 读取 authorized_keys 单行格式的主机公钥文件。
func loadHostKey(path string) (gossh.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pub, _, _, _, err := gossh.ParseAuthorizedKey(data)
	return pub, err
}
