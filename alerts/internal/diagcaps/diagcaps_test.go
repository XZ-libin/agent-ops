package diagcaps

import (
	"context"
	"strings"
	"testing"

	"github.com/ORG/agent-ops/alerts/internal/executor"
)

// TestFromEnvReadsAllVars 环境读取（含 kubeconfig 与命名空间）。
func TestFromEnvReadsAllVars(t *testing.T) {
	env := map[string]string{
		EnvAssetID:        "ast_env",
		EnvSSHAddr:        "127.0.0.1:2222",
		EnvSSHUser:        "agentops",
		EnvSSHKey:         "/tmp/k",
		EnvSSHHostKey:     "/tmp/hk",
		EnvDockerEndpoint: "unix:///var/run/docker.sock",
		EnvKubeconfig:     "/tmp/kc",
		EnvK8sNamespace:   "ns-1",
	}
	cfg := FromEnv(func(k string) string { return env[k] })
	if cfg.AssetID != "ast_env" || cfg.SSHAddr != "127.0.0.1:2222" || cfg.DockerEndpoint == "" ||
		cfg.KubeconfigPath != "/tmp/kc" || cfg.K8sNamespace != "ns-1" {
		t.Fatalf("环境读取不符：%+v", cfg)
	}
	t.Logf("[断言] 环境变量全部读入：kubeconfig=%q namespace=%q", cfg.KubeconfigPath, cfg.K8sNamespace)
}

// TestBuildWithoutClusterMarksRequiresCluster 未配置 kubeconfig 时：
// k8s 能力仍注册（以便执行器记为 no_cluster_configured）且标记 RequiresCluster，
// ClusterConfigured 为 false。
func TestBuildWithoutClusterMarksRequiresCluster(t *testing.T) {
	res, err := Build(Config{AssetID: "ast-x"})
	if err != nil {
		t.Fatal(err)
	}
	if res.ClusterConfigured {
		t.Fatal("未配置 kubeconfig 时 ClusterConfigured 必须为 false")
	}
	for _, name := range []string{"k8s.version", "k8s.pod.list", "k8s.deployment.list"} {
		entry, ok := res.Caps[name]
		if !ok {
			t.Fatalf("k8s 能力 %s 必须注册（否则会被记为 denied 而不是 no_cluster_configured）", name)
		}
		if !entry.RequiresCluster {
			t.Fatalf("k8s 能力 %s 必须标记 RequiresCluster", name)
		}
		// Run 不得静默成功。
		if _, err := entry.Run(context.Background(), executor.Request{Capability: name}); err == nil {
			t.Fatalf("配置缺失时 %s 的 Run 必须报错", name)
		}
	}
	t.Log("[断言] 未配置集群：k8s 能力注册 + RequiresCluster=true + Run 明确报错")
}

// TestBuildPartialSSHConfigFails 部分 SSH 配置 → fail-closed。
func TestBuildPartialSSHConfigFails(t *testing.T) {
	if _, err := Build(Config{SSHAddr: "127.0.0.1:2222"}); err == nil {
		t.Fatal("只给 SSH 地址（缺用户/密钥/主机公钥）必须报错")
	} else if !strings.Contains(err.Error(), "SSH 配置不完整") {
		t.Fatalf("错误应说明 SSH 配置不完整：%v", err)
	}
	t.Log("[断言] SSH 部分配置 → Build 报错（fail-closed）")
}

// TestBuildKubeconfigWithoutNamespaceFails 给了 kubeconfig 但缺命名空间 → 报错。
func TestBuildKubeconfigWithoutNamespaceFails(t *testing.T) {
	if _, err := Build(Config{KubeconfigPath: "/tmp/does-not-matter"}); err == nil {
		t.Fatal("配置 kubeconfig 但缺命名空间必须报错")
	} else if !strings.Contains(err.Error(), EnvK8sNamespace) {
		t.Fatalf("错误应指出缺少 %s：%v", EnvK8sNamespace, err)
	}
	t.Log("[断言] kubeconfig 已配置但缺命名空间 → Build 报错")
}

// TestBuildWithoutDockerEndpointMarksUnavailable 未配置 Docker 端点时
// docker 能力被标记为不可用（调用即报错，不静默成功）。
func TestBuildWithoutDockerEndpointMarksUnavailable(t *testing.T) {
	res, err := Build(Config{AssetID: "ast-x"})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"docker.version", "docker.info", "docker.container.list"} {
		entry, ok := res.Caps[name]
		if !ok {
			t.Fatalf("docker 能力 %s 必须注册", name)
		}
		if entry.RequiresCluster {
			t.Fatalf("docker 能力 %s 不应标记 RequiresCluster", name)
		}
		if _, err := entry.Run(context.Background(), executor.Request{Capability: name}); err == nil {
			t.Fatalf("未配置端点时 %s 的 Run 必须报错（不得静默成功）", name)
		}
	}
	t.Log("[断言] 未配置 Docker 端点：docker 能力注册但 Run 明确报错")
}

// TestBuildWithDockerEndpointRegistersAdapter 配置了端点时 docker 能力可构建
// （不实际调用守护进程，只校验接线成功且能力项存在）。
func TestBuildWithDockerEndpointRegistersAdapter(t *testing.T) {
	res, err := Build(Config{AssetID: "ast-x", DockerEndpoint: "unix:///var/run/docker.sock"})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"docker.version", "docker.info", "docker.container.list"} {
		if _, ok := res.Caps[name]; !ok {
			t.Fatalf("docker 能力 %s 必须注册", name)
		}
	}
	t.Log("[断言] 配置 Docker 端点后能力接线成功")
}

// TestLinuxCapabilitiesRegistered linux 能力始终注册（未配置 SSH 时标记不可用）。
func TestLinuxCapabilitiesRegistered(t *testing.T) {
	res, err := Build(Config{AssetID: "ast-x"})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"diagnose.disk_usage", "diagnose.memory_pressure", "diagnose.load_average"} {
		if _, ok := res.Caps[name]; !ok {
			t.Fatalf("linux 能力 %s 必须注册", name)
		}
	}
	t.Log("[断言] linux 三条只读能力均已注册")
}
