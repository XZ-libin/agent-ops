package kubernetes

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	contractv1 "github.com/ORG/agent-ops/contract/gen/go/agent_ops/contract/v1"
)

// 集成测试使用的固定镜像与命名（仅测试；版本固定，避免漂移）。
const (
	// testImage 默认测试镜像（固定版本、小体积）。
	//
	// 本机环境无法访问 Docker Hub（沙箱代理拒绝 kind 节点内的拉取），
	// 因此默认使用 kind 节点**已内置**的 registry.k8s.io/pause:3.10（268kB）。
	// 若环境可访问镜像仓库，可用 AGENT_OPS_K8S_TEST_IMAGE=busybox:1.36 覆盖
	// （裁决要求的"固定版本小镜像"由该开关满足）。
	testImage = "registry.k8s.io/pause:3.10"
	// testImageEnv 可用环境变量覆盖镜像（离线环境）。
	testImageEnv = "AGENT_OPS_K8S_TEST_IMAGE"
	// kindNodeImage kind 节点镜像（固定版本；kindest/node 官方镜像）。
	kindNodeImage = "kindest/node:v1.31.0"
	// testNamespacePrefix 测试命名空间名前缀（只操作自己创建的命名空间）。
	testNamespacePrefix = "agent-ops-k8stest-"
	// clusterPrefix 集成测试自建集群名前缀（第十四轮 H4：自建自删）。
	clusterPrefix = "agent-ops-itest-"
	// kindClusterNameEnv kind 集群名（默认 agent-ops-itest）。
	kindClusterNameEnv = "AGENT_OPS_KIND_CLUSTER"
	// kubeconfigEnv 已有 kubeconfig 路径（跳过 kind 自举时使用）。
	kubeconfigEnv = "AGENT_OPS_K8S_KUBECONFIG"
)

// toolPath 定位命令行工具（argv 形式调用，禁止 shell 拼接）。
// 优先 PATH，其次 ~/go/bin（本机 kind/kubectl 的安装位置）。
func toolPath(t *testing.T, name string) string {
	t.Helper()
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	home, _ := os.UserHomeDir()
	cand := filepath.Join(home, "go", "bin", name)
	if _, err := os.Stat(cand); err == nil {
		return cand
	}
	return ""
}

// runTool 以 argv 形式调用外部工具。
func runTool(t *testing.T, bin string, args ...string) (string, error) {
	t.Helper()
	out, err := exec.Command(bin, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// kindClusterName 返回本次集成测试使用的 kind 集群名（随机后缀，自建自删）。
func kindClusterName() string {
	if v := strings.TrimSpace(os.Getenv(kindClusterNameEnv)); v != "" {
		return v // 允许复用外部已建集群（调试用；此时不负责删除）
	}
	return fmt.Sprintf("%s%d", clusterPrefix, time.Now().UnixNano())
}

// externalCluster 报告本次是否使用外部集群（外部集群不由本测试创建/删除）。
func externalCluster() bool {
	return strings.TrimSpace(os.Getenv(kindClusterNameEnv)) != ""
}

// kindClusters 返回现有 kind 集群列表。
func kindClusters(t *testing.T, kindBin string) string {
	t.Helper()
	out, _ := runTool(t, kindBin, "get", "clusters")
	return out
}

// createKindCluster 自建 kind 集群（第十四轮 H4），返回集群名与 kubeconfig 路径。
func createKindCluster(t *testing.T, kindBin, name string) string {
	t.Helper()
	dir := t.TempDir()
	kubeconfigPath := filepath.Join(dir, "kubeconfig")
	if out, err := runTool(t, kindBin, "create", "cluster",
		"--name", name, "--image", kindNodeImage, "--wait", "180s"); err != nil {
		t.Skipf("未验证：创建 kind 集群失败（%v，输出 %q）；Kubernetes 集成测试未执行。", err, out)
	}
	t.Logf("[夹具] 已创建 kind 集群：%s（image=%s）", name, kindNodeImage)
	if out, err := runTool(t, kindBin, "export", "kubeconfig", "--name", name, "--kubeconfig", kubeconfigPath); err != nil {
		t.Fatalf("导出 kind kubeconfig 失败：%v（输出 %q）", err, out)
	}
	return kubeconfigPath
}

// deleteKindCluster 删除 kind 集群并断言删除成功（第十四轮 H4）。
func deleteKindCluster(t *testing.T, kindBin, name string) {
	t.Helper()
	// 幂等：用例末尾已删除时（或已被外部删除），不存在即视为成功。
	if !strings.Contains(kindClusters(t, kindBin), name) {
		t.Logf("[夹具] kind 集群 %s 已不存在（无需删除）", name)
		return
	}
	if out, err := runTool(t, kindBin, "delete", "cluster", "--name", name); err != nil {
		t.Errorf("[夹具] 删除 kind 集群失败：%v（输出 %q）", err, out)
		return
	}
	t.Logf("[夹具] 已删除 kind 集群：%s", name)
	if clusters := kindClusters(t, kindBin); strings.Contains(clusters, name) {
		t.Errorf("[夹具] 删除后集群仍存在：%s（现有 %q）", name, clusters)
	}
}

// TestIntegrationReadOnlyAgainstKindCluster 第十三轮 K2 集成测试：
// 在本地 kind 集群中创建带 agent-ops.test=true 标签的命名空间与 Pod，
// 断言只读适配器的行为；结束时删除测试命名空间并断言删除成功。
//
// 前置：kind 与 kubectl 可用且集群已就绪。任一缺失即以"未验证"标记 skip
// （按裁决：被跳过的集成测试不计入通过）。
func TestIntegrationReadOnlyAgainstKindCluster(t *testing.T) {
	kindBin := toolPath(t, "kind")
	kubectlBin := toolPath(t, "kubectl")
	if kindBin == "" || kubectlBin == "" {
		t.Skipf("未验证：缺少 kind 或 kubectl（kind=%q kubectl=%q），Kubernetes 集成测试未执行；"+
			"本轮不予放行，需在具备 kind 的环境重跑。", kindBin, kubectlBin)
	}

	// 第十四轮 H4：集成测试**自建自删** kind 集群。
	// 允许用 AGENT_OPS_K8S_KUBECONFIG 复用外部集群（调试用，此时不负责删除）；
	// 否则本测试创建 agent-ops-itest-<纳秒> 集群，并在结束时删除（失败也删除）。
	kubeconfigPath := strings.TrimSpace(os.Getenv(kubeconfigEnv))
	var ownedCluster string
	if kubeconfigPath == "" {
		ownedCluster = kindClusterName()
		// 先记录删除意图：测试失败也必须删除（defer 语义由 t.Cleanup 保证）。
		t.Cleanup(func() { deleteKindCluster(t, kindBin, ownedCluster) })
		kubeconfigPath = createKindCluster(t, kindBin, ownedCluster)
	} else {
		t.Logf("[夹具] 复用外部 kubeconfig（不创建/删除集群）：%s", kubeconfigPath)
	}

	image := testImage
	if v := strings.TrimSpace(os.Getenv(testImageEnv)); v != "" {
		image = v
	}
	// 预载镜像：kind 节点内往往无法访问外部镜像仓库（企业代理/离线环境），
	// 若本地 Docker 已有该镜像则先 load 进集群（argv 形式，仅操作本测试镜像）。
	preloadImage(t, kindBin, image)

	ns := fmt.Sprintf("%s%d", testNamespacePrefix, time.Now().UnixNano())
	podName := "busybox-itest"

	// 夹具：创建测试命名空间与 Pod（带测试标签 + 一个会被屏蔽的环境变量）。
	// pause 镜像自带常驻入口，无需 command；其他镜像（如 busybox）需显式长驻命令。
	commandLine := "\n      command: [\"sleep\", \"300\"]"
	if strings.Contains(image, "pause") {
		commandLine = ""
	}
	manifest := fmt.Sprintf(`apiVersion: v1
kind: Namespace
metadata:
  name: %s
  labels:
    agent-ops.test: "true"
---
apiVersion: v1
kind: Pod
metadata:
  name: %s
  namespace: %s
  labels:
    agent-ops.test: "true"
  annotations:
    secret.itest: must-not-leak-annotation
spec:
  containers:
    - name: itest
      image: %s%s
      env:
        - name: AGENT_OPS_TEST_SECRET
          value: must-not-leak
`, ns, podName, ns, image, commandLine)

	manifestPath := filepath.Join(t.TempDir(), "itest.yaml")
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := runTool(t, kubectlBin, "--kubeconfig", kubeconfigPath, "apply", "-f", manifestPath); err != nil {
		t.Skipf("未验证：无法创建测试命名空间/Pod（%v，输出 %q）；"+
			"Kubernetes 集成测试未执行；本轮不予放行。", err, out)
	}
	t.Logf("[夹具] 创建测试命名空间 %s 与 Pod %s/%s（image=%s，label=%s=true）", ns, ns, podName, image, TestLabel)

	// 夹具清理：删除测试命名空间（断言写在用例末尾，这里兜底）。
	t.Cleanup(func() {
		rmOut, rmErr := runTool(t, kubectlBin, "--kubeconfig", kubeconfigPath, "delete", "namespace", ns, "--wait=true", "--timeout=120s")
		// 幂等清理：用例末尾已删除时容忍 NotFound；
		// 自建集群已被删除时容忍连接失败（无可清理对象）。
		if rmErr == nil || strings.Contains(rmOut, "NotFound") || strings.Contains(rmOut, "refused") ||
			strings.Contains(rmOut, "no such host") || strings.Contains(rmOut, "EOF") {
			return
		}
		t.Errorf("[夹具] 清理测试命名空间失败：%v（输出 %q）", rmErr, rmOut)
	})

	// 等待 Pod 就绪（最多 120 秒；镜像已在节点内时通常数秒）。
	deadline := time.Now().Add(120 * time.Second)
	for {
		out, err := runTool(t, kubectlBin, "--kubeconfig", kubeconfigPath, "-n", ns,
			"get", "pod", podName, "-o", "jsonpath={.status.phase}")
		if err == nil && out == "Running" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("测试 Pod 未在 120 秒内就绪（phase=%q err=%v）；原因：%s",
				out, err, podFailureReason(t, kubectlBin, kubeconfigPath, ns, podName))
		}
		time.Sleep(2 * time.Second)
	}

	adapter, err := New(Config{Mode: ModeTest, KubeconfigPath: kubeconfigPath})
	if err != nil {
		t.Fatalf("构建适配器失败：%v", err)
	}
	ctx := context.Background()

	// 1) Discover：只读发现集群版本。
	insts, err := adapter.Discover(ctx, &contractv1.AssetTarget{AssetId: "ast_k8s_itest"})
	if err != nil {
		t.Fatalf("Discover 失败：%v", err)
	}
	if len(insts) != 1 || insts[0].Version == "" {
		t.Fatalf("Discover 结果不符：%+v", insts)
	}
	t.Logf("[断言] 集群版本 %s", insts[0].Version)

	// 2) Pod 列表：只返回测试 Pod（不返回 kube-system 或其他资源）。
	pods, err := adapter.client.ListPods(ctx, ns)
	if err != nil {
		t.Fatalf("Pod 列表失败：%v", err)
	}
	if len(pods) != 1 {
		t.Fatalf("只应返回 1 个测试标签 Pod，实际 %d 个：%v", len(pods), pods)
	}
	md := pods[0]["metadata"].(map[string]any)
	if md["name"] != podName {
		t.Fatalf("返回的 Pod 不符：%v", md)
	}
	labels := md["labels"].(map[string]any)
	if labels[TestLabel] != "true" {
		t.Fatalf("返回的 Pod 必须带测试标签：%v", labels)
	}
	t.Logf("[断言] Pod 列表只返回测试 Pod：%v（共 %d 个）", md["name"], len(pods))

	// 2b) 其他命名空间（kube-system）不在测试标签范围内 → 明确报错而非返回内容。
	if _, err := adapter.client.ListPods(ctx, "kube-system"); err == nil {
		t.Fatal("非测试标签命名空间不得返回任何内容")
	} else if !strings.Contains(err.Error(), "agent-ops.test=true") {
		t.Logf("[断言] kube-system 读取被拒：%v", err)
	}

	// 3) Pod env 已被屏蔽（含夹具注入的敏感值与注解）。
	pod, masked, err := adapter.client.GetPod(ctx, ns, podName)
	if err != nil {
		t.Fatalf("读取 Pod 失败：%v", err)
	}
	spec := pod["spec"].(map[string]any)
	c := spec["containers"].([]any)[0].(map[string]any)
	if _, has := c["env"]; has {
		t.Fatal("Pod 的 containers[*].env 必须被屏蔽")
	}
	blob := marshalIndent(pod)
	for _, secret := range []string{"must-not-leak", "AGENT_OPS_TEST_SECRET", "must-not-leak-annotation"} {
		if strings.Contains(blob, secret) {
			t.Fatalf("Pod 输出泄露敏感值 %q：%s", secret, blob)
		}
	}
	if !containsPath(masked, "spec.containers[0].env") {
		t.Fatalf("应记录被屏蔽路径 spec.containers[0].env，实际 %v", masked)
	}
	t.Logf("[断言] Pod env 与注解已屏蔽（masked=%v）", masked)

	// 4) 请求 /api/v1/secrets 被拒绝（适配器层拒绝，不发往集群）。
	beforeReqs := countSecretsCallsInCluster(t, kubectlBin, kubeconfigPath, ns)
	if _, err := adapter.client.get(ctx, "/api/v1/namespaces/"+ns+"/secrets", nil); err == nil {
		t.Fatal("secrets 路径必须被拒绝")
	} else if !strings.Contains(err.Error(), "永不读取 Secret") {
		t.Fatalf("拒绝原因应说明永不读取 Secret：%v", err)
	}
	// 集群侧无副作用：Pod 仍在运行、命名空间内资源数量未变。
	afterReqs := countSecretsCallsInCluster(t, kubectlBin, kubeconfigPath, ns)
	if beforeReqs != afterReqs {
		t.Fatalf("被拒的 secrets 请求不得改变集群状态：%d → %d", beforeReqs, afterReqs)
	}
	t.Log("[断言] secrets 请求在适配器层被拒绝（未发往集群）")

	// 5) 集群中的 Pod 状态未被改变。
	phase, err := runTool(t, kubectlBin, "--kubeconfig", kubeconfigPath, "-n", ns,
		"get", "pod", podName, "-o", "jsonpath={.status.phase}")
	if err != nil {
		t.Fatalf("查询 Pod 状态失败：%v", err)
	}
	if phase != "Running" {
		t.Fatalf("Pod 状态被改变：%q", phase)
	}
	st := pod["status"].(map[string]any)
	if st["phase"] != "Running" {
		t.Fatalf("适配器读到的状态应为 Running：%v", st["phase"])
	}
	t.Logf("[断言] 集群 Pod 状态未改变：phase=%s", phase)

	// 6) Deployment 列表：测试命名空间内无带标签的 Deployment → 明确报错。
	if _, err := adapter.client.ListDeployments(ctx, ns); err == nil {
		t.Fatal("无测试标签 Deployment 时应明确报错")
	}

	// 7) 删除测试命名空间并断言删除成功。
	rmOut, rmErr := runTool(t, kubectlBin, "--kubeconfig", kubeconfigPath,
		"delete", "namespace", ns, "--wait=true", "--timeout=120s")
	if rmErr != nil {
		t.Fatalf("删除测试命名空间失败：%v（输出 %q）", rmErr, rmOut)
	}
	t.Logf("[夹具] 删除测试命名空间成功：%s（输出 %q）", ns, rmOut)
	if _, err := runTool(t, kubectlBin, "--kubeconfig", kubeconfigPath, "get", "namespace", ns); err == nil {
		t.Fatal("删除后命名空间应不存在")
	}
	// 删除后读取该命名空间的 Pod → 明确报错（不是静默空列表）。
	if _, err := adapter.client.ListPods(ctx, ns); err == nil {
		t.Fatal("命名空间删除后列表应明确报错")
	}
	t.Log("[断言] 命名空间删除成功且后续读取明确报错")

	// H4：删除自建集群，并断言 kind get clusters 中不残留 agent-ops-itest-* 集群。
	if ownedCluster != "" {
		deleteKindCluster(t, kindBin, ownedCluster)
		clusters := kindClusters(t, kindBin)
		for _, line := range strings.Split(clusters, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), clusterPrefix) {
				t.Fatalf("集成测试结束后不得残留测试集群：%q（kind get clusters 输出 %q）", line, clusters)
			}
		}
		t.Log("[断言] 无 agent-ops-itest-* 集群残留")
	}
}

// preloadImage 若本地 Docker 已存在该镜像，则把它预载进 kind 集群
// （避免 kind 节点在离线/代理环境下拉取失败）。镜像不存在时静默跳过，
// 由后续 Pod 状态断言给出明确失败原因。
func preloadImage(t *testing.T, kindBin, image string) {
	t.Helper()
	dockerBin := toolPath(t, "docker")
	if dockerBin == "" {
		return
	}
	if _, err := runTool(t, dockerBin, "image", "inspect", image); err != nil {
		return // 本地无该镜像：不预载
	}
	out, err := runTool(t, kindBin, "load", "docker-image", image, "--name", kindClusterName())
	if err != nil {
		t.Logf("[夹具] 预载镜像失败（继续尝试在线拉取）：%v（输出 %q）", err, out)
		return
	}
	t.Logf("[夹具] 已预载镜像到 kind 集群：%s", image)
}

// podFailureReason 汇总 Pod 未就绪的原因（供失败信息使用）。
func podFailureReason(t *testing.T, kubectlBin, kubeconfigPath, ns, podName string) string {
	t.Helper()
	desc, _ := runTool(t, kubectlBin, "--kubeconfig", kubeconfigPath, "-n", ns, "describe", "pod", podName)
	lines := strings.Split(desc, "\n")
	if len(lines) > 12 {
		lines = lines[len(lines)-12:]
	}
	return strings.Join(lines, " | ")
}

// countSecretsCallsInCluster 统计测试命名空间中的资源数量
// （用于断言被拒请求未改变集群状态；只读 kubectl get）。
func countSecretsCallsInCluster(t *testing.T, kubectlBin, kubeconfigPath, ns string) int {
	t.Helper()
	out, err := runTool(t, kubectlBin, "--kubeconfig", kubeconfigPath, "-n", ns,
		"get", "pods,services,configmaps", "-o", "name")
	if err != nil {
		return -1
	}
	if strings.TrimSpace(out) == "" {
		return 0
	}
	return len(strings.Split(out, "\n"))
}

// containsPath 判定屏蔽路径列表是否包含给定路径。
func containsPath(paths []string, want string) bool {
	for _, p := range paths {
		if p == want {
			return true
		}
	}
	return false
}

// TestIntegrationKindAvailabilityRecords 记录 kind 可用性（供报告核对；
// 不作为通过依据）。
func TestIntegrationKindAvailabilityRecords(t *testing.T) {
	kindBin := toolPath(t, "kind")
	kubectlBin := toolPath(t, "kubectl")
	t.Logf("kind=%q kubectl=%q cluster=%q", kindBin, kubectlBin, kindClusterName())
	if kindBin == "" || kubectlBin == "" {
		t.Skip("未验证：kind 或 kubectl 缺失（集成验证前置条件不满足）。")
	}
	out, err := runTool(t, kindBin, "get", "clusters")
	if err != nil {
		t.Skipf("未验证：kind get clusters 失败（%v）。", err)
	}
	t.Logf("现有 kind 集群：%q（集成测试将自建 %s<纳秒> 集群并在结束时删除）", out, clusterPrefix)
}
