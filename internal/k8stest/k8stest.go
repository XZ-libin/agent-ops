// Package k8stest 提供 kind 集群测试夹具（第十八轮 K1/W2）。
//
// 约束（与既有集成测试一致）：
//   - **自建自删**：集群名带 agent-ops-itest-<纳秒> 前缀，测试结束（含失败）删除；
//   - 不连接任何真实集群：只使用本地 kind 创建的临时集群；
//   - 允许用 AGENT_OPS_K8S_KUBECONFIG 复用外部集群（调试用，此时不创建/删除）；
//   - kind / kubectl 缺失时 skip 并写明原因（skip 不计入通过）；
//   - 所有外部命令以 **argv** 形式调用，禁止 shell 拼接。
//
// 本包不含任何 HTTP 调用（仓库级守卫要求出站 HTTP 只出现在白名单文件），
// 集群交互全部经 kind/kubectl 命令行完成。
package k8stest

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/XZ-libin/agent-ops/internal/testdb"
	"github.com/XZ-libin/agent-ops/internal/toolpin"
)

const (
	// ClusterPrefix 测试集群名前缀（自建自删 + 残留断言）。
	ClusterPrefix = "agent-ops-itest-"
	// NamespacePrefix 测试命名空间名前缀。
	NamespacePrefix = "agent-ops-k8stest-"
	// NodeImage kind 节点镜像（固定版本，本机已缓存）。
	NodeImage = "kindest/node:v1.31.0"
	// TestImage 测试 Pod 镜像（固定版本；kind 节点内置）。
	TestImage = "registry.k8s.io/pause:3.10"
	// testImageEnv 可用环境变量覆盖测试镜像（离线环境）。
	testImageEnv = "AGENT_OPS_K8S_TEST_IMAGE"
	// kubeconfigEnv 复用外部集群的 kubeconfig 路径。
	kubeconfigEnv = "AGENT_OPS_K8S_KUBECONFIG"
	// clusterNameEnv 复用外部集群时的集群名。
	clusterNameEnv = "AGENT_OPS_KIND_CLUSTER"
)

// ToolPath 定位命令行工具：优先 PATH，其次 ~/go/bin。
func ToolPath(t *testing.T, name string) string {
	t.Helper()
	return toolPath(name)
}

// KubectlPinned 返回**与 docs/tooling.md 登记版本一致**的 kubectl 路径（第二十五轮 T2b）。
//
// 与 ToolPath 的区别：绝不接受"顺手能找到的其他版本"。解析失败、找不到、
// 或 gitVersion 与登记不符 → t.Fatal 并给出修复方式（设 AGENT_OPS_KUBECTL_BIN
// 或把校验过的产物放到 .tools/kubectl）。
func KubectlPinned(t *testing.T) string {
	t.Helper()
	bin, version, err := toolpin.PinnedKubectl()
	if err != nil {
		t.Fatalf("kubectl 版本闸门（T2）：%v", err)
	}
	t.Logf("[T2] kubectl 已钉到登记版本 %s（%s）", version, bin)
	return bin
}

// toolPath 定位命令行工具（不需要 *testing.T，供残留检查复用）。
func toolPath(name string) string {
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
func runTool(bin string, args ...string) (string, error) {
	out, err := exec.Command(bin, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// Cluster 一个可用的测试集群（自建或外部复用）。
type Cluster struct {
	// Name 集群名。
	Name string
	// KubeconfigPath kubeconfig 文件路径。
	KubeconfigPath string
	// Owned 是否由本测试创建（true 时由本测试删除）。
	Owned bool

	kindBin    string
	kubectlBin string
	// kindEnv kind 命令的额外环境（KUBECONFIG 指向本用例私有文件）。
	//
	// 为什么必须隔离：`kind create/delete cluster` 默认读写 ~/.kube/config，
	// 并行运行的另一个 kind 用例会与之争抢 config.lock，导致删除失败
	// （第十九轮实测：nodes 已删但 kubeconfig 更新报 "failed to lock config file"）。
	// 让每个用例用私有 KUBECONFIG 即可彻底消除该竞争。
	kindEnv []string
}

// kindRun 以私有 KUBECONFIG 调用 kind（argv 形式；不使用 shell 拼接）。
func (c *Cluster) kindRun(args ...string) (string, error) {
	if c == nil {
		return "", fmt.Errorf("k8stest：cluster 为空")
	}
	return runToolEnv(c.kindBin, c.kindEnv, args...)
}

// runToolEnv 以额外环境变量调用外部工具。
func runToolEnv(bin string, extraEnv []string, args ...string) (string, error) {
	cmd := exec.Command(bin, args...)
	if len(extraEnv) > 0 {
		cmd.Env = append(os.Environ(), extraEnv...)
	}
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// Start 准备测试集群：优先复用外部 kubeconfig；否则自建 kind 集群。
//
// 自建集群在 t.Cleanup 中删除（失败也删除），并在删除后断言无残留。
func Start(t *testing.T) *Cluster {
	t.Helper()
	if p := strings.TrimSpace(os.Getenv(kubeconfigEnv)); p != "" {
		t.Logf("[k8stest] 复用外部 kubeconfig（不创建/删除集群）：%s", p)
		return &Cluster{
			Name:           strings.TrimSpace(os.Getenv(clusterNameEnv)),
			KubeconfigPath: p,
			Owned:          false,
			kindBin:        ToolPath(t, "kind"),
			kubectlBin:     KubectlPinned(t),
		}
	}
	kindBin := ToolPath(t, "kind")
	kubectlBin := KubectlPinned(t)
	if kindBin == "" {
		t.Skipf("未验证：缺少 kind（kind=%q）；Kubernetes 集成测试未执行，不计入通过。", kindBin)
		return nil
	}
	name := fmt.Sprintf("%s%d", ClusterPrefix, time.Now().UnixNano())
	dir := t.TempDir()
	// 私有 KUBECONFIG：避免与并行 kind 用例争抢 ~/.kube/config 锁。
	privateKubeconfig := filepath.Join(dir, "kubeconfig")
	c := &Cluster{
		Name: name, Owned: true, kindBin: kindBin, kubectlBin: kubectlBin,
		kindEnv: []string{"KUBECONFIG=" + privateKubeconfig},
	}
	// 先登记删除意图：失败也必须删除。
	t.Cleanup(func() { c.delete(t) })

	if out, err := c.kindRun("create", "cluster", "--name", name, "--image", NodeImage, "--wait", "180s"); err != nil {
		t.Skipf("未验证：创建 kind 集群失败（%v，输出 %q）；Kubernetes 集成测试未执行，不计入通过。", err, out)
	}
	t.Logf("[k8stest] 已创建 kind 集群：%s（image=%s，私有 KUBECONFIG=%s）", name, NodeImage, privateKubeconfig)

	c.KubeconfigPath = filepath.Join(dir, "kubeconfig-export")
	if out, err := c.kindRun("export", "kubeconfig", "--name", name, "--kubeconfig", c.KubeconfigPath); err != nil {
		t.Fatalf("[k8stest] 导出 kubeconfig 失败：%v（输出 %q）", err, out)
	}
	return c
}

// delete 删除自建集群并断言无残留（幂等）。
func (c *Cluster) delete(t *testing.T) {
	t.Helper()
	if !c.Owned {
		return
	}
	if !strings.Contains(c.clusters(t), c.Name) {
		t.Logf("[k8stest] 集群 %s 已不存在（无需删除）", c.Name)
		return
	}
	if out, err := c.kindRun("delete", "cluster", "--name", c.Name); err != nil {
		// 容错：kind 可能"节点已删但 kubeconfig 更新失败"（如外部并发操作）。
		// 以 kind get clusters 的实际结果为准判定删除是否成功。
		if rest := c.clusters(t); !strings.Contains(rest, c.Name) {
			t.Logf("[k8stest] kind delete 报错但集群已不存在（以集群列表为准视为已删除）：%v（输出 %q）",
				err, out)
			return
		}
		t.Errorf("[k8stest] 删除 kind 集群失败：%v（输出 %q）", err, out)
		return
	}
	t.Logf("[k8stest] 已删除 kind 集群：%s", c.Name)
	if rest := c.clusters(t); strings.Contains(rest, c.Name) {
		t.Errorf("[k8stest] 删除后集群仍存在：%s（现有 %q）", c.Name, rest)
	}
}

func (c *Cluster) clusters(t *testing.T) string {
	t.Helper()
	out, _ := c.kindRun("get", "clusters")
	return out
}

// Kubectl 以 argv 形式调用 kubectl（自动带 --kubeconfig）。
func (c *Cluster) Kubectl(args ...string) (string, error) {
	full := append([]string{"--kubeconfig", c.KubeconfigPath}, args...)
	return runTool(c.kubectlBin, full...)
}

// KubectlIn 在指定命名空间内调用 kubectl。
func (c *Cluster) KubectlIn(ns string, args ...string) (string, error) {
	full := append([]string{"-n", ns}, args...)
	return c.Kubectl(full...)
}

// TestImage 返回测试 Pod 镜像（可被环境变量覆盖）。
func TestImageName() string {
	if v := strings.TrimSpace(os.Getenv(testImageEnv)); v != "" {
		return v
	}
	return TestImage
}

// CreatePodFixture 创建带测试标签的测试命名空间、Pod 与 Deployment。
//
//   - Pod 带一个会被屏蔽的环境变量与一个会被屏蔽的注解——用于断言结果中
//     不出现 env 值与注解原值（K1 ④，与第十三轮白名单一致）；
//   - Deployment 用 replicas=0：对象存在可被列出，但不额外产生 Pod。
//
// 命名空间在 t.Cleanup 中删除。
func (c *Cluster) CreatePodFixture(t *testing.T, ns, podName string) {
	t.Helper()
	image := TestImageName()
	// pause 镜像自带常驻入口，无需 command；其他镜像需显式长驻命令。
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
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: %s-deploy
  namespace: %s
  labels:
    agent-ops.test: "true"
spec:
  replicas: 0
  selector:
    matchLabels:
      app: %s-deploy
  template:
    metadata:
      labels:
        app: %s-deploy
    spec:
      containers:
        - name: itest
          image: %s%s
`, ns, podName, ns, image, commandLine, podName, ns, podName, podName, image, commandLine)

	path := filepath.Join(t.TempDir(), "fixture.yaml")
	if err := os.WriteFile(path, []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := c.Kubectl("apply", "-f", path); err != nil {
		t.Skipf("未验证：无法创建测试命名空间/Pod/Deployment（%v，输出 %q）；集成测试未执行，不计入通过。", err, out)
	}
	t.Logf("[k8stest] 已创建测试命名空间 %s、Pod %s/%s 与 Deployment %s/%s-deploy（image=%s）",
		ns, ns, podName, ns, podName, image)

	t.Cleanup(func() { c.DeleteNamespace(t, ns) })
}

// WaitPodRunning 等待 Pod 进入 Running（最多 120s）。
func (c *Cluster) WaitPodRunning(t *testing.T, ns, podName string) {
	t.Helper()
	deadline := time.Now().Add(120 * time.Second)
	for {
		out, err := c.KubectlIn(ns, "get", "pod", podName, "-o", "jsonpath={.status.phase}")
		if err == nil && out == "Running" {
			t.Logf("[k8stest] Pod %s/%s 已 Running", ns, podName)
			return
		}
		if time.Now().After(deadline) {
			desc, _ := c.KubectlIn(ns, "describe", "pod", podName)
			t.Fatalf("测试 Pod 未在 120 秒内就绪（phase=%q err=%v）：%s", out, err, tailLines(desc, 12))
		}
		time.Sleep(2 * time.Second)
	}
}

// DeleteNamespace 删除测试命名空间（幂等；集群已删除时容忍连接失败）。
func (c *Cluster) DeleteNamespace(t *testing.T, ns string) {
	t.Helper()
	out, err := c.Kubectl("delete", "namespace", ns, "--wait=true", "--timeout=120s")
	if err == nil || strings.Contains(out, "NotFound") || strings.Contains(out, "refused") ||
		strings.Contains(out, "no such host") || strings.Contains(out, "EOF") {
		return
	}
	t.Errorf("[k8stest] 删除测试命名空间失败：%v（输出 %q）", err, out)
}

// AssertClusterDeleted 断言**指定集群**已不存在（用于用例内的自建自删核对）。
//
// 注意：不要在此断言"所有 agent-ops-itest-* 集群都不存在"——`go test ./...`
// 会并行运行不同包，别的包可能正在使用自己的集群。全局残留检查由
// TestNoLeftoversAfterSuite（需显式开启）在全部用例结束后单独执行。
func AssertClusterDeleted(t *testing.T, name string) {
	t.Helper()
	kindBin := ToolPath(t, "kind")
	if kindBin == "" {
		t.Skip("未验证：缺少 kind，无法执行集群删除核对。")
	}
	out, err := runTool(kindBin, "get", "clusters")
	if err != nil {
		t.Skipf("未验证：kind get clusters 失败（%v）。", err)
	}
	if strings.Contains(out, name) {
		t.Errorf("自建集群未被删除：%s（现有 %q）", name, out)
		return
	}
	t.Logf("[k8stest] 自建集群已删除：%s（现有 %q）", name, out)
}

// ResidualCheckEnv 设为 "1" 时，才执行**全局残留检查**（见 residual_test.go）。
// 常量单一来源在 testdb（T3 的保留开关要认同一个环境变量）。
// 全局检查必须在全部用例结束后单独运行（`go test ./...` 的并行包会让它误报）。
const ResidualCheckEnv = testdb.ResidualCheckEnv

// tailLines 取文本末尾 n 行（失败信息用）。
func tailLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}
