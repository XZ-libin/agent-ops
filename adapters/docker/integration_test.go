package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	contractv1 "github.com/ORG/agent-ops/contract/gen/go/agent_ops/contract/v1"
)

// 集成测试使用的固定镜像与容器名（仅测试；版本固定，避免漂移）。
const (
	// testImage 固定版本的小镜像（busybox）。
	testImage = "busybox:1.36"
	// testImageEnv 可用环境变量覆盖镜像（离线环境）。
	testImageEnv = "AGENT_OPS_DOCKER_TEST_IMAGE"
	// testContainerPrefix 测试容器名前缀（只操作自己创建的容器）。
	testContainerPrefix = "agent-ops-dockertest-"
)

// dockerBinary 定位 docker CLI（仅测试夹具使用：创建/删除测试容器；
// 适配器代码本身只发白名单 GET，见 client.go 与 TestSourceContainsNoWriteMethods）。
func dockerBinary(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("docker")
	if err != nil {
		t.Skipf("集成测试 skip：docker 命令不可用（%v）。Docker 可用后将真跑只读适配器集成测试。", err)
	}
	return path
}

// runDocker 以 argv 形式调用 docker CLI（禁止 shell 拼接）。
func runDocker(t *testing.T, args ...string) (string, error) {
	t.Helper()
	out, err := exec.Command(dockerBinary(t), args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// dockerEndpoint 返回适配器使用的连接方式：优先 DOCKER_HOST，否则 unix socket。
func dockerEndpoint(t *testing.T) string {
	t.Helper()
	if host := strings.TrimSpace(os.Getenv("DOCKER_HOST")); host != "" {
		return host
	}
	for _, sock := range []string{
		"/var/run/docker.sock",
		os.Getenv("HOME") + "/.docker/run/docker.sock",
	} {
		if _, err := os.Stat(sock); err == nil {
			return "unix://" + sock
		}
	}
	t.Skip("集成测试 skip：未找到 Docker 守护进程 socket（设置 DOCKER_HOST 或启动 Docker Desktop）。")
	return ""
}

// TestIntegrationReadOnlyAgainstLocalDaemon 第十二轮 D2 集成测试：
// 在本地 Docker 上创建一个带 agent-ops.test=true 标签的测试容器，
// 断言只读适配器的行为；结束时删除测试容器并断言删除成功。
//
// 安全边界：只创建/删除自己创建的测试容器（名称前缀唯一）；
// 本机其他项目的容器一律不读取、不列出（列表经标签过滤，且逐项复核）。
func TestIntegrationReadOnlyAgainstLocalDaemon(t *testing.T) {
	endpoint := dockerEndpoint(t)
	image := testImage
	if v := strings.TrimSpace(os.Getenv(testImageEnv)); v != "" {
		image = v
	}
	name := fmt.Sprintf("%s%d", testContainerPrefix, time.Now().UnixNano())

	// 夹具：启动测试容器（固定镜像 + 测试标签 + 一个会被屏蔽的环境变量）。
	out, err := runDocker(t,
		"run", "-d", "--name", name,
		"--label", TestLabel+"=true",
		"-e", "AGENT_OPS_TEST_SECRET=must-not-leak",
		image, "sleep", "300")
	if err != nil {
		t.Skipf("集成测试 skip：无法启动测试容器（镜像 %s 拉取或启动失败：%v，输出 %q）。", image, err, out)
	}
	t.Logf("[夹具] 创建测试容器：name=%s image=%s label=%s=true（容器 ID %s）", name, image, TestLabel, out)

	// 夹具清理：删除测试容器并断言删除成功（断言写在用例末尾，这里兜底）。
	t.Cleanup(func() {
		rmOut, rmErr := runDocker(t, "rm", "-f", name)
		if rmErr != nil {
			t.Errorf("[夹具] 清理测试容器失败：%v（输出 %q）", rmErr, rmOut)
		}
	})

	adapter, err := New(Config{Endpoint: endpoint, Mode: ModeTest})
	if err != nil {
		t.Fatalf("构建适配器失败：%v", err)
	}
	ctx := context.Background()

	// 1) Discover：只读发现守护进程版本。
	insts, err := adapter.Discover(ctx, &contractv1.AssetTarget{AssetId: "ast_docker_itest"})
	if err != nil {
		t.Fatalf("Discover 失败：%v", err)
	}
	if len(insts) != 1 || insts[0].Version == "" {
		t.Fatalf("Discover 结果不符：%+v", insts)
	}

	// 2) 容器列表：只返回该测试容器（不返回其他任何容器）。
	items, err := adapter.client.ListContainers(ctx)
	if err != nil {
		t.Fatalf("容器列表失败：%v", err)
	}
	if len(items) != 1 {
		t.Fatalf("只应返回 1 个测试标签容器，实际 %d 个：%v", len(items), items)
	}
	gotID, _ := items[0]["Id"].(string)
	if gotID == "" {
		t.Fatalf("列表项缺少容器 ID：%v", items[0])
	}
	// 逐项复核标签（不依赖守护进程过滤）。
	labels, _ := items[0]["Labels"].(map[string]any)
	if labels[TestLabel] != "true" {
		t.Fatalf("返回的容器必须带测试标签：%v", items[0])
	}
	// 断言返回的容器就是本次创建的（名字前缀唯一）。
	if !containerNameMatches(t, name, gotID) {
		t.Fatalf("返回的容器不是本次创建的测试容器：id=%s name=%s", gotID, name)
	}
	t.Logf("[断言] 容器列表只返回测试容器：id=%s（共 1 个）", gotID)

	// 3) inspect：Env 被屏蔽（含夹具注入的敏感值）。
	detail, masked, err := adapter.client.InspectContainer(ctx, gotID)
	if err != nil {
		t.Fatalf("inspect 失败：%v", err)
	}
	cfg, _ := detail["Config"].(map[string]any)
	if _, has := cfg["Env"]; has {
		t.Fatal("inspect 结果不得包含 Config.Env")
	}
	blob := marshalIndent(detail)
	if strings.Contains(blob, "must-not-leak") || strings.Contains(blob, "AGENT_OPS_TEST_SECRET") {
		t.Fatalf("inspect 结果泄露环境变量：%s", blob)
	}
	if !containsPath(masked, "Config.Env") {
		t.Fatalf("应记录被屏蔽路径 Config.Env，实际 %v", masked)
	}
	t.Logf("[断言] Env 已屏蔽（masked_fields=%v）", masked)

	// 4) 写方法被拒绝：/containers/create 与 /containers/{id}/start 均被白名单拒绝。
	if err := AllowedEndpoint("POST", "/containers/create"); err == nil {
		t.Fatal("/containers/create 必须被拒绝")
	}
	if err := AllowedEndpoint("POST", "/containers/"+gotID+"/start"); err == nil {
		t.Fatal("/containers/{id}/start 必须被拒绝")
	}
	if _, err := adapter.client.get(ctx, "/containers/create", nil); err == nil {
		t.Fatal("客户端不得对 /containers/create 发起请求")
	}
	if _, err := adapter.client.get(ctx, "/containers/"+gotID+"/start", nil); err == nil {
		t.Fatal("客户端不得对 /containers/{id}/start 发起请求")
	}

	// 5) 守护进程状态未改变：容器仍运行、启动时间未变、数量仍为 1。
	after, _, err := adapter.client.InspectContainer(ctx, gotID)
	if err != nil {
		t.Fatalf("再次 inspect 失败：%v", err)
	}
	beforeState, _ := detail["State"].(map[string]any)
	afterState, _ := after["State"].(map[string]any)
	if beforeState["Running"] != afterState["Running"] || beforeState["StartedAt"] != afterState["StartedAt"] {
		t.Fatalf("被拒的写请求改变了容器状态：before=%v after=%v", beforeState, afterState)
	}
	if afterState["Running"] != true {
		t.Fatalf("测试容器应仍在运行：%v", afterState)
	}
	itemsAfter, err := adapter.client.ListContainers(ctx)
	if err != nil {
		t.Fatalf("复检列表失败：%v", err)
	}
	if len(itemsAfter) != 1 {
		t.Fatalf("被拒的写请求不得创建新容器：%d", len(itemsAfter))
	}
	t.Log("[断言] 写请求被拒且守护进程状态未改变")

	// 6) 通过适配器接口（Diagnose）复核状态能力可用。
	diag, err := adapter.Diagnose(ctx, insts[0], QuestionContainerStatusPrefix+gotID)
	if err != nil {
		t.Fatalf("Diagnose 状态失败：%v", err)
	}
	if !strings.Contains(diag.Conclusion, "running") {
		t.Fatalf("状态结论不符：%s", diag.Conclusion)
	}

	// 7) 删除测试容器并断言删除成功。
	rmOut, rmErr := runDocker(t, "rm", "-f", name)
	if rmErr != nil {
		t.Fatalf("删除测试容器失败：%v（输出 %q）", rmErr, rmOut)
	}
	t.Logf("[夹具] 删除测试容器成功：name=%s（输出 %q）", name, rmOut)
	// 断言容器已不存在（对指定容器 ID 的 inspect 返回错误）。
	if _, inspectErr := runDocker(t, "inspect", "--format", "{{.Id}}", gotID); inspectErr == nil {
		t.Fatal("删除后容器应不存在")
	}
	// 删除后列表应为空 → 明确报错（而非静默返回空列表）。
	if _, err := adapter.client.ListContainers(ctx); err == nil {
		t.Fatal("删除测试容器后列表应为空并明确报错")
	} else if !strings.Contains(err.Error(), "agent-ops.test=true") {
		t.Fatalf("空列表错误应说明标签过滤语义：%v", err)
	}
	t.Log("[断言] 删除成功且空列表明确报错")
}

// containerNameMatches 判定容器 ID 对应的名字是否为期望的测试容器名。
func containerNameMatches(t *testing.T, wantName, id string) bool {
	t.Helper()
	out, err := runDocker(t, "inspect", "--format", "{{.Name}}", id)
	if err != nil {
		t.Fatalf("查询容器名失败：%v（输出 %q）", err, out)
	}
	return strings.TrimPrefix(out, "/") == wantName
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

// TestIntegrationEmptyListErrorIsExplicit 空列表语义的集成侧复核（Docker 不可用时 skip）：
// 在没有任何测试标签容器时，列表必须明确报错而不是静默返回空。
func TestIntegrationEmptyListErrorIsExplicit(t *testing.T) {
	endpoint := dockerEndpoint(t)
	adapter, err := New(Config{Endpoint: endpoint, Mode: ModeTest})
	if err != nil {
		t.Fatalf("构建适配器失败：%v", err)
	}
	items, err := adapter.client.ListContainers(context.Background())
	if err == nil {
		// 环境中存在测试标签容器（例如并行运行的其他用例）：跳过本用例，不算失败。
		t.Skipf("skip：当前存在 %d 个测试标签容器，无法验证空列表报错语义。", len(items))
	}
	if !strings.Contains(err.Error(), "agent-ops.test=true") {
		t.Fatalf("空列表必须明确报错并说明标签语义：%v", err)
	}
}

// TestIntegrationJSONShape 记录 inspect 结果的 JSON 形状（调试辅助，Docker 不可用时 skip）。
func TestIntegrationJSONShape(t *testing.T) {
	endpoint := dockerEndpoint(t)
	adapter, err := New(Config{Endpoint: endpoint, Mode: ModeTest})
	if err != nil {
		t.Fatalf("构建适配器失败：%v", err)
	}
	ver, err := adapter.client.Version(context.Background())
	if err != nil {
		t.Skipf("skip：无法读取守护进程版本（%v）。", err)
	}
	b, _ := json.Marshal(ver)
	if len(b) == 0 {
		t.Fatal("版本信息不应为空")
	}
}
