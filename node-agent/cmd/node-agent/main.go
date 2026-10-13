// Command node-agent 是 Agent Ops 的节点代理入口（第二十二轮 N7）。
//
// 本轮**只做注册与心跳**，不接收任何命令：
//   - `-mode` 必填（test / prod）；**`-mode=prod` 直接拒绝启动**
//     （生产身份与证书来源未实现）；
//   - 注册令牌来自环境变量 `NODE_ENROLL_TOKEN_FILE` 指向的文件，
//     **文件权限必须为 0600**（组与其他用户不得有任何权限）；
//   - 引导信任（D4）：只信任 `-ca-file` 指定的 CA，并校验 `-server-name`；
//     **令牌只在服务端证书校验通过之后才发送**（Dial 强制完成 TLS 握手）；
//   - 证书只保存在内存中（**不落盘**）：重启需要重新注册（见 TODO）；
//   - SIGINT / SIGTERM → 优雅停机：停止心跳、关闭连接，不留半完成的注册。
//
// 本模块**不 import net/http**（仓库级守卫 TestNodeAgentModuleAvoidsHTTP 断言）；
// 与控制面之间使用 gRPC（不触发出站 HTTP 守卫）。
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	contractv1 "github.com/XZ-libin/agent-ops/contract/gen/go/agent_ops/contract/v1"
	"github.com/XZ-libin/agent-ops/internal/nodeidentity"
	"github.com/XZ-libin/agent-ops/node-agent/internal/agent"
	"github.com/XZ-libin/agent-ops/node-agent/internal/enrollclient"
	"github.com/XZ-libin/agent-ops/node-agent/internal/identity"
)

// version 节点代理版本（随构建注入或默认值）。
const version = "0.22.0-dev"

// DefaultServerName 默认期望的服务端名称（须与测试 CA 签发证书的 SAN 匹配）。
const DefaultServerName = "127.0.0.1"

func main() {
	addr := flag.String("addr", "127.0.0.1:9443", "控制面 gRPC 地址（host:port）")
	mode := flag.String("mode", "", "运行模式：test / prod（必填；prod 本轮拒绝启动）")
	serverName := flag.String("server-name", DefaultServerName,
		"期望的控制面服务端名称（必须与其证书 SAN 匹配）")
	caFile := flag.String("ca-file", "", "信任的 CA 证书（PEM）路径；只信任该 CA，不信任系统根证书")
	label := flag.String("display-label", "", "节点展示标签（仅用于展示，不参与身份）")
	interval := flag.Duration("interval", 10*time.Second, "心跳间隔")
	stateDir := flag.String("state-dir", "", "身份持久化目录（权限 0700、文件 0600；T2）")
	keepToken := flag.Bool("keep-token-file", false,
		"注册成功后**保留**令牌文件（默认删除：令牌是一次性的，保留无意义且增加泄露面）")
	flag.Parse()

	if err := run(*addr, *mode, *serverName, *caFile, *label, *interval, *stateDir, *keepToken); err != nil {
		log.Fatalf("node-agent 启动失败：%v", err)
	}
}

// run 装配并运行节点代理。
func run(addr, mode, serverName, caFile, label string, interval time.Duration,
	stateDir string, keepToken bool) error {
	// 1. 模式（必填；prod 拒绝）。
	m, err := agent.ParseMode(mode)
	if err != nil {
		return err
	}
	log.Printf("node-agent %s 启动中（mode=%s, addr=%s, server-name=%s）", version, m, addr, serverName)

	// 2. 注册令牌：环境变量指定文件 + 权限必须 0600。
	//
	// T2：若 state 目录里已有**有效身份**，则根本不需要令牌——此时缺失令牌文件
	// 不应阻止启动（重启复用场景）。因此这里把"缺令牌"延迟到确实需要注册时再报错：
	// 先探测身份是否可复用，只有需要注册时才强制要求令牌。
	tokenPath := strings.TrimSpace(os.Getenv(agent.EnvTokenFile))
	token, tokenErr := agent.ReadTokenFile(tokenPath)
	if tokenErr != nil && !errors.Is(tokenErr, agent.ErrTokenFileRequired) {
		// 权限过宽 / 文件损坏：**直接拒绝**（这类错误说明有人在乱动凭据）。
		return tokenErr
	}
	needsEnroll := tokenErr != nil
	if needsEnroll {
		if !identityUsable(stateDir) {
			return tokenErr // 无可用身份且无令牌 → 拒绝启动
		}
		token = "" // 复用路径不消耗令牌
	}

	// 3. 引导信任：CA 包（只信任它）与期望的服务端名称。
	if strings.TrimSpace(caFile) == "" {
		return fmt.Errorf("node-agent：必须通过 -ca-file 指定信任的 CA 证书（不信任系统根证书）")
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return fmt.Errorf("node-agent：读取 CA 证书失败：%w", err)
	}
	if len(caPEM) == 0 {
		return fmt.Errorf("node-agent：CA 证书文件为空")
	}

	// 4. 节点私钥（仅内存，不落盘）。
	nodeKey, err := nodeidentity.NewNodeKey(nil)
	if err != nil {
		return err
	}

	// 5. 建立 mTLS 连接（握手失败即返回；令牌不会离开本进程）。
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	client, err := enrollclient.Dial(ctx, enrollclient.Config{
		ServerAddr:   addr,
		ServerName:   serverName,
		CABundlePEM:  caPEM,
		NodeKey:      nodeKey,
		DisplayLabel: label,
		AgentVersion: version,
	})
	if err != nil {
		return err
	}

	// 6. 运行：复用身份或注册一次 + 心跳循环（直到 ctx 取消）。
	runner, err := agent.NewRunner(agent.Config{
		Mode:         m,
		Token:        token,
		DisplayLabel: label,
		AgentVersion: version,
		Interval:     interval,
		Load:         loadSummary(),
		// T2：身份持久化 + CA 校验持久化身份 + 注册后尽力删除令牌文件。
		StateDir:          stateDir,
		CABundlePEM:       caPEM,
		TokenFileToRemove: tokenPath,
		RemoveToken:       !keepToken,
	}, client)
	if err != nil {
		_ = client.Close()
		return err
	}

	runErr := runner.Run(ctx)
	log.Printf("node-agent 已停机（node_id=%s, 注册=%d 次, 心跳=%d 次, stopped=%v）",
		runner.NodeID(), runner.EnrollCount(), runner.HeartbeatCount(), runner.Stopped())
	return runErr
}

// identityUsable 探测 state 目录中是否已有可用身份（复用路径判定）。
//
// 只做"是否存在且能通过基本校验"的判断；详细校验与拒绝逻辑在 agent.Runner 内，
// 以便错误信息集中、可测。
func identityUsable(stateDir string) bool {
	if strings.TrimSpace(stateDir) == "" {
		return false
	}
	st, err := identity.New(stateDir, "")
	if err != nil {
		return false
	}
	// 用进程启动时刻与"无 CA 约束"快速探测（真正的 CA/身份校验在 Runner 内）。
	_, lerr := st.Load(time.Now(), nil, "")
	return lerr == nil
}

// loadSummary 采集负载摘要（**只有 CPU 核数与内存总量**，不含进程列表）。
func loadSummary() *contractv1.NodeLoadSummary {
	return &contractv1.NodeLoadSummary{
		CpuCores:         int32(runtime.NumCPU()),
		MemoryTotalBytes: int64(memoryTotalBytes()),
	}
}
