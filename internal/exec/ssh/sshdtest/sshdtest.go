// Package sshdtest 提供本地 sshd 测试容器工具（仅测试使用，D3 集成测试配套）。
//
// 约束（第八轮硬性约束）：
//   - 不连接真实服务器、不使用真实凭据：容器只绑定 127.0.0.1 的随机端口，
//     密钥对由本包临时生成，用完即弃；
//   - 容器名带 agent-ops-sshdtest- 前缀，绝不触碰其他项目的容器/端口；
//   - Docker 不可用或镜像无法拉取时 t.Skip 并输出原因——skip 不计入通过
//     （D3：不得伪造通过）。
//
// 镜像：linuxserver/openssh-server（Alpine 基础），PUBLIC_KEY 环境变量注入
// 临时公钥开启密钥认证；busybox 提供 df/free/uname/cat 等只读命令。
package sshdtest

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

// dockerImage sshd 测试容器镜像（工程默认；可被环境变量覆盖，便于离线环境）。
const dockerImageEnv = "AGENT_OPS_SSHD_TEST_IMAGE"

const defaultDockerImage = "lscr.io/linuxserver/openssh-server:latest"

// LocalSSHD 一个可用的本地 sshd 测试容器。
type LocalSSHD struct {
	// Addr host:port（127.0.0.1 随机端口）。
	Addr string
	// User 登录用户。
	User string
	// Signer 临时生成的客户端私钥（对应注入容器的公钥）。
	Signer gossh.Signer
	// HostKey 容器 sshd 主机公钥（客户端必须显式信任）。
	HostKey gossh.PublicKey
	// name 容器名（清理用）。
	name string
}

// runDocker 以 argv 形式调用 docker CLI（禁止 shell 拼接，硬性约束）。
func runDocker(args ...string) (string, error) {
	out, err := exec.Command("docker", args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// dockerAvailable Docker 是否可用；不可用时返回原因（调用方据此 skip）。
func dockerAvailable() (bool, string) {
	if _, err := exec.LookPath("docker"); err != nil {
		return false, fmt.Sprintf("docker 命令不存在：%v", err)
	}
	out, err := runDocker("info", "--format", "{{.ServerVersion}}")
	if err != nil {
		return false, fmt.Sprintf("docker daemon 不可用（%v，输出 %q）", err, out)
	}
	return true, ""
}

// StartLocalSSHD 启动本地 sshd 测试容器：
// 生成临时密钥对→注入 PUBLIC_KEY→绑定 127.0.0.1 随机端口→
// 等待 sshd 就绪→返回连接参数。失败一律 skip 并附原因（D3）。
func StartLocalSSHD(t *testing.T) *LocalSSHD {
	t.Helper()
	if ok, reason := dockerAvailable(); !ok {
		t.Skipf("集成测试 skip：%s。Docker 可用后将真跑本地 sshd 容器（D3：skip 不计入通过）。", reason)
	}

	// 临时密钥对（仅本测试运行有效，绝不使用真实凭据）。
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("生成临时密钥对失败：%v", err)
	}
	signer, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("构建签名器失败：%v", err)
	}

	image := defaultDockerImage
	if v := strings.TrimSpace(os.Getenv(dockerImageEnv)); v != "" {
		image = v
	}
	d := &LocalSSHD{
		User:   "agentops",
		Signer: signer,
		name:   fmt.Sprintf("agent-ops-sshdtest-%d", time.Now().UnixNano()),
	}

	args := []string{
		"run", "-d", "--name", d.name,
		"-e", "PUID=1000", "-e", "PGID=1000",
		"-e", "USER_NAME=" + d.User,
		"-e", "PASSWORD_ACCESS=false", // 只允许密钥认证（临时公钥）
		"-e", "PUBLIC_KEY=" + string(gossh.MarshalAuthorizedKey(signer.PublicKey())),
		"-p", "127.0.0.1::2222",
		image,
	}
	if out, err := runDocker(args...); err != nil {
		t.Skipf("集成测试 skip：无法启动 sshd 测试容器（镜像 %s 拉取或启动失败：%v，输出 %q；D3：skip 不计入通过）。", image, err, out)
	}
	t.Cleanup(func() {
		// 只清理自己启动的容器（名称前缀唯一，不触碰其他项目容器）。
		_, _ = runDocker("rm", "-f", d.name)
	})

	port := waitPort(t, d.name)
	d.Addr = net.JoinHostPort("127.0.0.1", port)
	d.HostKey = waitHostKey(t, d.name)
	waitSSHDReady(t, d)
	return d
}

// waitPort 轮询容器端口映射（最多 30s）。
func waitPort(t *testing.T, name string) string {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		out, err := runDocker("port", name, "2222/tcp")
		if err == nil && out != "" {
			// 输出形如 127.0.0.1:NNNN（或含多行）；取最后一个 host:port。
			fields := strings.Fields(out)
			for _, f := range fields {
				if strings.Contains(f, ":") {
					_, port, err := net.SplitHostPort(f)
					if err == nil && port != "" {
						return port
					}
				}
			}
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("等待容器端口映射超时（容器 %s）", name)
	return ""
}

// waitHostKey 轮询读取容器 sshd 的 ed25519 主机公钥（首次启动生成，最多 30s）。
func waitHostKey(t *testing.T, name string) gossh.PublicKey {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		out, err := runDocker("exec", name, "cat", "/etc/ssh/ssh_host_ed25519_key.pub")
		if err == nil {
			pub, _, _, _, err := gossh.ParseAuthorizedKey([]byte(out))
			if err == nil {
				return pub
			}
			lastErr = err
		} else {
			lastErr = err
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("读取 sshd 主机公钥超时（容器 %s）：%v", name, lastErr)
	return nil
}

// waitSSHDReady 用最终参数直连重试（最多 30s），确认 sshd 会话可用。
func waitSSHDReady(t *testing.T, d *LocalSSHD) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		cfg := &gossh.ClientConfig{
			User:              d.User,
			Auth:              []gossh.AuthMethod{gossh.PublicKeys(d.Signer)},
			HostKeyCallback:   gossh.FixedHostKey(d.HostKey),
			HostKeyAlgorithms: []string{d.HostKey.Type()},
			Timeout:           2 * time.Second,
		}
		c, err := gossh.Dial("tcp", d.Addr, cfg)
		if err == nil {
			_ = c.Close()
			return
		}
		lastErr = err
		time.Sleep(time.Second)
	}
	t.Fatalf("sshd 测试容器未在 30s 内就绪（%s）：%v", d.Addr, lastErr)
}
