package ssh

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/XZ-libin/agent-ops/internal/exec"
)

// —— 内嵌 SSH 测试服务器（不依赖外部 sshd / Docker）——
// 选型理由之一：x/crypto/ssh 允许在进程内起服务器，超时/截断行为可确定性验证。

// testServer 记录 onExec 调用次数；exec 指令按命令字符串分派到 handler。
type testServer struct {
	mu      sync.Mutex
	execCnt int
}

func newTestServer() *testServer { return &testServer{} }

// handleSession 处理一个 session：应答 exec 请求→写输出→回 exit-status。
func (ts *testServer) handleSession(requests <-chan *gossh.Request, ch gossh.Channel,
	onExec func(cmd string, out io.Writer) uint32) {
	defer ch.Close()
	for req := range requests {
		switch req.Type {
		case "exec":
			if len(req.Payload) < 4 {
				_ = req.Reply(false, nil)
				return
			}
			cmd := string(req.Payload[4:])
			ts.mu.Lock()
			ts.execCnt++
			ts.mu.Unlock()
			if err := req.Reply(true, nil); err != nil {
				return
			}
			code := onExec(cmd, ch)
			_, _ = ch.SendRequest("exit-status", false,
				gossh.Marshal(struct{ Status uint32 }{Status: uint32(code)}))
			return
		case "env":
			_ = req.Reply(true, nil)
		default:
			_ = req.Reply(false, nil)
		}
	}
}

// startTestSSHD 启动内嵌服务器，返回地址、主机公钥与 exec 计数器（execCount）。
func startTestSSHD(t *testing.T, onExec func(cmd string, out io.Writer) uint32) (string, gossh.PublicKey, func() int) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := gossh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &gossh.ServerConfig{
		PasswordCallback: func(meta gossh.ConnMetadata, password []byte) (*gossh.Permissions, error) {
			if string(password) == "test-password" {
				return nil, nil
			}
			return nil, fmt.Errorf("密码错误")
		},
	}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	ts := newTestServer()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, chans, reqs, err := gossh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				go gossh.DiscardRequests(reqs)
				for newCh := range chans {
					if newCh.ChannelType() != "session" {
						_ = newCh.Reject(gossh.UnknownChannelType, "只支持 session")
						continue
					}
					ch, requests, err := newCh.Accept()
					if err != nil {
						continue
					}
					go ts.handleSession(requests, ch, onExec)
				}
			}(c)
		}
	}()

	execCount := func() int {
		ts.mu.Lock()
		defer ts.mu.Unlock()
		return ts.execCnt
	}
	return ln.Addr().String(), signer.PublicKey(), execCount
}

// newTestRunner 以测试密码、固定主机公钥构建 Runner。
func newTestRunner(t *testing.T, addr string, hostKey gossh.PublicKey) *Runner {
	t.Helper()
	r, err := New(Options{Addr: addr, User: "tester", Password: "test-password", HostKey: hostKey})
	if err != nil {
		t.Fatalf("构建 Runner 失败：%v", err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

// TestEchoAndExitCode 基本执行：stdout 透传、成功与失败退出码。
func TestEchoAndExitCode(t *testing.T) {
	addr, hostKey, _ := startTestSSHD(t, func(cmd string, out io.Writer) uint32 {
		switch cmd {
		case "echo hello":
			_, _ = io.WriteString(out, "hello\n")
			return 0
		case "fail":
			_, _ = io.WriteString(out, "boom")
			return 7
		}
		return 127
	})
	r := newTestRunner(t, addr, hostKey)

	res, err := r.Run(context.Background(), []string{"echo", "hello"}, exec.RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if string(res.Stdout) != "hello\n" || res.ExitCode != 0 {
		t.Fatalf("stdout=%q exit=%d，期望 hello/0", res.Stdout, res.ExitCode)
	}

	res, err = r.Run(context.Background(), []string{"fail"}, exec.RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 7 || string(res.Stdout) != "boom" {
		t.Fatalf("exit=%d stdout=%q，期望 7/boom", res.ExitCode, res.Stdout)
	}
}

// TestTimeoutInterrupts 超时（RunOptions.Timeout）：命令被中断、置 TimedOut 且耗时受限。
func TestTimeoutInterrupts(t *testing.T) {
	addr, hostKey, _ := startTestSSHD(t, func(cmd string, out io.Writer) uint32 {
		if cmd == "slow" {
			time.Sleep(5 * time.Second)
			return 0
		}
		return 0
	})
	r := newTestRunner(t, addr, hostKey)

	start := time.Now()
	res, err := r.Run(context.Background(), []string{"slow"}, exec.RunOptions{Timeout: 300 * time.Millisecond})
	if err == nil {
		t.Fatal("超时场景应返回错误")
	}
	if !res.TimedOut {
		t.Fatal("应置 TimedOut 标记")
	}
	if res.ExitCode != -1 {
		t.Fatalf("超时中断 ExitCode 应为 -1，got %d", res.ExitCode)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("超时中断耗时过长：%v", elapsed)
	}
}

// TestContextDeadlineInterrupts 上下文截止时间同样中断执行。
func TestContextDeadlineInterrupts(t *testing.T) {
	addr, hostKey, _ := startTestSSHD(t, func(cmd string, out io.Writer) uint32 {
		if cmd == "slow" {
			time.Sleep(5 * time.Second)
		}
		return 0
	})
	r := newTestRunner(t, addr, hostKey)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	res, err := r.Run(ctx, []string{"slow"}, exec.RunOptions{})
	if err == nil || !res.TimedOut {
		t.Fatalf("ctx 截止应中断并置 TimedOut：res=%+v err=%v", res, err)
	}
}

// TestOutputTruncation 输出超过 64KB 被截断并置标记，命令仍正常结束（退出码 0）。
func TestOutputTruncation(t *testing.T) {
	big := make([]byte, 128*1024)
	for i := range big {
		big[i] = 'a'
	}
	addr, hostKey, _ := startTestSSHD(t, func(cmd string, out io.Writer) uint32 {
		if cmd == "big" {
			// 一次性写 128KB；客户端缓冲上限 64KB。
			_, _ = out.Write(big)
			return 0
		}
		return 0
	})
	r := newTestRunner(t, addr, hostKey)

	res, err := r.Run(context.Background(), []string{"big"}, exec.RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Stdout) != exec.MaxOutputBytes {
		t.Fatalf("stdout 应截断到 %d，实际 %d", exec.MaxOutputBytes, len(res.Stdout))
	}
	if !res.StdoutTruncated {
		t.Fatal("应置 stdout 截断标记")
	}
	if res.ExitCode != 0 {
		t.Fatalf("输出截断不应影响命令正常结束，exit=%d", res.ExitCode)
	}
}

// TestExactFitNotTruncated 恰好等于上限的输出不算截断。
func TestExactFitNotTruncated(t *testing.T) {
	exact := make([]byte, exec.MaxOutputBytes)
	addr, hostKey, _ := startTestSSHD(t, func(cmd string, out io.Writer) uint32 {
		if cmd == "exact" {
			_, _ = out.Write(exact)
		}
		return 0
	})
	r := newTestRunner(t, addr, hostKey)

	res, err := r.Run(context.Background(), []string{"exact"}, exec.RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Stdout) != exec.MaxOutputBytes || res.StdoutTruncated {
		t.Fatalf("恰好写满上限不应截断：len=%d truncated=%v", len(res.Stdout), res.StdoutTruncated)
	}
}

// TestUnsafeTokenRejectedBeforeExec 含 shell 语义的 argv 元素在连接后、执行前被拒绝：
// exec 计数必须为 0（不得到达远端执行层）。
func TestUnsafeTokenRejectedBeforeExec(t *testing.T) {
	addr, hostKey, execCount := startTestSSHD(t, func(cmd string, out io.Writer) uint32 {
		return 0
	})
	r := newTestRunner(t, addr, hostKey)

	_, err := r.Run(context.Background(),
		[]string{"cat", "/etc/passwd;rm -rf /"}, exec.RunOptions{})
	if err == nil {
		t.Fatal("危险 token 应被拒绝")
	}
	if n := execCount(); n != 0 {
		t.Fatalf("危险参数不得抵达远端执行层：exec 计数=%d", n)
	}
}

// TestEmptyArgvRejected 空 argv 直接拒绝。
func TestEmptyArgvRejected(t *testing.T) {
	addr, hostKey, _ := startTestSSHD(t, func(string, io.Writer) uint32 { return 0 })
	r := newTestRunner(t, addr, hostKey)
	if _, err := r.Run(context.Background(), nil, exec.RunOptions{}); err == nil {
		t.Fatal("空 argv 应被拒绝")
	}
}

// mustPub 任意合法公钥（仅用于配置类失败用例）。
func mustPub(t *testing.T) gossh.PublicKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := gossh.NewPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// TestNewFailsClosed 缺主机校验/缺认证必须拒绝（安全默认）。
func TestNewFailsClosed(t *testing.T) {
	cases := []struct {
		name string
		opts Options
	}{
		{"no-host-key", Options{Addr: "127.0.0.1:1", User: "u", Password: "p"}},
		{"no-auth", Options{Addr: "127.0.0.1:1", User: "u", HostKey: mustPub(t)}},
		{"no-addr", Options{User: "u", Password: "p", HostKey: mustPub(t)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.opts); err == nil {
				t.Fatal("应拒绝不完整配置")
			}
		})
	}
}

// TestPasswordNeverInError 认证失败的错误信息不得包含密码。
func TestPasswordNeverInError(t *testing.T) {
	addr, hostKey, _ := startTestSSHD(t, func(string, io.Writer) uint32 { return 0 })
	// 服务端拒绝密码 "wrong-password"。
	_, err := New(Options{Addr: addr, User: "tester", Password: "sup3r-s3cret-pass", HostKey: hostKey})
	if err == nil {
		t.Fatal("错误密码应连接失败")
	}
	if strings.Contains(err.Error(), "sup3r-s3cret-pass") {
		t.Fatalf("错误信息泄露密码：%v", err)
	}
}
