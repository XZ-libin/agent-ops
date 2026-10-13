// Package ssh 是 exec.Runner 的 SSH 传输实现（第七轮遗留决策 D1 / ADR-008）。
//
// 选型：基于 golang.org/x/crypto/ssh，而不是调用 ssh 命令。理由：
//  1. 单测可启动内嵌 SSH 服务器（ssh.NewServerConn），超时/截断行为无需外部
//     sshd 进程即可确定性验证；
//  2. 命令经 argv 传入后仅做与 OpenSSH 客户端相同的空格连接（session.Start），
//     不组装任何 shell 字符串；每个 argv 元素预先通过 validation.ValidShellToken
//     白名单把关（fail-closed），防止连接串被远端 shell 重新解释；
//  3. 超时在进程内完成：超时直接关闭会话通道，远端命令随之终止，
//     不依赖对本地 ssh 子进程的 kill；
//  4. 不依赖目标环境/宿主机存在 ssh 客户端二进制；
//  5. x/crypto 为官方维护库，与项目其余 golang.org/x 依赖一致。
//
// 安全默认（fail-closed）：
//   - 必须显式配置主机校验（HostKey 或 HostKeyCallback），不提供"跳过校验"选项；
//   - 必须显式配置认证（Password 或 Signer）；凭据只保存在本结构内，
//     绝不写入日志、错误与审计。
package ssh

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/XZ-libin/agent-ops/internal/exec"
	"github.com/XZ-libin/agent-ops/internal/validation"
)

// defaultDialTimeout 建立 SSH 连接的默认超时 10s（工程默认，待运维确认）。
const defaultDialTimeout = 10 * time.Second

// Options 构建 Runner 的参数。
type Options struct {
	// Addr host:port（目标主机地址）。
	Addr string
	// User 登录用户。
	User string
	// Password 密码认证（与 Signer 二选一，优先 Password）。
	// 注意：凭据只用于握手，不进入日志与错误信息。
	Password string
	// Signer 私钥认证（与 Password 二选一）。
	Signer gossh.Signer
	// HostKey 信任的服务器主机公钥（如 ssh-rsa/ed25519 公钥），优先于 HostKeyCallback。
	HostKey gossh.PublicKey
	// HostKeyCallback 高级场景的自定义主机校验回调；未配置 HostKey 时使用。
	HostKeyCallback gossh.HostKeyCallback
	// DialTimeout 连接超时；<=0 使用 defaultDialTimeout。
	DialTimeout time.Duration
}

// Runner exec.Runner 的 SSH 实现。
type Runner struct {
	client *gossh.Client
}

// 编译期断言：实现共享 Runner 接口。
var _ exec.Runner = (*Runner)(nil)

// New 构建并连接。缺主机校验、缺认证属配置错误，直接拒绝（fail-closed）。
func New(opts Options) (*Runner, error) {
	if strings.TrimSpace(opts.Addr) == "" || strings.TrimSpace(opts.User) == "" {
		return nil, errors.New("ssh runner：Addr 与 User 必填")
	}
	var auth []gossh.AuthMethod
	switch {
	case opts.Password != "":
		auth = []gossh.AuthMethod{gossh.Password(opts.Password)}
	case opts.Signer != nil:
		auth = []gossh.AuthMethod{gossh.PublicKeys(opts.Signer)}
	default:
		return nil, errors.New("ssh runner：必须显式配置认证（Password 或 Signer）")
	}
	var hostKeyCallback gossh.HostKeyCallback
	switch {
	case opts.HostKey != nil:
		hostKeyCallback = gossh.FixedHostKey(opts.HostKey)
	case opts.HostKeyCallback != nil:
		hostKeyCallback = opts.HostKeyCallback
	default:
		return nil, errors.New("ssh runner：必须显式配置主机校验（HostKey 或 HostKeyCallback），不提供跳过校验的路径")
	}
	dialTimeout := opts.DialTimeout
	if dialTimeout <= 0 {
		dialTimeout = defaultDialTimeout
	}
	cfg := &gossh.ClientConfig{
		User:            opts.User,
		Auth:            auth,
		HostKeyCallback: hostKeyCallback,
		Timeout:         dialTimeout,
	}
	if opts.HostKey != nil {
		// 让服务器优先协商我们信任的那种主机密钥算法，
		// 避免服务器默认选择其他类型密钥导致 FixedHostKey 匹配不到。
		cfg.HostKeyAlgorithms = []string{opts.HostKey.Type()}
	}
	client, err := gossh.Dial("tcp", opts.Addr, cfg)
	if err != nil {
		return nil, fmt.Errorf("ssh runner 连接失败：%w", err)
	}
	return &Runner{client: client}, nil
}

// Close 关闭底层连接。
func (r *Runner) Close() error { return r.client.Close() }

// Run 执行命令（argv 形式）。返回值语义见 exec.Runner。
//
// 超时：RunOptions.Timeout 与 ctx 截止时间共同生效（先到者为准）；
// 超时/取消时关闭会话通道终止远端命令，置 TimedOut 并返回错误。
//
// 输出上限：stdout/stderr 各自最多保留 exec.MaxOutputBytes；
// 超限部分读取后丢弃（不阻塞命令正常结束），置对应截断标记。
func (r *Runner) Run(ctx context.Context, argv []string, opts exec.RunOptions) (exec.Result, error) {
	res := exec.Result{ExitCode: -1}
	if len(argv) == 0 || argv[0] == "" {
		return res, errors.New("ssh runner：argv 不能为空")
	}
	// 安全把关（fail-closed）：argv 元素必须是无 shell 语义的 token，
	// 拼接（与 OpenSSH 客户端一致的空白连接）后才不会被远端 shell 重新解释。
	for _, a := range argv {
		if !validation.ValidShellToken(a) {
			return res, fmt.Errorf("ssh runner：命令参数不是无 shell 语义的安全 token，已拒绝执行：%q", a)
		}
	}

	session, err := r.client.NewSession()
	if err != nil {
		return res, fmt.Errorf("ssh runner 建立会话失败：%w", err)
	}
	defer session.Close()

	stdout := &cappedBuffer{max: exec.MaxOutputBytes}
	stderr := &cappedBuffer{max: exec.MaxOutputBytes}
	session.Stdout = stdout
	session.Stderr = stderr

	ctx2 := ctx
	var cancel context.CancelFunc
	if opts.Timeout > 0 {
		ctx2, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	if err := session.Start(strings.Join(argv, " ")); err != nil {
		return res, fmt.Errorf("ssh runner 启动命令失败：%w", err)
	}

	done := make(chan error, 1)
	go func() { done <- session.Wait() }()

	select {
	case err := <-done:
		res.Stdout, res.Stderr = stdout.Bytes(), stderr.Bytes()
		res.StdoutTruncated, res.StderrTruncated = stdout.Truncated(), stderr.Truncated()
		if err == nil {
			res.ExitCode = 0
			return res, nil
		}
		var ee *gossh.ExitError
		if errors.As(err, &ee) {
			// 远端命令以非 0 退出：正常返回结果（不以 error 中断），由调用方判断。
			res.ExitCode = ee.ExitStatus()
			return res, nil
		}
		return res, fmt.Errorf("ssh runner 等待命令结束失败：%w", err)
	case <-ctx2.Done():
		res.TimedOut = true
		res.Stdout, res.Stderr = stdout.Bytes(), stderr.Bytes()
		res.StdoutTruncated, res.StderrTruncated = stdout.Truncated(), stderr.Truncated()
		// 关闭会话通道终止远端命令；Wait 协程随之返回（防御性限时等待）。
		_ = session.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
		}
		reason := "RunOptions.Timeout 到期"
		if ctx.Err() != nil {
			reason = "ctx 已取消"
		}
		return res, fmt.Errorf("ssh runner：命令执行中断（%s），已关闭会话终止远端命令", reason)
	}
}

// cappedBuffer 有上限的输出缓冲：达到上限后继续吞掉（丢弃）后续内容，
// 保证命令不被输出瓶颈阻塞；同时记录是否发生过丢弃（截断）。
type cappedBuffer struct {
	buf       []byte
	max       int
	truncated bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	room := b.max - len(b.buf)
	if room > 0 {
		take := min(room, len(p))
		b.buf = append(b.buf, p[:take]...)
	}
	// 恰好写满上限不算截断；超出上限才置位。
	if room < len(p) {
		b.truncated = true
	}
	return len(p), nil // 始终"已消费"，超限部分等价于丢弃
}

// Bytes 已保留的输出（≤ max）。
func (b *cappedBuffer) Bytes() []byte { return b.buf }

// Truncated 是否因超过上限丢弃过内容。
func (b *cappedBuffer) Truncated() bool { return b.truncated }
