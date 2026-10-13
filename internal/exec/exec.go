// Package exec 提供对目标主机执行命令的最小共享抽象（第七轮遗留决策 D1 / ADR-008）。
//
// 适配器（如 adapters/linux）只依赖本接口，不依赖 ssh 等具体传输实现；
// 具体传输实现放在本包子树（internal/exec/ssh）。
//
// 接口要点：
//   - 命令必须以 argv 形式传递（argv[0] 为命令名），禁止拼接 shell 字符串；
//   - 每条命令可带超时（RunOptions.Timeout；ctx 截止时间始终生效）；
//   - 输出上限 64KB（stdout/stderr 各自封顶，MaxOutputBytes），
//     超限内容丢弃并置对应截断标记，命令本身不被截断行为杀死；
//   - 超时中断时置 TimedOut 标记并返回错误。
package exec

import (
	"context"
	"time"
)

// MaxOutputBytes 单条命令每路输出（stdout/stderr）的上限：64KB（工程默认，
// 待运维确认）。达到上限后继续丢弃读取（保证命令正常结束），并置截断标记。
const MaxOutputBytes = 64 * 1024

// Result 单条命令的执行结果。
type Result struct {
	Stdout []byte
	Stderr []byte
	// ExitCode 进程退出码；超时中断时为 -1。
	ExitCode int
	// StdoutTruncated / StderrTruncated 对应输出是否超过 MaxOutputBytes 被截断。
	StdoutTruncated bool
	StderrTruncated bool
	// TimedOut 命令是否因超时/上下文取消被中断。
	TimedOut bool
}

// RunOptions 单次 Run 的选项。
type RunOptions struct {
	// Timeout 本次执行超时；<=0 表示不额外设置（仅受 ctx 截止时间约束）。
	Timeout time.Duration
}

// Runner 执行命令的执行器抽象。
type Runner interface {
	Run(ctx context.Context, argv []string, opts RunOptions) (Result, error)
}
