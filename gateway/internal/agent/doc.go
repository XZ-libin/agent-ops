// Package agent 是节点 Agent 接入通道的骨架占位：
// mTLS 长连接、心跳离线标记、控制层签名指令验签。
// 工程默认值（默认值，待运维确认）：心跳周期 30s、连续 3 次未心跳判离线、
// 指令签名 Ed25519（OPEN_QUESTIONS Q4）。
package agent
