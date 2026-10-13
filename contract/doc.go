// Package contract 是 Agent Ops 的核心契约：统一适配器接口与跨模块数据结构。
//
// 数据类型（Capability、ChangePlan、AuditEvent、RiskTier 等）一律由 proto/ 下的
// protobuf 定义经 buf 生成（gen/go/），本包禁止手写镜像类型（ADR-002）；
// 适配器接口因为是进程内 Go interface，必须手写，但其载荷全部引用生成类型。
package contract
