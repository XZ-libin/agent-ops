//go:build !linux

package main

// memoryTotalBytes 非 Linux 平台（开发机 macOS / Windows）返回 0。
//
// 负载摘要缺失不影响注册与心跳（它只是运维信息）；
// 生产节点为 Linux，走 meminfo_linux.go 的实现。
func memoryTotalBytes() uint64 { return 0 }
