//go:build linux

package main

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// memoryTotalBytes 读取 /proc/meminfo 的 MemTotal（Linux）。
//
// 失败时返回 0（负载摘要缺失不影响注册与心跳——它只是运维信息）。
// 注意：**不读取任何进程信息**（N5：负载摘要不含进程列表）。
func memoryTotalBytes() uint64 {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "MemTotal:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0
		}
		kb, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return 0
		}
		return kb * 1024
	}
	return 0
}
