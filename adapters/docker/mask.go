// Package docker 是 Docker 主机只读适配器（第十二轮 D1）。
//
// 安全边界（本包的全部对外行为都受它约束）：
//
//  1. **只读**：只通过 Docker Engine API 的 GET 端点读取信息；本包代码中不存在
//     任何 POST / PUT / DELETE 请求路径（见 client.go 与 contract 测试）。
//  2. **端点白名单**：只允许 GET /version、/info、/containers/json、
//     /containers/{id}/json、/images/json；其余路径与方法一律拒绝，
//     拒绝发生在客户端内部（不依赖调用方自觉）。
//  3. **标签过滤**：容器与镜像列表只返回带标签 agent-ops.test=true 的对象；
//     过滤后为空时**明确报错**，不静默返回空列表。
//  4. **字段屏蔽**：容器 Config.Env、Mounts 宿主机路径与凭据类字段、Labels 中
//     以 secret/token/password 开头的键、/info 的 Swarm 与节点敏感字段，
//     一律不出现在返回值中（屏蔽规则见 mask.go，可单测）。
//  5. **资源上限**：每个请求 10 秒超时（可配）与 1MB 响应体上限（可配）。
//
// 与 Linux 适配器一致：Execute 对只读能力直接拒绝（提示走 Diagnose/Health），
// PlanRollback 恒返回 ErrNoRollbackNeeded。本轮不接入网关执行路径（D3）。
package docker

import (
	"fmt"
	"sort"
	"strings"
)

// maskMarker 被屏蔽字段的记录键：屏蔽是"删除 + 记录路径"，便于核对与测试。
const maskMarker = "masked_fields"

// credentialKeyPrefixes 凭据类键名前缀（大小写不敏感）：
// Labels 中以它们开头的键一律屏蔽；其余嵌套 map 同样适用（纵深防御）。
var credentialKeyPrefixes = []string{"secret", "token", "password"}

// MaskLabels 屏蔽标签中凭据类键（前缀匹配，大小写不敏感）。
// 返回屏蔽后的副本与被屏蔽的键名列表（原 map 不被修改）。
func MaskLabels(labels map[string]any) (map[string]any, []string) {
	out := make(map[string]any, len(labels))
	var masked []string
	for k, v := range labels {
		if isCredentialKey(k) {
			masked = append(masked, k)
			continue
		}
		out[k] = v
	}
	return out, masked
}

// MaskContainerInspect 屏蔽容器 inspect 结果中的敏感字段，返回副本与被屏蔽路径：
//
//   - Config.Env（容器全部环境变量）；
//   - Mounts[*].Source 与 HostConfig.Binds（宿主机路径）；
//   - 任意层级中凭据类键名（secret/token/password 前缀）；
//   - Labels 中的凭据类键（同上规则）。
//
// 屏蔽 = 删除该键并在结果中以 masked_fields 记录路径（不含原值）。
func MaskContainerInspect(raw map[string]any) (map[string]any, []string) {
	out := deepCopyMap(raw)
	var masked []string

	if cfg, ok := out["Config"].(map[string]any); ok {
		if _, has := cfg["Env"]; has {
			delete(cfg, "Env")
			masked = append(masked, "Config.Env")
		}
	}
	if mounts, ok := out["Mounts"].([]any); ok {
		for i, m := range mounts {
			mm, ok := m.(map[string]any)
			if !ok {
				continue
			}
			if _, has := mm["Source"]; has {
				delete(mm, "Source")
				masked = append(masked, pathAt("Mounts", i, "Source"))
			}
		}
	}
	if hc, ok := out["HostConfig"].(map[string]any); ok {
		if _, has := hc["Binds"]; has {
			delete(hc, "Binds")
			masked = append(masked, "HostConfig.Binds")
		}
	}
	masked = append(masked, maskCredentialKeys(out, "")...)
	return out, masked
}

// infoWhitelist /info 允许返回的字段白名单（第十三轮 F1，裁决）。
//
// 原实现为"删除已知敏感字段"，依赖字段清单与 Docker 版本同步——Docker 升级
// 新增敏感字段会直接泄露。现改为**白名单**：只返回下列字段，其余一律不返回。
var infoWhitelist = []string{
	"ServerVersion",     // 引擎版本
	"OperatingSystem",   // 操作系统
	"Architecture",      // 架构
	"NCPU",              // CPU 数
	"MemTotal",          // 内存总量
	"Containers",        // 容器总数
	"ContainersRunning", // 运行中容器数
	"ContainersPaused",  // 暂停容器数
	"ContainersStopped", // 停止容器数
	"Images",            // 镜像数
	"KernelVersion",     // 内核版本
}

// WhitelistInfo 按白名单裁剪 /info 输出（第十三轮 F1）：
// 只保留 infoWhitelist 中的字段，其余一律不返回（不做删除式屏蔽）。
// 返回裁剪后的副本与被裁剪掉的顶层字段名列表（便于核对与测试）。
func WhitelistInfo(raw map[string]any) (map[string]any, []string) {
	allowed := make(map[string]bool, len(infoWhitelist))
	for _, k := range infoWhitelist {
		allowed[k] = true
	}
	out := make(map[string]any, len(infoWhitelist))
	var dropped []string
	for k, v := range raw {
		if !allowed[k] {
			dropped = append(dropped, k)
			continue
		}
		out[k] = deepCopyValue(v)
	}
	sort.Strings(dropped)
	return out, dropped
}

// MaskContainerSummary 屏蔽容器列表项中的敏感字段（Labels 凭据类键 + 凭据类键名）。
func MaskContainerSummary(raw map[string]any) (map[string]any, []string) {
	out := deepCopyMap(raw)
	masked := maskCredentialKeys(out, "")
	return out, masked
}

// MaskImageSummary 屏蔽镜像列表项中的敏感字段（Labels 凭据类键 + 凭据类键名）。
func MaskImageSummary(raw map[string]any) (map[string]any, []string) {
	out := deepCopyMap(raw)
	masked := maskCredentialKeys(out, "")
	return out, masked
}

// isCredentialKey 判定键名是否为凭据类（前缀匹配，大小写不敏感）。
func isCredentialKey(key string) bool {
	lower := strings.ToLower(strings.TrimSpace(key))
	for _, p := range credentialKeyPrefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}

// maskCredentialKeys 递归屏蔽 map 中的凭据类键，返回被屏蔽的路径列表。
func maskCredentialKeys(v any, prefix string) []string {
	var masked []string
	switch node := v.(type) {
	case map[string]any:
		for k, child := range node {
			if isCredentialKey(k) {
				delete(node, k)
				masked = append(masked, joinPath(prefix, k))
				continue
			}
			masked = append(masked, maskCredentialKeys(child, joinPath(prefix, k))...)
		}
	case []any:
		for i, child := range node {
			masked = append(masked, maskCredentialKeys(child, pathAt(prefix, i, ""))...)
		}
	}
	return masked
}

// deepCopyMap 深拷贝 JSON 解码得到的 map（保证屏蔽不修改调用方数据）。
func deepCopyMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = deepCopyValue(v)
	}
	return out
}

func deepCopyValue(v any) any {
	switch node := v.(type) {
	case map[string]any:
		return deepCopyMap(node)
	case []any:
		out := make([]any, len(node))
		for i, child := range node {
			out[i] = deepCopyValue(child)
		}
		return out
	}
	return v
}

// joinPath 拼接路径（prefix 为空时直接用键名）。
func joinPath(prefix, key string) string {
	if prefix == "" {
		return key
	}
	if key == "" {
		return prefix
	}
	return prefix + "." + key
}

// pathAt 拼接带下标的路径（key 为空表示纯下标）。
func pathAt(prefix string, index int, key string) string {
	p := fmt.Sprintf("%s[%d]", prefix, index)
	if key == "" {
		return p
	}
	return p + "." + key
}
