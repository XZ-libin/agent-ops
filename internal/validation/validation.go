// Package validation 统一承载跨模块的名称与字符串校验规则（ADR-008 / 第七轮 D2）。
//
// 背景：能力名称、systemctl unit 名称等规则曾在多处重复定义（adapters/linux、
// control-plane/internal/registry），存在漂移风险。本包作为唯一来源，
// 两处一律引用本包；行为一致性由本包表驱动测试 + 引用方一致性测试保证。
//
// 所有校验均为 fail-closed：不合法即拒绝，不做大小写、空白等自动修正。
package validation

import (
	"regexp"
	"strings"
)

// CapabilityNamePattern 能力名称规则（第五轮修正，安全相关）：
// 只允许小写 ASCII 字母、数字、下划线，以 "." 分段。
var CapabilityNamePattern = regexp.MustCompile(`^[a-z0-9_]+(\.[a-z0-9_]+)*$`)

// ValidCapabilityName 校验能力名称。
// 注册处（适配器清单加载）与策略评估处都必须调用本函数。
func ValidCapabilityName(name string) bool {
	return CapabilityNamePattern.MatchString(name)
}

// UnitNamePattern systemd unit 名称规则（第七轮 linux 适配器引入）：
// 允许大小写字母、数字与 @._-，不允许 "/"、".." 与空白（防路径逃逸）。
var UnitNamePattern = regexp.MustCompile(`^[a-zA-Z0-9@._-]+$`)

// ValidUnitName 校验 systemctl unit 参数；不符合则不得调用命令。
func ValidUnitName(unit string) bool {
	return UnitNamePattern.MatchString(unit)
}

// shellTokenPattern 单条 argv 元素的安全规则（fail-closed）：
// 只允许字母、数字与常见无 shell 语义的符号。
// ssh Runner 在拼接远程命令行前用它对每个元素把关，
// 保证 argv 拼接（与 OpenSSH 客户端一致的空白连接方式）不会被 shell 重新解释。
var shellTokenPattern = regexp.MustCompile(`^[A-Za-z0-9@._/+:=-]+$`)

// ValidShellToken 校验单条 argv 元素是否为无 shell 语义的安全 token。
func ValidShellToken(s string) bool {
	return shellTokenPattern.MatchString(s)
}

// absUnixPathPattern 绝对 Unix 路径规则（路径类名称校验，工程默认，待运维确认）：
// 必须以 "/" 开头，逐段只允许字母、数字与 ._+-（不允许空白/控制字符）；
// "."、".." 与连续 "/" 由 ValidAbsUnixPath 追加排除（防路径逃逸）。
var absUnixPathPattern = regexp.MustCompile(`^/([A-Za-z0-9@._+=~-]+/?)*$`)

// ValidAbsUnixPath 校验绝对 Unix 路径（fail-closed）。空串不合法。
// 未来用于需要校验目标路径的只读能力；当前适配器命令集合为固定常量，暂无调用方。
func ValidAbsUnixPath(p string) bool {
	if p == "" || strings.Contains(p, "//") || !absUnixPathPattern.MatchString(p) {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// containerIDPattern Docker 容器标识规则（第十二轮 docker 适配器引入）：
// 只允许 Docker 的容器 ID/名称字符集（十六进制、字母、数字与 _ . -），
// 长度 1~128，且首字符必须是字母或数字——杜绝 "/"、".." 等路径逃逸
// 与额外的路径段（容器 inspect 端点为 /containers/{id}/json）。
var containerIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

// ValidContainerID 校验 Docker 容器标识（fail-closed，不做任何修正）。
func ValidContainerID(id string) bool {
	return containerIDPattern.MatchString(id)
}

// k8sNamespacePattern Kubernetes 命名空间名规则（第十三轮 kubernetes 适配器引入）：
// RFC 1123 label：小写字母/数字/短横线，首尾必须是字母或数字，长度 ≤63。
var k8sNamespacePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// ValidK8sNamespace 校验 Kubernetes 命名空间名（fail-closed）。
// 用于拼装 /api/v1/namespaces/{ns} 路径，杜绝路径逃逸与额外路径段。
func ValidK8sNamespace(ns string) bool {
	return k8sNamespacePattern.MatchString(ns)
}

// k8sNamePattern Kubernetes 对象名规则（RFC 1123 subdomain 的保守子集）：
// 小写字母/数字/短横线/点，首尾必须是字母或数字，长度 ≤253。
var k8sNamePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)

// ValidK8sName 校验 Kubernetes 对象名（Pod/Deployment 等，fail-closed）。
func ValidK8sName(name string) bool {
	return k8sNamePattern.MatchString(name)
}
