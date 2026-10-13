package kubernetes

import (
	"fmt"
	"sort"
	"strings"
)

// —— 第十四轮 H2：spec 白名单裁剪 ——
//
// 原实现是"删除式屏蔽"（删 env/envFrom/卷数据源/凭据类注解），
// 依赖敏感字段清单与 Kubernetes 版本同步——ephemeralContainers、lifecycle、
// command/args 等字段一旦新增就会直接泄露。
//
// 现改为**白名单裁剪**（与 Docker /info 同款思路）：
// 只保留下列明确列出的字段，其余一律不返回。
//
// 允许字段（Pod）：
//
//	metadata.name / namespace / labels（非凭据类）/ annotations（非凭据类与非敏感键）
//	spec.nodeName / restartPolicy / serviceAccountName
//	spec.containers[*].name / image / imagePullPolicy / resources
//	spec.containers[*].ports[*].name / containerPort
//	status.phase / conditions[*].type / status
//
// 一律不返回（节选）：spec.ephemeralContainers、spec.initContainers、spec.volumes、
//	containers[*].env、envFrom、lifecycle、command、args、volumeMounts、
//	securityContext、spec.tolerations、spec.nodeSelector、status.containerStatuses 等。

// credentialKeyPrefixes 凭据类键名前缀（注解/标签/任意键名，大小写不敏感）。
var credentialKeyPrefixes = []string{"secret", "token", "password", "credential"}

// sensitiveAnnotationKeys 需要整条删除的注解键（精确匹配）。
//
// kubectl.kubernetes.io/last-applied-configuration 由 kubectl apply 写入，
// **内嵌完整清单 JSON**——其中包含 env 取值与 secret 类注解的原值。
// 集成测试在真实集群上验证了这一点（第十三轮）。
var sensitiveAnnotationKeys = []string{
	"kubectl.kubernetes.io/last-applied-configuration",
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

// isSensitiveAnnotationKey 判定注解键是否整体敏感（精确键或含 last-applied）。
func isSensitiveAnnotationKey(key string) bool {
	lower := strings.ToLower(strings.TrimSpace(key))
	for _, k := range sensitiveAnnotationKeys {
		if lower == k {
			return true
		}
	}
	return strings.Contains(lower, "last-applied")
}

// MaskPod 白名单裁剪 Pod 对象（第十四轮 H2）。
// 返回裁剪后的副本与被裁剪/被保留的说明路径列表（便于核对与测试）。
func MaskPod(raw map[string]any) (map[string]any, []string) {
	var dropped []string
	out := map[string]any{}
	if v, ok := raw["apiVersion"]; ok {
		out["apiVersion"] = v
	}
	if v, ok := raw["kind"]; ok {
		out["kind"] = v
	}
	md, mdDropped := whitelistMetadata(raw["metadata"], "metadata")
	if md != nil {
		out["metadata"] = md
	}
	dropped = append(dropped, mdDropped...)

	spec, specDropped := whitelistPodSpec(raw["spec"], "spec")
	if spec != nil {
		out["spec"] = spec
	}
	dropped = append(dropped, specDropped...)

	if st, stDropped := whitelistPodStatus(raw["status"], "status"); st != nil {
		out["status"] = st
		dropped = append(dropped, stDropped...)
	} else {
		dropped = append(dropped, stDropped...)
	}
	sort.Strings(dropped)
	return out, dropped
}

// MaskDeployment 白名单裁剪 Deployment 对象（第十四轮 H2）。
func MaskDeployment(raw map[string]any) (map[string]any, []string) {
	var dropped []string
	out := map[string]any{}
	if v, ok := raw["apiVersion"]; ok {
		out["apiVersion"] = v
	}
	if v, ok := raw["kind"]; ok {
		out["kind"] = v
	}
	md, mdDropped := whitelistMetadata(raw["metadata"], "metadata")
	if md != nil {
		out["metadata"] = md
	}
	dropped = append(dropped, mdDropped...)

	spec, _ := raw["spec"].(map[string]any)
	if spec != nil {
		dspec := map[string]any{}
		if v, ok := spec["replicas"]; ok {
			dspec["replicas"] = v
		}
		if v, ok := spec["selector"]; ok {
			dspec["selector"] = v
		}
		if st, ok := spec["strategy"].(map[string]any); ok {
			if t, ok := st["type"]; ok {
				dspec["strategy"] = map[string]any{"type": t}
			}
		}
		if tmpl, ok := spec["template"].(map[string]any); ok {
			wtmpl := map[string]any{}
			tmd, tmdDropped := whitelistMetadata(tmpl["metadata"], "spec.template.metadata")
			if tmd != nil {
				wtmpl["metadata"] = tmd
			}
			dropped = append(dropped, tmdDropped...)
			tspec, tsDropped := whitelistPodSpec(tmpl["spec"], "spec.template.spec")
			if tspec != nil {
				wtmpl["spec"] = tspec
			}
			dropped = append(dropped, tsDropped...)
			dspec["template"] = wtmpl
		}
		out["spec"] = dspec
	}

	if st, _ := raw["status"].(map[string]any); st != nil {
		wst := map[string]any{}
		for _, k := range []string{"replicas", "readyReplicas", "availableReplicas"} {
			if v, ok := st[k]; ok {
				wst[k] = v
			}
		}
		if conds, _ := whitelistConditions(st["conditions"], true); conds != nil {
			wst["conditions"] = conds
		}
		out["status"] = wst
	}
	sort.Strings(dropped)
	return out, dropped
}

// MaskNamespace 白名单裁剪命名空间对象。
func MaskNamespace(raw map[string]any) (map[string]any, []string) {
	out := map[string]any{}
	if v, ok := raw["apiVersion"]; ok {
		out["apiVersion"] = v
	}
	if v, ok := raw["kind"]; ok {
		out["kind"] = v
	}
	md, dropped := whitelistMetadata(raw["metadata"], "metadata")
	if md != nil {
		out["metadata"] = md
	}
	if st, ok := raw["status"]; ok {
		out["status"] = st // 命名空间 status 仅 phase（非敏感）
	}
	sort.Strings(dropped)
	return out, dropped
}

// whitelistMetadata 裁剪 metadata：只保留 name/namespace/labels/annotations
// （labels 与 annotations 中凭据类键与敏感注解键一律删除）。
func whitelistMetadata(v any, prefix string) (map[string]any, []string) {
	md, ok := v.(map[string]any)
	if !ok {
		return nil, nil
	}
	out := map[string]any{}
	var dropped []string
	for _, k := range []string{"name", "namespace", "uid", "creationTimestamp"} {
		if val, ok := md[k]; ok {
			out[k] = val
		}
	}
	if labels, ok := md["labels"].(map[string]any); ok {
		out["labels"] = filterCredentialKeys(labels)
	}
	if ann, ok := md["annotations"].(map[string]any); ok {
		filtered := map[string]any{}
		for k, val := range ann {
			if isCredentialKey(k) || isSensitiveAnnotationKey(k) {
				dropped = append(dropped, fmt.Sprintf("%s.annotations.%s", prefix, k))
				continue
			}
			filtered[k] = val
		}
		if len(filtered) > 0 {
			out["annotations"] = filtered
		}
	}
	// managedFields 等其余 metadata 字段一律不返回。
	for k := range md {
		switch k {
		case "name", "namespace", "uid", "creationTimestamp", "labels", "annotations":
		default:
			dropped = append(dropped, fmt.Sprintf("%s.%s", prefix, k))
		}
	}
	return out, dropped
}

// filterCredentialKeys 删除 map 中凭据类键（用于 labels）。
func filterCredentialKeys(in map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range in {
		if isCredentialKey(k) {
			continue
		}
		out[k] = v
	}
	return out
}

// whitelistPodSpec 裁剪 Pod spec（含 Deployment 的 template.spec）。
func whitelistPodSpec(v any, prefix string) (map[string]any, []string) {
	spec, ok := v.(map[string]any)
	if !ok {
		return nil, nil
	}
	out := map[string]any{}
	var dropped []string
	for _, k := range []string{"nodeName", "restartPolicy", "serviceAccountName"} {
		if val, ok := spec[k]; ok {
			out[k] = val
		}
	}
	// containers：只保留 name/image/imagePullPolicy/resources/ports(name,containerPort)
	if list, ok := spec["containers"].([]any); ok {
		wl := make([]any, 0, len(list))
		for i, c := range list {
			cm, ok := c.(map[string]any)
			if !ok {
				continue
			}
			wc := map[string]any{}
			for _, k := range []string{"name", "image", "imagePullPolicy", "resources"} {
				if val, ok := cm[k]; ok {
					wc[k] = val
				}
			}
			if ports, ok := cm["ports"].([]any); ok {
				wports := make([]any, 0, len(ports))
				for _, p := range ports {
					pm, ok := p.(map[string]any)
					if !ok {
						continue
					}
					wp := map[string]any{}
					for _, k := range []string{"name", "containerPort"} {
						if val, ok := pm[k]; ok {
							wp[k] = val
						}
					}
					wports = append(wports, wp)
				}
				wc["ports"] = wports
			}
			// 记录被裁剪的容器内字段（便于核对）。
			for k := range cm {
				switch k {
				case "name", "image", "imagePullPolicy", "resources", "ports":
				default:
					dropped = append(dropped, fmt.Sprintf("%s.containers[%d].%s", prefix, i, k))
				}
			}
			wl = append(wl, wc)
		}
		out["containers"] = wl
	}
	// 其余 spec 字段一律不返回。
	for k := range spec {
		switch k {
		case "nodeName", "restartPolicy", "serviceAccountName", "containers":
		default:
			dropped = append(dropped, fmt.Sprintf("%s.%s", prefix, k))
		}
	}
	return out, dropped
}

// whitelistPodStatus 裁剪 Pod status：只保留 phase 与 conditions(type,status)。
func whitelistPodStatus(v any, prefix string) (map[string]any, []string) {
	st, ok := v.(map[string]any)
	if !ok {
		return nil, []string{prefix + "（缺失）"}
	}
	out := map[string]any{}
	var dropped []string
	if phase, ok := st["phase"]; ok {
		out["phase"] = phase
	}
	if conds, _ := whitelistConditions(st["conditions"], false); conds != nil {
		out["conditions"] = conds
	}
	for k := range st {
		switch k {
		case "phase", "conditions":
		default:
			dropped = append(dropped, fmt.Sprintf("%s.%s", prefix, k))
		}
	}
	return out, dropped
}

// whitelistConditions 裁剪 conditions：Pod 保留 type/status，
// Deployment 额外保留 reason。
func whitelistConditions(v any, withReason bool) ([]any, []string) {
	list, ok := v.([]any)
	if !ok {
		return nil, nil
	}
	out := make([]any, 0, len(list))
	for _, c := range list {
		cm, ok := c.(map[string]any)
		if !ok {
			continue
		}
		wc := map[string]any{}
		keys := []string{"type", "status"}
		if withReason {
			keys = append(keys, "reason")
		}
		for _, k := range keys {
			if val, ok := cm[k]; ok {
				wc[k] = val
			}
		}
		out = append(out, wc)
	}
	return out, nil
}
