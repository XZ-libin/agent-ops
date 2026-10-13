package registry

import (
	"testing"

	"github.com/ORG/agent-ops/internal/validation"
)

// TestValidCapabilityName 注册侧名称校验（规则唯一来源 internal/validation）。
func TestValidCapabilityName(t *testing.T) {
	valid := []string{
		"diagnose.slow_query",
		"restart.service",
		"log.cleanup_expired",
		"a",
		"a1.b2_c3.d4",
	}
	for _, name := range valid {
		if !ValidCapabilityName(name) {
			t.Errorf("%q 应为合法名称", name)
		}
	}

	invalid := []string{
		"Volume.Delete",  // 大写（大小写绕过）
		"VOLUME.DELETE",  // 全大写
		" volume.delete", // 前导空格
		"volume.delete ", // 尾随空格
		"volume..delete", // 空分段
		".volume.delete", // 前导点
		"volume.delete.", // 尾随点
		"诊断.采集",          // Unicode
		"vol-ume.delete", // 连字符
		"",               // 空名
	}
	for _, name := range invalid {
		if ValidCapabilityName(name) {
			t.Errorf("%q 应为非法名称", name)
		}
	}
}

// TestConsistentWithValidation 引用方一致性（第七轮遗留决策 D2）：
// 注册侧与 validation 包对同一组样本的判定必须完全一致。
func TestConsistentWithValidation(t *testing.T) {
	samples := []string{
		"diagnose.disk_usage", "restart.service", "a.b_c", "a",
		"Volume.Delete", "a b", "a..b", ".a", "a.", "诊断", "a-b", "a/b", "",
		"a\tb", "\u00e9.b", "a.b\n", "x.y.z", "a.b.c.d.e",
	}
	for _, s := range samples {
		if got, want := ValidCapabilityName(s), validation.ValidCapabilityName(s); got != want {
			t.Errorf("注册侧与 validation 判定不一致：%q registry=%v validation=%v", s, got, want)
		}
	}
}
