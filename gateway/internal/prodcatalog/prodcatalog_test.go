package prodcatalog

import (
	"strings"
	"testing"

	contractv1 "github.com/ORG/agent-ops/contract/gen/go/agent_ops/contract/v1"

	"github.com/ORG/agent-ops/gateway/internal/gateway"
)

// linuxManifest 与 adapters/linux/manifest.yaml 同构的最小样例（生产能力，
// 不含任何 test_only、不含写能力）。
const linuxManifest = `name: linux
capabilities:
  - name: diagnose.disk_usage
    risk_tier: read_only
    destructive: false
    rollbackable: false
    timeout: 60s
  - name: diagnose.service_state
    risk_tier: read_only
    destructive: false
    rollbackable: false
    timeout: 60s
`

// testOnlyManifest 仅测试目录清单（第十轮 G2 的启动守卫必须拒绝）。
const testOnlyManifest = `name: test-testwrite
capabilities:
  - name: test.write.marker
    risk_tier: low
    destructive: false
    rollbackable: true
    test_only: true
    timeout: 60s
`

// TestParseProductionManifest 解析生产能力清单：等级/超时/名称均经校验。
func TestParseProductionManifest(t *testing.T) {
	caps, err := Parse([]byte(linuxManifest))
	if err != nil {
		t.Fatal(err)
	}
	if len(caps) != 2 {
		t.Fatalf("应解析出 2 项能力：%d", len(caps))
	}
	if caps[0].Name != "diagnose.disk_usage" ||
		caps[0].RiskTier != contractv1.RiskTier_RISK_TIER_READ_ONLY {
		t.Fatalf("解析结果不符：%+v", caps[0])
	}
	if caps[0].Timeout == nil || caps[0].Timeout.AsDuration().Seconds() != 60 {
		t.Fatalf("超时解析不符：%+v", caps[0].Timeout)
	}
}

// TestParseRejectsInvalid 非法清单（坏名称/缺等级/坏超时）一律报错（fail-closed）。
func TestParseRejectsInvalid(t *testing.T) {
	cases := map[string]string{
		"坏名称": "capabilities:\n  - name: Bad.Name\n    risk_tier: low\n",
		"缺等级": "capabilities:\n  - name: diagnose.disk_usage\n",
		"坏超时": "capabilities:\n  - name: diagnose.disk_usage\n    risk_tier: read_only\n    timeout: 60\n",
		"空清单": "name: empty\ncapabilities: []\n",
	}
	for name, yaml := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(yaml)); err == nil {
				t.Fatal("非法清单应报错")
			}
		})
	}
}

// TestRegisterRejectsTestOnly 生产启动守卫（G2）：含 test_only 能力的清单
// 在生产注册表（gateway.NewRegistry）中注册失败。
func TestRegisterRejectsTestOnly(t *testing.T) {
	caps, err := Parse([]byte(testOnlyManifest))
	if err != nil {
		t.Fatal(err)
	}
	if !caps[0].TestOnly {
		t.Fatalf("前置：样例清单应标记 test_only：%+v", caps[0])
	}
	reg := gateway.NewRegistry() // 生产注册表
	if err := Register(reg, caps); err == nil {
		t.Fatal("生产注册表必须拒绝 test_only 能力")
	}
	if _, ok := reg.Lookup("test.write.marker"); ok {
		t.Fatal("生产目录中 test_only 能力必须不可见")
	}
	// 生产启动守卫：空注册表通过；仅测试注册表（含 test_only）不通过。
	empty := gateway.NewRegistry()
	if err := empty.AssertNoTestOnly(); err != nil {
		t.Fatalf("空生产目录应通过守卫：%v", err)
	}
	testReg := gateway.NewTestRegistry() // 仅测试
	if err := Register(testReg, caps); err != nil {
		t.Fatalf("仅测试注册表应可加载 test_only 能力：%v", err)
	}
	if err := testReg.AssertNoTestOnly(); err == nil {
		t.Fatal("含 test_only 能力的目录不得通过生产启动守卫")
	} else if !strings.Contains(err.Error(), "test.write.marker") {
		t.Fatalf("守卫错误应列出 offending 能力名：%v", err)
	}
}

// TestRegisterProductionCatalog 生产目录注册成功且不含 test_only。
func TestRegisterProductionCatalog(t *testing.T) {
	caps, err := Parse([]byte(linuxManifest))
	if err != nil {
		t.Fatal(err)
	}
	reg := gateway.NewRegistry()
	if err := Register(reg, caps); err != nil {
		t.Fatal(err)
	}
	if err := reg.AssertNoTestOnly(); err != nil {
		t.Fatalf("生产目录应通过启动守卫：%v", err)
	}
	// 未接线桩：调用即失败（不绕过任何门控，执行结果按 failed 处理）。
	if _, ok := reg.Lookup("diagnose.disk_usage"); !ok {
		t.Fatal("已注册能力应可查找")
	}
}
