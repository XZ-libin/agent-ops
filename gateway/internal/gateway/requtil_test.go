package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"google.golang.org/protobuf/types/known/structpb"

	contractv1 "github.com/ORG/agent-ops/contract/gen/go/agent_ops/contract/v1"
)

// TestCanonicalJSONRules ADR-009 逐条规则的行为测试。
func TestCanonicalJSONRules(t *testing.T) {
	// 键排序 + 紧凑无空白 + 数字最短表示 + null 与空值。
	got := string(canonicalJSON(map[string]any{
		"z": 1, "a": "x", "m": nil, "e": []any{}, "n": 1.0,
	}))
	want := `{"a":"x","e":[],"m":null,"n":1,"z":1}`
	if got != want {
		t.Fatalf("规范化不符：got %q want %q", got, want)
	}
	// HTML 字符不转义（TS/JSON.stringify 行为对齐）。
	grace := string(canonicalJSON(map[string]any{"s": "a<b&c>d"}))
	if !strings.Contains(grace, `"a<b&c>d"`) || strings.Contains(grace, `\u00`) {
		t.Fatalf("HTML 字符不应被转义：%q", grace)
	}
	// 非 ASCII 原样 UTF-8（Python 客户端须 ensure_ascii=False）。
	uni := string(canonicalJSON(map[string]any{"s": "磁盘"}))
	if !strings.Contains(uni, "磁盘") {
		t.Fatalf("非 ASCII 应原样输出：%q", uni)
	}
}

// TestCanonicalRequestHashGolden 黄金哈希（ADR-009，钉死规范化方式）：
// 输入为固定的网关执行请求 → sha256 hex 必须与黄金值一致。
// 该黄金值同时是 TS/Python 客户端的互操作基准。
func TestCanonicalRequestHashGolden(t *testing.T) {
	params, err := structpb.NewStruct(map[string]any{
		"unit":  "nginx",
		"note":  "a<b",
		"count": 2.0,
		"flag":  true,
	})
	if err != nil {
		t.Fatal(err)
	}
	req := Request{
		Actor:          "ops-lead",
		IdempotencyKey: "golden-key-1",
		Action: &contractv1.Action{
			Capability:  "diagnose.service_state",
			Params:      params,
			ImpactScope: "single",
			Expected:    "unit 状态查询",
			Target: &contractv1.AssetTarget{
				AssetId:    "ast_01HX",
				Access:     contractv1.AccessKind_ACCESS_SSH,
				Credential: &contractv1.CredentialRef{Id: "cred-1"},
			},
		},
		Environment:  contractv1.Environment_ENVIRONMENT_TEST,
		FreezeWindow: true,
	}

	raw := canonicalRequestBytes(req)
	got := hexSum(raw)

	// 黄金值：见 ADR-009。任何与规范化规则的偏差（含 HTML 转义、
	// 键序、数字格式、字段取舍——注意 CredentialRef 不参与哈希）都会破坏该值。
	// 对应规范化 JSON（ADR-009 附录）：
	// {"actor":"ops-lead","key":"golden-key-1","capability":"diagnose.service_state",
	//  "params":{"count":2,"flag":true,"note":"a<b","unit":"nginx"},
	//  "asset_id":"ast_01HX","access":"ACCESS_SSH","environment":"ENVIRONMENT_TEST",
	//  "impact_scope":"single","freeze_window":true}
	const want = "759950041a723c4af52ac3deb7d140c331e252d3d0296331b7bc7dffdf746893"
	if got != want {
		t.Fatalf("黄金哈希不一致：\n  got  %s\n  want %s\n  canonical=%s", got, want, raw)
	}

	// 确定性：相同请求重复计算不变。
	if again := hexSum(canonicalRequestBytes(req)); again != got {
		t.Fatal("相同输入哈希不稳定")
	}
}

func hexSum(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
