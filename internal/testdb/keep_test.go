package testdb

// T3（第二十五轮）：本地调试开关 AGENT_OPS_KEEP_SCHEMA 的边界。
//
// 第二十四轮 R1c 把"失败也删除 schema"变成硬策略，代价是**失去 DB 现场**。
// 本轮补一个只在本地生效的补偿开关：
//   - `AGENT_OPS_KEEP_SCHEMA=1` → 失败用例的 run schema 保留，便于连库排查；
//   - `CI=true`/`CI=1` 或残留检查模式（`AGENT_OPS_RESIDUAL_CHECK=1`）下**启动即失败**，
//     绝不允许它变成"在 CI 里制造残留"的后门；
//   - 残留门禁自身不读这个开关（见 internal/k8stest/residual_test.go：它只查 pg_namespace）。
//
// 通过/失败的判定仍是 `t.Failed()`：保留只发生在**失败**时，通过的用例一律删除。

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func TestKeepSchemaRefusedInCI(t *testing.T) {
	cases := []struct {
		name string
		ci   string
		res  string
	}{
		{"CI=true", "true", ""},
		{"CI=TRUE 大写", "TRUE", ""},
		{"CI=1", "1", ""},
		{"残留检查模式", "", "1"},
		{"CI 与残留检查同时存在", "true", "1"},
	}
	for _, c := range cases {
		t.Setenv(KeepSchemaEnv, "1")
		t.Setenv("CI", c.ci)
		t.Setenv(ResidualCheckEnv, c.res)
		keep, err := KeepSchemaEnabled()
		if err == nil {
			t.Errorf("[T3] %s：开关开启必须被拒绝，却返回 keep=%v", c.name, keep)
			continue
		}
		if keep {
			t.Errorf("[T3] %s：拒绝时不得返回 keep=true", c.name)
		}
		if !strings.Contains(err.Error(), KeepSchemaEnv) {
			t.Errorf("[T3] %s：错误信息应点名 %s，实际：%v", c.name, KeepSchemaEnv, err)
		}
	}
	t.Logf("[T3] CI / 残留检查模式下 %s 一律拒绝（fail-fast，在建 schema 之前就拒）", KeepSchemaEnv)
}

func TestKeepSchemaLocalOnly(t *testing.T) {
	// 默认：未设置开关 → 不保留（第二十四轮 R1c 的行为）。
	t.Setenv(KeepSchemaEnv, "")
	t.Setenv("CI", "")
	t.Setenv(ResidualCheckEnv, "")
	if keep, err := KeepSchemaEnabled(); err != nil || keep {
		t.Fatalf("未设开关应 keep=false 且无错误，实际 keep=%v err=%v", keep, err)
	}

	// 非"1" 的取值不生效（避免 KEEP_SCHEMA=0 被当成真）。
	for _, v := range []string{"0", "false", "yes", " "} {
		t.Setenv(KeepSchemaEnv, v)
		if keep, err := KeepSchemaEnabled(); err != nil || keep {
			t.Fatalf("%s=%q 不应生效（keep=%v err=%v）", KeepSchemaEnv, v, keep, err)
		}
	}

	// 本地（CI 未设、残留检查未开）→ 生效。
	t.Setenv(KeepSchemaEnv, "1")
	keep, err := KeepSchemaEnabled()
	if err != nil || !keep {
		t.Fatalf("本地开启应 keep=true，实际 keep=%v err=%v", keep, err)
	}

	// 判定函数真值表：只有"失败 + 开启"才保留。
	table := []struct{ failed, keep, want bool }{
		{false, false, false}, // 通过：一律删除
		{false, true, false},  // 通过且开了开关：仍然删除（开关只管失败用例）
		{true, false, false},  // 失败且未开开关：删除（R1c 默认）
		{true, true, true},    // 失败且开了开关：保留
	}
	for _, c := range table {
		if got := ShouldRetainOnFailure(c.failed, c.keep); got != c.want {
			t.Errorf("ShouldRetainOnFailure(failed=%v, keep=%v)=%v，期望 %v",
				c.failed, c.keep, got, c.want)
		}
	}
	t.Logf("[T3] 开关仅本地生效；保留只发生在失败用例（通过用例照旧删除）")
}

// TestKeepSchemaRetainsOnlyOnFailure 用**真实 schema** 走两条分支：
// 保留分支留下 schema（随后由本用例自己清掉），删除分支立即消失。
func TestKeepSchemaRetainsOnlyOnFailure(t *testing.T) {
	base, pool := adminPool(t)
	if pool == nil {
		return
	}
	ctx := context.Background()
	want := func(failed, keep bool) bool { return ShouldRetainOnFailure(failed, keep) }

	type made struct {
		name   string
		retain bool
	}
	var created []made
	// 兜底：无论断言怎么走，本用例自己创建的 schema 都必须消失。
	t.Cleanup(func() {
		for _, m := range created {
			if ok, _ := schemaExists(context.Background(), pool, m.name); ok {
				if err := CleanupRunSchema(context.Background(), base, m.name, true, t.Logf); err != nil {
					t.Errorf("兜底清理 %s 失败：%v", m.name, err)
				}
			}
		}
	})

	cases := []struct {
		failed, keep bool
	}{
		{false, false}, // 通过 → 删除
		{true, false},  // 失败、未开开关 → 删除（R1c）
		{true, true},   // 失败、开了开关 → 保留（T3）
	}
	for i, c := range cases {
		name := fmt.Sprintf("%s%d_keep%d", RunSchemaPrefix, i+1, boolInt(c.keep))
		if _, err := pool.Exec(ctx, fmt.Sprintf("CREATE SCHEMA %s", quoteIdent(name))); err != nil {
			t.Fatalf("建 schema %s 失败：%v", name, err)
		}
		created = append(created, made{name: name, retain: want(c.failed, c.keep)})
		if !want(c.failed, c.keep) {
			if err := CleanupRunSchema(ctx, base, name, c.failed, nil); err != nil {
				t.Fatalf("删除分支应清理成功：%v", err)
			}
		}
		ok, err := schemaExists(ctx, pool, name)
		if err != nil {
			t.Fatal(err)
		}
		if wantBool := c.failed && c.keep; ok != wantBool {
			t.Fatalf("用例 %d（failed=%v keep=%v）：schema 存在=%v，期望存在=%v",
				i+1, c.failed, c.keep, ok, wantBool)
		}
		t.Logf("[T3] failed=%-5v keep=%-5v → schema 存在=%v（符合预期）", c.failed, c.keep, ok)
	}
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
