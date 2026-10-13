package toolpin

// 第二十五轮 T2：把"测试所用 kubectl 必须是登记版本"变成可执行断言。
//
// 覆盖三件事：
//  1. 版本来源是 docs/tooling.md（按平台取行，跨行必须一致）；
//  2. 显式路径优先（AGENT_OPS_KUBECTL_BIN）；
//  3. 版本不符时**明确失败且不退回**——这是本轮要修的原始缺陷：
//     本机 PATH 上的 kubectl 是 v1.36.1，而登记的是 v1.31.4。

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFakeKubectl 生成一个只回吐固定 gitVersion 的假 kubectl（不联网、不依赖真二进制）。
func writeFakeKubectl(t *testing.T, gitVersion string) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "kubectl")
	body := "#!/bin/sh\necho '{\"clientVersion\":{\"gitVersion\":\"" + gitVersion + "\"}}'\n"
	if err := os.WriteFile(bin, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin
}

func TestPin_RegisteredVersionsComeFromToolingDoc(t *testing.T) {
	cases := []struct{ name, platform, want string }{
		{"kubectl", "linux/amd64", "v1.31.4"},
		{"kubectl", "darwin/arm64", "v1.31.4"},
		{"go", "linux/amd64", "1.27.2"},
		{"buf", "linux/amd64", "v1.47.2"},
		{"kind", "linux/amd64", "v0.30.0"},
	}
	for _, c := range cases {
		got, err := RegisteredVersionOn(c.name, c.platform)
		if err != nil {
			t.Fatalf("%s/%s 解析失败：%v", c.name, c.platform, err)
		}
		if got != c.want {
			t.Errorf("%s 在 %s 的登记版本应为 %s，实际 %s", c.name, c.platform, c.want, got)
		}
	}
	// 当前运行平台也必须能解析出来（否则测试会因"登记表没有本机行"而失败）。
	if v, err := RegisteredVersion("kubectl"); err != nil || v == "" {
		t.Fatalf("当前平台 kubectl 登记版本解析失败：%v（值 %q）", err, v)
	}
	t.Logf("[T2] 登记表解析：kubectl=v1.31.4 go=1.27.2 buf=v1.47.2 kind=v0.30.0")
}

func TestPin_UnknownToolFailsClosed(t *testing.T) {
	if _, err := RegisteredVersionOn("definitely-not-registered", "linux/amd64"); !errors.Is(err, ErrNotRegistered) {
		t.Fatalf("未登记的工具必须返回 ErrNotRegistered，实际 err=%v", err)
	}
	// 只有别的平台有行时也必须失败（不能拿别的平台的版本蒙过去）。
	if _, err := RegisteredVersionOn("go", "windows/arm64"); err == nil {
		t.Fatal("go 未登记 windows/arm64，必须失败")
	}
	t.Log("[T2] 未登记/平台缺失一律 fail-closed")
}

func TestPin_EnvPathWins(t *testing.T) {
	want, err := RegisteredVersion("kubectl")
	if err != nil {
		t.Fatal(err)
	}
	bin := writeFakeKubectl(t, want)
	t.Setenv(KubectlBinEnv, bin)

	got, version, err := PinnedKubectl()
	if err != nil {
		t.Fatalf("显式路径 + 版本相符应成功：%v", err)
	}
	if got != bin {
		t.Fatalf("应使用 %s（%s），实际 %s", bin, KubectlBinEnv, got)
	}
	if version != want {
		t.Fatalf("返回版本应为登记值 %s，实际 %s", want, version)
	}
	t.Logf("[T2] 显式路径优先并被接受：%s（%s）", got, version)
}

func TestPin_VersionMismatchFailsAndDoesNotFallBack(t *testing.T) {
	want, err := RegisteredVersion("kubectl")
	if err != nil {
		t.Fatal(err)
	}
	wrong := writeFakeKubectl(t, "v9.99.9")
	// 下一个候选**故意是版本相符的**：证明"版本不符"时不会顺延到它（那是静默退回）。
	good := writeFakeKubectl(t, want)

	path, version, err := resolveKubectl(want, []cand{{"fake-wrong", wrong}, {"fake-good", good}})
	if err == nil {
		t.Fatalf("版本不符必须失败，却返回了 path=%q version=%q", path, version)
	}
	if !strings.Contains(err.Error(), "不一致") {
		t.Fatalf("错误应说明版本不一致，实际：%v", err)
	}
	if path != "" {
		t.Fatalf("版本不符时不得返回任何路径（不得顺延），实际 %q", path)
	}
	t.Logf("[T2] 版本不符即失败（无顺延）：%v", err)
}

func TestPin_MissingPathFailsWithRemediation(t *testing.T) {
	want, err := RegisteredVersion("kubectl")
	if err != nil {
		t.Fatal(err)
	}
	// 所有候选都不存在：错误里必须带上"怎么办"（env 与 .tools 两个出路）。
	missing := filepath.Join(t.TempDir(), "nope")
	_, _, err = resolveKubectl(want, []cand{{KubectlBinEnv, missing}})
	if err == nil {
		t.Fatal("路径不存在必须失败")
	}
	for _, wantPart := range []string{KubectlBinEnv, ToolsDirName, want} {
		if !strings.Contains(err.Error(), wantPart) {
			t.Errorf("错误信息应包含修复线索 %q，实际：%v", wantPart, err)
		}
	}
	t.Logf("[T2] 缺路径时给出明确修复方式：%v", err)
}

func TestPin_EnvCandidateMissingFallsBackToNextSource(t *testing.T) {
	// 只有"该来源不存在"才允许顺延到下一个来源（与"版本不符即失败"形成对照）。
	want, err := RegisteredVersion("kubectl")
	if err != nil {
		t.Fatal(err)
	}
	good := writeFakeKubectl(t, want)
	path, version, err := resolveKubectl(want, []cand{
		{KubectlBinEnv, filepath.Join(t.TempDir(), "nope")},
		{"next", good},
	})
	if err != nil {
		t.Fatalf("来源不存在时应顺延到下一个相符候选：%v", err)
	}
	if path != good || version != want {
		t.Fatalf("应返回相符候选 %s（%s），实际 %s（%s）", good, want, path, version)
	}
	t.Logf("[T2] 不存在→顺延；版本不符→失败（两条路径分别验证）")
}

func TestPin_NormalizeAndPlatformDetection(t *testing.T) {
	if got := normalize(" **v1.47.2** "); got != "v1.47.2" {
		t.Errorf("normalize 应剥掉粗体与空白，实际 %q", got)
	}
	if got := normalize("v1.31.4 (darwin/arm64)"); got != "v1.31.4" {
		t.Errorf("normalize 应剥掉尾部括注，实际 %q", got)
	}
	if got := normalize("`https://x`"); got != "https://x" {
		t.Errorf("normalize 应剥掉反引号，实际 %q", got)
	}
	if !isPlatform("linux/amd64") || !isPlatform("darwin/arm64（本机实测）") {
		t.Error("平台行识别应接受 linux/amd64 与带括注的 darwin/arm64")
	}
	// URL 里含 linux/amd64，但**不是**以平台开头，不得被误判成平台列。
	if isPlatform("https://dl.k8s.io/release/v1.31.4/bin/linux/amd64/kubectl") {
		t.Error("URL 不应被识别为平台列")
	}
}
