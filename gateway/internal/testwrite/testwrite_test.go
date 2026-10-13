package testwrite

import (
	"context"
	"strings"
	"sync"
	"testing"

	"google.golang.org/protobuf/types/known/structpb"

	contractv1 "github.com/XZ-libin/agent-ops/contract/gen/go/agent_ops/contract/v1"

	"github.com/XZ-libin/agent-ops/gateway/internal/gateway"
	"github.com/XZ-libin/agent-ops/internal/exec"
)

// fakeRunner 记录 argv 调用的最小 Runner（不执行真实命令）。
type fakeRunner struct {
	mu    sync.Mutex
	calls [][]string
}

func (f *fakeRunner) Run(_ context.Context, argv []string, _ exec.RunOptions) (exec.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, append([]string{}, argv...))
	return exec.Result{ExitCode: 0}, nil
}

func (f *fakeRunner) joined() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := ""
	for _, c := range f.calls {
		out += strings.Join(c, " ") + ";"
	}
	return out
}

// TestWriteDeleteMarkerArgs 写/删标记文件的 argv 白名单：
// write = mkdir -p <dir> + touch -- <dir>/agent-ops-marker-<id>；
// delete = rm -- <path>；路径固定拼接，不接受任意路径。
func TestWriteDeleteMarkerArgs(t *testing.T) {
	r := &fakeRunner{}
	a := New(r)
	ctx := context.Background()

	if err := a.WriteMarker(ctx, "round9flag1"); err != nil {
		t.Fatal(err)
	}
	if err := a.DeleteMarker(ctx, "round9flag1"); err != nil {
		t.Fatal(err)
	}
	joined := r.joined()
	want := []string{
		"mkdir -p /tmp/agent-ops-test",
		"touch -- /tmp/agent-ops-test/agent-ops-marker-round9flag1",
		"rm -- /tmp/agent-ops-test/agent-ops-marker-round9flag1",
	}
	for _, w := range want {
		if !strings.Contains(joined, w) {
			t.Fatalf("缺少命令 %q：%s", w, joined)
		}
	}
}

// TestMarkerIDValidation 标识符校验（fail-closed）：不接受任意路径/逃逸。
func TestMarkerIDValidation(t *testing.T) {
	a := New(&fakeRunner{})
	valid := []string{"a", "round9flag1", "0123456789abcdef0123456789abcd"}
	invalid := []string{"", "A/B", "a b", "a;b", "../etc", "a-b", "UPPER", "a" + strings.Repeat("b", 33)}
	for _, id := range valid {
		if err := a.WriteMarker(context.Background(), id); err != nil {
			t.Errorf("应为合法标识符 %q：%v", id, err)
		}
	}
	for _, id := range invalid {
		if err := a.WriteMarker(context.Background(), id); err == nil {
			t.Errorf("应拒绝非法标识符 %q", id)
		}
	}
}

// TestPlanRollback 写标记的回滚计划 = 删除标记（B 项要求）。
func TestPlanRollback(t *testing.T) {
	a := New(&fakeRunner{})
	params, _ := structpbFor("marker-1")
	record := &contractv1.ActionRecord{
		Action: &contractv1.Action{Capability: CapWriteMarker, Params: params},
		Target: &contractv1.AssetTarget{AssetId: "ast_itest"},
	}
	plan, err := a.PlanRollback(record)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan) != 1 || plan[0].Capability != CapDeleteMarker {
		t.Fatalf("回滚计划应为删除标记动作：%+v", plan)
	}
	gotMarker, _ := plan[0].Params.AsMap()["marker"].(string)
	if gotMarker != "marker-1" {
		t.Fatalf("回滚应携带原 marker 标识：%q", gotMarker)
	}
}

// TestRegisterProdRejectsTestOnly 生产注册表拒绝 test_only 声明（约束 5/6）。
func TestRegisterProdRejectsTestOnly(t *testing.T) {
	prod := gateway.NewRegistry()
	if err := Register(prod, &fakeRunner{}); err == nil {
		t.Fatal("test_only 能力在生产注册表必须被拒绝")
	}
	if _, ok := prod.Lookup(CapWriteMarker); ok {
		t.Fatal("测试写能力在生产注册表不得可见")
	}

	testReg := gateway.NewTestRegistry() // 仅测试
	if err := Register(testReg, &fakeRunner{}); err != nil {
		t.Fatalf("测试注册表应可加载：%v", err)
	}
	if _, ok := testReg.Lookup(CapWriteMarker); !ok {
		t.Fatal("测试注册表应可见 test.write.marker")
	}
	// 清单声明的 TestOnly 必须为 true（防清单被误改成生产能力）。
	for _, name := range []string{CapWriteMarker, CapDeleteMarker} {
		entry, _ := testReg.Lookup(name)
		if !entry.Decl.TestOnly || entry.Decl.Destructive {
			t.Fatalf("能力 %s 声明不符（须 test_only=true, destructive=false）：%+v", name, entry.Decl)
		}
	}
}

func structpbFor(marker string) (*structpb.Struct, error) {
	return structpb.NewStruct(map[string]any{"marker": marker})
}
