// Package testwrite 是仅测试目录的写能力实现（第九轮 B 项 + 约束 5/6）：
//
//   - test.write.marker：在目标（sshd 测试容器）的 /tmp/agent-ops-test/ 下
//     写入带固定前缀（agent-ops-marker-）的标记文件；
//   - test.write.marker.delete：删除该标记文件，二者互为回滚
//     （各自 PlanRollback 返回对方动作）。
//
// 两个能力的声明均带 test_only: true（见 manifest.yaml）：
// 生产注册表（gateway.NewRegistry）拒绝加载——生产目录中不存在任何写能力；
// 只有测试配置（NewTestRegistry）可加载。
//
// 安全约束：
//   - 路径不接受任意输入：标识符须匹配 ^[a-z0-9]{1,32}$，最终路径由本包
//     固定拼接（/tmp/agent-ops-test/agent-ops-marker-<id>），并过
//     validation.ValidAbsUnixPath 校验（fail-closed）；
//   - 命令一律 argv 形式（mkdir -p / touch / rm），禁止 shell 拼接。
package testwrite

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"
	"gopkg.in/yaml.v3"

	contractv1 "github.com/XZ-libin/agent-ops/contract/gen/go/agent_ops/contract/v1"

	"github.com/XZ-libin/agent-ops/gateway/internal/gateway"
	"github.com/XZ-libin/agent-ops/internal/exec"
	"github.com/XZ-libin/agent-ops/internal/validation"
)

//go:embed manifest.yaml
var manifestYAML []byte

// 能力名（仅测试目录）。
const (
	// CapWriteMarker 写入测试标记文件。
	CapWriteMarker = "test.write.marker"
	// CapDeleteMarker 删除测试标记文件。
	CapDeleteMarker = "test.write.marker.delete"
)

// markerDir 标记文件目录（仅测试容器内）。
const markerDir = "/tmp/agent-ops-test"

// markerPrefix 标记文件名固定前缀。
const markerPrefix = "agent-ops-marker-"

// markerIDPattern 标记标识符：小写字母/数字，1~32 位（不接受任意路径）。
var markerIDPattern = regexp.MustCompile(`^[a-z0-9]{1,32}$`)

// manifestCapability 清单能力声明（本包所需字段）。
type manifestCapability struct {
	Name         string `yaml:"name"`
	RiskTier     string `yaml:"risk_tier"`
	Destructive  bool   `yaml:"destructive"`
	Rollbackable bool   `yaml:"rollbackable"`
	Idempotent   bool   `yaml:"idempotent"`
	TestOnly     bool   `yaml:"test_only"`
	Timeout      string `yaml:"timeout"`
}

type manifestFile struct {
	Name         string               `yaml:"name"`
	Capabilities []manifestCapability `yaml:"capabilities"`
}

// Adapter 测试写能力适配器（仅测试目录；实现写路径的最小验证逻辑）。
type Adapter struct {
	runner exec.Runner
}

// New 构建测试写适配器。
func New(r exec.Runner) *Adapter { return &Adapter{runner: r} }

// markerPath 由固定目录 + 固定前缀 + 已校验标识符拼接（不接受任意路径）。
func markerPath(markerID string) string {
	return markerDir + "/" + markerPrefix + markerID
}

// MarkerPath 标记文件最终路径（导出供集成测试断言容器内的落盘结果；
// 路径拼装规则仍由本包唯一持有，调用方不得自行拼装）。
func MarkerPath(markerID string) string { return markerPath(markerID) }

// validateMarker 校验标识符与最终路径（fail-closed）。
func validateMarker(markerID string) (string, error) {
	if !markerIDPattern.MatchString(markerID) {
		return "", fmt.Errorf("testwrite：marker 标识符不合法（须 ^[a-z0-9]{1,32}$）：%q", markerID)
	}
	p := markerPath(markerID)
	if !strings.HasPrefix(p, markerDir+"/") || !validation.ValidAbsUnixPath(p) {
		return "", fmt.Errorf("testwrite：marker 路径校验失败（不接受任意路径）：%q", p)
	}
	return p, nil
}

// run 执行一条命令并检查退出码（argv 形式）。
func (a *Adapter) run(ctx context.Context, argv ...string) error {
	res, err := a.runner.Run(ctx, argv, exec.RunOptions{Timeout: 60 * time.Second})
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("testwrite：命令 %q 退出 %d：%s", argv[0], res.ExitCode,
			strings.TrimSpace(string(res.Stderr)))
	}
	return nil
}

// WriteMarker 写入标记文件（mkdir -p 目录 + touch 文件，均为 argv）。
func (a *Adapter) WriteMarker(ctx context.Context, markerID string) error {
	path, err := validateMarker(markerID)
	if err != nil {
		return err
	}
	if err := a.run(ctx, "mkdir", "-p", markerDir); err != nil {
		return err
	}
	return a.run(ctx, "touch", "--", path)
}

// DeleteMarker 删除标记文件。
func (a *Adapter) DeleteMarker(ctx context.Context, markerID string) error {
	path, err := validateMarker(markerID)
	if err != nil {
		return err
	}
	return a.run(ctx, "rm", "--", path)
}

// PlanRollback 实现 test.write.marker 的回滚计划：删除该标记文件（B 项要求）。
// 输入 record 的 params 必须含带标记 ID 的 marker 字段。
func (a *Adapter) PlanRollback(record *contractv1.ActionRecord) ([]*contractv1.Action, error) {
	if record == nil || record.Action == nil {
		return nil, errors.New("testwrite：执行记录为空")
	}
	return []*contractv1.Action{{
		Capability: CapDeleteMarker,
		Params:     extractMarkerParam(record.Action.Params),
		Target:     record.Target,
		Expected:   "删除测试标记文件，恢复原状",
	}}, nil
}

// PlanRecreate 实现 test.write.marker.delete 的回滚计划：重新写入标记文件。
func (a *Adapter) PlanRecreate(record *contractv1.ActionRecord) ([]*contractv1.Action, error) {
	if record == nil || record.Action == nil {
		return nil, errors.New("testwrite：执行记录为空")
	}
	return []*contractv1.Action{{
		Capability: CapWriteMarker,
		Params:     extractMarkerParam(record.Action.Params),
		Target:     record.Target,
		Expected:   "重新写入测试标记文件（恢复回滚）",
	}}, nil
}

// extractMarkerParam 提取 params.marker（缺失时用空串让校验层拒绝）。
func extractMarkerParam(params *structpb.Struct) *structpb.Struct {
	marker := ""
	if params != nil {
		if v, ok := params.AsMap()["marker"].(string); ok {
			marker = v
		}
	}
	out, _ := structpb.NewStruct(map[string]any{"marker": marker})
	return out
}

// Register 把清单中的测试写能力注册进注册表（必须用 NewTestRegistry，
// 生产注册表会拒绝 test_only 声明——注册表守卫）。
func Register(reg *gateway.Registry, r exec.Runner) error {
	a := New(r)
	var mf manifestFile
	if err := yaml.Unmarshal(manifestYAML, &mf); err != nil {
		return fmt.Errorf("testwrite manifest: %w", err)
	}
	for _, c := range mf.Capabilities {
		timeout, err := parseTimeout(c.Timeout)
		if err != nil {
			return err
		}
		decl := &contractv1.Capability{
			Name:         c.Name,
			RiskTier:     contractv1.RiskTier_RISK_TIER_LOW,
			Idempotent:   c.Idempotent,
			Rollbackable: c.Rollbackable,
			Timeout:      durationpb.New(timeout),
			Destructive:  c.Destructive,
			TestOnly:     c.TestOnly,
		}
		var h gateway.Handler
		switch c.Name {
		case CapWriteMarker:
			h = a.markerHandler(true)
		case CapDeleteMarker:
			h = a.markerHandler(false)
		default:
			return fmt.Errorf("testwrite：未知能力 %q", c.Name)
		}
		if err := reg.Register(decl, h); err != nil {
			return err
		}
	}
	return nil
}

// markerHandler 写/删标记文件的 Handler。
func (a *Adapter) markerHandler(write bool) gateway.Handler {
	return func(ctx context.Context, req gateway.Request) (*contractv1.ActionResult, error) {
		if req.Action == nil || req.Action.Target == nil {
			return nil, errors.New("testwrite：目标资产缺失")
		}
		marker := ""
		if req.Action.Params != nil {
			marker, _ = req.Action.Params.AsMap()["marker"].(string)
		}
		var err error
		if write {
			err = a.WriteMarker(ctx, marker)
		} else {
			err = a.DeleteMarker(ctx, marker)
		}
		if err != nil {
			return nil, err
		}
		return &contractv1.ActionResult{Success: true}, nil
	}
}

// parseTimeout 解析清单超时（非法即报错，fail-closed）。
func parseTimeout(s string) (time.Duration, error) {
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("testwrite：超时无法解析 %q：%w", s, err)
	}
	return d, nil
}
