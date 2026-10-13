package gateway

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"

	contractv1 "github.com/XZ-libin/agent-ops/contract/gen/go/agent_ops/contract/v1"

	"github.com/XZ-libin/agent-ops/adapters/linux"
	"github.com/XZ-libin/agent-ops/internal/exec"
	"github.com/XZ-libin/agent-ops/internal/exec/ssh"
	"github.com/XZ-libin/agent-ops/internal/exec/ssh/sshdtest"
	"github.com/XZ-libin/agent-ops/internal/idempotency"
)

// TestGatewayIntegrationSSHD 网关端到端集成测试（D3）：
// Docker 可用则真跑本地 sshd 容器（临时密钥、127.0.0.1 随机端口，
// 不连接真实服务器、不使用真实凭据）；不可用则 skip 并输出原因。
// 断言：
//  1. 只读 capability（diagnose.disk_usage）经 策略→幂等→执行→审计 全链路
//     真实执行（SSH 调用数 > 0），同键重放不再执行；
//  2. destructive=true 的请求在网关层直接拒绝（第八轮约束 4），
//     SSH 层调用计数不变——破坏性操作未到达 SSH 层。
func TestGatewayIntegrationSSHD(t *testing.T) {
	sshd := sshdtest.StartLocalSSHD(t)

	// 真实 SSH Runner + 调用计数器。
	inner, err := ssh.New(ssh.Options{
		Addr:    sshd.Addr,
		User:    sshd.User,
		Signer:  sshd.Signer,
		HostKey: sshd.HostKey,
	})
	if err != nil {
		t.Fatalf("构建 SSH Runner 失败：%v", err)
	}
	t.Cleanup(func() { _ = inner.Close() })
	counter := &countingRunner{inner: inner}

	adapter, err := linux.New(counter)
	if err != nil {
		t.Fatalf("构建 Linux 适配器失败：%v", err)
	}

	af := &fakeAudit{}
	reg := NewRegistry()
	svc, err := New(DefaultConfig(), idempotency.NewMemoryStore(), af, newFakeApprovals(), reg)
	if err != nil {
		t.Fatalf("组装网关失败：%v", err)
	}
	// 注册只读诊断能力（linuxwire 等价的最小接线；linuxwire 路由逻辑由
	// internal/linuxwire 单测覆盖，此处避免测试包循环引用）。
	diagnoseDiskUsage := func(ctx context.Context, req Request) (*contractv1.ActionResult, error) {
		insts, err := adapter.Discover(ctx, req.Action.Target)
		if err != nil {
			return nil, err
		}
		diag, err := adapter.Diagnose(ctx, insts[0], linux.QuestionDiskUsage)
		if err != nil {
			return nil, err
		}
		return &contractv1.ActionResult{Success: true, Outputs: []*contractv1.OutputChunk{
			{Stream: "diagnosis", Content: diag.Conclusion},
		}}, nil
	}
	if err := reg.Register(&contractv1.Capability{
		Name: "diagnose.disk_usage", RiskTier: contractv1.RiskTier_RISK_TIER_READ_ONLY,
		Rollbackable: true, Timeout: durationpb.New(60 * time.Second),
	}, diagnoseDiskUsage); err != nil {
		t.Fatal(err)
	}
	// 仅测试：破坏性能力声明（现有生产清单无 destructive 能力，
	// 为断言「destructive 未到达 SSH 层」专用）。
	if err := reg.Register(&contractv1.Capability{
		Name: "test.destroy.disk", RiskTier: contractv1.RiskTier_RISK_TIER_READ_ONLY,
		Rollbackable: true, Destructive: true, // 仅测试
		Timeout: durationpb.New(60 * time.Second),
	}, diagnoseDiskUsage); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	req := Request{
		Actor:          "ops-lead",
		IdempotencyKey: "itest-disk-usage",
		Action: &contractv1.Action{
			Capability: "diagnose.disk_usage",
			Target:     &contractv1.AssetTarget{AssetId: "ast_itest", Access: contractv1.AccessKind_ACCESS_SSH},
		},
		Environment: contractv1.Environment_ENVIRONMENT_TEST,
	}

	// 1) 只读能力真实执行：容器内 uname/cat(df -P) 经 sshd 跑完。
	resp, err := svc.Execute(ctx, req)
	if err != nil {
		t.Fatalf("执行失败：%v", err)
	}
	if resp.Status != StatusSuccess {
		t.Fatalf("应执行成功：%+v", resp)
	}
	if n := counter.Count(); n == 0 {
		t.Fatal("执行未到达 SSH 层：调用计数为 0")
	}
	out := ""
	for _, o := range resp.Result.Outputs {
		out += o.Content
	}
	if !strings.Contains(out, "根分区使用率") {
		t.Fatalf("诊断结论缺失：%q", out)
	}

	// 同键重放：SSH 调用数不再增长。
	before := counter.Count()
	if _, err := svc.Execute(ctx, req); err != nil {
		t.Fatal(err)
	}
	if after := counter.Count(); after != before {
		t.Fatalf("同键重放不得再执行：before=%d after=%d", before, after)
	}

	// 2) destructive 请求未到达 SSH 层（约束 4 的 SSH 层断言）。
	before = counter.Count()
	denied, err := svc.Execute(ctx, Request{
		Actor:          "ops-lead",
		IdempotencyKey: "itest-destroy",
		Action: &contractv1.Action{
			Capability: "test.destroy.disk",
			Target:     &contractv1.AssetTarget{AssetId: "ast_itest", Access: contractv1.AccessKind_ACCESS_SSH},
		},
		Environment: contractv1.Environment_ENVIRONMENT_TEST,
	})
	if err != nil {
		t.Fatal(err)
	}
	if denied.Status != StatusDenied {
		t.Fatalf("destructive 应被拒绝：%+v", denied)
	}
	if after := counter.Count(); after != before {
		t.Fatalf("destructive 请求到达了 SSH 层：before=%d after=%d", before, after)
	}
	if len(denied.ApprovalID) != 0 {
		t.Fatalf("destructive 不得进入审批：%+v", denied)
	}
	// 审计断言：deny 决策已写入。
	found := false
	for _, a := range af.actions() {
		if a == "gateway.decision" {
			found = true
		}
	}
	if !found {
		t.Fatal("决策审计缺失")
	}
}

// countingRunner 包装 exec.Runner 统计 Run 调用次数（断言"未到达 SSH 层"）。
type countingRunner struct {
	mu    sync.Mutex
	inner exec.Runner
	n     int
}

func (c *countingRunner) Run(ctx context.Context, argv []string, opts exec.RunOptions) (exec.Result, error) {
	c.mu.Lock()
	c.n++
	c.mu.Unlock()
	return c.inner.Run(ctx, argv, opts)
}

// Count 已发生的 Run 调用次数。
func (c *countingRunner) Count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}
