package linux

import (
	"context"
	"testing"

	contractv1 "github.com/XZ-libin/agent-ops/contract/gen/go/agent_ops/contract/v1"

	"github.com/XZ-libin/agent-ops/internal/exec/ssh"
	"github.com/XZ-libin/agent-ops/internal/exec/ssh/sshdtest"
)

// TestLinuxAdapterIntegration 本地 sshd 容器集成测试（D3）：
// Docker 可用则真跑——临时密钥对、127.0.0.1 随机端口，不连接真实服务器、
// 不使用真实凭据；不可用则 skip 并输出原因（skip 不计入通过，见 sshdtest）。
// 通过真实 SSH 走一遍 Discover/Health/Diagnose（只读能力）。
func TestLinuxAdapterIntegration(t *testing.T) {
	sshd := sshdtest.StartLocalSSHD(t)

	runner, err := ssh.New(ssh.Options{
		Addr:    sshd.Addr,
		User:    sshd.User,
		Signer:  sshd.Signer,
		HostKey: sshd.HostKey,
	})
	if err != nil {
		t.Fatalf("构建 SSH Runner 失败：%v", err)
	}
	t.Cleanup(func() { _ = runner.Close() })

	a, err := New(runner)
	if err != nil {
		t.Fatalf("构建适配器失败：%v", err)
	}
	ctx := context.Background()
	target := &contractv1.AssetTarget{AssetId: "ast_itest"}

	// Discover：内核版本与发行版。
	insts, err := a.Discover(ctx, target)
	if err != nil {
		t.Fatalf("Discover 失败：%v", err)
	}
	if len(insts) != 1 || insts[0].Version == "" {
		t.Fatalf("Discover 应返回 1 个带版本号的实例，got %v", insts)
	}
	instance := insts[0]

	// Health：状态必须落在合法取值集合内。
	rep, err := a.Health(ctx, instance)
	if err != nil {
		t.Fatalf("Health 失败：%v", err)
	}
	switch rep.Status {
	case "healthy", "degraded", "unhealthy", "unknown":
	default:
		t.Fatalf("Health 状态不合法：%q", rep.Status)
	}

	// Diagnose：根分区使用率（容器内 df -P 真实执行）。
	diag, err := a.Diagnose(ctx, instance, QuestionDiskUsage)
	if err != nil {
		t.Fatalf("Diagnose(%s) 失败：%v", QuestionDiskUsage, err)
	}
	if diag == nil || len(diag.Findings) == 0 || len(diag.Findings[0].EvidenceRefs) == 0 {
		t.Fatalf("诊断必须附证据引用：%+v", diag)
	}
}
