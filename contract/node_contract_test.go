package contract

// 节点契约边界测试（第二十一轮 N1；第二十三轮 T1 扩展 Renew）。
//
// 本文件把"节点只做注册/心跳/续期、不接收任何命令"从文档约定变成**可执行断言**：
//   - 服务描述符里**恰好** Enroll / Heartbeat / Renew 三个方法；
//   - 不存在任何命令/执行类方法（Execute / Run / Command / Shell / Deploy / ...）；
//   - 未定义的方法由 gRPC 运行时返回 UNIMPLEMENTED（用 bufconn 实测）；
//   - 契约里没有任何私钥字段（硬性约束 7）。

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/reflect/protoreflect"

	contractv1 "github.com/XZ-libin/agent-ops/contract/gen/go/agent_ops/contract/v1"
)

// nodeServiceFullName NodeAgent 服务的全名（gRPC 方法路径用）。
const nodeServiceFullName = "agent_ops.contract.v1.NodeAgent"

// nodeAgentMethods 本服务允许存在的方法集合（第二十三轮：新增 Renew）。
var nodeAgentMethods = map[string]bool{"Enroll": true, "Heartbeat": true, "Renew": true}

// commandLikeTokens 任何"命令/执行"语义的方法名片段（出现即视为越界）。
//
// 说明：Renew 不在其中——它是**证书生命周期**操作，不是命令通道；
// 且它的请求体只有 CSR，不含任何可执行内容（见 proto 注释）。
var commandLikeTokens = []string{
	"execute", "run", "command", "shell", "exec", "deploy", "apply", "install",
	"start", "stop", "restart", "kill", "write", "delete", "update", "patch",
}

// TestNodeContractExposesOnlyEnrollAndHeartbeat（N1）服务只暴露注册与心跳。
func TestNodeContractExposesOnlyEnrollAndHeartbeat(t *testing.T) {
	md := contractv1.File_agent_ops_contract_v1_node_proto.Services().ByName("NodeAgent")
	if md == nil {
		t.Fatal("未找到 NodeAgent 服务定义")
	}
	if md.FullName() != nodeServiceFullName {
		t.Fatalf("服务全名不符：%s", md.FullName())
	}
	got := map[string]bool{}
	for i := 0; i < md.Methods().Len(); i++ {
		name := string(md.Methods().Get(i).Name())
		got[name] = true
		if lower := strings.ToLower(name); containsToken(lower, commandLikeTokens) {
			t.Errorf("[N1] 服务不得包含命令/执行类方法：%s", name)
		}
	}
	if len(got) != len(nodeAgentMethods) {
		t.Fatalf("服务方法集合必须恰好是 %v，实际 %v", keysOf(nodeAgentMethods), keysOf(got))
	}
	for m := range nodeAgentMethods {
		if !got[m] {
			t.Fatalf("服务必须包含方法 %s，实际 %v", m, keysOf(got))
		}
	}
	t.Logf("[N1] NodeAgent 只暴露 %v（无任何命令/执行类方法）", keysOf(got))
}

// TestNodeContractHasNoPrivateKeyFields（N1 硬性约束 7）契约中不得有私钥字段。
func TestNodeContractHasNoPrivateKeyFields(t *testing.T) {
	msgs := []string{
		"EnrollRequest", "EnrollResponse", "HeartbeatRequest", "HeartbeatResponse",
		"NodeLoadSummary", "RenewRequest", "RenewResponse",
	}
	for _, name := range msgs {
		md := contractv1.File_agent_ops_contract_v1_node_proto.Messages().ByName(protoreflect.Name(name))
		if md == nil {
			t.Fatalf("未找到消息定义：%s", name)
		}
		for i := 0; i < md.Fields().Len(); i++ {
			field := strings.ToLower(string(md.Fields().Get(i).Name()))
			for _, bad := range []string{"private", "secret", "password", "token_hash"} {
				if strings.Contains(field, bad) {
					t.Errorf("[N1] 消息 %s 不得包含字段 %q（硬性约束 7）", name, field)
				}
			}
		}
	}
	t.Log("[N1] 节点契约不含任何私钥/口令字段（仅 enrollment_token 明文一次）")
}

// TestNodeServerBoundaryUnimplemented（N1）经真实 gRPC（bufconn，进程内）验证：
// 未定义的方法一律 UNIMPLEMENTED；本测试用的是**未接线**的空服务实现，
// 因此已定义的三个方法也返回 UNIMPLEMENTED（fail-closed：不存在"忘记拒绝"的路径）。
func TestNodeServerBoundaryUnimplemented(t *testing.T) {
	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	// 只注册"未实现"服务：本轮不接线任何业务逻辑（设计 + 纯单元范围）。
	contractv1.RegisterNodeAgentServer(srv, contractv1.UnimplementedNodeAgentServer{})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("建立 bufconn 连接失败：%v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	client := contractv1.NewNodeAgentClient(conn)

	// 已定义但未接线的三个方法 → UNIMPLEMENTED。
	if _, err := client.Enroll(ctx, &contractv1.EnrollRequest{}); status.Code(err) != codes.Unimplemented {
		t.Fatalf("Enroll 未接线时应返回 UNIMPLEMENTED，实际 %v", err)
	}
	if _, err := client.Heartbeat(ctx, &contractv1.HeartbeatRequest{}); status.Code(err) != codes.Unimplemented {
		t.Fatalf("Heartbeat 未接线时应返回 UNIMPLEMENTED，实际 %v", err)
	}
	if _, err := client.Renew(ctx, &contractv1.RenewRequest{}); status.Code(err) != codes.Unimplemented {
		t.Fatalf("Renew 未接线时应返回 UNIMPLEMENTED，实际 %v", err)
	}

	// 未定义的方法（命令类语义）→ UNIMPLEMENTED。
	for _, method := range []string{"Execute", "RunCommand", "Shell", "Deploy"} {
		path := "/" + nodeServiceFullName + "/" + method
		var out contractv1.NodeLoadSummary
		err := conn.Invoke(ctx, path, &contractv1.NodeLoadSummary{}, &out)
		if status.Code(err) != codes.Unimplemented {
			t.Fatalf("未定义方法 %s 必须返回 UNIMPLEMENTED，实际 %v", path, err)
		}
	}
	t.Log("[N1] bufconn 实测：Enroll/Heartbeat/Renew 未接线→UNIMPLEMENTED；Execute/RunCommand/Shell/Deploy 未定义→UNIMPLEMENTED")
}

// containsToken 判定 s 是否含任一 token。
func containsToken(s string, tokens []string) bool {
	for _, tk := range tokens {
		if strings.Contains(s, tk) {
			return true
		}
	}
	return false
}

// keysOf 返回集合键（升序，便于稳定输出）。
func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
