package enrollclient

// D4 引导信任测试（第二十二轮）。
//
// 断言的核心是"**令牌只在服务端校验通过之后才发送**"：
// 当服务端证书非本 CA 签发、或服务端名称不匹配时，客户端必须在 TLS 握手阶段失败，
// 且**冒充的服务端收到的 Enroll 请求数必须为 0**。

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	contractv1 "github.com/XZ-libin/agent-ops/contract/gen/go/agent_ops/contract/v1"
	"github.com/XZ-libin/agent-ops/internal/nodeidentity"
)

// fixedNow 测试固定时钟。
var fixedNow = time.Unix(1791825000, 0).UTC()

// countingServer 记录收到的 Enroll / Heartbeat 次数（冒充服务端也用它计数）。
type countingServer struct {
	contractv1.UnimplementedNodeAgentServer
	enrolls    int64
	heartbeats int64
	// enrollFn 可注入的注册处理（nil 时返回固定成功响应）。
	enrollFn func(*contractv1.EnrollRequest) (*contractv1.EnrollResponse, error)
}

func (s *countingServer) Enroll(_ context.Context, req *contractv1.EnrollRequest) (*contractv1.EnrollResponse, error) {
	atomic.AddInt64(&s.enrolls, 1)
	if s.enrollFn != nil {
		return s.enrollFn(req)
	}
	return &contractv1.EnrollResponse{NodeId: "nod_01M4RHFDJ00000000000000000"}, nil
}

func (s *countingServer) Heartbeat(context.Context, *contractv1.HeartbeatRequest) (*contractv1.HeartbeatResponse, error) {
	atomic.AddInt64(&s.heartbeats, 1)
	return &contractv1.HeartbeatResponse{Status: contractv1.NodeStatus_NODE_STATUS_ONLINE}, nil
}

func (s *countingServer) enrollCount() int64    { return atomic.LoadInt64(&s.enrolls) }
func (s *countingServer) heartbeatCount() int64 { return atomic.LoadInt64(&s.heartbeats) }

// startTLSServer 用给定 CA 的服务端证书启动 mTLS gRPC 服务。
func startTLSServer(t *testing.T, ca *nodeidentity.TestCA, sans []string) (string, *countingServer) {
	t.Helper()
	cert, err := ca.IssueServerCert(fixedNow, sans, nil)
	if err != nil {
		t.Fatalf("签发服务端证书失败：%v", err)
	}
	tlsCert := tls.Certificate{
		Certificate: [][]byte{cert.CertificateDER},
		PrivateKey:  cert.PrivateKey,
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	})))
	cs := &countingServer{}
	contractv1.RegisterNodeAgentServer(srv, cs)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return lis.Addr().String(), cs
}

// newCA 生成测试 CA（7 天有效期、CA 自身 30 天）。
func newCA(t *testing.T) *nodeidentity.TestCA {
	t.Helper()
	ca, err := nodeidentity.NewTestCA(nodeidentity.CAConfig{
		Now: fixedNow, CAValidity: 30 * 24 * time.Hour,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

// nodeKey 生成节点私钥。
func nodeKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := nodeidentity.NewNodeKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// TestD4ImpersonatingServerReceivesZeroEnrolls（D4 ①）服务端证书由**其他 CA** 签发 →
// 节点拒绝连接，冒充服务端收到的 Enroll 请求数为 0。
func TestD4ImpersonatingServerReceivesZeroEnrolls(t *testing.T) {
	trustedCA := newCA(t)
	impostorCA := newCA(t)

	addr, impostor := startTLSServer(t, impostorCA, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// 客户端只信任 trustedCA，且服务端名称用默认 SAN（127.0.0.1）。
	cli, err := Dial(ctx, Config{
		ServerAddr:   addr,
		ServerName:   "127.0.0.1",
		CABundlePEM:  nodeidentity.CertificatePEM(trustedCA.CertificateDER()),
		NodeKey:      nodeKey(t),
		DisplayLabel: "d4-impostor",
		DialTimeout:  2 * time.Second,
	})
	if err == nil {
		_ = cli.Close()
		t.Fatal("其他 CA 签发的服务端证书必须被拒绝")
	}
	if !errors.Is(err, ErrHandshakeFailed) {
		t.Fatalf("应为握手失败（ErrHandshakeFailed），实际 %v", err)
	}
	if n := impostor.enrollCount(); n != 0 {
		t.Fatalf("冒充服务端收到的 Enroll 请求数必须为 0，实际 %d", n)
	}
	if n := impostor.heartbeatCount(); n != 0 {
		t.Fatalf("冒充服务端收到的 Heartbeat 请求数必须为 0，实际 %d", n)
	}
	t.Logf("[D4①] 其他 CA 签发 → 握手失败，冒充服务端 Enroll 请求数=0（%v）", err)
}

// TestD4ServerNameMismatchReceivesZeroEnrolls（D4 ②）服务端名称与 SAN 不匹配 →
// 拒绝，服务端收到的 Enroll 请求数为 0。
func TestD4ServerNameMismatchReceivesZeroEnrolls(t *testing.T) {
	ca := newCA(t)
	// 服务端证书 SAN 只有 127.0.0.1/localhost；客户端却期望别的名称。
	addr, srv := startTLSServer(t, ca, []string{"127.0.0.1", "localhost"})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cli, err := Dial(ctx, Config{
		ServerAddr:   addr,
		ServerName:   "control-plane.example", // 不在 SAN 中
		CABundlePEM:  nodeidentity.CertificatePEM(ca.CertificateDER()),
		NodeKey:      nodeKey(t),
		DisplayLabel: "d4-name-mismatch",
		DialTimeout:  2 * time.Second,
	})
	if err == nil {
		_ = cli.Close()
		t.Fatal("服务端名称不匹配必须被拒绝")
	}
	if n := srv.enrollCount(); n != 0 {
		t.Fatalf("名称不匹配时服务端收到的 Enroll 请求数必须为 0，实际 %d", n)
	}
	// 反向验证：SAN 里没有的名称必须拒绝，而 SAN 里有的必须接受（对照组）。
	if _, err := Dial(ctx, Config{
		ServerAddr: addr, ServerName: "localhost",
		CABundlePEM: nodeidentity.CertificatePEM(ca.CertificateDER()),
		NodeKey:     nodeKey(t), DialTimeout: 2 * time.Second,
	}); err != nil {
		t.Fatalf("SAN 中的名称 localhost 应可连接：%v", err)
	}
	t.Logf("[D4②] 名称不匹配 → 握手失败且 Enroll 请求数=0；对照组 localhost 连接成功")
}

// TestD4CorrectServerEnrolls（D4 ③）服务端证书正确 → 注册成功，令牌送达。
func TestD4CorrectServerEnrolls(t *testing.T) {
	ca := newCA(t)
	addr, srv := startTLSServer(t, ca, nil)
	const wantNodeID = "nod_01M4RHFDJ00000000000000000"
	srv.enrollFn = func(req *contractv1.EnrollRequest) (*contractv1.EnrollResponse, error) {
		// 断言请求内容符合 D2：CSR 是纯持有性证明、display_label 只作展示。
		if len(req.GetCsrDer()) == 0 {
			t.Error("Enroll 请求必须携带 CSR")
		}
		if req.GetDisplayLabel() != "d4-ok" {
			t.Errorf("display_label 应原样传递：%q", req.GetDisplayLabel())
		}
		// 真实签发：客户端会把这张证书装载进内存并重建 mTLS 连接，
		// 因此这里必须是**可解析的真实证书**（不能是占位字节）。
		certDER, _, err := ca.SignCSR(req.GetCsrDer(), wantNodeID, fixedNow, nil)
		if err != nil {
			return nil, err
		}
		return &contractv1.EnrollResponse{
			NodeId:                   wantNodeID,
			CertificateDer:           certDER,
			CaCertificateDer:         ca.CertificateDER(),
			HeartbeatIntervalSeconds: 10,
		}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cli, err := Dial(ctx, Config{
		ServerAddr:   addr,
		ServerName:   "127.0.0.1",
		CABundlePEM:  nodeidentity.CertificatePEM(ca.CertificateDER()),
		NodeKey:      nodeKey(t),
		DisplayLabel: "d4-ok",
		AgentVersion: "0.21.0-test",
		DialTimeout:  2 * time.Second,
	})
	if err != nil {
		t.Fatalf("正确服务端应可连接：%v", err)
	}
	defer func() { _ = cli.Close() }()

	res, err := cli.Enroll(ctx, "one-time-token-abcdef")
	if err != nil {
		t.Fatalf("注册应成功：%v", err)
	}
	if res.NodeID != wantNodeID {
		t.Fatalf("应返回分配的 node_id，实际 %q", res.NodeID)
	}
	if len(res.CertificateDER) == 0 {
		t.Fatal("注册响应必须携带证书（客户端据此重建 mTLS 连接）")
	}
	if res.HeartbeatInterval != 10*time.Second {
		t.Fatalf("心跳间隔应为 10s，实际 %s", res.HeartbeatInterval)
	}
	if srv.enrollCount() != 1 {
		t.Fatalf("正确服务端应收到恰好 1 次 Enroll，实际 %d", srv.enrollCount())
	}
	t.Logf("[D4③] 正确服务端：注册成功 node_id=%s（服务端 Enroll 计数=1）", res.NodeID)
}

// TestD4ConfigGuards（D4）缺 CA 包 / 缺服务端名称 → 拒绝（不允许退回系统根或不校验名称）。
func TestD4ConfigGuards(t *testing.T) {
	ctx := context.Background()
	key := nodeKey(t)
	if _, err := Dial(ctx, Config{ServerAddr: "127.0.0.1:1", ServerName: "x", NodeKey: key}); !errors.Is(err, ErrNoTrustAnchor) {
		t.Fatalf("缺 CA 包必须拒绝（ErrNoTrustAnchor），实际 %v", err)
	}
	if _, err := Dial(ctx, Config{ServerAddr: "127.0.0.1:1", NodeKey: key, CABundlePEM: []byte("x")}); !errors.Is(err, ErrServerNameRequired) {
		t.Fatalf("缺服务端名称必须拒绝（ErrServerNameRequired），实际 %v", err)
	}
	if _, err := Dial(ctx, Config{ServerAddr: "127.0.0.1:1", ServerName: "x", NodeKey: key, CABundlePEM: []byte("not-pem")}); err == nil {
		t.Fatal("非法 CA 包必须拒绝")
	} else if !strings.Contains(err.Error(), "CA 包") {
		t.Fatalf("错误应说明 CA 包问题：%v", err)
	}
	t.Log("[D4] 缺 CA 包 / 缺服务端名称 / 非法 CA 包 → 一律拒绝（fail-closed）")
}
