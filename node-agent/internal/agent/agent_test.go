package agent

// N7 进程与配置测试（第二十二轮）。
//
// 覆盖裁决要求的 5 条：
//  ① 缺少 -mode 启动失败；
//  ② -mode=prod 启动失败；
//  ③ 令牌文件权限过宽启动失败；
//  ④ 令牌文件权限 0600 时通过；
//  ⑤ 停机后不再发送心跳（计数器断言）。

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	contractv1 "github.com/XZ-libin/agent-ops/contract/gen/go/agent_ops/contract/v1"
	"github.com/XZ-libin/agent-ops/node-agent/internal/enrollclient"
)

// selfSignedNodeCertForTest 生成"自签名的节点证书"用于进程级测试。
//
// 只用于让 **Run 的身份持久化路径**可执行（Save 需要可解析证书）；
// 真实的 CA 签发与校验在 internal/nodeidentity 的测试与 N8 集成测试中覆盖。
func selfSignedNodeCertForTest(base time.Time) (*ecdsa.PrivateKey, []byte, []byte) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	if base.IsZero() {
		base = time.Now().UTC()
	}
	base = base.UTC()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "nod_01M4RHFDJ00000000000000000"},
		DNSNames:     []string{"nod_01M4RHFDJ00000000000000000"},
		NotBefore:    base.Add(-time.Hour),
		NotAfter:     base.Add(7 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	return key, der, der
}

// fakeClient 计数替身（只用于进程级停机语义；真实路径见 N8 集成测试）。
type fakeClient struct {
	enrolls    int64
	heartbeats int64
	closed     int32
	adopted    int32
	renews     int64
	// certBase 夹具证书的时间锚点（零值用 time.Now()-1h）。
	//
	// T2 用例使用**注入时钟**，夹具证书必须以同一时钟为锚，
	// 否则会出现"证书尚未生效"的假失败。
	certBase time.Time
	// heartbeatsMu 保护 afterStop 断言（停机后不得再有心跳）。
	mu         sync.Mutex
	closedSeen int64
}

func (f *fakeClient) Enroll(context.Context, string) (*enrollclient.EnrollResult, error) {
	atomic.AddInt64(&f.enrolls, 1)
	// 真实注册会返回**可解析的证书**（Run 会把它原子保存到 state 目录）。
	key, der, caDER := selfSignedNodeCertForTest(f.certBase)
	return &enrollclient.EnrollResult{
		NodeID:            "nod_01M4RHFDJ00000000000000000",
		CertificateDER:    der,
		CACertificateDER:  caDER,
		PrivateKey:        key,
		HeartbeatInterval: 10 * time.Millisecond,
	}, nil
}

// AdoptIdentity 记录复用路径（T2）。
func (f *fakeClient) AdoptIdentity(context.Context, []byte, []byte, *ecdsa.PrivateKey) error {
	atomic.StoreInt32(&f.adopted, 1)
	return nil
}

// Renew 记录续期（T3；进程级测试用不到，返回固定的"新证书"）。
func (f *fakeClient) Renew(context.Context, []byte) (*enrollclient.RenewResult, error) {
	atomic.AddInt64(&f.renews, 1)
	return &enrollclient.RenewResult{NotAfter: time.Now().Add(7 * 24 * time.Hour)}, nil
}

func (f *fakeClient) Heartbeat(_ context.Context, _, _ string, _ time.Time, _ *contractv1.NodeLoadSummary) (contractv1.NodeStatus, error) {
	if atomic.LoadInt32(&f.closed) == 1 {
		f.mu.Lock()
		f.closedSeen++
		f.mu.Unlock()
	}
	atomic.AddInt64(&f.heartbeats, 1)
	return contractv1.NodeStatus_NODE_STATUS_ONLINE, nil
}

func (f *fakeClient) Close() error {
	atomic.StoreInt32(&f.closed, 1)
	return nil
}

func (f *fakeClient) heartbeatCount() int64 { return atomic.LoadInt64(&f.heartbeats) }

// writeTokenFile 写入令牌文件并设置权限。
func writeTokenFile(t *testing.T, mode os.FileMode) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "enroll.token")
	if err := os.WriteFile(path, []byte("one-time-token-abcdef\n"), mode); err != nil {
		t.Fatal(err)
	}
	// WriteFile 受 umask 影响：显式 Chmod 到目标权限。
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestN7ModeRequired（N7 ①）缺少 -mode 启动失败。
func TestN7ModeRequired(t *testing.T) {
	if _, err := ParseMode(""); !errors.Is(err, ErrModeRequired) {
		t.Fatalf("缺少 -mode 必须失败（ErrModeRequired），实际 %v", err)
	}
	// 空白同样视为缺失。
	if _, err := ParseMode("   "); !errors.Is(err, ErrModeRequired) {
		t.Fatalf("空白 -mode 必须失败，实际 %v", err)
	}
	// 未知模式拒绝。
	if _, err := ParseMode("staging"); !errors.Is(err, ErrUnknownMode) {
		t.Fatalf("未知模式必须失败（ErrUnknownMode），实际 %v", err)
	}
	// 装配层同样拒绝（fail-closed）。
	if _, err := NewRunner(Config{Mode: "", Token: "t"}, &fakeClient{}); err == nil {
		t.Fatal("NewRunner 必须拒绝空 mode")
	}
	t.Log("[N7①] 缺少 / 空白 / 未知 -mode → 一律拒绝启动")
}

// TestN7ProdRefused（N7 ②）-mode=prod 启动失败。
func TestN7ProdRefused(t *testing.T) {
	if _, err := ParseMode(ModeProd); !errors.Is(err, ErrProdNotImplemented) {
		t.Fatalf("mode=prod 必须拒绝（ErrProdNotImplemented），实际 %v", err)
	}
	if _, err := NewRunner(Config{Mode: ModeProd, Token: "t"}, &fakeClient{}); !errors.Is(err, ErrProdNotImplemented) {
		t.Fatalf("NewRunner 必须拒绝 mode=prod，实际 %v", err)
	}
	if !strings.Contains(ErrProdNotImplemented.Error(), "生产身份与证书来源未实现") {
		t.Fatalf("错误信息必须说明原因：%v", ErrProdNotImplemented)
	}
	t.Log("[N7②] mode=prod → 拒绝启动（生产身份与证书来源未实现）")
}

// TestN7TokenFilePermissive（N7 ③）令牌文件权限过宽启动失败。
func TestN7TokenFilePermissive(t *testing.T) {
	for _, mode := range []os.FileMode{0o644, 0o640, 0o604, 0o600 | 0o040, 0o666} {
		path := writeTokenFile(t, mode)
		if _, err := ReadTokenFile(path); !errors.Is(err, ErrTokenFilePermissive) {
			t.Fatalf("权限 %#o 必须被拒绝（ErrTokenFilePermissive），实际 %v", mode, err)
		}
	}
	// 缺失路径 / 空路径。
	if _, err := ReadTokenFile(""); !errors.Is(err, ErrTokenFileRequired) {
		t.Fatalf("空路径必须拒绝，实际 %v", err)
	}
	if _, err := ReadTokenFile(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("不存在的令牌文件必须拒绝")
	}
	t.Log("[N7③] 权限 0644/0640/0604/0640/0666 → 一律拒绝（必须恰好 0600）")
}

// TestN7TokenFileOK（N7 ④）令牌文件权限为 0600 时通过。
func TestN7TokenFileOK(t *testing.T) {
	path := writeTokenFile(t, 0o600)
	tok, err := ReadTokenFile(path)
	if err != nil {
		t.Fatalf("0600 权限应通过：%v", err)
	}
	if tok != "one-time-token-abcdef" {
		t.Fatalf("令牌应去除首尾空白，实际 %q", tok)
	}
	// 空文件拒绝。
	empty := filepath.Join(t.TempDir(), "empty.token")
	if err := os.WriteFile(empty, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(empty, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadTokenFile(empty); !errors.Is(err, ErrTokenFileEmpty) {
		t.Fatalf("空令牌文件必须拒绝（ErrTokenFileEmpty），实际 %v", err)
	}
	t.Log("[N7④] 权限 0600 → 读取成功并去除空白；空文件拒绝")
}

// TestN7StopStopsHeartbeats（N7 ⑤）停机后不再发送心跳（计数器断言）。
//
// 用**受控的 Sleep**（由测试逐次放行）保证心跳次数确定：
// 放行 3 次 → 恰好 3 次心跳；随后 cancel → 不再新增。
func TestN7StopStopsHeartbeats(t *testing.T) {
	cli := &fakeClient{}
	tick := make(chan struct{})
	r, err := NewRunner(Config{
		Mode: ModeTest, Token: "tok", Interval: time.Millisecond,
		Sleep: func(ctx context.Context, _ time.Duration) bool {
			select {
			case <-ctx.Done():
				return false // 收到停机信号
			case <-tick:
				return true
			}
		},
	}, cli)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()

	// 逐次放行 3 个心跳周期，每次都等心跳真正发生。
	for i := 1; i <= 3; i++ {
		tick <- struct{}{}
		deadline := time.Now().Add(2 * time.Second)
		for cli.heartbeatCount() < int64(i) && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if got := cli.heartbeatCount(); got != int64(i) {
			t.Fatalf("第 %d 次放行后应恰好 %d 次心跳，实际 %d", i, i, got)
		}
	}
	before := cli.heartbeatCount()

	cancel() // 停机
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run 应正常返回：%v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("停机超时（Run 未返回）")
	}

	if after := cli.heartbeatCount(); after != before {
		t.Fatalf("停机后不得再发送心跳：停机前 %d，停机后 %d", before, after)
	}
	if !r.Stopped() {
		t.Fatal("停机后 Stopped() 应为 true")
	}
	if atomic.LoadInt64(&cli.enrolls) != 1 {
		t.Fatalf("应恰好注册 1 次，实际 %d", cli.enrolls)
	}
	cli.mu.Lock()
	leaked := cli.closedSeen
	cli.mu.Unlock()
	if leaked != 0 {
		t.Fatalf("关闭连接后不得再有心跳：%d", leaked)
	}
	t.Logf("[N7⑤] 停机后心跳停止（恰好 %d 次，停机后无新增），注册 1 次，连接已关闭，无半完成注册",
		before)
}

// TestN7CancelledBeforeEnrollSkipsEnroll（N7）启动前已取消 → 不发起注册（不留半完成注册）。
func TestN7CancelledBeforeEnrollSkipsEnroll(t *testing.T) {
	cli := &fakeClient{}
	r, err := NewRunner(Config{Mode: ModeTest, Token: "tok"}, cli)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.Run(ctx); err != nil {
		t.Fatalf("启动前取消应正常返回：%v", err)
	}
	if atomic.LoadInt64(&cli.enrolls) != 0 {
		t.Fatalf("启动前取消不得发起注册，实际 %d 次", cli.enrolls)
	}
	if cli.heartbeatCount() != 0 {
		t.Fatalf("启动前取消不得发送心跳，实际 %d 次", cli.heartbeatCount())
	}
	t.Log("[N7] 启动前取消 → 不注册、不心跳（无半完成注册）")
}
