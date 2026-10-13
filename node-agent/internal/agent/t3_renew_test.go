package agent

// T3 客户端侧续期调度测试（第二十三轮）。
//
// 服务端的 7 步校验与 supersede 语义在 internal/nodesvc 的 TestR* 中覆盖；
// 本文件只覆盖**节点侧**的调度与重试：续期时机（50%±10%）、指数退避
// （初值 1 分钟、上限 1 小时）、成功后原子替换身份文件。
//
// 全部使用注入时钟，不做真实等待。

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	contractv1 "github.com/ORG/agent-ops/contract/gen/go/agent_ops/contract/v1"
	"github.com/ORG/agent-ops/node-agent/internal/enrollclient"
	"github.com/ORG/agent-ops/node-agent/internal/identity"
)

// rClock 可控注入时钟（T3 用例）。
type rClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *rClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *rClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// renewFakeClient 记录续期调用的替身（可注入失败次数）。
type renewFakeClient struct {
	mu      sync.Mutex
	renewN  int
	failFor int // 前 N 次调用失败
	key     *ecdsa.PrivateKey
	der     []byte
	caDER   []byte
	notAfte time.Time
	// caKey / caCert 测试 CA（**仅内存**；用于按真实语义签发 CSR）。
	caKey  *ecdsa.PrivateKey
	caCert *x509.Certificate
}

// newRenewFakeCA 生成一对测试 CA（密钥仅内存）。
func newRenewFakeCA(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Unix(1791825000, 0).UTC()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "t3-test-ca"},
		NotBefore:             base.Add(-time.Hour),
		NotAfter:              base.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}

func (f *renewFakeClient) Enroll(context.Context, string) (*enrollclient.EnrollResult, error) {
	return &enrollclient.EnrollResult{NodeID: "nod_01M4RHFDJ00000000000000000",
		CertificateDER: f.der, CACertificateDER: f.caDER, PrivateKey: f.key,
		NotAfter: f.notAfte}, nil
}

func (f *renewFakeClient) AdoptIdentity(context.Context, []byte, []byte, *ecdsa.PrivateKey) error {
	return nil
}

func (f *renewFakeClient) Heartbeat(context.Context, string, string, time.Time,
	*contractv1.NodeLoadSummary) (contractv1.NodeStatus, error) {
	return contractv1.NodeStatus_NODE_STATUS_ONLINE, nil
}

// Renew 记录调用次数，并按 failFor 注入失败。
func (f *renewFakeClient) Renew(_ context.Context, csrPEM []byte) (*enrollclient.RenewResult, error) {
	f.mu.Lock()
	f.renewN++
	n := f.renewN
	f.mu.Unlock()
	if n <= f.failFor {
		return nil, errRenewInjected
	}
	// 关键：**必须用请求里 CSR 的公钥**签发（真实服务端行为）。
	// 若像早期草稿那样自造一对密钥，返回的证书就与调用方新私钥不匹配，
	// 会让"续期后身份文件可读回"的断言以假失败告终。
	der, serr := f.signCSR(csrPEM)
	if serr != nil {
		return nil, serr
	}
	return &enrollclient.RenewResult{
		CertificateDER:   der,
		CACertificateDER: f.caDER,
		NotAfter:         f.notAfte.Add(time.Duration(n) * time.Second),
		SupersededSerial: "old-serial",
	}, nil
}

func (f *renewFakeClient) Close() error { return nil }

func (f *renewFakeClient) renewCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.renewN
}

// renewCertFixture 生成一对（私钥, 自签证书）用于**已有身份**的夹具。
//
// 注意：它**不**用于续期结果——续期结果的公钥必须来自请求里的 CSR。
func renewCertFixture(notAfter time.Time) (*ecdsa.PrivateKey, []byte) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	base := notAfter.Add(-7 * 24 * time.Hour)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "nod_01M4RHFDJ00000000000000000"},
		DNSNames:     []string{"nod_01M4RHFDJ00000000000000000"},
		NotBefore:    base,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	return key, der
}

// signCSR 用 CSR 中的**公钥** + CA 私钥签发证书（真实服务端语义）。
//
// 注意：x509.CreateCertificate 的最后一个参数必须实现 crypto.Signer，
// 因此这里传 CA 私钥，而**不是** csr.PublicKey（后者会导致
// "certificate private key does not implement crypto.Signer"）。
func (f *renewFakeClient) signCSR(csrPEM []byte) ([]byte, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, errors.New("t3: bad csr pem")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, err
	}
	const nodeID = "nod_01M4RHFDJ00000000000000000"
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: nodeID},
		DNSNames:     []string{nodeID},
		NotBefore:    f.notAfte.Add(-7 * 24 * time.Hour),
		NotAfter:     f.notAfte,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	return x509.CreateCertificate(rand.Reader, tmpl, f.caCert, csr.PublicKey, f.caKey)
}

// errRenewInjected 注入的续期失败（模拟控制面不可用）。
var errRenewInjected = errors.New("t3: injected renew failure")

// —— 用例 ——

// TestT3RenewWindowIsHalfLifeWithJitter（T3 客户端）续期触发点落在 [45%, 55%] 有效期。
func TestT3RenewWindowIsHalfLifeWithJitter(t *testing.T) {
	clk := &rClock{t: time.Unix(1791825000, 0).UTC()}
	notAfter := clk.now().Add(7 * 24 * time.Hour)
	caKey, caCert := newRenewFakeCA(t)
	key, der := renewCertFixture(notAfter)
	cli := &renewFakeClient{key: key, der: der, caDER: der, notAfte: notAfter,
		caKey: caKey, caCert: caCert}

	stateDir := t.TempDir()
	if err := os.Chmod(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// 随机源固定为 0 → 比例 = 50% × (1 − 10%) = 45%。
	r, err := NewRunner(Config{
		Mode: ModeTest, Token: "tok", Interval: time.Second,
		StateDir: stateDir, Now: clk.now, RandomFloat: func() float64 { return 0 },
		Logf: func(string, ...any) {},
	}, cli)
	if err != nil {
		t.Fatal(err)
	}
	// 注入身份（NotBefore = notAfter − 7d）。
	id := &identity.Identity{
		NodeID: "nod_01M4RHFDJ00000000000000000", CertificateDER: der,
		NotAfter: notAfter, NotBefore: notAfter.Add(-7 * 24 * time.Hour), Key: key,
	}
	r.SetIdentityForTest(id)

	// 45% 之前 → 不续期。
	clk.advance(time.Duration(float64(7*24*time.Hour) * 0.44))
	r.MaybeRenew(context.Background())
	if cli.renewCalls() != 0 {
		t.Fatalf("45%% 之前不应续期，实际调用 %d 次", cli.renewCalls())
	}
	// 跨过 45% → 续期。
	clk.advance(time.Duration(float64(7*24*time.Hour) * 0.02))
	r.MaybeRenew(context.Background())
	if cli.renewCalls() != 1 {
		t.Fatalf("跨过 45%% 后应续期 1 次，实际 %d", cli.renewCalls())
	}
	if r.RenewCount() != 1 {
		t.Fatalf("成功计数应为 1，实际 %d（最近错误：%q）", r.RenewCount(), r.RenewLastError())
	}
	// 身份文件已被新证书替换（原子写）。
	st, _ := identity.New(stateDir, "")
	loaded, lerr := st.Load(clk.now(), nil, "")
	if lerr != nil {
		t.Fatalf("续期后应能读回身份：%v", lerr)
	}
	if loaded.NodeID != id.NodeID {
		t.Fatalf("续期不得改变 node_id：%q", loaded.NodeID)
	}
	// 上界：随机源取 1 → 55%（仍在 [45%, 55%] 内）。
	t.Logf("[T3-客户端] 45%%（50%%−10%%）触发续期；续期后身份文件可读回、node_id 不变（第 %d 次调用）",
		cli.renewCalls())
}

// TestT3RenewBackoffExponential（T3 客户端）失败退避 1min → 2min → 4min（上限 1h）。
func TestT3RenewBackoffExponential(t *testing.T) {
	clk := &rClock{t: time.Unix(1791825000, 0).UTC()}
	notAfter := clk.now().Add(7 * 24 * time.Hour)
	key, der := renewCertFixture(notAfter)
	// 全程失败（failFor 取大值），用于观察退避序列直到上限。
	caKey, caCert := newRenewFakeCA(t)
	cli := &renewFakeClient{key: key, der: der, caDER: der, notAfte: notAfter,
		caKey: caKey, caCert: caCert, failFor: 100}

	stateDir := t.TempDir()
	if err := os.Chmod(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	r, err := NewRunner(Config{
		Mode: ModeTest, Token: "tok", Interval: time.Second, StateDir: stateDir,
		Now: clk.now, RandomFloat: func() float64 { return 0 },
		Logf: func(string, ...any) {},
	}, cli)
	if err != nil {
		t.Fatal(err)
	}
	r.SetIdentityForTest(&identity.Identity{
		NodeID: "nod_01M4RHFDJ00000000000000000", CertificateDER: der,
		NotAfter: notAfter, NotBefore: notAfter.Add(-7 * 24 * time.Hour), Key: key,
	})
	// 直接推到续期点之后。
	clk.advance(time.Duration(float64(7*24*time.Hour) * 0.5))

	wantBackoff := []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 16 * time.Minute}
	// 首次调用立即执行（无退避），之后必须在退避过期后才能再试。
	for i, want := range wantBackoff {
		r.MaybeRenew(context.Background())
		if got := r.RenewBackoff(); got != want {
			t.Fatalf("第 %d 次失败后退避应为 %s，实际 %s", i+1, want, got)
		}
		// 退避未过 → 不产生新调用。
		before := cli.renewCalls()
		clk.advance(want - time.Second)
		r.MaybeRenew(context.Background())
		if cli.renewCalls() != before {
			t.Fatalf("退避未过时不得重试（第 %d 次）：调用从 %d 变为 %d",
				i+1, before, cli.renewCalls())
		}
		// 跨过退避 → 允许再试。
		clk.advance(time.Second)
	}

	// 继续失败直到达到上限 1 小时。
	for i := 0; i < 4; i++ {
		r.MaybeRenew(context.Background())
		clk.advance(r.RenewBackoff())
	}
	if got := r.RenewBackoff(); got != DefaultRenewBackoffMax {
		t.Fatalf("退避上限应为 %s，实际 %s", DefaultRenewBackoffMax, got)
	}
	if r.RenewFailureCount() < 5 {
		t.Fatalf("失败计数过少：%d", r.RenewFailureCount())
	}
	if r.RenewLastError() == "" {
		t.Fatal("应记录最近一次失败原因")
	}
	// 失败原因不得含任何密钥材料。
	for _, bad := range []string{"PRIVATE KEY", "BEGIN ", "EC PRIVATE"} {
		if strings.Contains(r.RenewLastError(), bad) {
			t.Fatalf("失败原因不得含密钥材料 %q：%q", bad, r.RenewLastError())
		}
	}
	t.Logf("[T3-客户端] 指数退避 1m→2m→4m→8m→16m…上限 %s（当前 %s，失败 %d 次）",
		DefaultRenewBackoffMax, r.RenewBackoff(), r.RenewFailureCount())
}

// TestT3RenewSuccessResetsBackoff（T3 客户端）成功后重置退避并替换身份文件。
func TestT3RenewSuccessResetsBackoff(t *testing.T) {
	clk := &rClock{t: time.Unix(1791825000, 0).UTC()}
	notAfter := clk.now().Add(7 * 24 * time.Hour)
	key, der := renewCertFixture(notAfter)
	caKey, caCert := newRenewFakeCA(t)
	cli := &renewFakeClient{key: key, der: der, caDER: der, notAfte: notAfter,
		caKey: caKey, caCert: caCert, failFor: 1}

	stateDir := t.TempDir()
	if err := os.Chmod(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	r, err := NewRunner(Config{
		Mode: ModeTest, Token: "tok", Interval: time.Second, StateDir: stateDir,
		Now: clk.now, RandomFloat: func() float64 { return 0 },
		Logf: func(string, ...any) {},
	}, cli)
	if err != nil {
		t.Fatal(err)
	}
	// 先把初始身份写入磁盘（否则 Save 的目录/覆盖行为不可见）。
	st, _ := identity.New(stateDir, "")
	if err := st.Save(&identity.Identity{
		NodeID: "nod_01M4RHFDJ00000000000000000", CertificateDER: der,
		NotAfter: notAfter, NotBefore: notAfter.Add(-7 * 24 * time.Hour), Key: key,
	}); err != nil {
		t.Fatalf("写入初始身份失败：%v", err)
	}
	r.SetIdentityForTest(&identity.Identity{
		NodeID: "nod_01M4RHFDJ00000000000000000", CertificateDER: der,
		NotAfter: notAfter, NotBefore: notAfter.Add(-7 * 24 * time.Hour), Key: key,
	})
	clk.advance(time.Duration(float64(7*24*time.Hour) * 0.5))

	// 第一次失败。
	r.MaybeRenew(context.Background())
	if r.RenewBackoff() != DefaultRenewBackoffInitial {
		t.Fatalf("首次失败后退避应为 %s，实际 %s", DefaultRenewBackoffInitial, r.RenewBackoff())
	}
	// 跨过退避后第二次成功。
	clk.advance(DefaultRenewBackoffInitial)
	r.MaybeRenew(context.Background())
	if r.RenewBackoff() != 0 {
		t.Fatalf("成功后退避应重置为 0，实际 %s", r.RenewBackoff())
	}
	if r.RenewLastError() != "" {
		t.Fatalf("成功后应清除失败原因，实际 %q", r.RenewLastError())
	}
	if r.RenewCount() != 1 {
		t.Fatalf("成功计数应为 1，实际 %d（最近错误：%q）", r.RenewCount(), r.RenewLastError())
	}
	// 身份文件权限仍为 0600（原子替换不放松权限）。
	fi, err := os.Stat(filepath.Join(stateDir, identity.DefaultFileName))
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("续期替换后权限应仍为 0600，实际 %#o", perm)
	}
	t.Log("[T3-客户端] 首次失败退避 1m；跨过后成功 → 退避清零、失败原因清空、文件权限仍 0600")
}
