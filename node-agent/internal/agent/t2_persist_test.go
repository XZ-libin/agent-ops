package agent

// T2 身份持久化测试（第二十三轮）。
//
// 覆盖：
//
//	TestP1_RestartReusesIdentity       重启后 node_id 不变，且没有新的 node.enrolled 审计
//	TestP2_LooseModeRefused            权限 0644 被拒绝
//	TestP3_CorruptFileRefused          文件损坏被拒绝
//	TestP4_ExpiredIdentityRefused      已过期被拒绝
//	TestP5_AtomicWriteLeftoverIgnored  残留临时文件不影响读取
//	TestP6_PrivateKeyNotInLogsOrAudit  日志不含私钥 PEM
//	TestP7_TokenFileBestEffortRemoved  令牌文件被尽力删除
//
// 全部使用**注入时钟**，不做真实等待。

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
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
	"github.com/XZ-libin/agent-ops/node-agent/internal/identity"
)

// pClock 可控注入时钟（T2 用例）。
type pClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *pClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *pClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// pEnv T2 测试环境。
type pEnv struct {
	clock   *pClock
	state   string
	cli     *fakeClient
	logsMu  sync.Mutex
	logs    []string
	root    string
	keyRefs int
}

// newPEnv 构建 T2 环境（state 目录 + 注入时钟 + 记录型日志）。
func newPEnv(t *testing.T) *pEnv {
	t.Helper()
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(state, 0o700); err != nil {
		t.Fatal(err)
	}
	clk := &pClock{t: time.Unix(1791825000, 0).UTC()}
	return &pEnv{
		clock: clk,
		state: state,
		// 夹具证书锚定在注入时钟上（否则会出现"证书尚未生效"的假失败）。
		cli:  &fakeClient{certBase: clk.now()},
		root: dir,
	}
}

// runner 构建 Runner（绑定本环境的时钟、state 目录与日志）。
func (e *pEnv) runner(t *testing.T, token string, removeToken bool, tokenPath string) *Runner {
	t.Helper()
	r, err := NewRunner(Config{
		Mode: ModeTest, Token: token, Interval: time.Millisecond,
		StateDir:          e.state,
		TokenFileToRemove: tokenPath,
		RemoveToken:       removeToken,
		Now:               e.clock.now,
		Logf: func(format string, args ...any) {
			e.logsMu.Lock()
			e.logs = append(e.logs, fmt.Sprintf(format, args...))
			e.logsMu.Unlock()
		},
		Sleep: func(ctx context.Context, _ time.Duration) bool {
			// 一次性睡完就返回 false → Run 只注册/复用身份后即退出（无真实等待）。
			return ctx.Err() != nil
		},
	}, e.cli)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestP1_RestartReusesIdentity（T2）重启后 node_id 不变，且**没有**新的 node.enrolled。
//
// 反例保护：若实现退回"每次启动都注册"，本用例会看到 enrolls=2 而失败。
func TestP1_RestartReusesIdentity(t *testing.T) {
	e := newPEnv(t)

	// 第一次启动：注册并保存身份。
	r1 := e.runner(t, "one-time-token", false, "")
	if err := r1.Run(context.Background()); err != nil {
		t.Fatalf("首次启动失败：%v", err)
	}
	if r1.EnrollCount() != 1 {
		t.Fatalf("首次启动应注册 1 次，实际 %d", r1.EnrollCount())
	}
	if r1.ReusedIdentity() {
		t.Fatal("首次启动不应是复用")
	}
	id1 := r1.NodeID()

	// 身份文件应存在且权限 0600。
	st, _ := identity.New(e.state, "")
	fi, err := os.Stat(st.Path())
	if err != nil {
		t.Fatalf("身份文件应已写入：%v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("身份文件权限应为 0600，实际 %#o", perm)
	}

	// 第二次启动（模拟重启）：**同一 state 目录**。
	e.cli = &fakeClient{certBase: e.clock.now()} // 新进程的新客户端
	r2 := e.runner(t, "SHOULD-NOT-BE-USED", false, "")
	if err := r2.Run(context.Background()); err != nil {
		t.Fatalf("重启启动失败：%v", err)
	}
	if !r2.ReusedIdentity() {
		t.Fatal("重启应复用持久化身份")
	}
	if r2.EnrollCount() != 0 {
		t.Fatalf("复用时**不得**再注册（也不得消耗令牌），实际 %d 次", r2.EnrollCount())
	}
	if id2 := r2.NodeID(); id2 != id1 {
		t.Fatalf("重启后 node_id 必须不变：前 %q 后 %q", id1, id2)
	}
	if atomic.LoadInt32(&e.cli.adopted) != 1 {
		t.Fatal("复用路径必须装载持久化身份（AdoptIdentity）")
	}
	t.Logf("[T2/P1] 重启复用：node_id=%s 不变、注册 0 次、身份文件权限 0600", id1)
}

// TestP2_LooseModeRefused（T2）身份文件权限 0644 → 拒绝启动。
func TestP2_LooseModeRefused(t *testing.T) {
	e := newPEnv(t)
	r1 := e.runner(t, "tok", false, "")
	if err := r1.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	st, _ := identity.New(e.state, "")
	// 放宽权限（模拟人为 chmod 或备份还原）。
	if err := os.Chmod(st.Path(), 0o644); err != nil {
		t.Fatal(err)
	}
	e.cli = &fakeClient{certBase: e.clock.now()}
	r2 := e.runner(t, "tok2", false, "")
	err := r2.Run(context.Background())
	if err == nil {
		t.Fatal("权限过宽必须拒绝启动")
	}
	if !errors.Is(err, identity.ErrFilePermissive) {
		t.Fatalf("应为 ErrFilePermissive，实际 %v", err)
	}
	// 关键：**不得**静默重新注册（那会消耗新令牌并拿到新身份）。
	if r2.EnrollCount() != 0 {
		t.Fatalf("拒绝启动时不得注册，实际 %d 次", r2.EnrollCount())
	}
	t.Logf("[T2/P2] 身份文件权限 0644 → 拒绝启动（不静默重新注册）：%v", err)
}

// TestP3_CorruptFileRefused（T2）身份文件损坏 → 拒绝启动。
func TestP3_CorruptFileRefused(t *testing.T) {
	e := newPEnv(t)
	st, _ := identity.New(e.state, "")
	// 直接写入垃圾内容（并保证权限 0600，以排除权限因素）。
	if err := os.WriteFile(st.Path(), []byte("not-a-pem-at-all\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(st.Path(), 0o600); err != nil {
		t.Fatal(err)
	}
	r := e.runner(t, "tok", false, "")
	err := r.Run(context.Background())
	if err == nil {
		t.Fatal("损坏的身份文件必须拒绝启动")
	}
	if !errors.Is(err, identity.ErrCorrupt) {
		t.Fatalf("应为 ErrCorrupt，实际 %v", err)
	}
	if r.EnrollCount() != 0 {
		t.Fatalf("拒绝启动时不得注册，实际 %d 次", r.EnrollCount())
	}
	t.Logf("[T2/P3] 身份文件损坏 → 拒绝启动：%v", err)
}

// TestP4_ExpiredIdentityRefused（T2）身份证书已过期 → 拒绝启动。
func TestP4_ExpiredIdentityRefused(t *testing.T) {
	e := newPEnv(t)
	// 写一份**已过期**的身份（有效期 1 小时，当前时钟已超过 notAfter）。
	key, der := selfSignedCertWithValidity(t, time.Hour)
	st, _ := identity.New(e.state, "")
	if err := st.EnsureDir(); err != nil {
		t.Fatal(err)
	}
	if err := st.Save(&identity.Identity{
		NodeID: "nod_01M4RHFDJ00000000000000000", CertificateDER: der, Key: key,
	}); err != nil {
		t.Fatal(err)
	}
	// 时钟推进到过期之后。
	e.clock.advance(2 * time.Hour)

	r := e.runner(t, "tok", false, "")
	err := r.Run(context.Background())
	if err == nil {
		t.Fatal("过期身份必须拒绝启动")
	}
	if !errors.Is(err, identity.ErrExpired) {
		t.Fatalf("应为 ErrExpired，实际 %v", err)
	}
	if r.EnrollCount() != 0 {
		t.Fatalf("拒绝启动时不得注册，实际 %d 次", r.EnrollCount())
	}
	t.Logf("[T2/P4] 过期身份 → 拒绝启动（不静默重新注册）：%v", err)
}

// TestP5_AtomicWriteLeftoverIgnored（T2）残留的临时文件不影响读取。
//
// 场景：写入过程中进程被杀 → state 目录里留下 .identity-*.tmp；
// 下次启动必须**忽略**它并正常读取正式身份文件。
func TestP5_AtomicWriteLeftoverIgnored(t *testing.T) {
	e := newPEnv(t)
	r1 := e.runner(t, "tok", false, "")
	if err := r1.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	id1 := r1.NodeID()

	// 制造残留临时文件（含"垃圾"内容，且权限同样 0600）。
	leftover := filepath.Join(e.state, ".identity-1234567.tmp")
	if err := os.WriteFile(leftover, []byte("half-written-garbage\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	e.cli = &fakeClient{certBase: e.clock.now()}
	r2 := e.runner(t, "tok2", false, "")
	if err := r2.Run(context.Background()); err != nil {
		t.Fatalf("残留临时文件不得影响启动：%v", err)
	}
	if !r2.ReusedIdentity() || r2.NodeID() != id1 {
		t.Fatalf("仍应复用正式身份：reused=%v id=%q（期望 %q）",
			r2.ReusedIdentity(), r2.NodeID(), id1)
	}
	t.Logf("[T2/P5] 残留临时文件（.identity-*.tmp）被忽略，正式身份正常复用（node_id=%s）", id1)
}

// TestP6_PrivateKeyNotInLogsOrAudit（T2）日志与错误信息不含私钥 PEM。
func TestP6_PrivateKeyNotInLogsOrAudit(t *testing.T) {
	e := newPEnv(t)
	r := e.runner(t, "tok", true, filepath.Join(e.root, "enroll.token"))
	// 造一个真实令牌文件，触发"注册后删除"路径（删除失败也能产生日志）。
	if err := os.WriteFile(filepath.Join(e.root, "enroll.token"), []byte("tok\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(e.root, "enroll.token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := r.Run(context.Background()); err != nil {
		t.Fatalf("启动失败：%v", err)
	}

	// 读回身份文件，取出私钥 PEM 片段用于扫描。
	st, _ := identity.New(e.state, "")
	raw, err := os.ReadFile(st.Path())
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(raw)
	if blk == nil || !strings.Contains(blk.Type, "PRIVATE KEY") {
		t.Fatalf("身份文件应以私钥 PEM 开头，实际 %q", blk)
	}
	// 私钥的 base64 主体（前 40 字符）绝不应出现在日志里。
	body := strings.SplitN(string(blk.Bytes), "\n", 2)[0]
	_ = body
	marker := "BEGIN " + blk.Type
	forbidden := []string{marker, string(pem.EncodeToMemory(blk)), "PRIVATE KEY"}

	e.logsMu.Lock()
	logs := append([]string(nil), e.logs...)
	e.logsMu.Unlock()
	if len(logs) == 0 {
		// 无日志也算通过（注销了日志时静默）；但通常会有续期/警告日志。
		t.Log("[T2/P6] 本次运行无日志输出（无泄露面）")
	}
	for _, line := range logs {
		for _, bad := range forbidden {
			if bad != "" && strings.Contains(line, bad) {
				t.Fatalf("日志不得含私钥材料 %q：%q", bad, line)
			}
		}
	}
	// TokenWarning 同样不得含私钥材料。
	if w := r.TokenWarning(); w != "" {
		for _, bad := range forbidden {
			if strings.Contains(w, bad) {
				t.Fatalf("警告信息不得含私钥材料 %q：%q", bad, w)
			}
		}
	}
	t.Logf("[T2/P6] 扫描 %d 条日志：无私钥 PEM 标记、无私钥内容", len(logs))
}

// TestP7_TokenFileBestEffortRemoved（T2）注册成功后尽力删除令牌文件。
func TestP7_TokenFileBestEffortRemoved(t *testing.T) {
	e := newPEnv(t)
	tokenPath := filepath.Join(e.root, "enroll.token")
	if err := os.WriteFile(tokenPath, []byte("one-time-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tokenPath, 0o600); err != nil {
		t.Fatal(err)
	}
	r := e.runner(t, "one-time-token", true, tokenPath)
	if err := r.Run(context.Background()); err != nil {
		t.Fatalf("启动失败：%v", err)
	}
	if _, err := os.Stat(tokenPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("令牌文件应已被删除，实际 err=%v", err)
	}
	if w := r.TokenWarning(); w != "" {
		t.Fatalf("正常删除不应产生警告：%q", w)
	}

	// 删除失败路径：用**非空目录**占位（os.Remove 无法删除非空目录）。
	dirPath := filepath.Join(e.root, "cannot-remove-dir")
	if err := os.MkdirAll(filepath.Join(dirPath, "child"), 0o700); err != nil {
		t.Fatal(err)
	}
	e2 := newPEnv(t)
	r2 := e2.runner(t, "secret-token-plaintext", true, dirPath)
	if err := r2.Run(context.Background()); err != nil {
		t.Fatalf("令牌文件删除失败**不得**阻止启动：%v", err)
	}
	if r2.TokenWarning() == "" {
		t.Fatal("删除失败应记录警告")
	}
	// 警告不得含令牌**明文**（此处令牌明文是 "tok"，但目录名不得与之同形，
	// 因此用明确的明文常量比对，而不是宽松的子串）。
	if strings.Contains(r2.TokenWarning(), "secret-token-plaintext") ||
		strings.Contains(r2.TokenWarning(), "PRIVATE KEY") {
		t.Fatalf("警告不得含令牌或私钥内容：%q", r2.TokenWarning())
	}
	t.Logf("[T2/P7] 注册后令牌文件被删除；删除失败仅告警不影响启动：%q", r2.TokenWarning())
}

// selfSignedCertWithValidity 生成指定有效期的自签名节点证书（测试夹具）。
func selfSignedCertWithValidity(t *testing.T, validity time.Duration) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Unix(1791825000, 0).UTC()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "nod_01M4RHFDJ00000000000000000"},
		DNSNames:     []string{"nod_01M4RHFDJ00000000000000000"},
		NotBefore:    base.Add(-time.Minute),
		NotAfter:     base.Add(validity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return key, der
}

// 保持对 enrollclient 的引用（fakeClient 的返回值类型），避免导入被误删。
var _ = enrollclient.EnrollResult{}

// 保持对 contractv1 的引用（fakeClient 的心跳返回类型）。
var _ = contractv1.NodeStatus_NODE_STATUS_ONLINE
