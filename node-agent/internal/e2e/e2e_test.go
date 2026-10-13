// Package e2e 是节点注册/心跳/mTLS 的**端到端集成测试**（第二十二轮 N8）。
//
// 真实路径，**不用替身**：
//   - 真实 gRPC over **mTLS**（控制面服务端证书 + 节点客户端证书，均由测试 CA 签发）；
//   - 真实 PostgreSQL（agent_ops_test 的独立 run schema，测试结束删除）；
//   - 真实 node-agent 侧客户端（enrollclient + agent.Runner）。
//
// 完整链路（D4 引导信任 → 注册 → 心跳 → 离线 → 恢复 → 吊销 → 拒绝）：
//
//	签发令牌 → node-agent 注册 → 心跳 → 停止心跳 30 秒（注入时钟）→ offline 审计
//	→ 恢复心跳 → online 审计 → 吊销证书 → 下一次心跳被拒绝 → 节点状态为 revoked
//
// 每一步断言 test_nodes 状态、test_enroll_tokens 已用状态、test_cert_revocations 行数、
// 审计行数与 **seq 连续性**。
package e2e

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	contractv1 "github.com/ORG/agent-ops/contract/gen/go/agent_ops/contract/v1"
	"github.com/ORG/agent-ops/internal/audit"
	"github.com/ORG/agent-ops/internal/nodehealth"
	"github.com/ORG/agent-ops/internal/nodeidentity"
	"github.com/ORG/agent-ops/internal/nodeserver"
	"github.com/ORG/agent-ops/internal/nodestore"
	"github.com/ORG/agent-ops/internal/nodesvc"
	"github.com/ORG/agent-ops/internal/testdb"
	"github.com/ORG/agent-ops/node-agent/internal/agent"
	"github.com/ORG/agent-ops/node-agent/internal/enrollclient"
)

// baseTime 测试固定时钟起点。
var baseTime = time.Unix(1791825000, 0).UTC()

// clock 可控注入时钟（控制面与节点共用，保证 skew=0）。
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: baseTime} }

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// harness 集成环境。
type harness struct {
	rs      *testdb.RunSchema
	store   *nodestore.Store
	ca      *nodeidentity.TestCA
	tracker *nodehealth.Tracker
	audit   *audit.Store
	svc     *nodesvc.Service
	srv     *grpc.Server
	addr    string
	clock   *clock
	auditT  string
}

// newHarness 装配控制面（真实 PG + 真实 mTLS gRPC 服务）。
func newHarness(t *testing.T) *harness {
	t.Helper()
	rs := testdb.NewRunSchema(t)
	if rs == nil {
		return nil
	}
	ctx := context.Background()
	clk := newClock()

	store, err := nodestore.New(nodestore.Config{Pool: rs.Pool(), Now: clk.now})
	if err != nil {
		t.Fatal(err)
	}
	// 建表 + **迁移**（T3/T4 新增列）；顺序不可颠倒（见 ADR-022 §6）。
	// 这里用 nodesvc.Service.EnsureSchema 统一入口。
	ca, err := nodeidentity.NewTestCA(nodeidentity.CAConfig{
		Now: clk.now(), Validity: nodeidentity.DefaultCertValidity,
		CAValidity: 30 * 24 * time.Hour,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tracker, err := nodehealth.NewTracker(nodehealth.Config{Now: clk.now})
	if err != nil {
		t.Fatal(err)
	}
	auditT := fmt.Sprintf("test_audit_events_node_e2e_%d", time.Now().UnixNano())
	aud := audit.NewTestStore(rs.Pool(), auditT)
	if err := aud.EnsureSchema(ctx); err != nil {
		t.Fatalf("审计建表失败：%v", err)
	}
	svc, err := nodesvc.New(nodesvc.Config{
		Store: store, CA: ca, Tracker: tracker, Audit: aud, Now: clk.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.EnsureSchema(ctx); err != nil {
		t.Fatalf("建表/迁移失败（非 skip）：%v", err)
	}
	srvImpl, err := nodeserver.New(nodeserver.Config{Service: svc, CA: ca, Now: clk.now})
	if err != nil {
		t.Fatal(err)
	}
	// 服务端证书 SAN = 127.0.0.1 / localhost（D4）。
	grpcSrv, err := srvImpl.GRPCServer(nil, clk.now())
	if err != nil {
		t.Fatal(err)
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = grpcSrv.Serve(lis) }()
	t.Cleanup(grpcSrv.Stop)

	return &harness{
		rs: rs, store: store, ca: ca, tracker: tracker, audit: aud, svc: svc,
		srv: grpcSrv, addr: lis.Addr().String(), clock: clk, auditT: auditT,
	}
}

// newToken 生成并保存一次性令牌，返回明文。
func (h *harness) newToken(t *testing.T) string {
	t.Helper()
	plain, hash, err := nodeidentity.GenerateToken(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.PutToken(context.Background(), hash,
		h.clock.now().Add(nodeidentity.TokenTTL)); err != nil {
		t.Fatal(err)
	}
	return plain
}

// node 节点侧：真实 enrollclient + agent.Runner。
type node struct {
	client *enrollclient.Client
	runner *agent.Runner
	tick   chan struct{}
	done   chan error
	cancel context.CancelFunc
}

// startNode 启动节点代理（真实 mTLS 客户端）。
func (h *harness) startNode(t *testing.T, token string) *node {
	t.Helper()
	key, err := nodeidentity.NewNodeKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cli, err := enrollclient.Dial(ctx, enrollclient.Config{
		ServerAddr:   h.addr,
		ServerName:   "127.0.0.1",
		CABundlePEM:  nodeidentity.CertificatePEM(h.ca.CertificateDER()),
		NodeKey:      key,
		DisplayLabel: "e2e-node",
		AgentVersion: "0.22.0-e2e",
		DialTimeout:  5 * time.Second,
	})
	if err != nil {
		cancel()
		t.Fatalf("节点连接控制面失败（mTLS 引导信任）：%v", err)
	}
	tick := make(chan struct{})
	runner, err := agent.NewRunner(agent.Config{
		Mode: agent.ModeTest, Token: token, Interval: time.Second,
		Now: h.clock.now,
		Sleep: func(ctx context.Context, _ time.Duration) bool {
			select {
			case <-ctx.Done():
				return false
			case <-tick:
				return true
			}
		},
	}, cli)
	if err != nil {
		_ = cli.Close()
		cancel()
		t.Fatal(err)
	}
	n := &node{client: cli, runner: runner, tick: tick, done: make(chan error, 1), cancel: cancel}
	go func() { n.done <- runner.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-n.done:
		case <-time.After(3 * time.Second):
		}
	})
	return n
}

// waitNodeID 等注册完成并返回分配的 node_id。
func (h *harness) waitNodeID(t *testing.T, n *node) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if id := n.runner.NodeID(); id != "" {
			return id
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("注册超时（未分配 node_id）")
	return ""
}

// heartbeat 放行一个心跳周期并等待其完成。
func (n *node) heartbeat(t *testing.T, want int64) {
	t.Helper()
	n.tick <- struct{}{}
	deadline := time.Now().Add(3 * time.Second)
	for n.runner.HeartbeatCount() < want && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := n.runner.HeartbeatCount(); got != want {
		t.Fatalf("心跳计数应为 %d，实际 %d", want, got)
	}
}

// nodeStatus 读取 test_nodes 状态。
func (h *harness) nodeStatus(t *testing.T, nodeID string) string {
	t.Helper()
	rec, ok, err := h.store.GetNode(context.Background(), nodeID)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatalf("test_nodes 中不存在节点 %s", nodeID)
	}
	return rec.Status
}

// tokenUsed 返回令牌是否已被消费及其绑定的节点。
func (h *harness) tokenUsed(t *testing.T, token string) (bool, string) {
	t.Helper()
	st, err := h.store.GetTokenState(context.Background(), nodeidentity.HashTokenOf(token))
	if err != nil {
		t.Fatal(err)
	}
	if !st.Found {
		t.Fatal("令牌应存在于 test_enroll_tokens")
	}
	return !st.UsedAt.IsZero(), st.UsedByNodeID
}

// revocations 吊销表行数。
func (h *harness) revocations(t *testing.T) int64 {
	t.Helper()
	n, err := h.store.RevocationCount(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// auditCount 某动作的审计行数。
func (h *harness) auditCount(t *testing.T, action string) int {
	t.Helper()
	evs, err := h.audit.ListByAction(context.Background(), action)
	if err != nil {
		t.Fatal(err)
	}
	return len(evs)
}

// waitAuditCount 轮询等待某动作的审计行数达到 want（避免 sleep 竞态）。
func (h *harness) waitAuditCount(t *testing.T, action string, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if h.auditCount(t, action) >= want {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("%s 审计行数未达到 %d（实际 %d）", action, want, h.auditCount(t, action))
}

// auditRow 审计总行数 + seq 连续性。
func (h *harness) auditRow(t *testing.T) (int, []int64) {
	t.Helper()
	rows, err := h.rs.Pool().Query(context.Background(),
		fmt.Sprintf(`SELECT seq FROM %s ORDER BY seq`, h.auditT))
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var seqs []int64
	for rows.Next() {
		var s int64
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		seqs = append(seqs, s)
	}
	return len(seqs), seqs
}

// TestN8FullNodeLifecycle 完整链路：注册 → 心跳 → 离线 → 恢复 → 吊销 → 拒绝。
func TestN8FullNodeLifecycle(t *testing.T) {
	h := newHarness(t)
	if h == nil {
		return
	}
	ctx := context.Background()

	// ① 签发一次性令牌。
	token := h.newToken(t)
	if used, _ := h.tokenUsed(t, token); used {
		t.Fatal("新令牌不应已被使用")
	}
	t.Logf("[N8-①] 已签发一次性令牌（仅存哈希，TTL=15min）")

	// ② 节点经 D4 引导信任注册。
	n := h.startNode(t, token)
	nodeID := h.waitNodeID(t, n)
	if err := nodeidentity.ValidateNodeID(nodeID); err != nil {
		t.Fatalf("分配的 node_id 格式非法：%v", err)
	}
	if !strings.HasPrefix(nodeID, "nod_") {
		t.Fatalf("node_id 必须以 nod_ 开头：%q", nodeID)
	}
	if used, by := h.tokenUsed(t, token); !used || by != nodeID {
		t.Fatalf("令牌应已消费并绑定 %s，实际 used=%v by=%q", nodeID, used, by)
	}
	if st := h.nodeStatus(t, nodeID); st != nodestore.StatusOnline {
		t.Fatalf("注册后 test_nodes.status 应为 online，实际 %q", st)
	}
	if got := h.auditCount(t, nodesvc.ActionEnrolled); got != 1 {
		t.Fatalf("node.enrolled 应恰好 1 条，实际 %d", got)
	}
	// 取证书 serial（心跳与吊销都按它查表）。
	rec, _, err := h.store.GetNode(ctx, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("[N8-②] 注册成功 node_id=%s serial=%s；令牌已用且绑定该节点；审计 node.enrolled=1",
		nodeID, rec.CertSerial)

	// ③ 心跳 → 保持 online。
	n.heartbeat(t, 1)
	if st := h.nodeStatus(t, nodeID); st != nodestore.StatusOnline {
		t.Fatalf("心跳后应为 online，实际 %q", st)
	}
	h.clock.advance(nodehealth.DefaultInterval)
	n.heartbeat(t, 2)
	if st := h.nodeStatus(t, nodeID); st != nodestore.StatusOnline {
		t.Fatalf("第二次心跳后应为 online，实际 %q", st)
	}
	// 心跳不产生状态迁移审计（已 online → online 不算迁移）。
	if got := h.auditCount(t, nodesvc.ActionOnline); got != 0 {
		t.Fatalf("无迁移时不应产生 node.online，实际 %d", got)
	}
	t.Logf("[N8-③] 2 次心跳：状态保持 online，无多余迁移审计（心跳计数=%d）", n.runner.HeartbeatCount())

	// ④ 停止心跳 30 秒（注入时钟）→ offline。
	h.clock.advance(3 * nodehealth.DefaultInterval)
	trs, err := h.svc.EvaluateOffline(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(trs) != 1 {
		t.Fatalf("应恰好 1 次迁移，实际 %d", len(trs))
	}
	if st := h.nodeStatus(t, nodeID); st != nodestore.StatusOffline {
		t.Fatalf("停止心跳 30 秒后应为 offline，实际 %q", st)
	}
	if got := h.auditCount(t, nodesvc.ActionOffline); got != 1 {
		t.Fatalf("node.offline 应恰好 1 条，实际 %d", got)
	}
	// 重复判定不重复写审计。
	if _, err := h.svc.EvaluateOffline(ctx); err != nil {
		t.Fatal(err)
	}
	if got := h.auditCount(t, nodesvc.ActionOffline); got != 1 {
		t.Fatalf("重复判定不得重复写 node.offline，实际 %d", got)
	}
	t.Logf("[N8-④] 停止心跳 30s → offline；审计 node.offline=1（重复判定不重复写）")

	// ⑤ 恢复心跳 → online。
	h.clock.advance(nodehealth.DefaultInterval)
	n.heartbeat(t, 3)
	if st := h.nodeStatus(t, nodeID); st != nodestore.StatusOnline {
		t.Fatalf("恢复心跳后应为 online，实际 %q", st)
	}
	if got := h.auditCount(t, nodesvc.ActionOnline); got != 1 {
		t.Fatalf("node.online 应恰好 1 条，实际 %d", got)
	}
	t.Logf("[N8-⑤] 恢复心跳 → online；审计 node.online=1")

	// ⑥ 吊销证书 → revoked（不可恢复）。
	if err := h.svc.RevokeCert(ctx, rec.CertSerial, nodeID, "e2e-revoke"); err != nil {
		t.Fatal(err)
	}
	if got := h.revocations(t); got != 1 {
		t.Fatalf("test_cert_revocations 应恰好 1 行，实际 %d", got)
	}
	if st := h.nodeStatus(t, nodeID); st != nodestore.StatusRevoked {
		t.Fatalf("吊销后 test_nodes.status 应为 revoked，实际 %q", st)
	}
	if got := h.auditCount(t, nodesvc.ActionCertRevoked); got != 1 {
		t.Fatalf("node.cert_revoked 应恰好 1 条，实际 %d", got)
	}
	t.Logf("[N8-⑥] 吊销 serial=%s → test_cert_revocations=1；status=revoked；审计 node.cert_revoked=1",
		rec.CertSerial)

	// ⑦ 吊销后的下一次心跳必须被拒绝（证书仍在有效期内）。
	//    直接走真实 gRPC 客户端，断言服务端返回 PermissionDenied。
	before := n.runner.HeartbeatCount()
	h.clock.advance(nodehealth.DefaultInterval)
	_, herr := n.client.Heartbeat(ctx, nodeID, "01M4RHFDJ0E2ESESSION00000000", h.clock.now(), nil)
	if herr == nil {
		t.Fatal("吊销后心跳必须被拒绝")
	}
	if st, _ := status.FromError(herr); st.Code() != codes.PermissionDenied {
		t.Fatalf("吊销后心跳应返回 PermissionDenied，实际 %v", herr)
	}
	if st := h.nodeStatus(t, nodeID); st != nodestore.StatusRevoked {
		t.Fatalf("被拒心跳不得把状态恢复为 online，实际 %q", st)
	}
	if got := h.auditCount(t, nodesvc.ActionHeartbeatRejected); got != 1 {
		t.Fatalf("node.heartbeat_rejected 应恰好 1 条，实际 %d", got)
	}
	// runner 侧继续放行心跳（同样应被拒绝），状态不得变化，审计再加 1 条。
	n.tick <- struct{}{}
	h.waitAuditCount(t, nodesvc.ActionHeartbeatRejected, 2)
	if st := h.nodeStatus(t, nodeID); st != nodestore.StatusRevoked {
		t.Fatalf("后续心跳不得恢复 revoked 状态，实际 %q", st)
	}
	if got := h.revocations(t); got != 1 {
		t.Fatalf("吊销表行数不应变化，实际 %d", got)
	}
	if st := h.nodeStatus(t, nodeID); st == nodestore.StatusOnline {
		t.Fatal("revoked 不可恢复为 online")
	}
	t.Logf("[N8-⑦] 吊销后心跳被拒（PermissionDenied，成功心跳计数保持 %d）；状态保持 revoked；"+
		"审计 node.heartbeat_rejected=2（直接调用 + runner 各 1）", before)

	// ⑧ 审计 seq 连续性 + 总数。
	total, seqs := h.auditRow(t)
	for i, s := range seqs {
		if s != int64(i+1) {
			t.Fatalf("审计 seq 必须连续（从 1 开始）：%v", seqs)
		}
	}
	if total < 5 {
		t.Fatalf("审计事件总数过少：%d", total)
	}
	if got := h.auditCount(t, nodesvc.ActionHeartbeatRejected); got != 2 {
		t.Fatalf("node.heartbeat_rejected 应为 2，实际 %d", got)
	}
	t.Logf("[N8-⑧] 审计 seq 连续 [1..%d]；各动作行数：enrolled=%d offline=%d online=%d cert_revoked=%d heartbeat_rejected=%d",
		total, h.auditCount(t, nodesvc.ActionEnrolled), h.auditCount(t, nodesvc.ActionOffline),
		h.auditCount(t, nodesvc.ActionOnline), h.auditCount(t, nodesvc.ActionCertRevoked),
		h.auditCount(t, nodesvc.ActionHeartbeatRejected))

	// ⑨ 停机：不再发送心跳。
	n.cancel()
	select {
	case <-n.done:
	case <-time.After(3 * time.Second):
		t.Fatal("节点停机超时")
	}
	countAtStop := n.runner.HeartbeatCount()
	time.Sleep(50 * time.Millisecond)
	if n.runner.HeartbeatCount() != countAtStop {
		t.Fatalf("停机后不得再发送心跳：停机时 %d，之后 %d",
			countAtStop, n.runner.HeartbeatCount())
	}
	t.Logf("[N8-⑨] 节点优雅停机：心跳计数冻结在 %d", countAtStop)
}

// TestN8UnauthenticatedWithoutClientCert（N4/N8）无客户端证书的心跳必须被拒绝。
//
// 用 **明文** gRPC 客户端（不带证书）调用 Heartbeat：服务端 mTLS 配置为
// RequestClientCert，因此连接可建立，但拦截器必须因"缺客户端证书"拒绝。
func TestN8UnauthenticatedWithoutClientCert(t *testing.T) {
	h := newHarness(t)
	if h == nil {
		return
	}
	// **真实 TLS 但不携带客户端证书**（等价于"节点没有证书"）：
	// 服务端 mTLS 用 RequestClientCert，因此握手可以成功，但 RPC 必须被拒绝。
	// 注意：这里刻意不使用任何"跳过校验"的选项（本模块有 AST 守卫）。
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(nodeidentity.CertificatePEM(h.ca.CertificateDER())) {
		t.Fatal("CA 包解析失败")
	}
	creds := credentials.NewTLS(&tls.Config{
		RootCAs:    pool,
		ServerName: "127.0.0.1",
		MinVersion: tls.VersionTLS12,
	})
	conn, err := grpc.NewClient(h.addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	cli := contractv1.NewNodeAgentClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, herr := cli.Heartbeat(ctx, &contractv1.HeartbeatRequest{NodeId: "nod_01M4RHFDJ00000000000000000"})
	if herr == nil {
		t.Fatal("无客户端证书的心跳必须被拒绝")
	}
	st, _ := status.FromError(herr)
	if st.Code() != codes.Unauthenticated {
		t.Fatalf("应为 UNAUTHENTICATED，实际 %v", herr)
	}
	t.Logf("[N8/N4] 无客户端证书 → 心跳被拒（%v）", st.Code())
}
