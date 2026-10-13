package nodeidentity

// D3 证书有效期与吊销测试（第二十二轮）。
//
// 新语义：
//   - 证书有效期默认 **7 天**，由**配置项**指定（不得硬编码）；
//   - 控制面维护吊销表（N6 落 PG 表 test_cert_revocations；本包只依赖 RevocationChecker 接口）；
//   - **每次 mTLS 连接与每次心跳**都检查证书 serial：吊销后即使未过期也必须拒绝；
//   - 节点被吊销后状态置 revoked，**不可恢复为 online**。

import (
	"errors"
	"testing"
	"time"

	"github.com/XZ-libin/agent-ops/internal/nodehealth"
)

// newHealthTracker 构建注入了固定时钟的心跳判定器（D3 的 revoked 终态用）。
func newHealthTracker(t *testing.T) *nodehealth.Tracker {
	t.Helper()
	tr, err := nodehealth.NewTracker(nodehealth.Config{Now: func() time.Time { return fixedNow }})
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

// memRevocations 内存吊销表（单测用；N6 提供 PG 实现）。
type memRevocations struct {
	revoked map[string]string // serial → node_id
}

func newMemRevocations() *memRevocations {
	return &memRevocations{revoked: map[string]string{}}
}

func (m *memRevocations) Revoke(serial, nodeID string) { m.revoked[serial] = nodeID }

func (m *memRevocations) IsRevoked(serial string) (bool, error) {
	_, ok := m.revoked[serial]
	return ok, nil
}

// newCAWithRevocations 构建带吊销表的测试 CA（7 天有效期；CA 自身有效期覆盖测试窗口）。
func newCAWithRevocations(t *testing.T, rev *memRevocations) *TestCA {
	t.Helper()
	ca, err := NewTestCA(CAConfig{
		Now:      fixedNow,
		Validity: DefaultCertValidity,
		// CA 自身必须活得比节点证书久，否则链校验会因 CA 过期而失败（与吊销无关）。
		CAValidity:  30 * 24 * time.Hour,
		Revocations: rev,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

// TestD3DefaultValidityIsSevenDays（D3）默认有效期为 7 天，且由配置项指定。
func TestD3DefaultValidityIsSevenDays(t *testing.T) {
	if DefaultCertValidity != 7*24*time.Hour {
		t.Fatalf("默认证书有效期应为 7 天，实际 %s", DefaultCertValidity)
	}
	// 配置项可覆盖（证明不是硬编码）。
	custom, err := NewTestCA(CAConfig{Validity: 3 * time.Hour}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if custom.Validity() != 3*time.Hour {
		t.Fatalf("有效期应取配置值 3h，实际 %s", custom.Validity())
	}
	// 未配置时取默认值。
	def, err := NewTestCA(CAConfig{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if def.Validity() != DefaultCertValidity {
		t.Fatalf("未配置时应取默认 7 天，实际 %s", def.Validity())
	}
	t.Logf("[D3] 默认有效期 %s（可配置），显式配置 3h 生效", DefaultCertValidity)
}

// TestD3ExpiryAfterSevenDays（D3 ③）签发后 7 天 + 1 秒，证书被拒绝（注入时钟）。
func TestD3ExpiryAfterSevenDays(t *testing.T) {
	rev := newMemRevocations()
	ca := newCAWithRevocations(t, rev)
	key, err := NewNodeKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := NewCSR(key, nil)
	if err != nil {
		t.Fatal(err)
	}
	nodeID, err := NewNodeID(fixedNow, nil)
	if err != nil {
		t.Fatal(err)
	}
	certDER, notAfter, err := ca.SignCSR(csr, nodeID, fixedNow, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !notAfter.Equal(fixedNow.Add(7 * 24 * time.Hour)) {
		t.Fatalf("notAfter 应为签发时刻 + 7 天，实际 %s", notAfter)
	}
	// 6 天 23 小时：仍有效。
	if _, err := ca.VerifyClientCert(certDER, fixedNow.Add(6*24*time.Hour+23*time.Hour)); err != nil {
		t.Fatalf("6d23h 应仍在有效期内：%v", err)
	}
	// 7 天 + 1 秒：拒绝。
	if _, err := ca.VerifyClientCert(certDER, fixedNow.Add(7*24*time.Hour+time.Second)); !errors.Is(err, ErrCertExpired) {
		t.Fatalf("7 天 + 1 秒必须拒绝（ErrCertExpired），实际 %v", err)
	}
	t.Logf("[D3③] 7 天有效期：6d23h 通过、7d+1s 拒绝（notAfter=%s）", notAfter.Format(time.RFC3339))
}

// TestD3RevokedCertRejectedWhileValid（D3 ①）吊销后心跳被拒绝（证书未过期）。
func TestD3RevokedCertRejectedWhileValid(t *testing.T) {
	rev := newMemRevocations()
	ca := newCAWithRevocations(t, rev)
	key, err := NewNodeKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := NewCSR(key, nil)
	if err != nil {
		t.Fatal(err)
	}
	nodeID, err := NewNodeID(fixedNow, nil)
	if err != nil {
		t.Fatal(err)
	}
	certDER, _, err := ca.SignCSR(csr, nodeID, fixedNow, nil)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.VerifyClientCert(certDER, fixedNow)
	if err != nil {
		t.Fatalf("吊销前应通过：%v", err)
	}
	// 吊销该证书（serial 入库）。
	rev.Revoke(leaf.SerialNumber.String(), nodeID)

	// 证书仍在有效期内（+1 小时），但已被吊销 → 必须拒绝。
	if _, err := ca.VerifyClientCert(certDER, fixedNow.Add(time.Hour)); !errors.Is(err, ErrCertRevoked) {
		t.Fatalf("已吊销证书必须拒绝（ErrCertRevoked），实际 %v", err)
	}
	t.Log("[D3①] 吊销后（证书未过期）mTLS 校验拒绝：ErrCertRevoked")
}

// TestD3RevocationIsTerminalForNode（D3 ②）吊销后 status=revoked，心跳不能把它恢复为 online。
func TestD3RevocationIsTerminalForNode(t *testing.T) {
	rev := newMemRevocations()
	ca := newCAWithRevocations(t, rev)
	key, _ := NewNodeKey(nil)
	csr, _ := NewCSR(key, nil)
	nodeID, _ := NewNodeID(fixedNow, nil)
	certDER, _, err := ca.SignCSR(csr, nodeID, fixedNow, nil)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := ca.VerifyClientCert(certDER, fixedNow)
	rev.Revoke(leaf.SerialNumber.String(), nodeID)

	// 状态机：吊销是终态。
	tr := newHealthTracker(t)
	tr.Register(nodeID)
	tr.Revoke(nodeID)

	st, _, _ := tr.Status(nodeID)
	if st != nodehealth.StatusRevoked {
		t.Fatalf("吊销后状态应为 revoked，实际 %q", st)
	}
	// 之后的心跳不得把它恢复为 online。
	if _, err := tr.Heartbeat(nodeID, "01M4RHFDJ0D3TESTSESSION0000000", fixedNow); !errors.Is(err, nodehealth.ErrNodeRevoked) {
		t.Fatalf("revoked 节点的心跳必须被拒绝（ErrNodeRevoked），实际 %v", err)
	}
	st2, _, _ := tr.Status(nodeID)
	if st2 != nodehealth.StatusRevoked {
		t.Fatalf("revoked 不可恢复，实际 %q", st2)
	}
	// 判定也不得把它改成 offline。
	if trs := tr.EvaluateAll(); len(trs) != 0 {
		t.Fatalf("revoked 节点不应产生状态迁移：%v", trs)
	}
	st3, _, _ := tr.Status(nodeID)
	if st3 != nodehealth.StatusRevoked {
		t.Fatalf("revoked 不可被判定改写，实际 %q", st3)
	}
	t.Log("[D3②] 吊销为终态：status=revoked，心跳被拒、判定不改写")
}

// TestD3RevocationIsolatedPerNode（D3 ④）吊销一个节点不影响另一个节点的心跳。
func TestD3RevocationIsolatedPerNode(t *testing.T) {
	rev := newMemRevocations()
	ca := newCAWithRevocations(t, rev)

	issue := func() (string, string, []byte) {
		key, _ := NewNodeKey(nil)
		csr, _ := NewCSR(key, nil)
		id, _ := NewNodeID(fixedNow, nil)
		der, _, err := ca.SignCSR(csr, id, fixedNow, nil)
		if err != nil {
			t.Fatal(err)
		}
		leaf, _ := ca.VerifyClientCert(der, fixedNow)
		return id, leaf.SerialNumber.String(), der
	}
	idA, serialA, derA := issue()
	idB, _, derB := issue()

	rev.Revoke(serialA, idA)

	// A 被拒。
	if _, err := ca.VerifyClientCert(derA, fixedNow); !errors.Is(err, ErrCertRevoked) {
		t.Fatalf("A 应被拒绝，实际 %v", err)
	}
	// B 不受影响。
	if _, err := ca.VerifyClientCert(derB, fixedNow); err != nil {
		t.Fatalf("吊销 A 不得影响 B：%v", err)
	}
	// 状态机层面同样隔离。
	tr := newHealthTracker(t)
	tr.Register(idA)
	tr.Register(idB)
	tr.Revoke(idA)
	if st, _, _ := tr.Status(idB); st != nodehealth.StatusOnline {
		t.Fatalf("B 应保持 online，实际 %q", st)
	}
	if _, err := tr.Heartbeat(idB, "01M4RHFDJ0D3TESTSESSION0000000", fixedNow); err != nil {
		t.Fatalf("B 的心跳应正常：%v", err)
	}
	t.Log("[D3④] 吊销隔离：A 被拒且 revoked，B 心跳正常、保持 online")
}
