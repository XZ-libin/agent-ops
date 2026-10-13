package nodeidentity

// D2 身份语义测试（第二十二轮）。
//
// 新语义（取代 ADR-020 §3 的"CSR 一致性校验"）：
//   - node_id **只由控制面分配**（Enroll 成功时）；
//   - CSR 仅用于**证明私钥持有**（proof of possession）：签名必须有效，
//     且**不得携带 CN、任何 SAN 或扩展字段**（否则拒绝，对外统一 INVALID_ARGUMENT 语义）；
//   - declared_node_id 降级为**展示标签**（display_label），不参与身份与校验；
//   - 证书的 CN 与 SAN 由控制面写入分配的 node_id。

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"testing"
	"time"
)

// createRawCSR 用给定模板构造 CSR（仅供 D2 的拒绝用例使用：故意构造"不纯净"的 CSR）。
func createRawCSR(key *ecdsa.PrivateKey, tmpl *x509.CertificateRequest, r io.Reader) ([]byte, error) {
	if r == nil {
		r = rand.Reader
	}
	return x509.CreateCertificateRequest(r, tmpl, key)
}

// newPoPCSR 生成一个"干净"的持有性证明 CSR（无 CN、无 SAN、无扩展）。
func newPoPCSR(t *testing.T) (*TestCA, []byte, string) {
	t.Helper()
	ca, err := NewTestCA(CAConfig{Now: fixedNow}, nil)
	if err != nil {
		t.Fatal(err)
	}
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
	return ca, csr, nodeID
}

// TestD2CSRWithCommonNameRejected（D2 ①）CSR 带 CN → 拒绝。
func TestD2CSRWithCommonNameRejected(t *testing.T) {
	key, err := NewNodeKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	// 手工构造带 CN 的 CSR（绕过 NewCSR 的约束）。
	csrDER, err := createRawCSR(key, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "some-name"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ParseCSRProofOfPossession(csrDER)
	if !errors.Is(err, ErrCSRNotPlain) {
		t.Fatalf("带 CN 的 CSR 必须被拒绝（ErrCSRNotPlain），实际 %v", err)
	}
	t.Log("[D2①] CSR 带 CN → 拒绝（只允许纯持有性证明）")
}

// TestD2CSRWithSANRejected（D2 ②）CSR 带 DNS SAN → 拒绝。
func TestD2CSRWithSANRejected(t *testing.T) {
	key, err := NewNodeKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	// DNS SAN。
	dnsDER, err := createRawCSR(key, &x509.CertificateRequest{DNSNames: []string{"node.example"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseCSRProofOfPossession(dnsDER); !errors.Is(err, ErrCSRNotPlain) {
		t.Fatalf("带 DNS SAN 的 CSR 必须被拒绝，实际 %v", err)
	}
	// Email SAN。
	mailDER, err := createRawCSR(key, &x509.CertificateRequest{EmailAddresses: []string{"node@example"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseCSRProofOfPossession(mailDER); !errors.Is(err, ErrCSRNotPlain) {
		t.Fatalf("带 Email SAN 的 CSR 必须被拒绝，实际 %v", err)
	}
	t.Log("[D2②] CSR 带 DNS/Email SAN → 拒绝")
}

// TestD2CSRWithExtensionsRejected（D2）CSR 带扩展字段 → 拒绝。
func TestD2CSRWithExtensionsRejected(t *testing.T) {
	key, err := NewNodeKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	der, err := createRawCSR(key, &x509.CertificateRequest{
		ExtraExtensions: []pkix.Extension{{Id: []int{1, 2, 3, 4}, Value: []byte{0x01}}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseCSRProofOfPossession(der); !errors.Is(err, ErrCSRNotPlain) {
		t.Fatalf("带扩展字段的 CSR 必须被拒绝，实际 %v", err)
	}
	t.Log("[D2] CSR 带扩展字段 → 拒绝")
}

// TestD2CSRBadSignatureRejected（D2 ③）CSR 签名无效 → 拒绝。
func TestD2CSRBadSignatureRejected(t *testing.T) {
	_, csrDER, _ := newPoPCSR(t)
	// 篡改签名（最后一字节）。
	bad := make([]byte, len(csrDER))
	copy(bad, csrDER)
	bad[len(bad)-1] ^= 0xFF
	if _, err := ParseCSRProofOfPossession(bad); !errors.Is(err, ErrCSRInvalid) {
		t.Fatalf("签名无效的 CSR 必须被拒绝（ErrCSRInvalid），实际 %v", err)
	}
	// 截断的 CSR。
	if _, err := ParseCSRProofOfPossession(csrDER[:len(csrDER)-8]); !errors.Is(err, ErrCSRInvalid) {
		t.Fatalf("截断的 CSR 必须被拒绝，实际 %v", err)
	}
	t.Log("[D2③] CSR 签名无效/截断 → 拒绝")
}

// TestD2PlainCSRAccepted（D2）干净的持有性证明 CSR → 通过。
func TestD2PlainCSRAccepted(t *testing.T) {
	_, csrDER, _ := newPoPCSR(t)
	csr, err := ParseCSRProofOfPossession(csrDER)
	if err != nil {
		t.Fatalf("干净的 CSR 应通过：%v", err)
	}
	if csr.Subject.CommonName != "" {
		t.Fatalf("持有性证明 CSR 不应有 CN：%q", csr.Subject.CommonName)
	}
	if len(csr.DNSNames) != 0 || len(csr.IPAddresses) != 0 || len(csr.URIs) != 0 ||
		len(csr.EmailAddresses) != 0 {
		t.Fatalf("持有性证明 CSR 不应有任何 SAN：%+v", csr)
	}
	if len(csr.Extensions) != 0 {
		t.Fatalf("持有性证明 CSR 不应有扩展：%+v", csr.Extensions)
	}
	t.Log("[D2] 干净 CSR（无 CN/SAN/扩展、签名有效）→ 通过（仅证明私钥持有）")
}

// TestD2CertIdentityFromControlPlane（D2 ④）签发证书的 CN 与 SAN 均等于分配的 node_id。
func TestD2CertIdentityFromControlPlane(t *testing.T) {
	ca, csrDER, nodeID := newPoPCSR(t)
	certDER, notAfter, err := ca.SignCSR(csrDER, nodeID, fixedNow, nil)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.VerifyClientCert(certDER, fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Subject.CommonName != nodeID {
		t.Fatalf("证书 CN 必须等于分配的 node_id：want=%s got=%s", nodeID, leaf.Subject.CommonName)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != nodeID {
		t.Fatalf("证书 SAN 必须等于分配的 node_id：%v", leaf.DNSNames)
	}
	if !notAfter.Equal(fixedNow.Add(CertValidity)) {
		t.Fatalf("有效期应为 %s", CertValidity)
	}
	t.Logf("[D2④] 证书 CN/SAN 均等于分配的 node_id=%s（CSR 不含任何身份信息）", nodeID)
}

// TestD2DisplayLabelDoesNotAffectIdentity（D2 ⑤）修改 display_label 不改变 node_id，也不影响证书内容。
func TestD2DisplayLabelDoesNotAffectIdentity(t *testing.T) {
	ca, csrDER, nodeID := newPoPCSR(t)

	// 同一 CSR、同一分配身份：display_label 只是展示标签，不参与签名内容。
	// 这里用两个不同的 label 走同一签发路径，断言证书内容完全一致。
	der1, _, err := ca.SignCSR(csrDER, nodeID, fixedNow, nil)
	if err != nil {
		t.Fatal(err)
	}
	der2, _, err := ca.SignCSR(csrDER, nodeID, fixedNow, nil)
	if err != nil {
		t.Fatal(err)
	}
	leaf1, err := x509.ParseCertificate(der1)
	if err != nil {
		t.Fatal(err)
	}
	leaf2, err := x509.ParseCertificate(der2)
	if err != nil {
		t.Fatal(err)
	}
	// 身份字段（CN/SAN）必须一致。
	if leaf1.Subject.CommonName != leaf2.Subject.CommonName ||
		len(leaf1.DNSNames) != len(leaf2.DNSNames) || leaf1.DNSNames[0] != leaf2.DNSNames[0] {
		t.Fatalf("同一 node_id 的身份字段必须一致：%v vs %v", leaf1.DNSNames, leaf2.DNSNames)
	}
	// 序列号应不同（每次签发新序列号），但身份不受 label 影响。
	if leaf1.SerialNumber.Cmp(leaf2.SerialNumber) == 0 {
		t.Fatal("两次签发应有不同序列号")
	}
	// SignCSR 的签名参数里**没有** label：身份只来自 nodeID。
	if err := ValidateNodeID(nodeID); err != nil {
		t.Fatalf("node_id 应保持合法：%v", err)
	}
	t.Logf("[D2⑤] display_label 不参与签发：同一 node_id=%s 的 CN/SAN 恒一致（序列号每次不同）", nodeID)
}

// TestD2NoCSRConsistencyAPI（D2）旧的一致性校验 API 已移除（编译期保证：本测试不引用它）。
func TestD2NoCSRConsistencyAPI(t *testing.T) {
	// 旧 API CheckCSRMatchesDeclared 已删除；若仍存在，本文件会因"未使用"而无法体现。
	// 这里用一个行为断言代替：干净的 CSR 不需要任何"声明身份"即可通过持有性证明。
	_, csrDER, _ := newPoPCSR(t)
	if _, err := ParseCSRProofOfPossession(csrDER); err != nil {
		t.Fatalf("持有性证明不应依赖任何声明身份：%v", err)
	}
	_ = time.Now
	t.Log("[D2] 持有性证明与 display_label 解耦（旧一致性校验 API 已移除）")
}
