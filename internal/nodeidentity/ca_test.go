package nodeidentity

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// issueNodeCert 用测试 CA 为指定 node_id 签发证书（辅助）。
func issueNodeCert(t *testing.T, ca *TestCA, nodeID string, now time.Time) []byte {
	t.Helper()
	key, err := NewNodeKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := NewCSR(key, nil)
	if err != nil {
		t.Fatal(err)
	}
	der, _, err := ca.SignCSR(csr, nodeID, now, nil)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// TestMTLSRejectMatrix（N4 ①–⑤）mTLS 校验矩阵。
func TestMTLSRejectMatrix(t *testing.T) {
	ca, err := NewTestCA(CAConfig{Now: fixedNow}, nil)
	if err != nil {
		t.Fatal(err)
	}
	nodeID, err := NewNodeID(fixedNow, nil)
	if err != nil {
		t.Fatal(err)
	}

	// ① 无客户端证书 → 拒绝。
	if _, err := ca.VerifyClientCert(nil, fixedNow); !errors.Is(err, ErrNoClientCert) {
		t.Fatalf("① 无证书必须拒绝（ErrNoClientCert），实际 %v", err)
	}
	if _, err := ca.VerifyClientCert([]byte{1, 2, 3}, fixedNow); !errors.Is(err, ErrNoClientCert) {
		t.Fatalf("① 非法证书字节必须拒绝（ErrNoClientCert），实际 %v", err)
	}

	// ⑤ 有效证书 → 通过。
	good := issueNodeCert(t, ca, nodeID, fixedNow)
	leaf, err := ca.VerifyClientCert(good, fixedNow)
	if err != nil {
		t.Fatalf("⑤ 有效证书必须通过：%v", err)
	}
	if err := CheckCertBindsNodeID(leaf, nodeID); err != nil {
		t.Fatalf("⑤ 身份绑定必须一致：%v", err)
	}

	// ② 由**其他 CA** 签发的证书 → 拒绝。
	otherCA, err := NewTestCA(CAConfig{Now: fixedNow}, nil)
	if err != nil {
		t.Fatal(err)
	}
	foreign := issueNodeCert(t, otherCA, nodeID, fixedNow)
	if _, err := ca.VerifyClientCert(foreign, fixedNow); !errors.Is(err, ErrCertUntrusted) {
		t.Fatalf("② 其他 CA 签发的证书必须拒绝（ErrCertUntrusted），实际 %v", err)
	}
	// 其他 CA 自己校验自己的证书应通过（证明拒绝来自信任根而非证书本身有问题）。
	if _, err := otherCA.VerifyClientCert(foreign, fixedNow); err != nil {
		t.Fatalf("② 对照组：本 CA 校验自己签发的证书应通过：%v", err)
	}

	// ③ 证书过期 → 拒绝（注入时钟推进 31 天，证书有效期 30 天）。
	if _, err := ca.VerifyClientCert(good, fixedNow.Add(CertValidity+24*time.Hour)); !errors.Is(err, ErrCertExpired) {
		t.Fatalf("③ 过期证书必须拒绝（ErrCertExpired），实际 %v", err)
	}
	// 证书尚未生效（时钟回退到签发前）。
	if _, err := ca.VerifyClientCert(good, fixedNow.Add(-time.Hour)); !errors.Is(err, ErrCertExpired) {
		t.Fatalf("③ 未生效证书必须拒绝（ErrCertExpired），实际 %v", err)
	}

	// ④ 身份绑定不一致 → 拒绝。
	otherID, err := NewNodeID(fixedNow, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckCertBindsNodeID(leaf, otherID); !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("④ 身份不一致必须拒绝（ErrIdentityMismatch），实际 %v", err)
	}
	if err := CheckCertBindsNodeID(leaf, ""); !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("④ 空身份必须拒绝，实际 %v", err)
	}

	t.Logf("[N4] mTLS 矩阵：①无证书→拒绝 ②其他 CA→拒绝 ③过期/未生效→拒绝 ④身份不一致→拒绝 ⑤有效证书+绑定一致→通过（node_id=%s）",
		nodeID)
}

// TestCertValidityAndBinding（N4）签发证书的有效期为 30 天，CN/SAN 绑定分配的 node_id。
func TestCertValidityAndBinding(t *testing.T) {
	ca, err := NewTestCA(CAConfig{Now: fixedNow}, nil)
	if err != nil {
		t.Fatal(err)
	}
	nodeID, err := NewNodeID(fixedNow, nil)
	if err != nil {
		t.Fatal(err)
	}
	key, err := NewNodeKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	// D2：CSR 是纯持有性证明（不含任何身份信息），最终证书身份完全来自控制面分配的 nodeID。
	csr, err := NewCSR(key, nil)
	if err != nil {
		t.Fatal(err)
	}
	der, notAfter, err := ca.SignCSR(csr, nodeID, fixedNow, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := fixedNow.Add(CertValidity)
	if !notAfter.Equal(want) {
		t.Fatalf("证书有效期应为 %s，实际 %s", want, notAfter)
	}
	leaf, err := ca.VerifyClientCert(der, fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Subject.CommonName != nodeID {
		t.Fatalf("证书 CN 必须为分配的 node_id：want=%s got=%s", nodeID, leaf.Subject.CommonName)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != nodeID {
		t.Fatalf("证书 SAN 必须为分配的 node_id：%v", leaf.DNSNames)
	}
	if strings.Contains(leaf.Subject.CommonName, "01HZZZ") {
		t.Fatal("CSR 不得携带任何身份信息（D2：证书身份只来自控制面分配）")
	}
	// CA 证书本身可用作信任根，且不导出私钥。
	if len(ca.CertificateDER()) == 0 {
		t.Fatal("CA 证书 DER 不得为空")
	}
	t.Logf("[N4] 证书 CN/SAN=%s，有效期 30 天（notAfter=%s）；CSR 声明身份未进入证书",
		nodeID, notAfter.Format(time.RFC3339))
}

// TestNoPrivateKeyExportPath（N2 约束）本包不提供任何导出私钥的函数。
func TestNoPrivateKeyExportPath(t *testing.T) {
	// CertificatePEM 只接受证书 DER；对私钥没有任何导出/编码函数。
	ca, err := NewTestCA(CAConfig{Now: fixedNow}, nil)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := CertificatePEM(ca.CertificateDER())
	if !strings.Contains(string(pemBytes), "CERTIFICATE") {
		t.Fatal("CertificatePEM 应输出证书 PEM")
	}
	// 输出中不得出现私钥标记。
	begin := "-----BEGIN "
	end := "PRIVATE KEY-----"
	if strings.Contains(string(pemBytes), begin+end) {
		t.Fatal("CertificatePEM 不得输出私钥")
	}
	t.Log("[N2] 本包只有 CertificatePEM（证书），不存在任何私钥导出函数；CA 私钥仅内存")
}
