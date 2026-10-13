package nodeidentity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/url"
	"strings"
	"time"
)

// **仅测试** CA 与 mTLS 校验（第二十一轮 N2/N4）。
//
// 安全约束（硬性约束 1、7）：
//   - CA 私钥与节点私钥只在内存中生成与持有，**不落盘、不提交**；
//   - 本包**不提供**任何把私钥写文件的函数；
//   - 证书、私钥、CSR 原文都不得出现在错误信息中。
//
// 本轮不实现 CRL / OCSP（见报告 TODO）。

// DefaultCertValidity 签发给节点的证书有效期默认值（第二十二轮 D3：**7 天**）。
//
// 工程默认值，待安全团队确认。**必须由配置项指定**（CAConfig.Validity），
// 不得在签发路径上硬编码——缩短有效期是为后续 Renew（第二十三轮）留出窗口。
const DefaultCertValidity = 7 * 24 * time.Hour

// CertValidity 兼容别名（= DefaultCertValidity）。新代码请用 CAConfig.Validity。
const CertValidity = DefaultCertValidity

// DefaultCAValidity 测试 CA 自身的有效期默认值（工程默认：24 小时，够跑完测试）。
const DefaultCAValidity = 24 * time.Hour

// 错误。
var (
	// ErrCSRInvalid CSR 无法解析或缺少公钥。
	ErrCSRInvalid = errors.New("nodeidentity：CSR 非法")
	// ErrCSRNotPlain CSR 不是"纯持有性证明"（含 CN / SAN / 扩展字段）。
	// D2：CSR 只用于证明私钥持有，不得携带任何身份信息或扩展。
	// 对外统一映射为 INVALID_ARGUMENT，且**不说明具体是哪个字段**。
	ErrCSRNotPlain = errors.New("nodeidentity：CSR 必须是不含 CN/SAN/扩展的纯持有性证明")
	// ErrNoClientCert 请求未携带客户端证书。
	ErrNoClientCert = errors.New("nodeidentity：请求未携带客户端证书")
	// ErrCertUntrusted 客户端证书不是由本 CA 签发（或链不完整）。
	ErrCertUntrusted = errors.New("nodeidentity：客户端证书不可信（非本 CA 签发或链不完整）")
	// ErrCertExpired 客户端证书已过期（或尚未生效）。
	ErrCertExpired = errors.New("nodeidentity：客户端证书不在有效期内")
	// ErrIdentityMismatch 证书身份与请求声明的 node_id 不一致。
	ErrIdentityMismatch = errors.New("nodeidentity：证书身份与 node_id 不一致")
	// ErrCertRevoked 证书已被吊销（D3：即使仍在有效期内也必须拒绝）。
	ErrCertRevoked = errors.New("nodeidentity：证书已被吊销")
)

// RevocationChecker 证书吊销检查（D3）。
//
// 控制面维护吊销表（N6 落 PG 表 test_cert_revocations，serial 为主键）；
// 本包只依赖该接口，**每次 mTLS 校验都会查询**。
type RevocationChecker interface {
	// IsRevoked 判定 serial 是否已被吊销。
	IsRevoked(serial string) (bool, error)
}

// CAConfig CA 配置。
type CAConfig struct {
	// Validity 签发给节点的证书有效期（<=0 用 DefaultCertValidity=7 天）。
	// **必须由配置项指定**：不得在签发路径硬编码。
	Validity time.Duration
	// Revocations 吊销检查器（可为 nil：表示未配置，此时跳过吊销检查——
	// 生产必须配置；测试中 nil 仅用于"无吊销"的对照场景）。
	Revocations RevocationChecker
	// CAValidity CA 自身有效期（<=0 用 DefaultCAValidity）。
	CAValidity time.Duration
	// Now CA 自身的签发时刻（零值用 time.Now；测试注入固定时钟）。
	Now time.Time
}

// TestCA 仅测试的证书颁发机构（私钥仅内存）。
type TestCA struct {
	// key CA 私钥（仅内存；不导出）。
	key *ecdsa.PrivateKey
	// cert CA 证书。
	cert *x509.Certificate
	// certDER CA 证书 DER（可安全分发）。
	certDER []byte
	// cfg 配置（有效期、吊销检查器）。
	cfg CAConfig
}

// NewTestCA 生成测试 CA（ECDSA P-256；私钥不落盘）。
//
// 有效期与吊销检查器由 CAConfig 指定（D3：不得硬编码有效期）。
func NewTestCA(cfg CAConfig, r io.Reader) (*TestCA, error) {
	if r == nil {
		r = rand.Reader
	}
	if cfg.Validity <= 0 {
		cfg.Validity = DefaultCertValidity
	}
	caValidity := cfg.CAValidity
	if caValidity <= 0 {
		caValidity = DefaultCAValidity
	}
	cfg.CAValidity = caValidity
	now := cfg.Now
	if now.IsZero() {
		now = time.Now()
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), r)
	if err != nil {
		return nil, fmt.Errorf("nodeidentity：生成 CA 私钥失败：%w", err)
	}
	serial, err := randomSerial(r)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "agent-ops test CA", Organization: []string{"agent-ops (test)"}},
		NotBefore:             now.UTC().Add(-time.Minute),
		NotAfter:              now.UTC().Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}
	der, err := x509.CreateCertificate(r, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("nodeidentity：签发 CA 证书失败：%w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("nodeidentity：解析 CA 证书失败：%w", err)
	}
	return &TestCA{key: key, cert: cert, certDER: der, cfg: cfg}, nil
}

// Validity 返回生效的证书有效期（供运维核对与测试断言）。
func (ca *TestCA) Validity() time.Duration { return ca.cfg.Validity }

// SetRevocations 设置/替换吊销检查器（N6 在 PG 就绪后注入）。
func (ca *TestCA) SetRevocations(rc RevocationChecker) { ca.cfg.Revocations = rc }

// CertificateDER 返回 CA 证书 DER（可安全分发/用于测试客户端信任根）。
func (ca *TestCA) CertificateDER() []byte {
	out := make([]byte, len(ca.certDER))
	copy(out, ca.certDER)
	return out
}

// Pool 返回只含本 CA 的信任池。
func (ca *TestCA) Pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	return pool
}

// SerialNumber 返回 CA 证书序列号（运维核对用）。
func (ca *TestCA) SerialNumber() *big.Int { return ca.cert.SerialNumber }

// NewNodeKey 生成节点私钥（ECDSA P-256；仅内存）。
func NewNodeKey(r io.Reader) (*ecdsa.PrivateKey, error) {
	if r == nil {
		r = rand.Reader
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), r)
	if err != nil {
		return nil, fmt.Errorf("nodeidentity：生成节点私钥失败：%w", err)
	}
	return key, nil
}

// NewCSR 用给定私钥生成**纯持有性证明** CSR（DER）。
//
// D2：CSR **不含 CN、不含任何 SAN、不含扩展字段**——它唯一的作用是证明
// 请求方持有对应私钥。身份（node_id）**只由控制面在 Enroll 成功时分配**。
func NewCSR(key *ecdsa.PrivateKey, r io.Reader) ([]byte, error) {
	if r == nil {
		r = rand.Reader
	}
	tmpl := &x509.CertificateRequest{} // 空 Subject、无 SAN、无扩展
	der, err := x509.CreateCertificateRequest(r, tmpl, key)
	if err != nil {
		return nil, fmt.Errorf("nodeidentity：生成 CSR 失败：%w", err)
	}
	return der, nil
}

// ParseCSRProofOfPossession（D2）解析并校验"纯持有性证明"CSR：
//  1. 可解析、签名有效、含公钥；
//  2. **不含 CN**；
//  3. **不含任何 SAN**（DNS / IP / URI / Email）；
//  4. **不含任何扩展字段**。
//
// 违反 2–4 一律返回 ErrCSRNotPlain（对外统一 INVALID_ARGUMENT，不说明具体字段）。
func ParseCSRProofOfPossession(csrDER []byte) (*x509.CertificateRequest, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("%w：解析失败", ErrCSRInvalid)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("%w：自签名校验失败", ErrCSRInvalid)
	}
	if csr.PublicKey == nil {
		return nil, fmt.Errorf("%w：缺少公钥", ErrCSRInvalid)
	}
	if strings.TrimSpace(csr.Subject.CommonName) != "" {
		return nil, ErrCSRNotPlain
	}
	if len(csr.DNSNames) > 0 || len(csr.IPAddresses) > 0 || len(csr.URIs) > 0 ||
		len(csr.EmailAddresses) > 0 {
		return nil, ErrCSRNotPlain
	}
	if len(csr.Extensions) > 0 {
		return nil, ErrCSRNotPlain
	}
	// Subject 的其他字段（O/OU/L/...）同样不允许：持有性证明不应携带任何身份信息。
	if len(csr.Subject.Organization) > 0 || len(csr.Subject.OrganizationalUnit) > 0 ||
		len(csr.Subject.Locality) > 0 || len(csr.Subject.Province) > 0 ||
		len(csr.Subject.Country) > 0 || len(csr.Subject.StreetAddress) > 0 ||
		len(csr.Subject.PostalCode) > 0 || len(csr.Subject.SerialNumber) > 0 ||
		len(csr.Subject.Names) > 0 || len(csr.Subject.ExtraNames) > 0 {
		return nil, ErrCSRNotPlain
	}
	return csr, nil
}

// ParseCSRProofOfPossessionPEM（T3）PEM 形态的持有性证明校验。
//
// Renew 请求携带 PEM（便于运维人工核对），因此与 Enroll 的 DER 入口分开；
// 校验规则完全一致（无 CN / 无 SAN / 无扩展 / 签名有效），
// 解析失败统一映射为 ErrCSRInvalid / ErrCSRNotPlain。
func ParseCSRProofOfPossessionPEM(csrPEM []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, fmt.Errorf("%w：PEM 解码失败", ErrCSRInvalid)
	}
	if block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("%w：PEM 类型不是证书请求", ErrCSRInvalid)
	}
	return ParseCSRProofOfPossession(block.Bytes)
}

// CertificateRequestPEM 把 DER CSR 编码为 PEM（节点侧生成请求用）。
func CertificateRequestPEM(csrDER []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
}

// SignCSRFromPEM（T3）PEM 形态的签发入口，语义与 SignCSR 完全一致。
func (ca *TestCA) SignCSRFromPEM(csrPEM []byte, nodeID string, now time.Time,
	r io.Reader) (certDER []byte, notAfter time.Time, err error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, time.Time{}, fmt.Errorf("%w：PEM 解码失败", ErrCSRInvalid)
	}
	return ca.SignCSR(block.Bytes, nodeID, now, r)
}

// SignCSR（N3）用 CSR 的公钥签发节点证书：CN 与 SAN 均为**控制面分配的** nodeID。
//
// 注意：CSR 中的声明身份只用于一致性校验，**不进入最终证书**——权威身份由控制面
// 分配（nod_<ULID>），证书身份与之严格绑定。
func (ca *TestCA) SignCSR(csrDER []byte, nodeID string, now time.Time, r io.Reader) (certDER []byte, notAfter time.Time, err error) {
	if err := ValidateNodeID(nodeID); err != nil {
		return nil, time.Time{}, err
	}
	csr, err := ParseCSRProofOfPossession(csrDER)
	if err != nil {
		return nil, time.Time{}, err
	}
	if r == nil {
		r = rand.Reader
	}
	serial, err := randomSerial(r)
	if err != nil {
		return nil, time.Time{}, err
	}
	notAfter = now.UTC().Add(ca.cfg.Validity)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: nodeID, Organization: []string{"agent-ops node"}},
		DNSNames:     []string{nodeID},
		// URI SAN 便于后续扩展为 spiffe-like 身份；本轮与 DNS SAN 同值。
		URIs:                  []*url.URL{mustURL("agent-ops://node/" + nodeID)},
		NotBefore:             now.UTC().Add(-time.Minute),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(r, tmpl, ca.cert, csr.PublicKey, ca.key)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("nodeidentity：签发节点证书失败：%w", err)
	}
	return der, notAfter, nil
}

// VerifyClientCert（N4）校验客户端证书：由本 CA 签发、在有效期内（注入时钟）。
//
// 返回解析后的证书；任何失败都返回上面的哨兵错误（不泄露证书内容）。
func (ca *TestCA) VerifyClientCert(certDER []byte, now time.Time) (*x509.Certificate, error) {
	if len(certDER) == 0 {
		return nil, ErrNoClientCert
	}
	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, ErrNoClientCert
	}
	// 有效期：用注入时钟显式判定（x509.Verify 也会判，但这里给出精确错误）。
	if now.UTC().Before(leaf.NotBefore) || !now.UTC().Before(leaf.NotAfter) {
		return nil, ErrCertExpired
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:       ca.Pool(),
		CurrentTime: now.UTC(),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		// 区分"过期"与"不可信"：过期在上面的显式判定中已拦截，
		// 走到这里基本是链/用途问题。
		return nil, ErrCertUntrusted
	}
	// D3：吊销检查——即使证书仍在有效期内，被吊销也必须拒绝。
	if ca.cfg.Revocations != nil {
		revoked, rerr := ca.cfg.Revocations.IsRevoked(leaf.SerialNumber.String())
		if rerr != nil {
			// 吊销表不可读时 fail-closed：宁可拒绝，也不放行一个可能已吊销的证书。
			return nil, fmt.Errorf("%w：吊销表查询失败", ErrCertUntrusted)
		}
		if revoked {
			return nil, ErrCertRevoked
		}
	}
	return leaf, nil
}

// CheckCertBindsNodeID（N4）证书的 CN 或 SAN 必须与请求声明的 node_id 一致。
func CheckCertBindsNodeID(cert *x509.Certificate, nodeID string) error {
	if cert == nil || nodeID == "" {
		return ErrIdentityMismatch
	}
	if cert.Subject.CommonName == nodeID {
		return nil
	}
	for _, dns := range cert.DNSNames {
		if dns == nodeID {
			return nil
		}
	}
	for _, u := range cert.URIs {
		if u != nil && u.String() == "agent-ops://node/"+nodeID {
			return nil
		}
	}
	return ErrIdentityMismatch
}

// CertificatePEM 把 DER 编码为 PEM（**只用于公钥/证书**，私钥无对应函数）。
func CertificatePEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// randomSerial 生成证书序列号（128 位随机正数）。
func randomSerial(r io.Reader) (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(r, limit)
	if err != nil {
		return nil, fmt.Errorf("nodeidentity：生成证书序列号失败：%w", err)
	}
	return n, nil
}

// mustURL 解析固定形态的 URL（构造常量时使用；失败即 panic，属编程错误）。
func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic("nodeidentity：内部 URL 常量非法：" + err.Error())
	}
	return u
}
