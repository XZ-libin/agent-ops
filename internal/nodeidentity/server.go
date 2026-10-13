package nodeidentity

// 控制面**服务端**证书（第二十二轮 D4：引导信任）。
//
// 控制面的 gRPC 服务端证书由**同一个 CA** 签发，SAN 为 `127.0.0.1` 与 `localhost`。
// 节点侧必须：
//   - 只信任配置的 CA（CA 包）；
//   - 校验**期望的服务端名称**（ServerName）；
//   - **绝不**使用 InsecureSkipVerify 或等价选项（仓库级 AST 守卫断言）。
//
// 私钥只在内存中生成与持有，不落盘、不提交。

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"net"
	"time"
)

// DefaultServerSANs 控制面服务端证书的默认 SAN（工程默认，待运维确认）。
var DefaultServerSANs = []string{"127.0.0.1", "localhost"}

// ServerCert 控制面服务端证书（含私钥，**仅内存**）。
type ServerCert struct {
	// CertificateDER 证书 DER。
	CertificateDER []byte
	// PrivateKey 私钥（仅内存；不落盘、不导出为文件）。
	PrivateKey *ecdsa.PrivateKey
	// NotAfter 到期时间。
	NotAfter time.Time
}

// IssueServerCert 用本 CA 签发控制面服务端证书（SAN: 127.0.0.1, localhost）。
//
// sans 为 nil 时使用 DefaultServerSANs；可用于测试"名称不匹配"的负例。
func (ca *TestCA) IssueServerCert(now time.Time, sans []string, r io.Reader) (*ServerCert, error) {
	if ca == nil {
		return nil, fmt.Errorf("nodeidentity：CA 为空")
	}
	if r == nil {
		r = rand.Reader
	}
	names := sans
	if names == nil {
		names = DefaultServerSANs
	}
	key, err := ecdsa.GenerateKey(ca.key.Curve, r)
	if err != nil {
		return nil, fmt.Errorf("nodeidentity：生成服务端私钥失败：%w", err)
	}
	serial, err := randomSerial(r)
	if err != nil {
		return nil, err
	}
	var ips []net.IP
	var dns []string
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			ips = append(ips, ip)
			continue
		}
		dns = append(dns, n)
	}
	notAfter := now.UTC().Add(ca.cfg.Validity)
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "agent-ops control-plane (test)", Organization: []string{"agent-ops (test)"}},
		DNSNames:              dns,
		IPAddresses:           ips,
		NotBefore:             now.UTC().Add(-time.Minute),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(r, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, fmt.Errorf("nodeidentity：签发服务端证书失败：%w", err)
	}
	return &ServerCert{CertificateDER: der, PrivateKey: key, NotAfter: notAfter}, nil
}
