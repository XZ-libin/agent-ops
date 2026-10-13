// Package enrollclient 是节点侧的注册/心跳客户端（第二十二轮 D4/N7）。
//
// 引导信任（D4）是本包的核心约束：
//   - **只信任配置的 CA**（CABundlePEM），不使用系统根证书；
//   - **必须校验期望的服务端名称**（ServerName，须与证书 SAN 匹配）；
//   - **绝不**使用 InsecureSkipVerify 或任何等价跳过校验的选项
//     （仓库级 AST 守卫 TestNodeAgentModuleAvoidsInsecureTLS 断言）；
//   - **注册令牌只在服务端证书校验通过之后才发送**：Dial 会强制完成 TLS 握手
//     （等待连接进入 READY），握手失败即返回错误，此时令牌尚未离开本进程。
//
// 私钥只在内存中持有（由调用方生成/传入），不落盘、不提交。
package enrollclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/timestamppb"

	contractv1 "github.com/ORG/agent-ops/contract/gen/go/agent_ops/contract/v1"
	"github.com/ORG/agent-ops/internal/nodeidentity"
)

// DefaultDialTimeout 建立连接（含 TLS 握手）的默认超时。
const DefaultDialTimeout = 10 * time.Second

// 错误。
var (
	// ErrBadConfig 配置不完整。
	ErrBadConfig = errors.New("enrollclient：配置不完整")
	// ErrNoTrustAnchor 未提供 CA 包（禁止退回系统根证书）。
	ErrNoTrustAnchor = errors.New("enrollclient：必须提供 CA 包（CABundlePEM），不信任系统根证书")
	// ErrServerNameRequired 未提供服务端名称（禁止跳过名称校验）。
	ErrServerNameRequired = errors.New("enrollclient：必须提供期望的服务端名称（ServerName）")
	// ErrHandshakeFailed TLS 握手失败（服务端证书校验未通过）。
	ErrHandshakeFailed = errors.New("enrollclient：与服务端的 TLS 握手失败（证书校验未通过）")
)

// Config 客户端配置。
type Config struct {
	// ServerAddr 控制面地址 host:port。
	ServerAddr string
	// ServerName **期望的服务端名称**（必须与证书 SAN 匹配）。
	ServerName string
	// CABundlePEM 信任的 CA 证书（PEM，可含多个）。
	CABundlePEM []byte
	// NodeKey 节点私钥（仅内存）。
	NodeKey *ecdsa.PrivateKey
	// DisplayLabel 展示标签（不参与身份）。
	DisplayLabel string
	// AgentVersion 节点代理版本。
	AgentVersion string
	// DialTimeout 连接（含握手）超时（<=0 用 DefaultDialTimeout）。
	DialTimeout time.Duration
}

// Client 节点侧客户端。
//
// **两阶段连接**：注册前没有客户端证书（引导阶段），注册后必须用控制面签发的
// 证书重新握手——否则后续心跳在服务端看来是"无客户端证书"，会被拒绝。
// 因此这里保留 tls.Config，并在拿到证书后**重建连接**。
type Client struct {
	conn   *grpc.ClientConn
	rpc    contractv1.NodeAgentClient
	cfg    Config
	tlsCfg *tls.Config

	certMu sync.RWMutex
	leaf   *tls.Certificate
}

// EnrollResult 注册结果（证书与身份均在内存）。
type EnrollResult struct {
	NodeID            string
	CertificateDER    []byte
	CACertificateDER  []byte
	NotAfter          time.Time
	HeartbeatInterval time.Duration
	// PrivateKey 节点私钥（**仅内存**；调用方负责持久化或用完即弃）。
	PrivateKey *ecdsa.PrivateKey
}

// RenewResult 续期结果。
type RenewResult struct {
	// CertificateDER 新证书。
	CertificateDER []byte
	// CACertificateDER CA 证书。
	CACertificateDER []byte
	// NotAfter 新证书到期时刻。
	NotAfter time.Time
	// SupersededSerial 被取代的旧序列号（服务端确认后写入吊销表）。
	SupersededSerial string
}

// Dial 建立到控制面的 **mTLS** 连接，并在返回前完成 TLS 握手。
//
// 握手失败（服务端证书非本 CA 签发、名称不匹配、已过期/吊销等）时直接返回错误，
// **此时不会发送任何请求**——注册令牌因此不可能被发送给未通过校验的服务端。
func Dial(ctx context.Context, cfg Config) (*Client, error) {
	if strings.TrimSpace(cfg.ServerAddr) == "" {
		return nil, fmt.Errorf("%w：ServerAddr 必填", ErrBadConfig)
	}
	if strings.TrimSpace(cfg.ServerName) == "" {
		return nil, ErrServerNameRequired
	}
	if len(cfg.CABundlePEM) == 0 {
		return nil, ErrNoTrustAnchor
	}
	if cfg.NodeKey == nil {
		return nil, fmt.Errorf("%w：NodeKey 必填", ErrBadConfig)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(cfg.CABundlePEM) {
		return nil, fmt.Errorf("%w：CA 包无法解析（PEM 非法）", ErrBadConfig)
	}
	timeout := cfg.DialTimeout
	if timeout <= 0 {
		timeout = DefaultDialTimeout
	}
	// 严格 TLS：只信任配置的 CA，必须匹配服务端名称。
	// 注意：这里**没有** InsecureSkipVerify，也不提供任何跳过校验的开关。
	c := &Client{cfg: cfg}
	c.tlsCfg = &tls.Config{
		RootCAs:    pool,
		ServerName: cfg.ServerName,
		MinVersion: tls.VersionTLS12,
		// 动态出示客户端证书：注册前为空（引导阶段），注册后为控制面签发的那张。
		//
		// 注意：这里**必须**返回非 nil 的 *tls.Certificate——crypto/tls 在收到
		// 证书请求时会对返回值直接解引用（nil 会 panic）。"没有证书"用
		// 空 Certificate 切片表示，等价于发送空的 Certificate 消息。
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			if cert := c.currentCert(); cert != nil {
				return cert, nil
			}
			return &tls.Certificate{}, nil
		},
	}
	if err := c.connect(ctx, timeout); err != nil {
		return nil, err
	}
	return c, nil
}

// connect 建立连接并等待 TLS 握手完成（READY）。
func (c *Client) connect(ctx context.Context, timeout time.Duration) error {
	conn, err := grpc.NewClient(c.cfg.ServerAddr,
		grpc.WithTransportCredentials(credentials.NewTLS(c.tlsCfg)))
	if err != nil {
		return fmt.Errorf("enrollclient：建立连接失败：%w", err)
	}
	c.conn = conn
	c.rpc = contractv1.NewNodeAgentClient(conn)
	if err := c.waitReady(ctx, timeout); err != nil {
		_ = conn.Close()
		return err
	}
	return nil
}

// currentCert 返回当前客户端证书（未注册时为 nil = 不出示证书）。
func (c *Client) currentCert() *tls.Certificate {
	c.certMu.RLock()
	defer c.certMu.RUnlock()
	return c.leaf
}

// setIssuedCert 装载控制面签发的证书（**仅内存**）。
func (c *Client) setIssuedCert(certDER []byte) error {
	if len(certDER) == 0 {
		return fmt.Errorf("%w：注册响应未包含证书", ErrBadConfig)
	}
	// 直接构造 tls.Certificate：**不序列化私钥**（nodeidentity 刻意不提供任何
	// 私钥导出路径，仓库级守卫 TestNoPrivateKeyExportPath 断言这一点）。
	leaf := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  c.cfg.NodeKey,
	}
	// 自检：私钥必须与证书公钥匹配（否则后续握手会失败）。
	parsed, perr := x509.ParseCertificate(certDER)
	if perr != nil {
		return fmt.Errorf("enrollclient：签发的证书无法解析：%w", perr)
	}
	if !c.cfg.NodeKey.PublicKey.Equal(parsed.PublicKey) {
		return fmt.Errorf("enrollclient：签发的证书与本地私钥不匹配")
	}
	leaf.Leaf = parsed
	c.certMu.Lock()
	c.leaf = &leaf
	c.certMu.Unlock()
	return nil
}

// reconnect 用（已装载的）客户端证书重建连接，保证后续 RPC 走 mTLS。
func (c *Client) reconnect(ctx context.Context) error {
	timeout := c.cfg.DialTimeout
	if timeout <= 0 {
		timeout = DefaultDialTimeout
	}
	if c.conn != nil {
		_ = c.conn.Close()
	}
	return c.connect(ctx, timeout)
}

// waitReady 触发连接并等待进入 READY（= TLS 握手已完成、服务端证书已通过校验）。
func (c *Client) waitReady(ctx context.Context, timeout time.Duration) error {
	c.conn.Connect()
	wctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		st := c.conn.GetState()
		if st == connectivity.Ready {
			return nil
		}
		if !c.conn.WaitForStateChange(wctx, st) {
			return fmt.Errorf("%w：等待连接就绪超时（状态 %s）", ErrHandshakeFailed, st)
		}
		if wctx.Err() != nil {
			return fmt.Errorf("%w：等待连接就绪超时（状态 %s）", ErrHandshakeFailed, c.conn.GetState())
		}
	}
}

// Enroll 用一次性令牌注册，换取控制面分配的 node_id 与证书。
//
// 调用前 Dial 已完成服务端校验，因此令牌只会发送给已通过校验的服务端。
func (c *Client) Enroll(ctx context.Context, token string) (*EnrollResult, error) {
	if strings.TrimSpace(token) == "" {
		return nil, fmt.Errorf("%w：注册令牌为空", ErrBadConfig)
	}
	// CSR 是**纯持有性证明**（D2：不含 CN / SAN / 扩展）。
	csrDER, err := nodeidentity.NewCSR(c.cfg.NodeKey, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.rpc.Enroll(ctx, &contractv1.EnrollRequest{
		EnrollmentToken: token,
		CsrDer:          csrDER,
		DisplayLabel:    c.cfg.DisplayLabel,
		AgentVersion:    c.cfg.AgentVersion,
	})
	if err != nil {
		return nil, err
	}
	// 装载签发的证书并**重建连接**：此后的心跳才是真正的 mTLS（服务端可见客户端证书）。
	if err := c.setIssuedCert(resp.GetCertificateDer()); err != nil {
		return nil, err
	}
	if err := c.reconnect(ctx); err != nil {
		return nil, err
	}

	out := &EnrollResult{
		NodeID:           resp.GetNodeId(),
		CertificateDER:   resp.GetCertificateDer(),
		CACertificateDER: resp.GetCaCertificateDer(),
		PrivateKey:       c.cfg.NodeKey,
	}
	if ts := resp.GetNotAfter(); ts != nil {
		out.NotAfter = ts.AsTime()
	}
	if secs := resp.GetHeartbeatIntervalSeconds(); secs > 0 {
		out.HeartbeatInterval = time.Duration(secs) * time.Second
	}
	return out, nil
}

// Heartbeat 单向上报一次心跳（携带会话标识；D6）。
func (c *Client) Heartbeat(ctx context.Context, nodeID, bootSessionID string,
	sentAt time.Time, load *contractv1.NodeLoadSummary) (contractv1.NodeStatus, error) {
	resp, err := c.rpc.Heartbeat(ctx, &contractv1.HeartbeatRequest{
		NodeId:        nodeID,
		SentAt:        timestamppb.New(sentAt),
		AgentVersion:  c.cfg.AgentVersion,
		Load:          load,
		BootSessionId: bootSessionID,
	})
	if err != nil {
		return contractv1.NodeStatus_NODE_STATUS_UNSPECIFIED, err
	}
	return resp.GetStatus(), nil
}

// AdoptIdentity 装载**已持久化**的身份并重建 mTLS 连接（T2 重启复用路径）。
//
// 与注册路径的区别：不消耗令牌、不调用任何 RPC——直接用手上的证书重新握手。
func (c *Client) AdoptIdentity(ctx context.Context, certDER, caDER []byte,
	key *ecdsa.PrivateKey) error {
	if len(certDER) == 0 || key == nil {
		return fmt.Errorf("%w：证书或私钥为空", ErrBadConfig)
	}
	parsed, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("enrollclient：持久化证书无法解析：%w", err)
	}
	if !key.PublicKey.Equal(parsed.PublicKey) {
		return fmt.Errorf("%w：持久化证书与私钥不匹配", ErrBadConfig)
	}
	c.certMu.Lock()
	c.leaf = &tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: key, Leaf: parsed}
	c.certMu.Unlock()
	return c.reconnect(ctx)
}

// Renew 用新 CSR（PEM）续期证书（T3）。
//
// 请求只包含 CSR——node_id 由服务端从**客户端证书**的 CN 读取，节点无法自报。
// 成功后立即装载新证书并重建连接（后续心跳携带新序列号，服务端据此确认旧证书 supersede）。
func (c *Client) Renew(ctx context.Context, csrPEM []byte) (*RenewResult, error) {
	if len(csrPEM) == 0 {
		return nil, fmt.Errorf("%w：CSR 为空", ErrBadConfig)
	}
	resp, err := c.rpc.Renew(ctx, &contractv1.RenewRequest{CsrPem: csrPEM})
	if err != nil {
		return nil, err
	}
	out := &RenewResult{
		CertificateDER:   resp.GetCertificateDer(),
		CACertificateDER: resp.GetCaCertificateDer(),
		SupersededSerial: resp.GetSupersededSerial(),
	}
	if ts := resp.GetNotAfter(); ts != nil {
		out.NotAfter = ts.AsTime()
	}
	// 装载新证书（用**同一个**私钥——节点私钥永不离开节点）。
	if err := c.setIssuedCert(resp.GetCertificateDer()); err != nil {
		return nil, err
	}
	if err := c.reconnect(ctx); err != nil {
		return nil, err
	}
	return out, nil
}

// Close 关闭连接。
func (c *Client) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	return c.conn.Close()
}
