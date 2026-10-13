// Package nodeserver 是控制面的节点 gRPC 服务端（第二十二轮 N8）。
//
// 边界与约束：
//   - **只暴露 Enroll 与 Heartbeat**（N1）：契约里没有命令类 RPC，
//     UnimplementedNodeAgentServer 保证任何未知/未来方法一律 UNIMPLEMENTED；
//   - **mTLS**（N4/D3）：服务端证书由同一测试 CA 签发；除 Enroll 外的每个 RPC
//     都要求**客户端证书**，并校验其由本 CA 签发、未过期、**未被吊销**；
//   - **身份绑定**：客户端证书的 CN 必须等于请求中的 node_id，否则拒绝；
//   - **Enroll 不要求客户端证书**——节点首次注册时还没有证书（引导阶段），
//     它靠一次性令牌 + CSR 持有性证明建立身份；这是本轮唯一的无证书 RPC；
//   - 错误映射对外**统一**：注册拒绝 → INVALID_ARGUMENT（不说明具体字段）；
//     心跳被拒 → PERMISSION_DENIED / INVALID_ARGUMENT；证书问题 → UNAUTHENTICATED。
//
// 证书/令牌/CSR/私钥**绝不**进入日志、错误与审计 payload。
package nodeserver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	contractv1 "github.com/XZ-libin/agent-ops/contract/gen/go/agent_ops/contract/v1"
	"github.com/XZ-libin/agent-ops/internal/nodehealth"
	"github.com/XZ-libin/agent-ops/internal/nodeidentity"
	"github.com/XZ-libin/agent-ops/internal/nodesvc"
)

// Server 节点 gRPC 服务端。
type Server struct {
	contractv1.UnimplementedNodeAgentServer

	svc *nodesvc.Service
	ca  *nodeidentity.TestCA
	now func() time.Time
}

// Config 服务端配置。
type Config struct {
	// Service 编排服务（必填）。
	Service *nodesvc.Service
	// CA 证书颁发机构（必填；用于签发服务端证书与校验客户端证书）。
	CA *nodeidentity.TestCA
	// Now 注入时钟（必填）。
	Now func() time.Time
}

// New 构建服务端。
func New(cfg Config) (*Server, error) {
	if cfg.Service == nil || cfg.CA == nil {
		return nil, errors.New("nodeserver：Service/CA 必填")
	}
	if cfg.Now == nil {
		return nil, errors.New("nodeserver：必须注入时钟（Config.Now）")
	}
	return &Server{svc: cfg.Service, ca: cfg.CA, now: cfg.Now}, nil
}

// TLSConfig 返回服务端的 mTLS 配置。
//
// ClientAuth 用 RequestClientCert 而非 RequireAndVerifyClientCert：
// 因为 **Enroll 是引导阶段**，节点此时还没有证书。要求与否在**每个 RPC 内**判定
// （见 requireClientCert），这样既能允许引导，又不会放过任何需要证书的调用。
func (s *Server) TLSConfig(sans []string, now time.Time) (*tls.Config, error) {
	if len(sans) == 0 {
		sans = nodeidentity.DefaultServerSANs
	}
	cert, err := s.ca.IssueServerCert(now, sans, nil)
	if err != nil {
		return nil, fmt.Errorf("nodeserver：签发服务端证书失败：%w", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{cert.CertificateDER},
			PrivateKey:  cert.PrivateKey,
		}},
		// 请求客户端证书（握手时携带）；是否必需由 RPC 层判定。
		ClientAuth: tls.RequestClientCert,
		ClientCAs:  s.ca.Pool(),
		MinVersion: tls.VersionTLS12,
	}, nil
}

// GRPCServer 构建带 mTLS 与拦截器的 gRPC 服务端。
func (s *Server) GRPCServer(sans []string, now time.Time, extra ...grpc.ServerOption) (*grpc.Server, error) {
	tlsCfg, err := s.TLSConfig(sans, now)
	if err != nil {
		return nil, err
	}
	opts := []grpc.ServerOption{
		grpc.Creds(credentials.NewTLS(tlsCfg)),
		grpc.ChainUnaryInterceptor(s.verifyUnaryInterceptor),
	}
	opts = append(opts, extra...)
	srv := grpc.NewServer(opts...)
	contractv1.RegisterNodeAgentServer(srv, s)
	return srv, nil
}

// EnrollMethods 允许在**无客户端证书**下调用的方法（仅引导注册）。
var EnrollMethods = map[string]bool{
	"/agent_ops.contract.v1.NodeAgent/Enroll": true,
}

// verifyUnaryInterceptor 对非引导方法做 mTLS 校验（链 + 有效期 + **吊销**）。
//
// 这是"每次 mTLS 连接都检查 serial"的落点：连接级校验 + 业务级（心跳）校验。
func (s *Server) verifyUnaryInterceptor(ctx context.Context, req any,
	info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	if EnrollMethods[info.FullMethod] {
		return handler(ctx, req)
	}
	if _, err := s.verifiedClientCert(ctx); err != nil {
		return nil, err
	}
	return handler(ctx, req)
}

// ClientCertFromContext 从 gRPC 上下文取客户端叶子证书。
//
// 注意：这里**只取不验**（链/有效期/吊销由调用方通过 CA 校验），
// 目的是让"是否携带证书"与"证书是否可信"两类失败可分别映射错误码。
func ClientCertFromContext(ctx context.Context) (*tls.Certificate, error) {
	p, ok := peer.FromContext(ctx)
	if !ok || p.AuthInfo == nil {
		return nil, status.Error(codes.Unauthenticated, "缺少客户端证书")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "缺少客户端证书")
	}
	if len(tlsInfo.State.PeerCertificates) == 0 {
		return nil, status.Error(codes.Unauthenticated, "缺少客户端证书")
	}
	return &tls.Certificate{Certificate: [][]byte{tlsInfo.State.PeerCertificates[0].Raw}}, nil
}

// Enroll 处理注册（引导阶段：不要求客户端证书）。
func (s *Server) Enroll(ctx context.Context, req *contractv1.EnrollRequest) (*contractv1.EnrollResponse, error) {
	out, err := s.svc.Enroll(ctx, req.GetEnrollmentToken(), req.GetCsrDer(),
		req.GetDisplayLabel(), req.GetAgentVersion())
	if err != nil {
		// 统一 INVALID_ARGUMENT：不说明是令牌、CSR 还是哪一部分不匹配。
		return nil, status.Error(codes.InvalidArgument, "注册被拒绝")
	}
	return &contractv1.EnrollResponse{
		NodeId:                   out.NodeID,
		CertificateDer:           out.CertificateDER,
		CaCertificateDer:         out.CACertificateDER,
		NotAfter:                 timestamppb.New(out.NotAfter),
		HeartbeatIntervalSeconds: int32(out.HeartbeatInterval / time.Second),
	}, nil
}

// Heartbeat 处理心跳（要求客户端证书，且 CN 必须等于请求中的 node_id）。
func (s *Server) Heartbeat(ctx context.Context, req *contractv1.HeartbeatRequest) (*contractv1.HeartbeatResponse, error) {
	nodeID := strings.TrimSpace(req.GetNodeId())
	if nodeID == "" {
		return nil, status.Error(codes.InvalidArgument, "node_id 必填")
	}
	leaf, err := s.verifiedClientCert(ctx)
	if err != nil {
		return nil, err
	}
	// 身份绑定（N4）：证书 CN 必须等于请求声明的 node_id。
	if berr := nodeidentity.CheckCertBindsNodeID(leaf, nodeID); berr != nil {
		return nil, status.Error(codes.PermissionDenied, "证书身份与 node_id 不一致")
	}

	sentAt := time.Time{}
	if ts := req.GetSentAt(); ts != nil {
		sentAt = ts.AsTime().UTC()
	}
	out, err := s.svc.Heartbeat(ctx, nodeID, strings.TrimSpace(req.GetBootSessionId()),
		sentAt, leaf.SerialNumber.String())
	if err != nil {
		switch {
		case errors.Is(err, nodesvc.ErrCertRevoked):
			return nil, status.Error(codes.PermissionDenied, "证书已被吊销")
		case errors.Is(err, nodesvc.ErrCertSuperseded):
			// T1：心跳携带 superseded 序列号 → 拒绝（不改变任何状态）。
			return nil, status.Error(codes.PermissionDenied, "证书已被取代")
		case errors.Is(err, nodesvc.ErrHeartbeatRejected):
			return nil, status.Error(codes.InvalidArgument, "心跳被拒绝")
		}
		return nil, status.Error(codes.Internal, "心跳处理失败")
	}
	return &contractv1.HeartbeatResponse{
		Status:     statusOf(out.Status),
		ServerTime: timestamppb.New(s.now().UTC()),
	}, nil
}

// Renew 处理证书续期（T3；**必须携带 mTLS 客户端证书**）。
//
// 校验顺序（与 nodesvc.Renew 一致；第 1 步由拦截器 + verifiedClientCert 完成）：
//  1. 证书由本 CA 签发且有效 → 已由拦截器校验；
//  2. 序列号未被吊销 → 拦截器（VerifyClientCert 内含吊销查询）已校验；
//  3. 证书 CN 与 SAN 与 node_id 绑定 → 本方法内校验；
//  4. 节点状态不是 revoked → service 内校验；
//  5. CSR 签名有效；6) 必须换钥；7) 签发新证书 → service 内校验。
//
// 任一步失败：统一拒绝，**不改变状态**，service 写 node.renew_rejected 审计。
func (s *Server) Renew(ctx context.Context, req *contractv1.RenewRequest) (*contractv1.RenewResponse, error) {
	raw, err := ClientCertFromContext(ctx)
	if err != nil {
		return nil, err
	}
	leaf, verr := s.ca.VerifyClientCert(raw.Certificate[0], s.now().UTC())
	if verr != nil {
		return nil, status.Error(codes.Unauthenticated, "客户端证书未通过校验")
	}
	// node_id 取自证书的 CN（**不信任请求体**；契约里也没有该字段）。
	nodeID := leaf.Subject.CommonName
	if err := nodeidentity.ValidateNodeID(nodeID); err != nil {
		return nil, status.Error(codes.Unauthenticated, "客户端证书身份非法")
	}
	// 身份绑定（CN 与 SAN 都必须等于 node_id）。
	if berr := nodeidentity.CheckCertBindsNodeID(leaf, nodeID); berr != nil {
		return nil, status.Error(codes.PermissionDenied, "证书身份与 node_id 不一致")
	}

	out, rerr := s.svc.Renew(ctx, nodeID, leaf.SerialNumber.String(),
		raw.Certificate[0], req.GetCsrPem())
	if rerr != nil {
		switch {
		case errors.Is(rerr, nodesvc.ErrRenewRejected):
			return nil, status.Error(codes.InvalidArgument, "续期被拒绝")
		}
		return nil, status.Error(codes.Internal, "续期处理失败")
	}
	return &contractv1.RenewResponse{
		CertificateDer:   out.CertificateDER,
		CaCertificateDer: out.CACertificateDER,
		NotAfter:         timestamppb.New(out.NotAfter),
		SupersededSerial: out.OldSerial,
	}, nil
}

// verifiedClientCert 取客户端证书并完成链/有效期/吊销校验。
func (s *Server) verifiedClientCert(ctx context.Context) (*x509.Certificate, error) {
	raw, err := ClientCertFromContext(ctx)
	if err != nil {
		return nil, err
	}
	leaf, verr := s.ca.VerifyClientCert(raw.Certificate[0], s.now().UTC())
	if verr != nil {
		return nil, status.Error(codes.Unauthenticated, "客户端证书未通过校验")
	}
	return leaf, nil
}

// statusOf 把内部状态映射为契约枚举。
func statusOf(st nodehealth.Status) contractv1.NodeStatus {
	switch st {
	case nodehealth.StatusOnline:
		return contractv1.NodeStatus_NODE_STATUS_ONLINE
	case nodehealth.StatusOffline:
		return contractv1.NodeStatus_NODE_STATUS_OFFLINE
	case nodehealth.StatusRevoked:
		return contractv1.NodeStatus_NODE_STATUS_REVOKED
	}
	return contractv1.NodeStatus_NODE_STATUS_UNSPECIFIED
}
