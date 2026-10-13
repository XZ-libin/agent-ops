// Package grpcwire 把执行网关（internal/gateway）接线为 gRPC 服务（第十轮 G1）。
//
// 身份（actor）一律取自认证后的身份：静态令牌的映射值，或 OIDC 令牌的 sub 声明。
// **不接受请求体自报的 actor**——契约消息中没有 actor 字段，服务端也不读取任何
// 自报身份头。
//
// 错误码映射固定（与业务语义一一对应，不随实现漂移）：
//
//	策略拒绝（含 destructive/能力未声明）  → PERMISSION_DENIED
//	幂等冲突（同键不同内容 422 / 处理中 409）→ ALREADY_EXISTS
//	审批状态不允许（pending/expired/consumed/executing/abandoned）→ FAILED_PRECONDITION
//	审计写入失败（fail closed）           → INTERNAL
//
// 本轮认证方式有两类：
//   - **仅测试**的静态 token（StaticTokenAuth）：token → actor 的映射由调用方
//     （cmd/gateway 的 -test-static-tokens）注入，绝不硬编码真实凭据；
//     mode=prod 下启用即拒绝启动；
//   - **生产** OIDC（OIDCAuth，第十九轮 A1）：校验 OIDC 访问令牌，
//     actor 取自 sub 声明；mode=prod 下这是**唯一**放行的认证方式。
package grpcwire

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// MetaAuthorization 认证 metadata 键（值形如 "Bearer <token>"）。
const MetaAuthorization = "authorization"

// Mode 运行模式（第十一轮 H3）：必须由调用方**显式**指定，不得默认。
//
// 静态 token 认证（StaticTokenAuth）只在 mode=test 下允许启用；
// mode=prod 时启用即拒绝启动（代码层面强制，不依赖文档说明）。
type Mode string

const (
	// ModeTest 测试模式：允许仅测试的静态 token 认证。
	ModeTest Mode = "test"
	// ModeProd 生产模式：禁止仅测试的静态 token 认证。
	ModeProd Mode = "prod"
)

// ErrModeRequired mode 未显式指定（H3：不得默认为 test）。
var ErrModeRequired = errors.New("grpcwire：必须显式指定运行模式（-mode test|prod），不得依赖默认值")

// ErrTestAuthInProduction 生产模式启用了仅测试的静态 token 认证（H3）。
var ErrTestAuthInProduction = errors.New("grpcwire：mode=prod 禁止启用仅测试的静态 token 认证（生产认证接入前不得以 prod 启动）")

// ParseMode 解析运行模式：必须显式指定（空串即错误），只接受 test / prod。
func ParseMode(s string) (Mode, error) {
	switch Mode(strings.TrimSpace(s)) {
	case ModeTest:
		return ModeTest, nil
	case ModeProd:
		return ModeProd, nil
	case "":
		return "", ErrModeRequired
	}
	return "", fmt.Errorf("grpcwire：未知运行模式 %q（仅接受 test / prod）", s)
}

// GuardAuth 校验"模式 × 认证方式"组合（第十一轮 H3；第十九轮 A1 起支持 OIDC）：
//   - mode=test：允许仅测试的静态 token 认证，也允许 OIDC（用于本地联调）；
//   - mode=prod：**禁止** StaticTokenAuth（含未配置 token 的实例）——
//     OIDC 是 prod 唯一放行的认证方式；其余实现一律拒绝（fail-closed）。
//
// 生产模式**不开放任何写能力**：prodcatalog 的生产目录仍返回未实现错误，
// 本门禁只负责"谁能进来"，不负责"能做什么"。
func GuardAuth(mode Mode, auth Authenticator) error {
	if mode == ModeTest {
		return nil
	}
	if _, ok := auth.(*StaticTokenAuth); ok {
		return ErrTestAuthInProduction
	}
	if _, ok := auth.(*OIDCAuth); ok {
		return nil // 第十九轮 A1：OIDC 是 prod 唯一允许的认证方式
	}
	return fmt.Errorf("grpcwire：mode=prod 只允许 OIDCAuth，收到 %T（fail-closed）", auth)
}

// ErrUnauthenticated 身份缺失或不可信（映射 UNAUTHENTICATED）。
var ErrUnauthenticated = errors.New("grpcwire：请求缺少可信身份")

// Authenticator 从 gRPC metadata 解析认证后的身份（actor）。
// 实现必须是纯函数式的：不修改状态、不回写上下文。
type Authenticator interface {
	// Authenticate 返回认证后的 actor；不可信时返回错误（映射 UNAUTHENTICATED）。
	Authenticate(ctx context.Context) (string, error)
}

// StaticTokenAuth **仅测试**的静态 token 认证：token → actor 的静态映射。
// 常量比较（不做任何解析/回退）；未配置任何 token 时所有请求一律拒绝（fail-closed）。
type StaticTokenAuth struct {
	tokens map[string]string // token → actor
}

// NewStaticTokenAuth 构建仅测试的静态 token 认证（tokens 为 token → actor 映射）。
func NewStaticTokenAuth(tokens map[string]string) *StaticTokenAuth {
	cp := make(map[string]string, len(tokens))
	for k, v := range tokens {
		if strings.TrimSpace(k) == "" || strings.TrimSpace(v) == "" {
			continue // 拒绝空 token / 空 actor（fail-closed）
		}
		cp[k] = v
	}
	return &StaticTokenAuth{tokens: cp}
}

// Authenticate 从 metadata 的 authorization: Bearer <token> 解析 actor。
func (a *StaticTokenAuth) Authenticate(ctx context.Context) (string, error) {
	if a == nil || len(a.tokens) == 0 {
		return "", ErrUnauthenticated // 未配置身份 → 一律拒绝
	}
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", ErrUnauthenticated
	}
	vals := md.Get(MetaAuthorization)
	if len(vals) == 0 {
		return "", ErrUnauthenticated
	}
	raw := strings.TrimSpace(vals[0])
	if !strings.HasPrefix(strings.ToLower(raw), "bearer ") {
		return "", ErrUnauthenticated
	}
	token := strings.TrimSpace(raw[len("bearer "):])
	if token == "" {
		return "", ErrUnauthenticated
	}
	actor, ok := a.tokens[token]
	if !ok || strings.TrimSpace(actor) == "" {
		return "", ErrUnauthenticated
	}
	return actor, nil
}

// authenticate 统一入口：认证失败映射 UNAUTHENTICATED（不泄露 token 是否有效）。
func (s *Server) authenticate(ctx context.Context) (string, error) {
	if s.auth == nil {
		return "", status.Error(codes.Unauthenticated, "gateway：未配置身份认证（fail closed）")
	}
	actor, err := s.auth.Authenticate(ctx)
	if err != nil || strings.TrimSpace(actor) == "" {
		// 不回显具体原因（避免凭据探测）；服务端日志同样不记录 token。
		return "", status.Error(codes.Unauthenticated, "gateway：请求未通过身份认证")
	}
	return actor, nil
}
