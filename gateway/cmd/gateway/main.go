// Command gateway 是 Agent Ops 执行网关入口（第十轮 G2）。
//
// 启动顺序（fail-closed，任何一步失败即退出，不进入监听状态）：
//
//	解析配置 → 连接 PostgreSQL（本地 55432，绝不触碰 5432）→ 建/升级审计、审批、
//	幂等表结构 → 加载生产能力清单（生产注册表，拒绝 test_only）→ 生产启动守卫
//	（注册表中不得存在 test_only 能力）→ 组装网关服务 → 启动前对账（崩溃恢复）
//	→ 监听 gRPC（默认仅本机 127.0.0.1:9090）→ 优雅停机。
//
// 认证：第十九轮 A1 起支持两类。
//   - mode=test：仅测试的静态 token（-test-static-tokens，token=actor 映射）；
//     未配置任何 token 时所有 RPC 以 UNAUTHENTICATED 拒绝；
//   - mode=prod：**只允许 OIDC**（-oidc-issuer / -oidc-audience / -oidc-jwks-url），
//     actor 取自访问令牌的 sub 声明；静态 token 在 prod 下启用即拒绝启动。
//
// TODO(待决策)：资产 → SSH 通道（凭据解析）随接入通道批次实现，本轮能力执行
// Handler 为"未接线"桩（立即失败，不绕过任何策略/审计门控）。
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"

	contractv1 "github.com/XZ-libin/agent-ops/contract/gen/go/agent_ops/contract/v1"

	"github.com/XZ-libin/agent-ops/gateway/internal/approvals"
	"github.com/XZ-libin/agent-ops/gateway/internal/gateway"
	"github.com/XZ-libin/agent-ops/gateway/internal/grpcwire"
	"github.com/XZ-libin/agent-ops/gateway/internal/prodcatalog"
	"github.com/XZ-libin/agent-ops/internal/audit"
	"github.com/XZ-libin/agent-ops/internal/idempotency"
)

const version = "0.10.0-dev"

// approvalTable 生产审批表名（试点阶段名称；TODO(待决策)：生产表名待运维确认）。
const approvalTable = "approvals"

func main() {
	addr := flag.String("addr", "127.0.0.1:9090", "gRPC 监听地址（默认仅本机回环）")
	dsn := flag.String("dsn", approvals.DefaultLocalDSN, "PostgreSQL 连接串（本地 55432；绝不触碰 5432）")
	manifest := flag.String("manifest", "adapters/linux/manifest.yaml",
		"生产能力清单（adapter manifest YAML）；含 test_only 能力时拒绝启动")
	testTokens := flag.String("test-static-tokens", "",
		"仅测试：静态 token 映射，格式 \"token=actor,token2=actor2\"（mode=prod 时禁止）")
	oidcIssuer := flag.String("oidc-issuer", "",
		"生产 OIDC：期望的 issuer（精确匹配；mode=prod 必填）")
	oidcAudience := flag.String("oidc-audience", "",
		"生产 OIDC：期望的 audience（精确匹配；mode=prod 必填）")
	oidcJWKSURL := flag.String("oidc-jwks-url", "",
		"生产 OIDC：JWKS 地址（http(s):// 或本地文件路径；mode=prod 必填）")
	mode := flag.String("mode", "",
		"运行模式：test / prod（必填，无默认值；mode=prod 禁止启用仅测试静态 token，必须配置 OIDC）")
	flag.Parse()

	if err := run(*addr, *dsn, *manifest, *testTokens, *oidcIssuer, *oidcAudience, *oidcJWKSURL, *mode); err != nil {
		log.Fatalf("gateway 启动失败：%v", err)
	}
}

func run(addr, dsn, manifestPath, testTokens, oidcIssuer, oidcAudience, oidcJWKSURL, modeStr string) error {
	// H3：mode 必须显式指定；mode=prod 不得启用仅测试静态 token。
	mode, err := grpcwire.ParseMode(modeStr)
	if err != nil {
		return err
	}

	log.Printf("agent-ops gateway %s 启动中（addr=%s, mode=%s）", version, addr, mode)
	ctx := context.Background()

	// 1. 存储依赖（本地 55432；DSN 由配置注入，代码中不含真实凭据）。
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return fmt.Errorf("数据库连接失败：%w", err)
	}
	defer pool.Close()
	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		return fmt.Errorf("数据库不可达：%w", err)
	}

	// 2. 建表/升级（幂等）。
	auditStore := audit.NewStore(pool)
	if err := auditStore.EnsureSchema(ctx); err != nil {
		return fmt.Errorf("审计表结构就绪失败：%w", err)
	}
	approvalStore := approvals.NewPostgresStore(pool, approvalTable)
	if err := approvalStore.EnsureSchema(ctx); err != nil {
		return fmt.Errorf("审批表结构就绪失败：%w", err)
	}
	idemStore := idempotency.NewPostgresStore(pool)
	if err := idemStore.EnsureSchema(ctx); err != nil {
		return fmt.Errorf("幂等表结构就绪失败：%w", err)
	}

	// 3. 生产能力注册表（拒绝 test_only）+ 启动守卫。
	reg := gateway.NewRegistry()
	caps, err := prodcatalog.Load(reg, resolveManifest(manifestPath))
	if err != nil {
		return fmt.Errorf("加载生产能力清单失败：%w", err)
	}
	log.Printf("生产能力目录：%d 项（清单 %s）", len(caps), manifestPath)
	// 生产启动守卫（G2）：注册表中不得存在任何 test_only 能力。
	if err := reg.AssertNoTestOnly(); err != nil {
		return fmt.Errorf("生产启动守卫：%w", err)
	}

	// 4. 组装网关服务（生产默认配置：低风险自动执行清单为空）。
	svc, err := gateway.New(gateway.DefaultConfig(), idemStore, auditStore, approvalStore, reg)
	if err != nil {
		return fmt.Errorf("组装网关服务失败：%w", err)
	}

	// 5. 单实例守卫（H1）：存在其他实例的有效执行租约即拒绝启动。
	if err := svc.GuardSingleInstance(ctx); err != nil {
		return err
	}

	// 5b. 启动前对账：把上次崩溃遗留的、租约已过期的 executing 执行与审批标记
	// abandoned（不重放；未过期的一律跳过）。
	n, err := svc.Reconcile(ctx)
	if err != nil {
		return fmt.Errorf("启动前对账失败：%w", err)
	}
	if n > 0 {
		log.Printf("启动前对账：标记 %d 条中断执行为 abandoned（不重放）", n)
	}

	// 6. gRPC 服务（认证；H3 + A1：mode=prod 时仅测试静态 token 一律拒绝启动，
	//    且必须提供 OIDC 配置——OIDC 是 prod 唯一放行的认证方式）。
	var auth grpcwire.Authenticator = grpcwire.NewStaticTokenAuth(parseTestTokens(testTokens))
	if strings.TrimSpace(oidcIssuer) != "" || strings.TrimSpace(oidcAudience) != "" ||
		strings.TrimSpace(oidcJWKSURL) != "" {
		// 配置了任一 OIDC 参数 → 构建 OIDC 认证（会立即拉取一次 JWKS，
		// 配置/网络问题在启动期暴露而不是首个请求才失败）。
		oidcAuth, oerr := grpcwire.NewOIDCAuth(grpcwire.OIDCConfig{
			Issuer:   oidcIssuer,
			Audience: oidcAudience,
			Fetcher:  jwksFetcher(oidcJWKSURL),
		})
		if oerr != nil {
			return fmt.Errorf("OIDC 认证初始化失败：%w", oerr)
		}
		auth = oidcAuth
	}
	if err := grpcwire.GuardAuth(mode, auth); err != nil {
		return err
	}
	if mode == grpcwire.ModeProd {
		if _, ok := auth.(*grpcwire.OIDCAuth); !ok {
			return fmt.Errorf("mode=prod 必须配置 OIDC（-oidc-issuer / -oidc-audience / -oidc-jwks-url）")
		}
		log.Print("已启用 OIDC 生产认证（actor 取自令牌 sub 声明）")
	} else if strings.TrimSpace(testTokens) != "" {
		log.Print("警告：已启用仅测试的静态 token 认证（不得用于生产；生产认证接入前不得以 prod 启动）")
	}
	srv := grpc.NewServer()
	contractv1.RegisterGatewayServer(srv, grpcwire.NewServer(svc, auth))

	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("监听 %s 失败：%w", addr, err)
	}

	errCh := make(chan error, 1)
	go func() {
		log.Printf("gateway 已监听 %s（gRPC）", addr)
		errCh <- srv.Serve(lis)
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	select {
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("gRPC 服务异常退出：%w", err)
		}
		return nil
	case sig := <-stop:
		log.Printf("收到信号 %v，优雅停机中…", sig)
		srv.GracefulStop()
		return nil
	}
}

// jwksFetcher 按地址形态选择 JWKS 获取器：http(s):// 走 HTTP，其余视为本地文件。
func jwksFetcher(url string) grpcwire.JWKSFetcher {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(url)), "http") {
		return grpcwire.NewHTTPJWKSFetcher(url, 0)
	}
	return grpcwire.NewFileJWKSFetcher(url)
}

// resolveManifest 定位清单文件：先用给定路径（默认相对仓库根的
// adapters/linux/manifest.yaml），不存在时从当前目录逐级向上找仓库根
// （含 go.mod 与 adapters 目录），保证从任意子目录启动都可用。
// 找不到则原样返回，由 Load 报出明确错误。
func resolveManifest(path string) string {
	if path == "" {
		return "adapters/linux/manifest.yaml"
	}
	if fileExists(path) {
		return path
	}
	dir, err := os.Getwd()
	if err != nil {
		return path
	}
	for i := 0; i < 4; i++ {
		cand := filepath.Join(dir, "adapters/linux/manifest.yaml")
		if fileExists(cand) {
			return cand
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return path
}

// fileExists 判断文件是否存在（且不是目录）。
func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// parseTestTokens 解析仅测试的静态 token 映射（"token=actor,token2=actor2"）。
func parseTestTokens(spec string) map[string]string {
	out := map[string]string{}
	for _, pair := range strings.Split(spec, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		tok, actor, ok := strings.Cut(pair, "=")
		if !ok {
			continue
		}
		if tok = strings.TrimSpace(tok); tok == "" {
			continue
		}
		if actor = strings.TrimSpace(actor); actor == "" {
			continue
		}
		out[tok] = actor
	}
	return out
}
