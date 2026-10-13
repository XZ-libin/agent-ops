// Command alerts 是告警入口进程（第十五轮 R5；第十八轮 W1 增加测试模式 worker）。
//
// 配置全部来自环境变量与显式参数；启动前完成校验（fail-closed，任一缺失即拒绝启动）：
//   - 运行模式 -mode 必填（test / prod）；mode=prod 本轮直接拒绝（生产认证未实现）；
//   - 源白名单 AGENT_OPS_ALERT_SOURCES 必填，且每个已列出源必须有密钥
//     AGENT_OPS_ALERT_KEY_<SOURCE> 与画像 AGENT_OPS_ALERT_PROFILE_<SOURCE>；
//   - 数据库 DSN 的库名必须是 agent_ops_test（复用 internal/testdb 校验）；
//   - -worker 仅 test 模式可用（prod 开启即拒绝启动）。
//
// 子命令：`alerts redrive ...`（人工重投，仅 test 模式）。
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ORG/agent-ops/alerts/internal/consumer"
	"github.com/ORG/agent-ops/alerts/internal/diagcaps"
	"github.com/ORG/agent-ops/alerts/internal/executor"
	"github.com/ORG/agent-ops/alerts/internal/httpapi"
	"github.com/ORG/agent-ops/alerts/internal/ingest"
	"github.com/ORG/agent-ops/alerts/internal/planner"
	"github.com/ORG/agent-ops/alerts/internal/redrive"
	"github.com/ORG/agent-ops/alerts/internal/store"
	"github.com/ORG/agent-ops/alerts/internal/worker"
	contractv1 "github.com/ORG/agent-ops/contract/gen/go/agent_ops/contract/v1"
	"github.com/ORG/agent-ops/internal/audit"
	"github.com/ORG/agent-ops/internal/policy"
	"github.com/ORG/agent-ops/internal/testdb"
)

// workerAuditTable worker 在测试模式使用的审计表（test_ 前缀，绝不写生产表）。
const workerAuditTable = "test_audit_events_alerts"

// Mode 运行模式。
type Mode string

const (
	modeTest Mode = "test"
	modeProd Mode = "prod"
)

// parseMode 解析运行模式：必填；prod 本轮直接拒绝。
func parseMode(s string) (Mode, error) {
	switch Mode(strings.TrimSpace(s)) {
	case modeTest:
		return modeTest, nil
	case modeProd:
		return "", errors.New("alerts：mode=prod 本轮不可用（生产认证未实现），拒绝启动")
	case "":
		return "", errors.New("alerts：必须显式指定 -mode（test|prod），不得依赖默认值")
	}
	return "", fmt.Errorf("alerts：未知运行模式 %q（仅接受 test / prod）", s)
}

// loadConfig 从环境变量加载并校验配置（启动前校验，缺失即拒绝）。
func loadConfig(getenv func(string) string, mode Mode) (*ingest.SourceSet, string, error) {
	if mode != modeTest {
		return nil, "", errors.New("alerts：仅 test 模式可用（生产认证未实现）")
	}
	rawSources := getenv(ingest.EnvSources)
	sources, err := ingest.ParseSources(rawSources)
	if err != nil {
		return nil, "", fmt.Errorf("alerts：%w", err)
	}
	set, err := ingest.NewSourceSet(sources, getenv)
	if err != nil {
		return nil, "", fmt.Errorf("alerts：%w", err)
	}
	dsn := strings.TrimSpace(getenv("AGENT_OPS_ALERT_DSN"))
	if dsn == "" {
		dsn = testdb.DefaultDSN
	}
	if err := testdb.Validate(dsn); err != nil {
		return nil, "", fmt.Errorf("alerts：%w", err)
	}
	return set, dsn, nil
}

func main() {
	// 子命令：`alerts redrive ...` 走人工重投（仅测试模式）；否则走服务启动。
	if len(os.Args) > 1 && os.Args[1] == "redrive" {
		if err := runRedrive(os.Args[2:], os.Getenv); err != nil {
			log.Fatalf("redrive 失败：%v", err)
		}
		return
	}

	addr := flag.String("addr", "127.0.0.1:8088", "监听地址（默认仅本机回环）")
	mode := flag.String("mode", "", "运行模式：test / prod（必填；prod 本轮不可用）")
	withWorker := flag.Bool("worker", false, "启动常驻 worker（consumer→planner→executor）；仅 test 模式可用")
	flag.Parse()

	if err := run(*addr, *mode, *withWorker); err != nil {
		log.Fatalf("alerts 启动失败：%v", err)
	}
}

// checkWorkerMode 校验 -worker 与运行模式的组合（fail-closed）。
func checkWorkerMode(withWorker bool, mode Mode) error {
	if withWorker && mode != modeTest {
		return errors.New("alerts：-worker 仅 test 模式可用；mode=prod 开启 worker 一律拒绝启动")
	}
	return nil
}

// runRedrive 执行人工重投子命令（第十七轮 P3）。
//
// 用法：alerts redrive -mode test -event-id <N> -confirm -operator <名称>
// 拒绝条件：mode 不是 test / 缺 -confirm / 缺 -operator / 事件不存在 / 事件非 dead。
func runRedrive(args []string, getenv func(string) string) error {
	fs := flag.NewFlagSet("redrive", flag.ContinueOnError)
	mode := fs.String("mode", "", "运行模式：仅 test 可用（必填）")
	eventID := fs.Int64("event-id", 0, "要重投的 outbox 事件 ID（必填）")
	confirm := fs.Bool("confirm", false, "确认执行重投（必填；缺省拒绝）")
	operator := fs.String("operator", "", "操作人名称（必填，用于留痕）")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *eventID <= 0 {
		return errors.New("redrive：必须提供 -event-id <正整数>")
	}
	// 配置校验（复用与启动同一套：源白名单/密钥/画像/库名）。
	m, err := parseMode(*mode)
	if err != nil {
		return err
	}
	_, dsn, err := loadConfig(getenv, m)
	if err != nil {
		return err
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return fmt.Errorf("数据库连接失败：%w", err)
	}
	defer pool.Close()
	r, err := redrive.New(redrive.Config{Pool: pool})
	if err != nil {
		return err
	}
	if err := r.EnsureSchema(ctx); err != nil {
		return err
	}
	if err := r.Redrive(ctx, *eventID, *operator, *confirm, string(m)); err != nil {
		return err
	}
	log.Printf("redrive 成功：event_id=%d operator=%s（状态置回 pending，attempts 归零）", *eventID, *operator)
	return nil
}

func run(addr, modeStr string, withWorker bool) error {
	m, err := parseMode(modeStr)
	if err != nil {
		return err
	}
	if err := checkWorkerMode(withWorker, m); err != nil {
		return err
	}
	set, dsn, err := loadConfig(os.Getenv, m)
	if err != nil {
		return err
	}
	log.Printf("alerts 启动中（addr=%s, mode=%s, worker=%v）", addr, m, withWorker)

	ctx := context.Background()
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
	st, err := store.New(pool, store.DefaultAlertsTable, store.DefaultOutboxTable)
	if err != nil {
		return err
	}
	if err := st.EnsureSchema(ctx); err != nil {
		return fmt.Errorf("告警表结构就绪失败：%w", err)
	}

	// 停止信号：HTTP 服务与 worker 共用同一个可取消上下文。
	runCtx, stopRun := context.WithCancel(ctx)
	defer stopRun()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-stop
		log.Printf("收到信号 %v，优雅停机中…（完成当前条目后退出）", sig)
		stopRun()
	}()

	// 测试模式 worker（W1）：**先同步取单实例锁**，取不到即拒绝启动。
	if withWorker {
		wk, closeCaps, err := buildWorker(runCtx, pool, set)
		if err != nil {
			return err
		}
		if closeCaps != nil {
			defer closeCaps()
		}
		release, err := wk.Acquire(runCtx)
		if err != nil {
			return fmt.Errorf("worker 单实例校验失败：%w", err)
		}
		log.Printf("worker 已获取单实例锁（key=%d），开始循环", worker.DefaultLockKey)
		go func() {
			if err := wk.Serve(runCtx, release); err != nil && !errors.Is(err, context.Canceled) {
				log.Printf("worker 退出：%v", err)
				stopRun() // worker 异常退出 → 整体停机
			}
		}()
	}

	// 限流器由 httpapi 按白名单预分配（R2）；此处不传 Limiter。
	srv, err := httpapi.New(httpapi.Config{Sources: set, Recorder: st})
	if err != nil {
		return err
	}

	// 监听与优雅停机由 httpapi 负责（入站 HTTP 符号集中在该文件）。
	log.Printf("alerts 已监听 %s（POST /v1/alerts）", addr)
	return srv.Run(runCtx, addr)
}

// buildWorker 装配测试模式 worker（consumer / planner / executor + 只读能力接线）。
// 返回 worker、能力接线释放函数（可为 nil）与错误。
func buildWorker(ctx context.Context, pool *pgxpool.Pool, set *ingest.SourceSet) (*worker.Worker, func(), error) {
	caps, err := diagcaps.Build(diagcaps.FromEnv(os.Getenv))
	if err != nil {
		return nil, nil, fmt.Errorf("只读能力接线失败：%w", err)
	}
	cons, err := consumer.New(consumer.Config{Pool: pool})
	if err != nil {
		return nil, caps.Close, err
	}
	if err := cons.EnsureSchema(ctx); err != nil {
		return nil, caps.Close, fmt.Errorf("待诊断请求表就绪失败：%w", err)
	}
	pl, err := planner.New(planner.Config{Pool: pool, Profiles: set.Profiles()})
	if err != nil {
		return nil, caps.Close, err
	}
	if err := pl.EnsureSchema(ctx); err != nil {
		return nil, caps.Close, fmt.Errorf("计划表就绪失败：%w", err)
	}
	ast := audit.NewTestStore(pool, workerAuditTable)
	if err := ast.EnsureSchema(ctx); err != nil {
		return nil, caps.Close, fmt.Errorf("审计表就绪失败：%w", err)
	}
	ex, err := executor.New(executor.Config{
		Pool: pool, Caps: caps.Caps, Policy: policy.DefaultConfig(),
		Environment:       contractv1.Environment_ENVIRONMENT_TEST,
		ClusterConfigured: caps.ClusterConfigured,
	})
	if err != nil {
		return nil, caps.Close, err
	}
	if err := ex.EnsureSchema(ctx); err != nil {
		return nil, caps.Close, fmt.Errorf("诊断结果表就绪失败：%w", err)
	}
	wk, err := worker.New(worker.Config{
		Pool: pool, Consumer: cons, Planner: pl, Executor: ex,
		AuditSink: worker.NewAuditAdapter(ast),
	})
	if err != nil {
		return nil, caps.Close, err
	}
	return wk, caps.Close, nil
}
