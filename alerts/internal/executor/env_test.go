package executor

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/XZ-libin/agent-ops/adapters/docker"
	"github.com/XZ-libin/agent-ops/adapters/linux"
	contractv1 "github.com/XZ-libin/agent-ops/contract/gen/go/agent_ops/contract/v1"
	"github.com/XZ-libin/agent-ops/internal/audit"
	"github.com/XZ-libin/agent-ops/internal/exec/ssh"
	"github.com/XZ-libin/agent-ops/internal/exec/ssh/sshdtest"
	"github.com/XZ-libin/agent-ops/internal/policy"
	"github.com/XZ-libin/agent-ops/internal/testdb"
)

// auditAdapter 把 internal/audit.Store 适配为执行器的 AuditSink（避免执行器耦合审计包）。
type auditAdapter struct {
	mu  sync.Mutex
	st  *audit.Store
	seq int
}

func (a *auditAdapter) Append(ctx context.Context, ev AuditEvent) (string, error) {
	a.mu.Lock()
	a.seq++
	id := ev.ID
	if id == "" {
		id = fmt.Sprintf("evt-diag-%d", a.seq)
	}
	a.mu.Unlock()
	return a.st.Append(ctx, audit.Event{
		ID: id, Actor: ev.Actor, Action: ev.Action, Target: ev.Target, Payload: ev.Payload,
	})
}

// 测试用能力声明（只读；非测试目录使用，避免与生产目录混淆）。
func readOnlyDecl(name string) *contractv1.Capability {
	return &contractv1.Capability{
		Name: name, RiskTier: contractv1.RiskTier_RISK_TIER_READ_ONLY,
		Idempotent: true, Rollbackable: false, Destructive: false,
	}
}

// —— 环境构造 ——

// newExecEnv 建立真实 PG 环境（独立 run schema）+ 执行器 + 审计存储。
func newExecEnv(t *testing.T, caps map[string]CapEntry, policyCfg policy.Config) (*Executor, *auditAdapter, *testdb.RunSchema) {
	t.Helper()
	return newExecEnvCluster(t, caps, policyCfg, false)
}

// newExecEnvCluster 同上，但可指定是否"已配置集群"（第十八轮 K1）。
func newExecEnvCluster(t *testing.T, caps map[string]CapEntry, policyCfg policy.Config, cluster bool) (*Executor, *auditAdapter, *testdb.RunSchema) {
	t.Helper()
	rs := testdb.NewRunSchema(t)
	if rs == nil {
		return nil, nil, nil
	}
	ctx := context.Background()
	pool := rs.Pool()

	// 计划表（结构与规划器一致）。
	if _, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS test_diagnosis_plans (
    id          bigserial   PRIMARY KEY,
    event_id    bigint      NOT NULL UNIQUE,
    fingerprint text        NOT NULL DEFAULT '',
    source      text        NOT NULL DEFAULT '',
    severity    text        NOT NULL DEFAULT '',
    profile     text        NOT NULL DEFAULT '',
    status      text        NOT NULL DEFAULT 'planned'
                CHECK (status IN ('planned','no_rule','running','done','failed','deferred','partial','not_executed')),
    rule_id     text        NOT NULL DEFAULT '',
    capabilities text[]     NOT NULL DEFAULT '{}',
    reason      text        NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL,
    updated_at  timestamptz NOT NULL
);`); err != nil {
		t.Fatalf("建计划表失败：%v", err)
	}

	ex, err := New(Config{Pool: pool, Caps: caps, Policy: policyCfg,
		Environment:       contractv1.Environment_ENVIRONMENT_TEST,
		ClusterConfigured: cluster,
		Now:               func() time.Time { return time.Unix(1791825000, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	if err := ex.EnsureSchema(ctx); err != nil {
		t.Fatalf("建结果表失败：%v", err)
	}

	auditTable := fmt.Sprintf("test_audit_events_diag_%d", time.Now().UnixNano())
	ast := audit.NewTestStore(pool, auditTable)
	if err := ast.EnsureSchema(ctx); err != nil {
		t.Fatalf("建审计表失败：%v", err)
	}
	t.Logf("[H5] schema：%s，审计表：%s", rs.Name(), auditTable)
	return ex, &auditAdapter{st: ast}, rs
}

// planRow 插入一条计划并返回 plan_id。
func planRow(t *testing.T, rs *testdb.RunSchema, eventID int64, profile string, caps []string, status string) int64 {
	t.Helper()
	var id int64
	if err := rs.Pool().QueryRow(context.Background(), `INSERT INTO test_diagnosis_plans
(event_id, fingerprint, source, severity, profile, status, rule_id, capabilities, reason, created_at, updated_at)
VALUES ($1,$2,'test-source-a','critical',$3,$4,'R-TEST',$5,'',now(),now()) RETURNING id`,
		eventID, fmt.Sprintf("fp-%d", eventID), profile, status, caps).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// auditSeq 返回审计表的 seq 序列（升序）。
func auditSeq(t *testing.T, rs *testdb.RunSchema, table string) []int64 {
	t.Helper()
	rows, err := rs.Pool().Query(context.Background(), fmt.Sprintf(`SELECT seq FROM %s ORDER BY seq`, table))
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var s int64
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	return out
}

// —— 真实适配器接线 ——

// linuxCaps 通过真实 sshd 测试容器接线 Linux 只读能力。
func linuxCaps(t *testing.T) map[string]CapEntry {
	t.Helper()
	sshd := sshdtest.StartLocalSSHD(t)
	runner, err := ssh.New(ssh.Options{Addr: sshd.Addr, User: sshd.User, Signer: sshd.Signer, HostKey: sshd.HostKey})
	if err != nil {
		t.Fatalf("构建 SSH Runner 失败：%v", err)
	}
	t.Cleanup(func() { _ = runner.Close() })
	adapter, err := linux.New(runner)
	if err != nil {
		t.Fatal(err)
	}
	questions := map[string]string{
		"diagnose.disk_usage":      linux.QuestionDiskUsage,
		"diagnose.memory_pressure": linux.QuestionMemoryPressure,
		"diagnose.load_average":    linux.QuestionLoadAverage,
	}
	out := map[string]CapEntry{}
	for name, q := range questions {
		name, q := name, q
		out[name] = CapEntry{Decl: readOnlyDecl(name), Run: func(ctx context.Context, req Request) (Report, error) {
			insts, derr := adapter.Discover(ctx, &contractv1.AssetTarget{AssetId: "ast_exec_itest"})
			if derr != nil {
				return Report{}, derr
			}
			diag, derr := adapter.Diagnose(ctx, insts[0], q)
			if derr != nil {
				return Report{}, derr
			}
			return Report{Conclusion: diag.Conclusion, Success: true}, nil
		}}
	}
	return out
}

// dockerCaps 通过本地 Docker 守护进程 + 测试容器接线 Docker 只读能力。
func dockerCaps(t *testing.T) (map[string]CapEntry, func()) {
	t.Helper()
	endpoint := dockerEndpoint(t)
	dockerBin := toolPath(t, "docker")
	image := "busybox:1.36"
	name := fmt.Sprintf("agent-ops-diagtest-%d", time.Now().UnixNano())
	if out, err := exec.Command(dockerBin, "run", "-d", "--name", name,
		"--label", docker.TestLabel+"=true", image, "sleep", "300").CombinedOutput(); err != nil {
		t.Skipf("Docker 集成测试 skip：无法启动测试容器（%v，输出 %q）。", err, strings.TrimSpace(string(out)))
		return nil, nil
	}
	cleanup := func() {
		_ = exec.Command(dockerBin, "rm", "-f", name).Run()
	}
	adapter, err := docker.New(docker.Config{Endpoint: endpoint, Mode: docker.ModeTest})
	if err != nil {
		cleanup()
		t.Fatalf("构建 docker 适配器失败：%v", err)
	}
	questions := map[string]string{
		"docker.version":        docker.QuestionVersion,
		"docker.info":           docker.QuestionInfo,
		"docker.container.list": docker.QuestionContainerList,
		"docker.image.list":     docker.QuestionImageList,
	}
	out := map[string]CapEntry{}
	for name, q := range questions {
		name, q := name, q
		out[name] = CapEntry{Decl: readOnlyDecl(name), Run: func(ctx context.Context, req Request) (Report, error) {
			diag, derr := adapter.Diagnose(ctx, nil, q)
			if derr != nil {
				return Report{}, derr
			}
			return Report{Conclusion: diag.Conclusion, Success: true}, nil
		}}
	}
	return out, cleanup
}

// dockerEndpoint 定位本地 Docker 守护进程（unix socket）。
func dockerEndpoint(t *testing.T) string {
	t.Helper()
	if host := strings.TrimSpace(os.Getenv("DOCKER_HOST")); host != "" {
		return host
	}
	home, _ := os.UserHomeDir()
	for _, sock := range []string{"/var/run/docker.sock", filepath.Join(home, ".docker/run/docker.sock")} {
		if _, err := os.Stat(sock); err == nil {
			return "unix://" + sock
		}
	}
	t.Skip("Docker 集成测试 skip：未找到 Docker socket。")
	return ""
}

// toolPath 定位命令行工具（PATH → ~/go/bin）。
func toolPath(t *testing.T, name string) string {
	t.Helper()
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	home, _ := os.UserHomeDir()
	cand := filepath.Join(home, "go", "bin", name)
	if _, err := os.Stat(cand); err == nil {
		return cand
	}
	t.Skipf("未找到 %s（Docker 集成测试 skip）。", name)
	return ""
}
