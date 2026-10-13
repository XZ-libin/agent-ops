package httpapi

// 第二十七轮 C4：控制台只读 API 的守卫与全栈测试。
//
// 分三类：
//   静态守卫（不连库）：路由表只允许 GET、控制台包不引入写路径、
//     入站白名单精确等于 ADR-024 的两项、OpenAPI 与路由/proto 双向一致；
//   数据层自证：test_console_reader 只有 SELECT、审计链篡改可被定位；
//   全栈行为：鉴权 401、405 + Allow、404、400 边界、响应头、
//     payload 白名单与值级密钥筛查不回传。
//
// 时间一律注入（fakeClock），不使用 sleep；数据库只用 agent_ops_test 的 run schema。

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	consolev1 "github.com/XZ-libin/agent-ops/contract/gen/go/agent_ops/console/v1"
	"github.com/XZ-libin/agent-ops/internal/audit"
	"github.com/XZ-libin/agent-ops/internal/console"
	"github.com/XZ-libin/agent-ops/internal/policy"
	"github.com/XZ-libin/agent-ops/internal/repoguard"
	"github.com/XZ-libin/agent-ops/internal/testdb"
)

// —— 夹具 ——

// fakeClock 可推进的注入时钟（禁止 sleep）。
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// testKeys 合成 JWKS：运行时生成、仅存内存、不落盘不入库（硬性约束 6/7）。
type testKeys struct {
	key *rsa.PrivateKey
	kid string
}

func (k testKeys) Keys(context.Context) (map[string]*rsa.PublicKey, error) {
	return map[string]*rsa.PublicKey{k.kid: &k.key.PublicKey}, nil
}

// fakePEM 值级筛查的夹具输入：形似 PEM 私钥的一段文本（不是任何真实密钥）。
var fakePEM = "-----BEGIN " + "RSA " + "PRIVATE KEY-----" + "MII-fixture-not-a-key" +
	"-----END " + "RSA " + "PRIVATE KEY-----"

const (
	testIssuer = "https://idp.console.test"
	testAud    = "agent-ops-console"
)

// mint 造一个 RS256 令牌；alg/kid/claims 可控以覆盖异常分支。
func mint(t *testing.T, k testKeys, alg, kid string, claims map[string]any) string {
	t.Helper()
	head, _ := json.Marshal(map[string]string{"alg": alg, "typ": "JWT", "kid": kid})
	body, _ := json.Marshal(claims)
	signing := enc(head) + "." + enc(body)
	if alg != "RS256" {
		return signing + "." + enc([]byte("garbage"))
	}
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, k.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + enc(sig)
}

func enc(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// fixtureManifest 能力清单夹具（真实提供方在控制层，控制台不 import 适配器包）。
type fixtureManifest struct {
	items []*consolev1.AdapterManifestView
}

func (f fixtureManifest) Manifest(context.Context) ([]*consolev1.AdapterManifestView, error) {
	return f.items, nil
}

// testEnv 一次全栈夹具：服务、注入时钟、表名配置、run schema、合成 JWKS 密钥。
type testEnv struct {
	srv   *Server
	clock *fakeClock
	cfg   console.Config
	rs    *testdb.RunSchema
	keys  testKeys
}

// newEnv 建 run schema、造表、灌数据、装配 Server。
func newEnv(t *testing.T) *testEnv {
	t.Helper()
	rs := testdb.NewRunSchema(t)
	if rs == nil {
		return nil // 已 skip（NewRunSchema 内部 t.Skipf）
	}
	ctx := context.Background()
	pool := rs.Pool()
	cfg := console.DefaultConfig()
	cfg.Mode = console.ModeTest

	ddl := []string{
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
    node_id          text PRIMARY KEY,
    status           text NOT NULL,
    display_label    text NOT NULL DEFAULT '',
    cert_serial      text NOT NULL DEFAULT '',
    last_received_at timestamptz,
    created_at       timestamptz NOT NULL DEFAULT now())`, cfg.NodesTable),
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
    serial text PRIMARY KEY, node_id text NOT NULL, state text NOT NULL,
    issued_at timestamptz NOT NULL, not_after timestamptz NOT NULL,
    confirmed_at timestamptz)`, cfg.CertsTable),
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
    id text PRIMARY KEY, actor text NOT NULL, capability text NOT NULL,
    request_hash text NOT NULL, idem_key text NOT NULL DEFAULT '',
    status text NOT NULL, created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL, expires_at timestamptz NOT NULL,
    approved_at timestamptz, decided_by text NOT NULL DEFAULT '',
    reason text NOT NULL DEFAULT '', lease_until timestamptz)`, cfg.ApprovalsTable),
	}
	for _, stmt := range ddl {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("建夹具表失败：%v", err)
		}
	}
	if err := audit.NewTestStore(pool, cfg.AuditTable).EnsureSchema(ctx); err != nil {
		t.Fatalf("审计夹具建表失败：%v", err)
	}

	base := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	if _, err := pool.Exec(ctx, fmt.Sprintf(
		`INSERT INTO %s (node_id, status, display_label, cert_serial, last_received_at, created_at)
		 VALUES ('nod_AAA','online','web-01','1826230000000000000001',$1,$1)`, cfg.NodesTable), base); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, fmt.Sprintf(
		`INSERT INTO %s (node_id, status, display_label, cert_serial, last_received_at, created_at)
		 VALUES ('nod_BBB','offline','', '', $1, $1)`, cfg.NodesTable), base.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, fmt.Sprintf(
		`INSERT INTO %s (serial, node_id, state, issued_at, not_after, confirmed_at)
		 VALUES ('1826230000000000000001','nod_AAA','active',$1,$2,$1)`, cfg.CertsTable),
		base, base.Add(7*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, fmt.Sprintf(
		`INSERT INTO %s (id, actor, capability, request_hash, status, created_at, updated_at, expires_at, decided_by)
		 VALUES ('apv_001','operator-a','linux.service.restart','hash-1','pending',$1,$1,$2,''),
		        ('apv_002','operator-b','diagnose.disk_usage','hash-2','approved',$1,$1,$2,'approver-c')`,
		cfg.ApprovalsTable), base, base.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}

	// 审计：既有白名单键，也有夹带的秘密材料（键级与值级两种夹带方式）。
	store := audit.NewTestStore(pool, cfg.AuditTable)
	events := []audit.Event{
		{ID: "ev1", Actor: "node:nod_AAA", Action: "node.cert_renewed", Target: "nod_AAA",
			Payload: []byte(`{"node_id":"nod_AAA","boot_session_id":"s-1","event_kind":"renew","reason_code":"ok"}`)},
		{ID: "ev2", Actor: "operator-a", Action: "approval.approved", Target: "apv_002",
			Payload: []byte(`{"approval_id":"apv_002","capability":"diagnose.disk_usage","status":"approved",
              "token":"tok-PLAINTEXT-should-drop","token_hash":"sha256:deadbeef-should-drop"}`)},
		{ID: "ev3", Actor: "executor", Action: "execution.succeeded", Target: "linux.service.restart",
			// 假 PEM 用片段拼接：仓库内不得出现成块的 PEM 私钥标记
			// （TestNoPrivateKeysCommittedInRepo 会扫到，本仓库既有做法同样如此）。
			Payload: []byte(`{"capability":"linux.service.restart","status":"ok","exit_class":"zero",
              "stdout":"` + fakePEM + `"}`)},}
		{ID: "ev4", Actor: "node:nod_AAA", Action: "node.enrolled", Target: "nod_AAA",
			// 值级夹带：合法键里塞 PEM/JWT 特征，必须被值级筛查丢弃。
			Payload: []byte(`{"node_id":"nod_AAA","event_kind":"-----BEGIN CERTIFICATE REQUEST-----QwAAAA",
              "reason_code":"eyJhbGciOiJIUzI1NiJ9.payload.signature","boot_session_id":"s-1"}`)},
	}
	for _, ev := range events {
		if _, err := store.Append(ctx, ev); err != nil {
			t.Fatalf("审计夹具写入失败：%v", err)
		}
	}

	manifest := fixtureManifest{items: []*consolev1.AdapterManifestView{
		{Adapter: "linux", Capability: "linux.service.restart", Tier: "RISK_TIER_HIGH", Destructive: true},
		{Adapter: "linux", Capability: "diagnose.disk_usage", Tier: "RISK_TIER_READ_ONLY", ReadOnly: true},
		{Adapter: "docker", Capability: "docker.container.list", Tier: "RISK_TIER_READ_ONLY", ReadOnly: true},
		{Adapter: "kubernetes", Capability: "k8s.pod.list", Tier: "RISK_TIER_READ_ONLY", ReadOnly: true},
	}}
	clock := &fakeClock{t: base}
	reader, err := console.NewReader(pool, cfg, manifest, policy.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	keys := testKeys{kid: "kid-1"}
	if keys.key, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		t.Fatal(err)
	}
	verifier, err := console.NewVerifier(console.AuthConfig{
		Mode: console.ModeTest, Issuer: testIssuer, Audience: testAud,
		Keys: keys, Now: clock.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(reader, verifier, console.DefaultTimeout)
	if err != nil {
		t.Fatal(err)
	}
	return &testEnv{srv: srv, clock: clock, cfg: cfg, rs: rs, keys: keys}
}

func mintValid(t *testing.T, k testKeys, clock *fakeClock) string {
	t.Helper()
	return "Bearer " + mint(t, k, "RS256", k.kid, map[string]any{
		"iss": testIssuer, "aud": testAud, "sub": "operator-a",
		"exp": clock.Now().Add(5 * time.Minute).Unix(),
	})
}

// get 发一次请求；token 为完整 Authorization 头值。
func get(t *testing.T, srv *Server, token, target string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	if token != "" {
		req.Header.Set("Authorization", token)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func mustDecode(t *testing.T, rec *httptest.ResponseRecorder) any {
	t.Helper()
	var out any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("响应不是合法 JSON：%v（body=%s）", err, rec.Body.String())
	}
	return out
}

// —— 静态守卫 ——

// TestConsoleRouteTableGETOnly 路由表里每一条的 Method 必须是 "GET"，
// 且整个 httpapi 包不得出现其他 HTTP 方法字面量。
func TestConsoleRouteTableGETOnly(t *testing.T) {
	root := repoRootFrom(t)
	dir := filepath.Join(root, "internal", "console", "httpapi")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	methods := 0
	seen := []string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, parser.SkipObjectResolution)
		if perr != nil {
			t.Fatal(perr)
		}
		var routeStructs int
		_ = routeStructs
		for _, st := range f.Decls {
			_ = st
		}
		// 找 Route 组合字面量的 Method 取值。
		for _, lit := range findRouteLits(f) {
			if len(lit.Elts) == 0 {
				continue // Route{} 零值（如未命中时的返回值）不是路由登记
			}
			var method string
			for _, elt := range lit.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				if keyName(kv.Key) == "Method" {
					if bl, ok2 := kv.Value.(*ast.BasicLit); ok2 {
						method, _ = unquote(bl.Value)
					}
				}
			}
			if method == "" {
				t.Fatalf("%s：发现没有 Method 的路由登记（守卫无法判定）", e.Name())
			}
			if method != http.MethodGet {
				t.Errorf("%s：路由 Method=%q 必须是 GET（只读边界）", e.Name(), method)
			}
			methods++
			seen = append(seen, method)
		}
		// 全包层面：其他方法字面量不得出现（注释与 errorMessages 的 "method_not_allowed" 不在此列）。
		src, rerr := os.ReadFile(filepath.Join(dir, e.Name()))
		if rerr != nil {
			t.Fatal(rerr)
		}
		for _, verb := range []string{`"POST"`, `"PUT"`, `"PATCH"`, `"DELETE"`} {
			if strings.Contains(string(src), verb) {
				t.Errorf("%s：出现写方法字面量 %s", e.Name(), verb)
			}
		}
	}
	if methods != len(Routes()) {
		t.Fatalf("解析到 %d 条路由登记，与 Routes() 的 %d 条不一致", methods, len(Routes()))
	}
	if methods != 9 {
		t.Fatalf("路由条数应为 9（ADR-024 §7），实际 %d：%v", methods, seen)
	}
	t.Logf("[C4] %d 条路由全部为 GET", methods)
}

// TestConsoleNoWriteImports 控制台包（含 httpapi）不得引入写路径。
func TestConsoleNoWriteImports(t *testing.T) {
	root := repoRootFrom(t)
	dirs := []string{
		filepath.Join(root, "internal", "console"),
		filepath.Join(root, "internal", "console", "httpapi"),
	}
	forbiddenImports := []string{
		"/gateway/",      // 审批/执行写侧都在 gateway 模块
		"/adapters/",     // 适配器上有 Execute*
		"/internal/exec", // 命令执行
		"/node-agent/", "/control-plane/",
	}
	forbiddenSymbols := []string{
		".Append(", ".EnsureSchema(", "Approve(", "Reject(", "ExecuteApproved(",
		"exec.Command", "http.Client", "http.NewRequest", "http.Post", "http.Get(",
	}
	checked := 0
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			path := filepath.Join(dir, e.Name())
			src, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			checked++
			text := string(src)
			impBlock := text
			if i := strings.Index(text, ")"); strings.Contains(text, "import (") && i > 0 {
				impBlock = text[:i]
			}
			for _, bad := range forbiddenImports {
				if strings.Contains(impBlock, bad) {
					t.Errorf("%s：import 了写侧路径 %s", e.Name(), bad)
				}
			}
			// 符号检查跳过注释行（注释里会出现"不得出现 Append"这类说明）。
			for _, line := range strings.Split(text, "\n") {
				trim := strings.TrimSpace(line)
				if strings.HasPrefix(trim, "//") {
					continue
				}
				for _, bad := range forbiddenSymbols {
					if strings.Contains(trim, bad) {
						t.Errorf("%s：出现写/出站符号 %s", e.Name(), bad)
					}
				}
			}
		}
	}
	if checked < 4 {
		t.Fatalf("只检查了 %d 个源文件，覆盖面异常", checked)
	}
	t.Logf("[C4] %d 个控制台源文件无写路径 import、无写符号", checked)
}

// TestConsoleInboundHTTPAllowlistExact 入站 HTTP 白名单必须**精确等于** ADR-024 的两项。
func TestConsoleInboundHTTPAllowlistExact(t *testing.T) {
	want := []string{"alerts/internal/httpapi/server.go", "internal/console/httpapi/"}
	got := append([]string(nil), repoguard.AllowedInboundHTTPFiles...)
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("[C4] 入站白名单必须恰好是 %v，实际 %v（新增条目需要另一份 ADR）", want, got)
	}
	t.Log("[C4] 入站白名单精确两项：告警入口文件 + 控制台 httpapi 目录")
}

// TestConsoleOpenAPIMatchesRoutes OpenAPI 的 paths 与路由表**双向相等**，
// 且每个路径只声明 get。
func TestConsoleOpenAPIMatchesRoutes(t *testing.T) {
	doc := loadOpenAPI(t)
	declared := map[string]bool{}
	for path, m := range doc.Paths {
		for verb := range m {
			if verb != "get" {
				t.Errorf("[C4] %s 声明了非 GET 操作 %q（只读边界）", path, verb)
			}
		}
		declared[path] = true
	}
	want := map[string]bool{}
	for _, r := range Routes() {
		want[r.Path] = true
	}
	var missing, extra []string
	for p := range want {
		if !declared[p] {
			missing = append(missing, p)
		}
	}
	for p := range declared {
		if !want[p] {
			extra = append(extra, p)
		}
	}
	if len(missing) > 0 || len(extra) > 0 {
		sort.Strings(missing)
		sort.Strings(extra)
		t.Fatalf("[C4] OpenAPI 与路由表不一致：路由有而文档缺 %v；文档有而路由无 %v", missing, extra)
	}
	t.Logf("[C4] OpenAPI paths 与 %d 条路由完全一致，且全部只有 get", len(want))
}

// TestConsoleSchemaMatchesProto components.schemas 的字段与 proto 消息字段一一对应。
func TestConsoleSchemaMatchesProto(t *testing.T) {
	root := repoRootFrom(t)
	msgs := parseProtoMessages(t, filepath.Join(root, "proto", "agent_ops", "console", "v1", "console.proto"))
	if len(msgs) != 7 {
		t.Fatalf("proto 应有 7 条契约消息，实际 %d：%v", len(msgs), keysOf(msgs))
	}
	doc := loadOpenAPI(t)
	nonContract := map[string]bool{"ErrorEnvelope": true} // 传输层错误信封，非领域契约（ADR-024 §4）

	schemas := map[string]map[string]any{}
	for name, body := range doc.Components.Schemas {
		schemas[name] = body.Properties
	}
	for name, fields := range msgs {
		props, ok := schemas[name]
		if !ok {
			t.Errorf("[C4] OpenAPI 缺少 schema %s（proto 已定义）", name)
			continue
		}
		if len(props) != len(fields) {
			t.Errorf("[C4] %s 字段数不符：proto %d %v / openapi %d %v",
				name, len(fields), fields, len(props), keysOf2(props))
			continue
		}
		for _, f := range fields {
			if _, has := props[f]; !has {
				t.Errorf("[C4] %s：OpenAPI 缺字段 %s", name, f)
			}
		}
	}
	for name := range schemas {
		if _, isMsg := msgs[name]; isMsg {
			continue
		}
		if !nonContract[name] {
			t.Errorf("[C4] OpenAPI 多出非契约 schema %s（proto 未定义且未申报例外）", name)
		}
	}
	t.Logf("[C4] 7 条消息与 OpenAPI schema 字段一一对应（另含申报的传输层 %d 个）", len(nonContract))
}

// —— 数据层自证 ——

// TestConsoleDBRoleReadOnly test_console_reader 只能 SELECT。
func TestConsoleDBRoleReadOnly(t *testing.T) {
	e := newEnv(t)
	cfg, rs := e.cfg, e.rs
	ctx := context.Background()

	if _, err := rs.Pool().Exec(ctx, `DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'test_console_reader') THEN
    CREATE ROLE test_console_reader NOLOGIN;
  END IF;
END $$;`); err != nil {
		t.Fatal(err)
	}
	tables := []string{cfg.NodesTable, cfg.CertsTable, cfg.ApprovalsTable, cfg.AuditTable}
	for _, stmt := range []string{
		fmt.Sprintf("GRANT USAGE ON SCHEMA %s TO test_console_reader", quote(rs.Name())),
		fmt.Sprintf("GRANT SELECT ON %s TO test_console_reader", strings.Join(tables, ", ")),
		fmt.Sprintf("GRANT SELECT ON %s TO test_console_reader", auditSeqSequence(cfg.AuditTable)),
	} {
		if _, err := rs.Pool().Exec(ctx, stmt); err != nil {
			t.Fatalf("授权失败：%v", err)
		}
	}

	conn, err := rs.Pool().Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "SET ROLE test_console_reader"); err != nil {
		t.Fatalf("切换角色失败：%v", err)
	}
	defer func() {
		_, _ = conn.Exec(context.Background(), "RESET ROLE")
	}()

	// 读应当可用。
	var n int
	if err := conn.QueryRow(ctx, fmt.Sprintf(`SELECT count(*) FROM %s`, cfg.NodesTable)).Scan(&n); err != nil {
		t.Fatalf("只读角色应能 SELECT 节点表：%v", err)
	}
	if n < 1 {
		t.Fatal("夹具节点数据缺失")
	}

	mutations := []string{
		fmt.Sprintf(`INSERT INTO %s (node_id, status, created_at) VALUES ('nod_ZZZ','online',now())`, cfg.NodesTable),
		fmt.Sprintf(`UPDATE %s SET status = 'revoked' WHERE node_id = 'nod_AAA'`, cfg.NodesTable),
		fmt.Sprintf(`DELETE FROM %s WHERE node_id = 'nod_BBB'`, cfg.NodesTable),
		fmt.Sprintf(`INSERT INTO %s (id, actor, capability, request_hash, status, created_at, updated_at, expires_at)
      VALUES ('apv_x','a','c','h','pending',now(),now(),now())`, cfg.ApprovalsTable),
		fmt.Sprintf(`UPDATE %s SET status = 'consumed' WHERE id = 'apv_002'`, cfg.ApprovalsTable),
		fmt.Sprintf(`DELETE FROM %s WHERE id = 'apv_001'`, cfg.ApprovalsTable),
		fmt.Sprintf(`UPDATE %s SET action = 'tampered' WHERE seq = 1`, cfg.AuditTable),
		fmt.Sprintf(`DELETE FROM %s WHERE seq = 1`, cfg.AuditTable),
		fmt.Sprintf(`INSERT INTO %s (id, actor, action, target, payload, prev_hash, hash)
      VALUES ('x','a','node.enrolled','t','{}','h','h')`, cfg.AuditTable),
	}
	for _, stmt := range mutations {
		_, err := conn.Exec(ctx, stmt)
		if err == nil {
			t.Fatalf("[C4] 语句被放行了（只读角色失效）：%s", firstLine(stmt))
		}
		msg := strings.ToLower(err.Error())
		if !strings.Contains(msg, "permission denied") && !strings.Contains(msg, "只追加") &&
			!strings.Contains(msg, "must be owner") {
			t.Errorf("[C4] 拒绝原因应是权限/只追加类错误，实际：%v", err)
		}
	}
	// DDL 同样不允许。
	if _, err := conn.Exec(ctx, fmt.Sprintf("DROP TABLE IF EXISTS %s", cfg.CertsTable)); err == nil {
		t.Fatal("[C4] 只读角色不得有 DDL 权限")
	}
	t.Logf("[C4] test_console_reader：%d 条写语句与 1 条 DDL 全部被拒，SELECT 正常", len(mutations))
}

// TestConsoleAuditVerifyReportsTamper 链篡改必须给出准确 first_bad_seq，且不回显 payload。
func TestConsoleAuditVerifyReportsTamper(t *testing.T) {
	e := newEnv(t)
	srv, clock, cfg, rs := e.srv, e.clock, e.cfg, e.rs
	ctx := context.Background()

	// 先确认干净链是通过的。
	rec := get(t, srv, mintValid(t, e.keys, clock), "/v1/audit/verify")
	if rec.Code != http.StatusOK {
		t.Fatalf("verify 应 200，实际 %d body=%s", rec.Code, rec.Body.String())
	}
	var clean map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &clean); err != nil {
		t.Fatal(err)
	}
	if clean["ok"] != true {
		t.Fatalf("未篡改时 ok 应为 true：%v", clean)
	}

	// 模拟篡改：临时禁用只追加触发器，改第 2 条的 payload（保留 hash 字段不动）。
	// 这只发生在**本测试自己的 run schema**里，public 表与审计记录一律未动（硬性约束 3）。
	target := int64(2)
	if _, err := rs.Pool().Exec(ctx, fmt.Sprintf("ALTER TABLE %s DISABLE TRIGGER ALL", cfg.AuditTable)); err != nil {
		t.Fatal(err)
	}
	if _, err := rs.Pool().Exec(ctx, fmt.Sprintf(
		`UPDATE %s SET payload = '{"capability":"swapped","status":"ok","exit_class":"zero"}'::jsonb WHERE seq = $1`,
		cfg.AuditTable), target); err != nil {
		t.Fatal(err)
	}
	if _, err := rs.Pool().Exec(ctx, fmt.Sprintf("ALTER TABLE %s ENABLE TRIGGER ALL", cfg.AuditTable)); err != nil {
		t.Fatal(err)
	}

	rec = get(t, srv, mintValid(t, e.keys, clock), "/v1/audit/verify")
	if rec.Code != http.StatusOK {
		t.Fatalf("篡改后的 verify 仍应 200（结论在响应体里），实际 %d", rec.Code)
	}
	var bad map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &bad); err != nil {
		t.Fatal(err)
	}
	if bad["ok"] != false {
		t.Fatalf("篡改必须 ok=false：%v", bad)
	}
	if got, _ := bad["first_bad_seq"].(string); got != fmt.Sprint(target) {
		t.Fatalf("first_bad_seq 应为 %d（protojson 把 int64 编码为字符串），实际 %v", target, bad["first_bad_seq"])
	}
	if bad["reason"] != "VERIFY_REASON_HASH_MISMATCH" {
		t.Fatalf("原因应为哈希不一致，实际 %v", bad["reason"])
	}
	body := rec.Body.String()
	for _, leak := range []string{"swapped", "payload", "PLAINTEXT", "BEGIN"} {
		if strings.Contains(body, leak) {
			t.Fatalf("verify 响应不得含 %q：%s", leak, body)
		}
	}
	t.Logf("[C4] 篡改定位准确 first_bad_seq=%d，reason=%s，响应不含 payload", target, bad["reason"])
}

// —— 全栈行为 ——

// TestConsoleAuth 401：无令牌、错误签名、alg=none、HS256、kid 不认识、过期。
func TestConsoleAuth(t *testing.T) {
	e := newEnv(t)
	srv, clock, k := e.srv, e.clock, e.keys
	for _, target := range []string{"/v1/health", "/v1/nodes", "/v1/audit/verify", "/v1/policy"} {
		rec := get(t, srv, "", target)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s 无令牌应 401，实际 %d", target, rec.Code)
		}
		assertNoReasonLeak(t, rec.Body.String())
	}
	weak := []struct {
		name, value string
	}{
		{"alg=none", "Bearer " + mint(t, k, "none", k.kid, map[string]any{
			"iss": testIssuer, "aud": testAud, "sub": "o", "exp": clock.Now().Add(time.Minute).Unix()})},
		{"HS256", "Bearer " + mint(t, k, "HS256", k.kid, map[string]any{
			"iss": testIssuer, "aud": testAud, "sub": "o", "exp": clock.Now().Add(time.Minute).Unix()})},
		{"kid 未知", "Bearer " + mint(t, k, "RS256", "other", map[string]any{
			"iss": testIssuer, "aud": testAud, "sub": "o", "exp": clock.Now().Add(time.Minute).Unix()})},
		{"已过期", mintValidExpired(t, k, clock)},
		{"缺 Bearer 前缀", strings.TrimPrefix(mintValid(t, k, clock), "Bearer ")},
		{"裸垃圾", "Bearer not-a-jwt"},
	}
	for _, c := range weak {
		rec := get(t, srv, c.value, "/v1/nodes")
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s 应 401，实际 %d", c.name, rec.Code)
		}
		assertNoReasonLeak(t, rec.Body.String())
	}
	// 正例：有效令牌 + 200。
	if rec := get(t, srv, mintValid(t, k, clock), "/v1/health"); rec.Code != http.StatusOK {
		t.Fatalf("有效令牌应 200，实际 %d body=%s", rec.Code, rec.Body.String())
	}
	t.Log("[C4] 鉴权失败统一 401 且不回显原因；有效令牌 200")
}

// TestConsolePaginationBoundsOverHTTP limit=0/-1/201 → 400；200 → 200。
func TestConsolePaginationBoundsOverHTTP(t *testing.T) {
	e := newEnv(t)
	srv, clock := e.srv, e.clock
	token := mintValid(t, e.keys, clock)
	for _, bad := range []string{"0", "-1", "201", "abc"} {
		for _, target := range []string{"/v1/approvals?limit=" + bad, "/v1/audit/events?limit=" + bad} {
			rec := get(t, srv, token, target)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("%s 应 400，实际 %d", target, rec.Code)
			}
			assertEnvelope(t, rec.Body.String(), "bad_request")
		}
	}
	// after_seq 负值同样 400。
	if rec := get(t, srv, token, "/v1/audit/events?after_seq=-5"); rec.Code != http.StatusBadRequest {
		t.Errorf("after_seq=-5 应 400，实际 %d", rec.Code)
	}
	if rec := get(t, srv, token, "/v1/approvals?limit=200"); rec.Code != http.StatusOK {
		t.Fatalf("limit=200 应 200，实际 %d", rec.Code)
	}
	if rec := get(t, srv, token, "/v1/audit/events?limit=200&after_seq=0"); rec.Code != http.StatusOK {
		t.Fatalf("limit=200 应 200，实际 %d", rec.Code)
	}
	t.Log("[C4] 分页边界：0/-1/201/非数字 → 400；200 → 200")
}

// TestConsoleNoSecretsInResponses 所有接口都不得回传凭据类材料。
func TestConsoleNoSecretsInResponses(t *testing.T) {
	e := newEnv(t)
	srv, clock := e.srv, e.clock
	token := mintValid(t, e.keys, clock)
	targets := []string{
		"/v1/health", "/v1/nodes", "/v1/nodes/nod_AAA", "/v1/nodes/nod_BBB",
		"/v1/approvals", "/v1/approvals?status=approved", "/v1/approvals/apv_001",
		"/v1/audit/events", "/v1/audit/events?limit=10", "/v1/audit/verify",
		"/v1/adapters", "/v1/policy",
	}
	needles := []string{
		"tok-PLAINTEXT", "sha256:deadbeef", "BEGIN RSA PRIVATE KEY", "BEGIN CERTIFICATE",
		"PRIVATE KEY", "eyJhbGciOi", "MIIsecret", "should-drop", "swapped",
		"postgres://", "token_hash",
	}
	for _, target := range targets {
		rec := get(t, srv, token, target)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s 应 200，实际 %d body=%s", target, rec.Code, rec.Body.String())
		}
		for _, n := range needles {
			if strings.Contains(rec.Body.String(), n) {
				t.Errorf("%s 响应含敏感片段 %q：%s", target, n, rec.Body.String())
			}
		}
	}
	// 审计事件的 payload 只应含白名单键。
	rec := get(t, srv, token, "/v1/audit/events")
	var events []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &events); err != nil {
		t.Fatal(err)
	}
	if len(events) != 4 {
		t.Fatalf("应有 4 条夹具事件，实际 %d", len(events))
	}
	for _, ev := range events {
		payload, _ := ev["payload"].(map[string]any)
		for _, banned := range []string{"stdout", "token", "token_hash", "raw_request_body", "stderr"} {
			if _, has := payload[banned]; has {
				t.Errorf("payload 含未登记键 %q：%v", banned, payload)
			}
		}
		for k := range payload {
			if !allowedPayloadKey(k) {
				t.Errorf("payload 出现白名单外的键 %q：%v", k, payload)
			}
		}
	}
	t.Logf("[C4] %d 个接口、%d 条事件均未回传凭据材料", len(targets), len(events))
}

// TestConsoleReadonlyStatusCodes 405 + Allow、404、响应头、只读语义。
func TestConsoleReadonlyStatusCodes(t *testing.T) {
	e := newEnv(t)
	srv, clock := e.srv, e.clock
	token := mintValid(t, e.keys, clock)

	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		req := httptest.NewRequest(m, "/v1/nodes", nil)
		req.Header.Set("Authorization", token)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s /v1/nodes 应 405，实际 %d", m, rec.Code)
		}
		if got := rec.Header().Get("Allow"); got != "GET" {
			t.Errorf("%s 的 Allow 应为 GET，实际 %q", m, got)
		}
	}
	// 未登记路径 404（且带鉴权在先：无令牌时仍是 401，不泄漏路径存在性）。
	if rec := get(t, srv, "", "/v1/unknown"); rec.Code != http.StatusUnauthorized {
		t.Errorf("无令牌的未知路径应 401，实际 %d", rec.Code)
	}
	if rec := get(t, srv, token, "/v1/unknown"); rec.Code != http.StatusNotFound {
		t.Errorf("未知路径应 404，实际 %d", rec.Code)
	}
	if rec := get(t, srv, token, "/v1/nodes/nod_NOPE"); rec.Code != http.StatusNotFound {
		t.Errorf("不存在的节点应 404，实际 %d", rec.Code)
	}
	// 响应头。
	rec := get(t, srv, token, "/v1/health")
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control 应为 no-store，实际 %q", rec.Header().Get("Cache-Control"))
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("应带 nosniff，实际 %q", rec.Header().Get("X-Content-Type-Options"))
	}
	// health 与 nodes 内容抽查（snake_case 键名来自 protojson UseProtoNames）。
	var health map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &health); err != nil {
		t.Fatal(err)
	}
	if health["status"] != "ok" || health["db_ok"] != true {
		t.Fatalf("health 内容异常：%v", health)
	}
	if _, has := health["schema_version"]; !has {
		t.Errorf("health 应含 schema_version：%v", health)
	}
	rec = get(t, srv, token, "/v1/nodes")
	var nodes []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &nodes); err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 2 {
		t.Fatalf("应有 2 个节点，实际 %d", len(nodes))
	}
	if nodes[0]["node_id"] != "nod_AAA" || nodes[0]["cert_state"] != "active" {
		t.Errorf("节点视图字段映射异常：%v", nodes[0])
	}
	if nodes[1]["cert_state"] != "" || nodes[1]["last_seen"] == nil {
		t.Errorf("无证书节点应为空 cert_state 且保留 last_seen：%v", nodes[1])
	}
	t.Logf("[C4] 405+Allow、404、no-store/nosniff 与只读内容映射全部符合 ADR-024")
}
