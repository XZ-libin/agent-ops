// 全局残留检查（第十八轮 W2；第十九轮 F1 改为**强制门禁**）。
//
// 两层用法：
//   - TestNoLeftoversAfterSuite：整套测试结束后运行（`make residual-check` 强制开启，
//     不依赖操作者手动设置环境变量；任一残留即返回非零退出码）。
//   - TestResidualGateDetectsLeftover：**始终运行**，人为制造一个残留并断言检测器
//     能发现它、清理后消失——用于证明门禁本身有效（否则"门禁永远通过"毫无意义）。
//
// 为什么需要显式开关：`go test ./...` 会并行运行不同包，别的包可能正在使用自己的
// kind 集群 / 测试容器 / run schema，此时做全局检查会误报。因此全局检查只在
// 整套测试跑完之后、由 make residual-check 单独触发：
//
//	make residual-check
package k8stest

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ORG/agent-ops/internal/testdb"
)

// ResidualViolations 返回当前的全部残留（kind 集群 / 测试容器 / test_run_* schema）。
// 返回空切片表示无残留。
func ResidualViolations(ctx context.Context) ([]string, error) {
	var out []string

	// ① kind 集群。
	kindBin := toolPath("kind")
	if kindBin == "" {
		out = append(out, "缺少 kind 可执行文件：无法检查集群残留")
	} else {
		raw, err := runTool(kindBin, "get", "clusters")
		if err != nil {
			out = append(out, fmt.Sprintf("kind get clusters 失败：%v", err))
		} else {
			for _, line := range strings.Split(raw, "\n") {
				if strings.HasPrefix(strings.TrimSpace(line), ClusterPrefix) {
					out = append(out, "残留 kind 集群："+strings.TrimSpace(line))
				}
			}
		}
	}

	// ② 测试容器。
	dockerBin := toolPath("docker")
	if dockerBin == "" {
		out = append(out, "缺少 docker CLI：无法检查容器残留")
	} else {
		raw, err := exec.Command(dockerBin, "ps", "-a", "--filter", "label=agent-ops.test=true",
			"--format", "{{.Names}}").CombinedOutput()
		if err != nil {
			out = append(out, fmt.Sprintf("docker ps 失败：%v（输出 %q）", err, strings.TrimSpace(string(raw))))
		} else {
			for _, name := range strings.Fields(strings.TrimSpace(string(raw))) {
				out = append(out, "残留测试容器："+name)
			}
		}
	}

	// ③ test_run_* schema。
	names, err := runSchemaNames(ctx)
	if err != nil {
		out = append(out, fmt.Sprintf("查询 test_run_* schema 失败：%v", err))
	} else {
		for _, n := range names {
			out = append(out, "残留 run schema："+n)
		}
	}
	return out, nil
}

// TestNoLeftoversAfterSuite 全局残留检查（`make residual-check` 强制开启）。
func TestNoLeftoversAfterSuite(t *testing.T) {
	if strings.TrimSpace(os.Getenv(ResidualCheckEnv)) != "1" {
		t.Skipf("未开启全局残留检查（由 `make residual-check` 强制开启，%s=1）。", ResidualCheckEnv)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	violations, err := ResidualViolations(ctx)
	if err != nil {
		t.Fatalf("残留检查执行失败：%v", err)
	}
	if len(violations) > 0 {
		for _, v := range violations {
			t.Errorf("[残留] %s", v)
		}
		t.Fatalf("残留检查失败：发现 %d 项残留", len(violations))
	}
	t.Log("[残留检查] kind 集群 0、agent-ops.test=true 容器 0、test_run_* schema 0")
}

// TestResidualGateDetectsLeftover（F1）门禁有效性自证：
// 人为在测试库中留一张表（模拟残留）时检测必须报出；清理后必须消失。
//
// 本用例**始终运行**（不受 ResidualCheckEnv 影响），且只针对自己创建的残留断言，
// 因此可与其他包并行执行而不误报。
func TestResidualGateDetectsLeftover(t *testing.T) {
	ctx := context.Background()
	name, err := createLeftoverSchema(ctx)
	if err != nil {
		t.Skipf("PostgreSQL 不可用，跳过门禁自证用例（%v）。", err)
	}
	// 登记清理（失败也清理，避免把自证用例自己变成残留）。
	t.Cleanup(func() {
		if derr := dropSchema(context.Background(), name); derr != nil {
			t.Errorf("清理自证残留失败：%v", derr)
		}
	})

	violations, err := ResidualViolations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !containsViolation(violations, name) {
		t.Fatalf("门禁未检出人为残留 %s（检出项：%v）", name, violations)
	}
	t.Logf("[F1] 人为残留被检出：%s（检出项共 %d 条，门禁将失败）", name, len(violations))

	if err := dropSchema(ctx, name); err != nil {
		t.Fatalf("清理残留失败：%v", err)
	}
	violations, err = ResidualViolations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if containsViolation(violations, name) {
		t.Fatalf("清理后仍检出残留 %s（检出项：%v）", name, violations)
	}
	t.Logf("[F1] 清理后该残留已消失：%s（门禁恢复通过）", name)
}

// containsViolation 判定检出项中是否包含指定 schema 名。
func containsViolation(violations []string, schema string) bool {
	for _, v := range violations {
		if strings.Contains(v, schema) {
			return true
		}
	}
	return false
}

// createLeftoverSchema 在测试库中创建一个 test_run_<纳秒> schema 并建一张表
// （模拟"测试失败保留的残留"），返回 schema 名。
func createLeftoverSchema(ctx context.Context) (string, error) {
	dsn, err := testdb.Resolve()
	if err != nil {
		return "", err
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return "", err
	}
	defer pool.Close()
	name := fmt.Sprintf("%s%d", testdb.RunSchemaPrefix, time.Now().UnixNano())
	if err := testdb.ValidateSchemaName(name); err != nil {
		return "", err
	}
	if _, err := pool.Exec(ctx, fmt.Sprintf(`CREATE SCHEMA %q`, name)); err != nil {
		return "", err
	}
	if _, err := pool.Exec(ctx, fmt.Sprintf(`CREATE TABLE %q.leftover_probe (id bigserial PRIMARY KEY)`, name)); err != nil {
		_ = dropSchema(ctx, name)
		return "", err
	}
	return name, nil
}

// dropSchema 删除指定 schema（删除前强制校验前缀：绝不触碰 public）。
func dropSchema(ctx context.Context, name string) error {
	if err := testdb.ValidateSchemaName(name); err != nil {
		return err
	}
	dsn, err := testdb.Resolve()
	if err != nil {
		return err
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return err
	}
	defer pool.Close()
	_, err = pool.Exec(ctx, fmt.Sprintf(`DROP SCHEMA IF EXISTS %q CASCADE`, name))
	return err
}

// runSchemaNames 列出 test_run_* schema（升序）。
func runSchemaNames(ctx context.Context) ([]string, error) {
	dsn, err := testdb.Resolve()
	if err != nil {
		return nil, err
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	defer pool.Close()
	rows, err := pool.Query(ctx,
		`SELECT nspname FROM pg_namespace WHERE nspname LIKE 'test_run_%' ORDER BY nspname`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}
