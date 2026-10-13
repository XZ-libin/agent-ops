// Package testdb 统一测试数据库入口（第十一轮 H2，工程约束）。
//
// 裁决（第十一轮）：所有测试运行统一使用**独立数据库 agent_ops_test**；
// 绝不允许再在 55432 的默认库 agent_ops 中创建表（含生产命名表）。
// 本包是这一约束的唯一执行点：测试连接池建立前必须经 Validate 校验库名，
// 库名不是 agent_ops_test 时测试直接失败（而不是用错误的库跑完再污染数据）。
//
// 三个 DefaultLocalDSN（audit / idempotency / approvals）保留给生产路径默认值，
// 测试一律经 Resolve 获取 DSN，不再直接引用它们。
package testdb

import (
	"fmt"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestDatabase 测试数据库名（裁决：独立数据库，不得与默认开发库混用）。
const TestDatabase = "agent_ops_test"

// EnvDSN 测试连接串环境变量（优先级高于默认值）。
const EnvDSN = "AGENT_OPS_TEST_DATABASE_URL"

// DefaultDSN 本地测试数据库连接串（占位值，非真实凭据；宿主端口 55432，
// 绝不触碰 5432 的 opsforge-postgres）。
const DefaultDSN = "postgres://agent_ops:agent_ops@localhost:55432/" + TestDatabase + "?sslmode=disable"

// Resolve 返回测试用 DSN：环境变量优先，否则默认值；并校验库名。
// 校验失败返回错误（调用方应 fail-closed，不得继续连接）。
func Resolve() (string, error) {
	dsn := os.Getenv(EnvDSN)
	if dsn == "" {
		dsn = DefaultDSN
	}
	if err := Validate(dsn); err != nil {
		return "", err
	}
	return dsn, nil
}

// Validate 校验 DSN 指向 agent_ops_test；否则返回错误（fail-closed）。
func Validate(dsn string) error {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return fmt.Errorf("testdb：连接串无法解析：%w", err)
	}
	if cfg.ConnConfig.Database != TestDatabase {
		return fmt.Errorf("testdb：测试必须使用数据库 %s，当前为 %s（禁止在默认库建表）",
			TestDatabase, cfg.ConnConfig.Database)
	}
	return nil
}
