package executor

// 本文件把内部测试辅助导出给外部测试包（package executor_test），
// 使其可以使用 diagcaps 等依赖 executor 的包而不产生 import 环。
// 仅参与测试编译（_test.go）。

import (
	"testing"

	contractv1 "github.com/ORG/agent-ops/contract/gen/go/agent_ops/contract/v1"
	"github.com/ORG/agent-ops/internal/policy"
	"github.com/ORG/agent-ops/internal/testdb"
)

// NewExecEnvCluster 建立真实 PG 测试环境（独立 run schema）+ 执行器 + 审计接收端。
func NewExecEnvCluster(t *testing.T, caps map[string]CapEntry, policyCfg policy.Config, cluster bool) (*Executor, AuditSink, *testdb.RunSchema) {
	t.Helper()
	ex, aud, rs := newExecEnvCluster(t, caps, policyCfg, cluster)
	if aud == nil {
		return ex, nil, rs
	}
	return ex, aud, rs
}

// InsertPlan 插入一条计划并返回 plan_id。
func InsertPlan(t *testing.T, rs *testdb.RunSchema, eventID int64, profile string, caps []string, status string) int64 {
	t.Helper()
	return planRow(t, rs, eventID, profile, caps, status)
}

// AuditSeqOf 返回审计表的 seq 序列（升序）。
func AuditSeqOf(t *testing.T, rs *testdb.RunSchema, table string) []int64 {
	t.Helper()
	return auditSeq(t, rs, table)
}

// AuditTableNameOf 返回本次 run schema 中唯一的审计表名。
func AuditTableNameOf(t *testing.T, rs *testdb.RunSchema) string {
	t.Helper()
	return auditTableName(t, rs)
}

// ReadOnlyDecl 构造只读能力声明。
func ReadOnlyDecl(name string) *contractv1.Capability {
	return readOnlyDecl(name)
}
