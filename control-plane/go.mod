// TODO(待决策：组织域名)：模块路径中的 ORG 为占位符，
// 确定组织域名后替换为真实组织。
module github.com/ORG/agent-ops/control-plane

go 1.27

// TODO(待决策：组织域名，确定后移除本 replace 指令)。
replace github.com/ORG/agent-ops/contract => ../contract

// 共享内核（ADR-008）：policy/idempotency/audit/validation 等已迁移至根模块。
replace github.com/ORG/agent-ops => ../

require (
	github.com/ORG/agent-ops v0.0.0-00010101000000-000000000000
	github.com/jackc/pgx/v5 v5.11.0
)

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/oklog/ulid/v2 v2.1.2 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/text v0.40.0 // indirect
)
