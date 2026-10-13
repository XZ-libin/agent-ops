// 模块路径已确定为 github.com/XZ-libin/agent-ops，决定日期 2026-10-13。
module github.com/XZ-libin/agent-ops/control-plane

go 1.27

replace github.com/XZ-libin/agent-ops/contract => ../contract

// 共享内核（ADR-008）：policy/idempotency/audit/validation 等已迁移至根模块。
replace github.com/XZ-libin/agent-ops => ../

require (
	github.com/XZ-libin/agent-ops v0.0.0-00010101000000-000000000000
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
