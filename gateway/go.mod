// 模块路径已确定为 github.com/XZ-libin/agent-ops，决定日期 2026-10-13。
module github.com/XZ-libin/agent-ops/gateway

go 1.27

replace github.com/XZ-libin/agent-ops/contract => ../contract

replace github.com/XZ-libin/agent-ops/adapters => ../adapters

// 共享内核（ADR-008）：internal/{policy,idempotency,audit,exec,validation}。
replace github.com/XZ-libin/agent-ops => ../

require (
	github.com/XZ-libin/agent-ops v0.0.0-00010101000000-000000000000
	github.com/XZ-libin/agent-ops/adapters v0.0.0-00010101000000-000000000000
	github.com/XZ-libin/agent-ops/contract v0.0.0-00010101000000-000000000000
	github.com/jackc/pgx/v5 v5.11.0
	google.golang.org/grpc v1.84.0
	google.golang.org/protobuf v1.36.12
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/rogpeppe/go-internal v1.16.0 // indirect
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/net v0.57.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.40.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260706201446-f0a921348800 // indirect
)
