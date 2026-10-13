// 模块路径已确定为 github.com/XZ-libin/agent-ops，决定日期 2026-10-13。
//
// 本模块是 monorepo 的共享内核（ADR-008）：承载跨模块使用的 internal 包
// （exec/ssh、validation、policy、idempotency、audit 等）。
// Go 的 internal 规则按导入路径生效，只有模块路径为所有子模块公共前缀的
// 根模块才能让 adapters / gateway / control-plane 各自导入同一个 internal 包。
module github.com/XZ-libin/agent-ops

go 1.27

replace github.com/XZ-libin/agent-ops/contract => ./contract

require (
	github.com/XZ-libin/agent-ops/contract v0.0.0-00010101000000-000000000000
	github.com/jackc/pgx/v5 v5.11.0
	golang.org/x/crypto v0.54.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/oklog/ulid/v2 v2.1.2 // indirect
	golang.org/x/net v0.57.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.40.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260706201446-f0a921348800 // indirect
	google.golang.org/grpc v1.84.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)
