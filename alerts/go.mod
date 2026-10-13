// TODO(待决策：组织域名)：模块路径中的 ORG 为占位符，
// 确定组织域名后替换为真实组织。
module github.com/ORG/agent-ops/alerts

go 1.27

// TODO(待决策：组织域名，确定后移除本 replace 指令)。
replace github.com/ORG/agent-ops/contract => ../contract

// 共享内核（ADR-008）：internal/testdb（测试库名校验与每轮 schema）。
replace github.com/ORG/agent-ops => ../

require (
	github.com/ORG/agent-ops v0.0.0-00010101000000-000000000000
	github.com/ORG/agent-ops/contract v0.0.0-00010101000000-000000000000
	github.com/jackc/pgx/v5 v5.11.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/rogpeppe/go-internal v1.16.0 // indirect
	golang.org/x/net v0.57.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.40.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260706201446-f0a921348800 // indirect
	google.golang.org/grpc v1.84.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)
