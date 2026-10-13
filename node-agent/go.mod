// TODO(待决策：组织域名)：模块路径中的 ORG 为占位符，
// 确定组织域名后替换为真实组织。
module github.com/ORG/agent-ops/node-agent

go 1.27

// TODO(待决策：组织域名，确定后移除 replace 指令)。
replace github.com/ORG/agent-ops => ../

replace github.com/ORG/agent-ops/contract => ../contract

require (
	github.com/ORG/agent-ops v0.0.0-00010101000000-000000000000
	github.com/ORG/agent-ops/contract v0.0.0-00010101000000-000000000000
	google.golang.org/grpc v1.84.0
	google.golang.org/protobuf v1.36.12
)

require (
	github.com/oklog/ulid/v2 v2.1.2 // indirect
	golang.org/x/net v0.57.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.40.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260706201446-f0a921348800 // indirect
)
