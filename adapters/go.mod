// 模块路径已确定为 github.com/XZ-libin/agent-ops，决定日期 2026-10-13。
module github.com/XZ-libin/agent-ops/adapters

go 1.27

replace github.com/XZ-libin/agent-ops/contract => ../contract

// 共享内核（ADR-008）：internal/exec（Runner 接口）与 internal/validation。
replace github.com/XZ-libin/agent-ops => ../

require (
	github.com/XZ-libin/agent-ops v0.0.0-00010101000000-000000000000
	github.com/XZ-libin/agent-ops/contract v0.0.0-00010101000000-000000000000
	google.golang.org/protobuf v1.36.12
	gopkg.in/yaml.v3 v3.0.1
)

require (
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/net v0.57.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.40.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260706201446-f0a921348800 // indirect
	google.golang.org/grpc v1.84.0 // indirect
)
