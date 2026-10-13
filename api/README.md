# api/

OpenAPI 生成产物目录。自 2026-10-12 起（Q2 已决策）：**protobuf 为契约唯一源**，
本目录只存放由 proto 生成的 OpenAPI 定义，禁止手写、禁止重复定义。

生成管道（gateway.proto 补 HTTP 注解 + proto→OpenAPI 插件 + gen-check 覆盖）在后续批次接入；
接入前 REST 契约以 proto/agent_ops/contract/v1/gateway.proto 的服务定义为准。