# Agent Ops

AI Agent 辅助的 Linux 主机 / Kubernetes 集群 / Docker 主机 / 公共组件运维系统（monorepo 骨架）。
设计文档：开发文档 v2；架构决策：docs/adr/；未决事项：docs/OPEN_QUESTIONS.md。

## 目录

| 目录 | 说明 |
| --- | --- |
| proto/ | 契约唯一源（protobuf，Q2 已决策），buf 管理 |
| api/ | OpenAPI 生成产物目录：由 proto 生成，生成管道后续批次接入 |
| docs/adr/ | 架构决策记录（ADR-001~023）与待决策清单（OPEN_QUESTIONS.md） |
| docs/ops/ | 运维文档（terminal-states.md：计划终态语义；node-cert-lifecycle.md：节点证书生命周期与扫描器） |
| internal/ | 根共享模块（ADR-008）：exec/ssh、validation、policy、idempotency、audit、testdb（测试库名校验）、repoguard（仓库级只读守卫）、k8stest（kind 集群测试夹具：自建自删） |
| contract/ | Go 模块：生成类型 + 适配器接口（Adapter）+ 单元测试 |
| control-plane/ | Go 模块：控制层（骨架） |
| alerts/ | Go 模块：告警入口（HMAC 签名、源白名单 + 画像、限流、fingerprint 去重、outbox、消费者重试/死信、规划器、只读诊断执行器（Linux/Docker/Kubernetes）、测试模式 worker、人工重投） |
| gateway/ | Go 模块：执行网关（第八轮链路；第九轮审批受控执行；第十轮修订 + gRPC 对外入口；第十一轮执行租约/对账/单实例/mode 守卫；第十九轮 OIDC 生产认证） |
| node-agent/ | Go 模块：节点 Agent（mTLS 注册/心跳/续期 + 身份持久化 + 优雅停机；**不执行任何命令**，见 ADR-021/022） |
| adapters/ | 各组件适配器（linux / docker / kubernetes 只读已就绪；均无写能力，K8s 永不读取 Secret） |
| diagnostics/ | Python 诊断辅助：自研状态机（uv） |
| web/ | TypeScript + React + Ant Design（pnpm） |
| docs/tooling.md | 外部二进制的来源与 SHA-256 记录（下载前必须登记） |
| deploy/migrations/ | PostgreSQL 迁移占位 |
| contract-tests/ | 适配器契约测试套件占位 |

Gateway 模块内部：`internal/gateway`（服务与策略/幂等/审计/审批链路）、
`internal/grpcwire`（gRPC 对外入口：认证取 actor → 契约转换 → 固定错误码映射）、
`internal/prodcatalog`（生产能力清单加载 + 生产启动守卫，拒绝 test_only）、
`internal/approvals`（审批存储：先占后执行、pending 按 (actor, request_hash) 去重）、
`internal/linuxwire`、`internal/testwrite`（仅测试目录的写能力）。

## 常用命令（Go 侧）

```sh
make deps        # 安装代码生成插件（protoc-gen-go / protoc-gen-go-grpc，版本固定）
make gen         # 从 proto 生成 Go 代码到 contract/gen/go
make gen-check   # 校验生成代码与源文件一致（CI 门禁，ADR-002）
make build       # 编译全部 Go 模块（go workspace）
make test        # 运行全部单元测试
```

约束：本阶段不含任何适配器实现与业务逻辑；不接入真实服务器、集群或凭据，测试只用本地模拟；未确认参数一律 `TODO(待决策)` 标注。