# ADR-024：控制台只读 API

- 状态：**待确认**（本 ADR 的两项决定需用户签署后才能进入实现：见 §1、§6）
- 日期：2026-10-13
- 轮次：第二十七轮（控制台只读 API；只读，不含写路径、前端与真实 issuer）
- 基线：本地 `chore/module-path-r26` HEAD `b6232d7`（第二十六轮模块路径改完之后）
- 关系：鉴权沿用 [ADR-019](ADR-019-CI门禁落地-JWKS刷新限速-exp必填与运维文档一致性.md) 的 OIDC 规则；
  模块划分沿用 [ADR-008](ADR-008-执行网关链路与共享内核模块化.md)；不修改任何历史 ADR 正文
  （ADR-008 仅在文末追加一行指向本 ADR）。

> **验证状态：本地实现与本地门禁；CI 未验证。**

---

## 1. 决定一：入站 HTTP 白名单扩展（**需用户确认，未确认不实现**）

`internal/repoguard` 的入站 HTTP 允许文件目前只有一个：

```go
var AllowedInboundHTTPFiles = []string{
    "alerts/internal/httpapi/server.go",
}
```

本 ADR 请求把它扩展为**恰好两项**：

| 允许项 | 用途 |
| --- | --- |
| `alerts/internal/httpapi/server.go` | 既有：告警入口（第十四轮） |
| `internal/console/httpapi/` | 新增：控制台只读 API（本 ADR） |

约束与自证：

- **仅此两项**。新增第三处入站 HTTP 必须再来一份 ADR；
- 由 `TestConsoleInboundHTTPAllowlistExact` 断言白名单**精确等于**该集合
  （不是"包含"，而是"等于"——多一个也算失败），防止白名单悄悄长大；
- 该扩展**不放宽**任何既有断言：出站 HTTP 符号、写方法字面量、
  `node-agent` 的 HTTP 禁令全部原样保留；
- 控制台的 `http.Server` 只在 `internal/console/httpapi/` 内出现，
  且只注册 GET 路由（由 `TestConsoleRouteTableGETOnly` 用 go/parser 静态校验）。

**理由**：控制台的只读查询接口必须在服务端暴露 HTTP 端点，这是 ADR-008"业务 API 在控制层"
的自然延伸；用白名单 + 精确相等断言，比"哪个包都能起 server"更容易守。

## 2. 只读边界

- 控制台所有接口**只接受 GET**；不存在任何写路径（不建、不改、不删、不执行）；
- 非 GET → `405` 且响应带 `Allow: GET`；未知路径 → `404`；
- 数据访问层只暴露 list / get / verify / manifest / effective-config 五类只读方法，
  **控制台包内不得出现任何写方法**（`TestConsoleNoWriteImports` 静态校验：
  不得 import 网关写路径 Approve/Reject/ExecuteApproved、`internal/exec/*`，
  不得调用 adapter 的执行类函数）；
- 数据库侧的写保护不靠代码自觉，而是**独立只读角色**（§5）。

## 3. 鉴权

| 模式 | 规则 |
| --- | --- |
| 生产 | 沿用 ADR-019 的 OIDC：仅 **RS256**；`iss`、`aud` **精确匹配**（不做前缀/子串）；`exp` 必填；`kid` 必须存在于 JWKS；签名值用 JWKS 公钥校验；时钟偏差容忍 **60 秒**（**工程默认，待确认**）；JWKS 刷新限速沿用 ADR-019 |
| 生产 | **拒绝静态令牌**：配置里出现静态 token 即启动失败（`TestConsoleProdRejectsStaticToken`） |
| 测试 | 合成 JWKS 夹具（RSA 2048 运行时生成、仅存内存、不落盘、不入库），与 ADR-019 的测试做法一致 |
| 两种模式 | 鉴权失败一律 `401`，**不回显失败原因**（不发 `invalid signature` 之类的区分信息） |

不采纳的方案：cookie/session 鉴权（控制台是 API，不引入会话状态）；
把 actor 从请求头自报（必须来自已验签的令牌，否则审计里 actor 不可信）。

## 4. 分页与响应形态

| 项 | 取值 | 状态 |
| --- | --- | --- |
| 审计游标 | 按 `seq` 单调递增，参数 `after_seq` | 工程默认，待确认 |
| `limit` 默认 | **50** | 工程默认，待确认 |
| `limit` 上限 | **200** | 工程默认，待确认 |
| 非法 `limit` | `0`、负数、`> 200` → `400` | 工程默认，待确认 |
| 服务端超时 | **10 秒** | 工程默认，待确认 |
| 响应头 | `Cache-Control: no-store`、`X-Content-Type-Options: nosniff` | 硬性（只读接口不得被缓存） |

**本轮不做速率限制**（列入 §8 未完成项）。理由：无真实部署与流量画像，
先拍一个数字会成为"看着像安全设置的装饰"；接入前端与真实 issuer 时再定。

错误信封统一为：

```json
{"error":{"code":"...","message":"..."}}
```

`message` 为固定文本表（不拼接内部错误、不带上层堆栈、不回显 SQL/表名/连接串）。

## 5. 数据访问与 payload 白名单

**只读角色**（测试夹具创建，名字必须 `test_` 开头，用 `IF NOT EXISTS`）：

| 角色 | 权限 | 覆盖对象 |
| --- | --- | --- |
| `test_console_reader` | **仅 SELECT** | 控制台所需表（节点、审批、审计事件、能力清单相关表）；不含任何写权限、不含 DDL |

由 `TestConsoleDBRoleReadOnly` 自证：以该角色对授权表执行 `INSERT/UPDATE/DELETE`
**必须全部返回权限错误**。这样"只读"不依赖代码自觉。

**审计 payload 白名单投影**（只保留下列键，其余一律丢弃，不回传原始 `jsonb`）：

| 事件族 | 保留键 |
| --- | --- |
| 节点事件 | `node_id`、`boot_session_id`、`event_kind`、`reason_code` |
| 审批事件 | `approval_id`、`capability`、`status` |
| 诊断与执行事件 | `capability`、`status`、`exit_class` |

理由：审计 payload 历史上被写入过宽字段（第十七轮的录像输出教训）；
白名单比黑名单可靠——新事件族忘记登记时表现为"字段缺失"（可发现），
而不是"敏感字段泄漏"（不可发现）。

**响应中不得出现的材料**（`TestConsoleNoSecretsInResponses` 用夹具注入后逐一断言）：
令牌明文、令牌哈希、CSR PEM、证书 PEM、私钥标记、签名值、数据库连接串。
Kubernetes Secret 任何路径、任何方式都不读取（硬性约束 4）。

## 6. 决定二：OpenAPI 手写 + 一致性守卫（**需用户确认，未确认不实现**）

本轮**手写** `openapi/console.yaml`，不引入生成插件。配两条守卫把它钉住：

| 守卫 | 断言 |
| --- | --- |
| `TestConsoleOpenAPIMatchesRoutes` | `console.yaml` 的 `paths` 集合与 `httpapi` 路由表**完全相同**（双向：多一条少一条都失败） |
| `TestConsoleSchemaMatchesProto` | 每个 schema 的字段集合与对应 proto 消息字段**一一对应** |

理由与代价说清楚：

- 为什么不自动生成：`api/` 目录至今是占位（Q2 的"生成管道接入"仍是待办），
  引入 `protoc-openapi` 一类插件需要新增外部二进制/插件版本登记（硬性约束 5 本轮禁止新增二进制），
  且 HTTP 注解要写进 `proto/console`，属于本 ADR §1 之外的另一项变更；
- 手写的风险是"文档与代码漂移"，所以用上面两条守卫把漂移变成**测试失败**而不是评审意见；
- 自动生成仍列为 §8 未完成项，届时用手写产物作为回归对照。

## 7. 路由表（只读，全部要求鉴权）

| 方法 | 路径 | 说明 / 关键返回字段 | 分页 |
| --- | --- | --- | --- |
| GET | `/v1/health` | `status`、`db_ok`、`schema_version` | — |
| GET | `/v1/nodes` | `NodeView[]`：`node_id`、`status`、`last_seen`(取 `received_at`)、证书有效期摘要（**不含 PEM**） | — |
| GET | `/v1/nodes/{node_id}` | 单个 `NodeView` | — |
| GET | `/v1/approvals` | `ApprovalView[]`：`approval_id`、`capability`、`tier`、`status`、`requester`、`approver`、创建/过期时间、`request_hash`（**不含原始请求体**） | `status`、`limit`、`cursor` |
| GET | `/v1/approvals/{approval_id}` | 单个 `ApprovalView` | — |
| GET | `/v1/audit/events` | `AuditEventView[]`：`seq`、`id`、`actor`、`action`、`target`、`created_at`、`payload`（白名单投影） | `after_seq`、`limit` |
| GET | `/v1/audit/verify` | `AuditVerifyResult`：`ok`、`first_bad_seq`、`reason`（固定枚举，**不含 payload**） | — |
| GET | `/v1/adapters` | `AdapterManifestView[]`：`adapter`、`capability`、`tier`、`destructive`、`read_only` | — |
| GET | `/v1/policy` | `PolicyView`：有效策略摘要（**不含密钥、令牌、连接串**） | — |

`last_seen` 的取值决定（沿用 ADR-021）：**服务端接收时间** `received_at`，
不采用节点自报的 `sent_at` 作为"存活证据"——节点时钟不可信。

## 8. 未完成项（不在本 ADR 范围内，不得用默认值实现）

- OpenAPI 自动生成工具选型与 HTTP 注解（本 ADR §6 的手写产物作为回归对照）；
- 速率限制与并发上限（需要真实流量画像）；
- 前端接入（本轮无 UI）；
- 真实 issuer 联调（需要含 `exp` 的脱敏令牌样本）；
- 写操作与审批入口（超出只读边界，需另立 ADR）；
- `-mode=prod` 的整体放行仍受 ADR-023 §6 未决项约束（生产 CA、凭据存储、补发流程）。

## 9. 待用户确认的两项（本 ADR 的唯一阻塞点）

| # | 待确认内容 | 未确认时的行为 |
| --- | --- | --- |
| 1 | 守卫例外：入站 HTTP 白名单扩展为 `{alerts/internal/httpapi/server.go, internal/console/httpapi/}`（§1） | 不实现 C1–C6，本轮止于 C0 |
| 2 | OpenAPI 本轮手写 + 两条一致性守卫，自动生成留待后续（§6） | 不实现 C1–C6，本轮止于 C0 |

确认后按 §1–§7 实现，交付物与验证按轮次提示词 C1–C6 执行；
两处决定都标注"工程默认，待确认"，其中 §4 的 50/200/10 秒/60 秒偏差为纯工程默认值。
