# 控制台只读 API（运维手册）

> **状态：本地实现并本地验证；未经 CI。** 契约与决定见
> [ADR-024](../adr/ADR-024-控制台只读API.md)。第二十七轮交付。

适用对象：需要以只读方式查看节点、审批、审计、能力清单与有效策略的运维与集成方。
**本 API 不提供任何写操作**（改审批、执行、吊销都不在这里）。

---

## 1. 代码位置与边界

| 位置 | 职责 |
| --- | --- |
| `proto/agent_ops/console/v1/console.proto` | 响应契约（7 条消息 + 1 个枚举，无 service） |
| `internal/console` | 配置与边界、payload 投影、只读数据访问、OIDC 验证 |
| `internal/console/httpapi` | 路由表与 HTTP 行为（本仓库第二个入站 HTTP 白名单条目） |
| `openapi/console.yaml` | **手写**的 OpenAPI（本轮不引入生成插件） |

只读的三层强制：包内只有 SELECT；静态守卫禁止 import 写路径与写符号；
数据库角色 `test_console_reader` 只有 SELECT。

## 2. 路由表

| 方法 | 路径 | 查询参数 | 返回 |
| --- | --- | --- | --- |
| GET | `/v1/health` | — | `HealthView` |
| GET | `/v1/nodes` | — | `NodeView[]`（内部封顶 200 行） |
| GET | `/v1/nodes/{node_id}` | — | `NodeView` |
| GET | `/v1/approvals` | `status`、`limit`、`cursor` | `ApprovalView[]` |
| GET | `/v1/approvals/{approval_id}` | — | `ApprovalView` |
| GET | `/v1/audit/events` | `after_seq`、`limit` | `AuditEventView[]` |
| GET | `/v1/audit/verify` | — | `AuditVerifyResult` |
| GET | `/v1/adapters` | — | `AdapterManifestView[]` |
| GET | `/v1/policy` | — | `PolicyView` |

非 GET 命中以上路径 → `405` + `Allow: GET`；其余路径 → `404`。

## 3. 鉴权

- 生产：OIDC id_token。仅 `RS256`；`iss`、`aud` **精确匹配**；`exp` 必填；
  `kid` 必须出现在 JWKS；时钟偏差容忍 **60 秒**（工程默认，待确认）。
  **生产模式配置静态令牌会直接启动失败**。
- 测试：合成 JWKS 夹具（密钥运行时生成、仅存内存），或测试模式静态令牌。
- 失败一律 `401`，响应体只含固定信封，**不区分**"过期 / 签名不对 / kid 不认识"，
  也不回显 `iss`、`exp` 等内部判定信息。
- 鉴权在路由匹配**之前**执行：未认证者拿不到"这个路径是否存在"的信息。

```sh
# 有效令牌（RS256，sub 作为 actor）
curl -sS -H "Authorization: Bearer $ID_TOKEN" http://127.0.0.1:8080/v1/nodes
```

## 4. 分页

| 参数 | 规则 |
| --- | --- |
| `limit` | 默认 **50**，上限 **200**；`0`、负数、非数字、`>200` → `400 bad_request`；空值与纯空白等同未提供 |
| `after_seq`（审计） | 游标，返回 `seq > after_seq` 的升序记录；负数与非数字 → `400` |
| `cursor`（审批） | 上一页最后一条 `approval_id`，返回严格大于它的记录（升序） |
| 无分页参数 | `/v1/nodes` 内部封顶 200 行（表大时请改用详情接口，避免无界查询） |

64 位整数在 JSON 里是**字符串**（protojson 约定）：`seq`、`first_bad_seq`、
`events_total`、`schema_version`、`hard_deny_rules` 都按字符串读取。

## 5. 响应形态与头

- 成功：proto 原样 snake_case；未填充字段**照样输出**（`ok:false`、`cert_state:""` 必须可见）；
- 列表是 JSON 数组，不包壳；
- 错误：`{"error":{"code":"...","message":"..."}}`，`message` 取自固定文本表；
- 每个响应都带：`Cache-Control: no-store`、`X-Content-Type-Options: nosniff`；
- 单请求服务端超时 **10 秒**（工程默认，待确认）。

## 6. payload 投影（审计事件）

只回传下列键，且只回传标量值；其余全部丢弃：

| 动作前缀 | 保留键 |
| --- | --- |
| `node.` | `node_id`、`boot_session_id`、`event_kind`、`reason_code` |
| `approval.` | `approval_id`、`capability`、`status` |
| `diagnosis.`、`execution.` | `capability`、`status`、`exit_class` |

另有**值级筛查**：出现 `-----BEGIN`、`PRIVATE KEY`、`PUBLIC KEY`、`eyJ`（JWT 头）
或长度超过 256 字符的值，一律丢弃。理由见 ADR-024 §5——白名单挡不住"把 PEM 写进合法键"。

## 7. 本地运行与自检

当前**没有独立的可执行入口**（`cmd/console` 未落地：生产装配需要 JWKS 拉取通道与真实表名，
两者都还在待决清单里）。本机验证方式：

```sh
# 全栈用例（httptest + run schema，含只读角色与篡改定位）
go test ./internal/console/... -v -count=1

# 契约一致性（路由 ↔ OpenAPI ↔ proto）
go test ./internal/console/httpapi/ -run 'TestConsoleOpenAPIMatchesRoutes|TestConsoleSchemaMatchesProto' -v -count=1

# 仓库守卫（入站白名单必须恰好两项）
go test ./internal/repoguard/ -run 'TestConsoleInboundHTTPAllowlistExact|TestInboundAllowlistIsExplicit' -v -count=1
```

若要起真实端口，装配代码这样写（`ListenAndServe` 就在入站白名单目录里）：

```go
reader, _ := console.NewReader(pool, cfg, manifest, policy.DefaultConfig())
verifier, _ := console.NewVerifier(console.AuthConfig{
        Mode: console.ModeProd, Issuer: iss, Audience: aud, Keys: jwksSource,
})
srv, _ := httpapi.NewServer(reader, verifier, 0) // 0 → 默认 10 秒
_ = srv.ListenAndServe("127.0.0.1:8080")
```

## 8. 限制与未完成项

- **无速率限制、无并发上限**（需真实流量画像后再定，见 ADR-024 §4）；
- **无前端**：本轮只做 API，`web/` 未接入；
- **OpenAPI 手写**：自动生成需要新增 protoc 插件（外部二进制，本轮禁止），
  漂移由 `TestConsoleOpenAPIMatchesRoutes` / `TestConsoleSchemaMatchesProto` 兜住；
- **真实 issuer 未联调**：需要含 `exp` 的脱敏令牌样本；
- **生产表名未定**：`console.Config` 目前强制 `test_` 前缀（fail-closed），
  生产表名确认后需同时放宽校验与配套守卫；
- 审计链的**尾部截断**检测仍需外部锚点（ADR-005 既有待办，本 API 不改变该结论）。
