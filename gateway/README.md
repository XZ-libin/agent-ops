# 执行网关（gateway）

对外入口：gRPC 服务（`proto/agent_ops/contract/v1/gateway.proto`，实现于
`internal/grpcwire`）；入口实现 `cmd/gateway`。

```
提交链路：请求校验 → 能力查找 → destructive 拒绝 → 策略引擎 → 低风险白名单
          → 决策审计（fail-closed）→ deny / require_approval / auto

审批执行：校验审批 → 能力/destructive/test_only 复核 → 策略重评
          → 原子抢占（approved→executing，写入执行租约）→ executing 审计
          → 幂等检查 → 执行（期间续租）→ executed/failed 审计 → 消费审批
```

## 单实例约束（第十一轮 H1）

**本进程要求单实例运行，多实例部署被禁止。**

依据：执行租约 + 对账机制以"同一时刻只有一个实例在执行"为前提；并发实例的
在飞行执行会被启动对账误判为中断并标记 abandoned。启动时
`Service.GuardSingleInstance` 会检查审批存储，若发现其他实例持有的**有效**
执行租约（`status='executing'` 且 `lease_until` 未过期），立即拒绝启动。

多实例部署需先完成：跨实例租约协调（如数据库行锁/lease 表的 CAS 租借）与
对账口径改造；在此之前一律单实例。

## 执行租约与对账（H1）

| 项 | 值 | 说明 |
| --- | --- | --- |
| 续期间隔 `LeaseRenewInterval` | 20s（固定） | 执行期间每 20s 续期一次 |
| 执行租约 | **按能力超时推导** | `租约 = 能力超时 + 2×续期间隔`（`approvals.LeaseFor`） |

租约不再是全局固定值（第十二轮 H6 裁决：固定 60 秒会把合法的长耗时执行误判为
崩溃）。启动时对每个已注册能力强校验：租约必须大于续期间隔的 2 倍、且不得小于
该能力超时；能力未声明正超时则在注册期即被拒绝（`Registry.Register`）。

- 续期失败（含租约过期）→ 取消执行上下文 → Handler 中止 → 写 `failed` 审计 →
  审批标记 `abandoned`（**不重放、不消费**，需重新提交审批）；
- 对账 `Service.Reconcile` **只**处理 `lease_until` 已过期的 `executing` 记录
  （未过期的一律跳过——它可能仍在执行中）；
- 对账应在启动后、对外提供服务前执行（cmd/gateway 已固定此顺序）。

## 运行模式（H3）

`-mode` **必填，无默认值**：`test` / `prod`。

- `mode=prod`：**禁止**启用仅测试的静态 token 认证（代码层拒绝启动，
  `grpcwire.GuardAuth`），与是否配置了 token 无关；**必须**配置 OIDC
  （`-oidc-issuer` / `-oidc-audience` / `-oidc-jwks-url`）——OIDC 是 prod
  唯一放行的认证方式；
- `mode=test`：允许仅测试的静态 token 认证（`-test-static-tokens tok=actor,...`），
  仅用于测试，不得用于任何生产环境；OIDC 在 test 下也可启用（本地联调）；
- OIDC 校验（第十九轮 A1；第二十轮 O1/O2 硬化）：只接受 `alg=RS256`，
  `kid` 必须在 JWKS 中，`iss`/`aud` 精确匹配，**`exp` 必填**（缺失或非正数一律拒绝），
  `nbf` 可选（缺失时不做未生效判定），`exp`/`nbf` 允许 ±60 秒偏差，actor 取自 `sub`；
- JWKS 刷新限速（O1）：未知 `kid` 触发的刷新间隔 **≥30 秒**；间隔不足时直接拒绝
  该令牌且**不发起外部请求**（防随机 `kid` 放大）；已知 `kid` 命中缓存不受限速影响；
- **生产写能力为零**：`prodcatalog` 的执行 Handler 仍是未接线桩，
  任何执行请求返回未实现错误，不绕过任何策略/审计门控。

## 测试数据库（H2）

所有测试运行统一使用**独立数据库 `agent_ops_test`**：

- DSN 默认 `postgres://agent_ops:agent_ops@localhost:55432/agent_ops_test?sslmode=disable`，
  可用 `AGENT_OPS_TEST_DATABASE_URL` 覆盖；
- 连接前必须通过 `internal/testdb.Validate` 校验库名，**不是 `agent_ops_test` 即拒绝运行**
  （防止测试在默认库建表——曾因此在默认库产生生产命名表）；
- 审计记录**绝不删除**；历史测试数据已按裁决复制到 `agent_ops_test`（源表保留）。

## 启动

```sh
go run ./cmd/gateway \
  -addr 127.0.0.1:9090 \
  -dsn postgres://agent_ops:agent_ops@localhost:55432/agent_ops_test?sslmode=disable \
  -manifest adapters/linux/manifest.yaml \
  -mode test \
  -test-static-tokens 'tok-requester=ops-lead,tok-approver=ops-auditor'
```

启动顺序（fail-closed，任一步失败即退出，不进入监听）：
解析 mode → 连库（55432）→ 建/升级表结构 → 加载生产能力清单（拒绝 test_only）
→ 生产启动守卫 → 组装服务 → **单实例守卫** → 启动对账 → 监听 → 优雅停机。

## 固定错误码映射

| 结局 | gRPC 码 |
| --- | --- |
| 策略拒绝（含 destructive / 能力未声明 / 四眼拒绝） | `PERMISSION_DENIED` |
| 幂等冲突（同键不同内容 422 / 处理中 409） | `ALREADY_EXISTS` |
| 审批状态不允许（pending/expired/consumed/executing/abandoned、单实例冲突） | `FAILED_PRECONDITION` |
| 审计写入失败（fail closed） | `INTERNAL` |
| 执行失败（`failed` 结局） | `INTERNAL`（详情随 `ExecuteOutcome` 回传） |
| 记录不存在 / 参数非法 / 未认证 | `NOT_FOUND` / `INVALID_ARGUMENT` / `UNAUTHENTICATED` |
