# ADR-018：计划终态语义修订、worker 逐条停止与宽限期、OIDC 生产认证边界

- 状态：已接受
- 日期：2026-10-13（第十九轮）
- 决策者：业务方裁决（本轮裁决 1–5）
- 关系：**不修改 ADR-001 至 ADR-016**。本 ADR：
  - **修订 ADR-016 §4** 的计划终态判定（新增 `not_executed`，收窄 `partial`）；
  - **修订 ADR-017 §2** 的 worker 停止粒度与超时（阶段级 → **能力级**，2 分钟 → 30 秒宽限期）；
  - 新增 OIDC 生产认证边界（ADR-011 / 第十一轮 H3 的"生产认证待决策"由此落地）；
  - 其余条款（含 ADR-017 的 K8s 执行边界、单实例锁）继续有效。

## 背景

第十八轮落地"K8s 只读执行 + 测试模式 worker"后，评审指出三处问题：

1. **残留检查形同虚设**：`TestNoLeftoversAfterSuite` 默认 SKIP，"残留为 0"需要
   人工开启环境变量才检查，等于没有检查。
2. **`partial` 承载两种语义**："部分完成"与"一个能力都没执行（如集群未配置）"
   共用 `partial`，监控无法区分，容易误读为"部分成功"。
3. **worker 停止粒度过粗**：阶段结束后才检查停止信号，最坏要等 2 分钟（阶段超时）；
   停止期间进程仍占用执行能力。
4. **生产认证缺位**：`mode=prod` 只有"禁止静态令牌"的拒绝规则，没有任何可用的
   生产认证方式，MVP 无法对外提供服务。

## 决策

### 1. 残留检查改为强制门禁（F1）

- 新增 `make residual-check`：**强制开启**全局残留检查（不依赖操作者设置环境变量），
  任一残留（kind 集群 / `agent-ops.test=true` 容器 / `test_run_*` schema）
  即**非零退出码**；
- 用例被 SKIP（门禁未真正执行）同样视为**失败**——"SKIP 不计入通过"；
- `make ci` 把 `residual-check` 作为**独立必选步骤**（`gen-check → build → test →
  residual-check`），不允许跳过；
- 普通 `go test ./...` 中该用例仍可 SKIP（并行包会让全局检查误报），
  因此门禁**必须**单独执行；
- **门禁自证**：`TestResidualGateDetectsLeftover` 始终运行，人为制造一个
  `test_run_*` 残留并断言检测器能发现它、清理后消失——否则"门禁永远通过"
  毫无意义。

### 2. 计划终态：新增 `not_executed`，收窄 `partial`（F2，修订 ADR-016 §4）

终态映射（**每种组合唯一确定**）：

| 能力结果组合 | 计划终态 | reason |
| --- | --- | --- |
| 任一能力**执行失败**（含 interrupted） | `failed` | 有 N 条能力执行失败 |
| 全部能力成功（ok = 全部） | `done` | 空 |
| 至少一个 ok，且至少一个 denied / no_cluster_configured / deferred | `partial` | 部分完成：ok/denied/deferred/no_cluster_configured 计数 |
| **没有任何能力被执行**（全部 denied / no_cluster_configured / deferred） | `not_executed` | 首要原因（优先级：集群未配置 > 被拒绝 > 被推迟 > 无能力） |
| 计划不含任何能力（防御性） | `not_executed` | 无能力 |

关键性质：

- `partial` **只**表示"至少一个能力被执行、且至少一个被拒绝/推迟"；
- `not_executed` 明确表示"**一个能力都没有执行**"——集群未配置是典型场景；
- **`done` 与 `partial` 都不再承担"全部未执行"的语义**，监控可据此区分
  "部分成功"与"根本没跑"；
- `failed` 的优先级最高（ADR-016 原决定保持不变）；
- 数据库 CHECK 约束扩展 `not_executed`（计划表）；**旧数据不变**
  （新增枚举值不改变既有行的取值）。

### 3. worker 停止粒度与宽限期（F3，修订 ADR-017 §2）

- **每个能力调用前**检查停止信号（能力粒度，替代原"阶段粒度"）；
- **单个能力调用超时 30 秒**（`DefaultCapabilityTimeout`，替代原 2 分钟阶段超时）；
- 收到 SIGINT / SIGTERM 后：
  1. **当前能力**在宽限期（= 单能力超时 30 秒）内跑完，结果照常写入；
  2. 之后的**剩余能力不再执行**；
  3. 若当前能力在宽限期内未完成 → 取消其上下文，把该计划标记为
     **`failed`，reason = `interrupted`**，并写一条审计
     （`diagnosis.interrupted`，seq 连续）；
- 停止过程中出现的错误**不计为本轮失败**（停止不是故障）；
- **数据库操作**使用与停止信号解耦的上下文，保证停止后仍能落终态与审计；
- 强杀（SIGKILL）/ 崩溃场景**仍由对账处理**（`ReconcileRunning` →
  `failed(stale_running)`）；对账后的计划需要**人工重新规划或重投**，
  **不自动重跑**。

### 4. OIDC 生产认证（A1，仅网关 gRPC 入口）

- **范围**：只覆盖网关的 gRPC 入口；**生产写能力为零**——`prodcatalog` 的
  Handler 仍是"未接线"桩，任何执行请求返回未实现错误，不绕过任何门控；
- **配置**：`-oidc-issuer`、`-oidc-audience`、`-oidc-jwks-url`
  （`http(s)://` 走 HTTP，其余视为本地文件路径）；
- **校验链（顺序固定，任一不过即 UNAUTHENTICATED）**：

  | # | 校验项 | 拒绝条件 |
  | --- | --- | --- |
  | ① | 承载格式 | 缺少 `authorization: Bearer` 或非 Bearer |
  | ② | `alg` | **不是恰好 `RS256`**（`none`、`HS*`、`RS512` 等一律拒绝） |
  | ③ | `kid` | 缺失，或不在 JWKS 中 |
  | ④ | 签名 | RSASSA-PKCS1-v1_5 + SHA-256 校验失败 |
  | ⑤ | `iss` | 与配置**精确不匹配** |
  | ⑥ | `aud` | 与配置**精确不匹配**（支持字符串与数组形态） |
  | ⑦ | `exp` / `nbf` | 经注入时钟校验，**允许 ±60 秒**偏差，超出即拒绝 |

- **actor 取自 `sub` 声明**；**永不**接受请求体或自报头里的 actor
  （契约消息中没有 actor 字段）；
- **mode=prod**：静态令牌（含未配置 token 的实例）**一律拒绝启动**；
  OIDC 是 prod **唯一**放行的认证方式（`GuardAuth` 对未知实现 fail-closed）；
- **mode=test**：保留静态令牌便于本地测试；OIDC 在 test 下也可启用，
  但**不替代**静态令牌的启动校验；
- **密钥与令牌**：不写入日志、错误、审计 payload（错误只回固定文案，
  避免凭据探测）；
- **测试密钥**：运行时生成 RSA 密钥、JWKS 由本地 httptest 提供；
  **不提交任何密钥文件**、不连接真实身份提供商。

### 5. 出站 HTTP 白名单扩展（实现细节，记录备查）

JWKS 拉取需要 HTTP 客户端。按 ADR-013 / ADR-014 建立的仓库级守卫
（`internal/repoguard`），出站 HTTP 只允许出现在登记文件里；因此本 ADR 记录
**新增一个登记文件**：`gateway/internal/grpcwire/jwks.go`。
该文件只发 GET、不做 URL 拼接、响应体有上限、只处理公钥集合。
OIDC 的其余逻辑（`oidc.go`）**不 import 任何 HTTP 包**，只依赖
`JWKSFetcher` 接口。

## 影响

- `Makefile`：新增 `residual-check`；`ci` 加入该独立必选步骤；
- `internal/k8stest/residual_test.go`：抽出 `ResidualViolations`（可复用）；
  新增 `TestResidualGateDetectsLeftover`（门禁自证）；
- `alerts/internal/executor/executor.go`：新增 `PlanNotExecuted`、
  `ActionInterrupted`、`ReasonInterrupted`、`DefaultCapabilityTimeout`、
  `Config.CapabilityTimeout`、`SetCapabilityTimeout`、`finishInterrupted`、
  `notExecutedReason`；终态判定改为四分支；能力调用前检查停止信号；
- `alerts/internal/planner/rules.go` + `store.go`：`StatusNotExecuted`；
  计划表 CHECK 扩展 `not_executed`；
- `alerts/internal/worker/worker.go`：executor 阶段传入**可取消**上下文
  （由执行器按能力粒度停止）；consumer / planner 仍用解耦上下文跑完当前批次；
- `gateway/internal/grpcwire/jwks.go`（新增）：JWKS 解析 + 获取器；
- `gateway/internal/grpcwire/oidc.go`（新增）：OIDC 令牌校验；
- `gateway/internal/grpcwire/auth.go`：`GuardAuth` 放行 OIDC、拒绝其余实现；
- `gateway/cmd/gateway/main.go`：新增 `-oidc-issuer` / `-oidc-audience` /
  `-oidc-jwks-url`，prod 必须配置 OIDC；
- `internal/repoguard/repoguard.go`：`AllowedHTTPFiles` 新增
  `gateway/internal/grpcwire/jwks.go`；
- ADR-016 §4 的终态判定与 ADR-017 §2 的停止粒度以本 ADR 为准；
  两者的其余条款继续有效。

## 未决 / TODO

- **真实身份提供商接入**：issuer/audience/JWKS 的运维配置、密钥轮换与
  JWKS 缓存失效策略、多租户（多个 issuer）支持；
- **生产 prodcatalog**：资产 → SSH 通道与凭据解析尚未实现，生产执行 Handler
  仍是未接线桩；生产写能力**必须保持为 0**，直到接入通道与审批流程就绪；
- **生产 worker 形态**：`alerts -worker` 仍仅测试模式可用（ADR-017 §2）；
- **JWKS 缓存**：当前"未知 kid 触发一次刷新"，未实现定时刷新与
  `Cache-Control` 遵从；
- **mTLS**：本 ADR 只落地 OIDC；如后续需要 mTLS，另行记录。
