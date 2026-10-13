# ADR-020：节点身份（注册 / 心跳 / mTLS）与 CI 残留门禁修订

- 状态：已接受
- 日期：2026-10-13（第二十一轮）
- 决策者：业务方裁决（本轮裁决 1–3 + 第二十一轮关键决定）
- 关系：**不修改 ADR-001 至 ADR-019 的已定决策**。本 ADR：
  - **修订 ADR-019 §1 / ADR-018 §1**：CI 的独立 `residual-check` job 取消，
    残留门禁**合并进 `test` job**（分支保护只需 `test` 一项）；
  - 新增节点身份、mTLS、离线判定与协议选型；
  - 本轮**不引入命令通道**（节点代理只能注册与心跳）。

## 背景

1. **CI 残留门禁形同虚设**：ADR-019 §1 把残留检查放在独立的 `residual-check`
   job。但 GitHub 托管的 runner **每个 job 都是全新环境**，该 job 看不到 `test`
   job 产生的任何残留，只能检查它自己。
2. **CI 从未真实运行**：`docs/tooling.md` 中 `kubectl linux/amd64` 与 Go
   `linux/amd64` 的 SHA-256 仍是"待回填"；kind 在托管 runner 上是否可用、
   PG service 就绪时序都未验证。裁决 2 明确：**在仓库推送 GitHub 并完成首次
   CI 运行之前，第二十一轮不接受**。
3. **`exp` 必填的真实影响未知**：ADR-019 §3 把 `exp` 改为必填；若真实 issuer
   不发 `exp`，接入时会拒绝所有请求。裁决 3：真实 issuer 联调的准入条件之一是
   提供其令牌样本（脱敏）证明含 `exp`。
4. **节点代理是 MVP 下一个必需项**：需要"身份建立"能力（注册、心跳、mTLS），
   但**命令执行**必须留到下一轮，把风险隔离在身份建立上。

## 决策

### 1. CI 残留门禁修订（修订 ADR-018 §1 / ADR-019 §1）

- **取消**独立的 `residual-check` job；CI 变为**三个** job：
  `gen-check` / `build` / `test`；
- 残留门禁（`make residual-check`）作为 **`test` job 的最后一步**，与测试
  **同一个 runner**、测试之后立即执行——只有这样才能看到本次测试真实遗留的
  kind 集群 / 测试容器 / `test_run_*` schema；
- **分支保护只需把 `test` 设为必需检查**；
- 保留 ADR-018 §1 的其余约束：不得设置绕过开关、不得用 `if` 跳过、用例被 SKIP
  同样判失败；
- 由 `internal/repoguard` 的 `TestCIConfigGuards` 断言：三个 job 齐备、
  **不得再出现独立的 `residual-check` job**（防回归）、`make residual-check`
  必须在 `test` job 内执行。

**取舍说明**：这与第二十轮裁决的"四个独立 job"冲突。选择**检测有效性优先**——
一个看不到真实残留的门禁没有意义。代价是分支保护粒度变粗（test 与残留检查
共用一个必需检查），可接受。

### 2. 协议选型：gRPC（不使用 net/http 出站）

- 节点 ↔ 控制面使用 **gRPC**；
- 理由：
  1. 仓库级 AST 守卫（ADR-013/ADR-014）禁止非允许文件使用**出站 HTTP**；
     gRPC 不触发该规则，因此**无需修改守卫白名单**（保持约束面不扩大）；
  2. 契约已在 proto 中集中管理（ADR-002），gRPC 与既有 `gateway` 服务同构，
     代码生成、错误码映射、拦截器（认证/审计）可直接复用；
  3. 双向能力（下一轮的命令通道）可在不改协议栈的前提下扩展。
- 由 `internal/repoguard` 的 `TestNodeAgentModuleAvoidsHTTP` 固化：
  `node-agent` 模块**不得** import `net/http`（含测试文件）。

### 3. 心跳形态：单向上报（unary），不用双向流

- `Heartbeat` 定义为 **unary RPC**（`HeartbeatRequest → HeartbeatResponse`）；
- 理由：
  1. 本轮**服务端没有任何下行消息**（节点不接收命令），双向流没有承载内容；
  2. 双向流会引入长连接状态机、重连与背压复杂度，而本轮只需要"上报 + 判定"；
  3. unary 天然幂等（`node_id` + `sent_at` 可作幂等键），便于重试与离线判定；
  4. 10 秒一次的低频上报用 unary 完全够用——连接复用由 HTTP/2 承担，
     不需要应用层流。
- 下一轮引入命令通道时，**新增** service 或新增双向流 RPC，
  不改动本 service 的语义。

### 4. 契约边界：只注册与心跳（N1）

- `NodeAgent` service **只定义** `Enroll` 与 `Heartbeat` 两个 RPC；
- **不定义任何命令/执行类 RPC**：未定义的方法由 gRPC 运行时自然返回
  `UNIMPLEMENTED`（fail-closed，不存在"忘记拒绝"的路径）；
- 由 `contract/node_contract_test.go` 断言：
  1. 服务方法集合**恰好**是 `{Enroll, Heartbeat}`，且不含任何命令类方法名
     （execute/run/command/shell/exec/deploy/...）；
  2. 契约中**没有**任何私钥/口令字段；
  3. 经真实 gRPC（bufconn，进程内）实测：未接线的方法与未定义的方法
     （`Execute`/`RunCommand`/`Shell`/`Deploy`）一律 `UNIMPLEMENTED`。

### 5. 节点身份与注册（N3）

- 权威身份格式 **`nod_<ULID>`**：前缀 `nod_` + 26 位 Crockford Base32 ULID
  （48 位毫秒时间戳 + 80 位随机）；ULID **自实现**（无第三方依赖），
  位序约定为"128 位放进 26×5=130 位空间、最高 2 位补零"，因此首字符必 ≤ `7`；
- **注册令牌一次性**：
  - 由控制面生成（32 字节随机 → base64url 明文）；
  - 控制面**只保存 SHA-256 哈希**（`TokenHash`），不保存明文；
  - 有效期 **15 分钟**（注入时钟）；
  - **用后立即失效**（`UsedAt` / `UsedByNodeID`）；
  - 校验失败对外**只有一个错误**（`ErrTokenRejected`），不泄露"是哈希不匹配、
    还是过期、还是已使用"；具体原因通过内部 `Outcome` 返回，仅供审计与测试；
- **CSR 一致性**：请求声明的 `declared_node_id` 必须与 CSR 的 CN 或 SAN 一致，
  否则拒绝（证明请求方持有其所声明身份对应的私钥，防止 CSR 被替换）；
- **证书签发**：控制面用 CSR 的公钥签发节点证书，有效期 **30 天**；
  证书的 **CN 与 SAN 均为控制面分配的 `node_id`**（CSR 中的声明身份**不进入**
  最终证书）——权威身份由控制面分配。

### 6. mTLS 与身份绑定（N4）

- 控制面的 gRPC 服务**要求客户端证书**，并校验其由本 CA 签发；
- 节点证书的 CN 或 SAN 必须与其 `node_id` 绑定；不一致即拒绝；
- 校验项与错误（不泄露证书内容）：无证书 `ErrNoClientCert`、
  非本 CA 签发 `ErrCertUntrusted`、过期/未生效 `ErrCertExpired`（注入时钟）、
  身份不一致 `ErrIdentityMismatch`；
- **本轮不实现 CRL / OCSP**（见 TODO）。

### 7. 测试 CA（N2）

- 仅测试：运行时生成 ECDSA P-256 的 CA 密钥对与节点证书；
- **CA 私钥只在内存中持有**：本包**不提供任何导出/写盘私钥的函数**
  （只有 `CertificatePEM` 用于证书）；私钥随进程退出丢弃；
- 仓库级断言：`TestNoPrivateKeysCommittedInRepo`（全仓）+
  `TestNodePathsContainNoPrivateKeyMarkers`（节点相关路径）。

### 8. 心跳与离线判定（N5）

- 心跳间隔 **10 秒**；连续 **3 次**（= 30 秒）未收到 → 标记 **`offline`**；
  收到心跳立即恢复 **`online`**；
- **时钟注入**：`NewTracker` 要求显式提供 `Config.Now`，未提供即拒绝构建
  （fail-closed，防误用真实时间）；测试不使用真实 sleep；
- **时间戳回退**：心跳的 `sent_at` 早于上一次 → 拒绝（`ErrTimestampRollback`）
  并记录，且**不刷新 `last_seen`**（防止用旧时间戳伪造在线）；
  注册时把 `last_sent_at` **锚定为注册时刻**（节点不可能在注册前发过心跳）；
- 批量判定只返回**发生状态变化**的迁移（供写审计）。

### 9. 审计约定（N6，本轮为设计）

- 注册、心跳状态变化（`online ↔ offline`）、证书拒绝均写审计；
- **actor 约定**：节点相关事件写 `node:<node_id>`；**拒绝事件**（令牌无效、
  证书不可信、身份不一致）写 `system`；
- **payload 不含**：证书私钥、令牌明文、CSR 原文（只写令牌哈希前缀/内部原因码）。

### 10. 本轮实现范围（前置条件降级）

裁决 2 明确"首次 CI 运行之前第二十一轮不接受"，任务前置条件规定
"CI 首次运行结果未提供时，本轮**只做设计与纯单元部分**，并标明'CI 未验证'"。
本轮**未收到任何 CI 首次运行结果**，因此：

| 项 | 本轮状态 |
| --- | --- |
| N1 协议与边界 | ✅ 已完成（proto + 生成 + 边界断言） |
| N2 测试 CA | ✅ 已完成（纯单元） |
| N3 注册（令牌 / CSR / 身份） | ✅ 已完成**纯逻辑**；PG 持久化待 CI 验证后补 |
| N4 mTLS 校验 | ✅ 已完成（纯逻辑，注入时钟） |
| N5 心跳与离线判定 | ✅ 已完成（纯逻辑，注入时钟） |
| N6 审计写入 | ⏸ 设计完成；PG 写入与行数断言待 CI 验证后补 |
| N7 `cmd/node-agent` 进程 | ⏸ 未实现（仍为骨架） |
| N8 集成测试（真实 gRPC + PG） | ⏸ 未实现 |

## 影响

- `.github/workflows/ci.yml`：三个 job（gen-check / build / test），
  残留门禁移入 `test` job 末尾；
- `internal/repoguard/ciworkflow_test.go`：required jobs 改为 3 个，
  新增"不得存在独立 residual-check job"与"残留检查必须在 test job 内"断言；
- `internal/repoguard/nodemodule_test.go`（新增）：node-agent 不得 import
  net/http；节点相关路径无私钥字样；
- `proto/agent_ops/contract/v1/node.proto`（新增）：NodeStatus / NodeLoadSummary /
  Enroll{Request,Response} / Heartbeat{Request,Response} / service NodeAgent；
- `contract/gen/go/agent_ops/contract/v1/node{,_grpc}.pb.go`（新增，生成产物）；
- `contract/node_contract_test.go`（新增）：契约边界断言 + bufconn 实测；
- `control-plane/internal/nodeidentity/`（新增）：nodeid.go（ULID）、token.go
  （一次性令牌）、ca.go（测试 CA / CSR / 签发 / mTLS 校验）；
- `control-plane/internal/nodehealth/`（新增）：心跳与离线判定状态机；
- ADR-018 §1 与 ADR-019 §1 关于"独立 residual-check job"的条款以本 ADR 为准；
  其余条款继续有效。

## 未决 / TODO

- **首次 CI 运行**（阻塞第二十一轮验收）：推送 GitHub 后回填
  `docs/tooling.md` 的 linux/amd64 SHA-256，并把 actions 钉到 commit SHA；
- **真实 issuer 联调**：准入条件之一 = 提供其令牌样本（脱敏）证明含 `exp`；
- **证书吊销（CRL / OCSP）**：本轮不实现——节点证书 30 天有效期内无法吊销；
  需要引入短期证书 + 定期轮换，或 OCSP Stapling；
- **证书持久化**：本轮证书只在节点内存中，**重启需重新注册**；
  生产需要安全落盘（文件权限 / TPM / keyring）与轮换流程；
- **证书轮换**：未实现（30 天有效期，需在到期前自动续签）；
- **生产 CA**：本轮只有测试 CA；生产 CA 的来源、根信任分发与离线签名流程未定；
- **PG 持久化与审计写入**（N3/N6）：令牌表、节点状态表、审计写入与行数断言；
- **`cmd/node-agent`（N7）与集成测试（N8）**：未实现；
- **命令通道**：下一轮（新增 service 或双向流 RPC）。

---

> **修订说明（第二十二轮）**：本 ADR 的 §3（注册与身份：CSR 一致性与 `declared_node_id`）、
> §5（心跳锚点）、§7（证书 30 天有效期与不实现吊销）**已被
> [ADR-021](ADR-021-心跳接收时间-控制面分配身份-证书7天与吊销表-引导信任与CI门禁解耦.md) 取代**；
> 本 ADR 其余条款继续有效。正文未作修改。
