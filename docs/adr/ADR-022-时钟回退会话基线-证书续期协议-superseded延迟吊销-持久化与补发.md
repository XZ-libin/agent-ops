# ADR-022：时钟回退会话基线、证书续期协议、superseded 延迟吊销、证书持久化与吊销后补发

- 状态：已接受
- 日期：2026-10-13
- 轮次：第二十三轮（T1–T5 修正 + N6–N8 补齐后的硬化）
- 关系：**不修改 ADR-001 ~ ADR-021 的正文**；本 ADR 记录第二十三轮的新决定。
  被修订的条款（ADR-021 的"sent_at 严格递增"、"证书仅内存"、"吊销后无恢复路径"）
  在本文中显式标注。

> **验证状态：全部结论为「本地通过，CI 未验证」。** CI 首次运行结果尚未提供。

---

## 1. D6 时钟回退：防重放基线按 (node_id, boot_session_id) 维护

**修订 ADR-021 §1 的"同一节点内 sent_at 必须严格递增"。**

### 1.1 问题

`sent_at` 严格递增的防重放规则，在节点**系统时钟回拨**后会让所有心跳被判为 `replay`；
节点在时钟追平之前**一直离线**——这与 D1 修复的"注册时刻锚点"是同一类**永久失联**。

### 1.2 决定

| 项 | 内容 |
|---|---|
| 会话标识 | `HeartbeatRequest.boot_session_id`（proto field 5）：节点**进程启动**时生成的 ULID |
| 基线键 | **(node_id, boot_session_id)**；控制面按会话维护 `session_sent_at` |
| 新会话 | 首个心跳**不与旧会话比较**，直接建立新基线（`NewSession=true`） |
| 同会话 | `sent_at` 必须严格递增：小于 → `replay`；等于 → `duplicate`；**都不刷新任何状态**（与 D1 一致） |
| 连续异常重置 | 同会话**连续 3 次** replay/duplicate（**工程默认，待确认**）→ 基线重置为当前 `sent_at`，写 `node.clock_regression_reset` 审计，并**按正常心跳接受** |
| 兼容 | `boot_session_id` 为空时退化为 ADR-021 的跨会话单调语义（仅用于旧节点，**会**在时钟回拨后失联） |

**审计 payload（仅三要素）**：`node_id`、`boot_session_id`、`replay_streak`。
不含证书、令牌、私钥或任何会话外信息。

### 1.3 为什么"重置"而不是"永久拒绝"

永久拒绝 = 永久失联。重置的代价是"攻击者可用 3 个伪造心跳把基线拉低"，
但在**同会话**前提下，攻击者必须已持有该节点的 mTLS 证书——此时它本就能发有效心跳，
重放攻击的额外收益为零。因此重置的收益（避免永久失联）显著大于风险。

---

## 2. 证书与私钥持久化（T2）

**修订 ADR-021 §6 的"证书仅存内存、重启需重新注册"。**

| 项 | 内容 |
|---|---|
| state 目录 | 权限 **0700**（已存在则校验，不符即拒绝启动） |
| 身份文件 | 权限 **0600**；内容 = 私钥 + 叶证书 + CA 证书 + `# node_id` 注释 |
| 写入 | **临时文件 + fsync + rename** 原子替换（同一文件系统内 rename 原子） |
| 启动 | 身份文件**有效** → **复用**（不注册、不消耗令牌）；**不存在** → 注册并保存；**损坏/权限过宽/已过期** → **拒绝启动**（绝不静默重新注册） |
| 校验项 | 权限恰好 0600、PEM 可解析、公私钥匹配、未过期、CA 可验证、CN 与 SAN 均等于 `node_id` |
| 令牌文件 | 注册成功后**尽力删除**（`NODE_ENROLL_TOKEN_FILE`）；失败只记录警告，不影响启动 |
| CA 路径 | **仅由启动参数 `-ca-file` 指定**，不接受环境变量覆盖（防止环境被污染时指向攻击者的 CA） |

**残留临时文件**：`.identity-*.tmp` 在下次启动时被**忽略**（正式身份文件优先），
不需要清理——rename 失败或进程被杀都会留它，忽略即可保证可用性。

---

## 3. Renew：证书续期协议（T3）

### 3.1 协议

新增 `Renew` RPC（走 mTLS）。**请求只包含新 CSR（PEM）**——`node_id` 由服务端从
**客户端证书的 CN** 读取，节点无法自报（与 D2 的"身份只由控制面分配/从证书读取"一致）。

### 3.2 服务端校验顺序（任一步失败 → 统一拒绝，不改变状态，写 `node.renew_rejected`）

| # | 校验项 | 失败内部 reason |
|---|---|---|
| 1 | mTLS 证书由本 CA 签发且有效 | `cert_invalid` / `cert_expired` |
| 2 | 序列号未被吊销 | `serial_revoked` |
| 3 | 证书 CN 与 SAN 与 `node_id` 绑定 | `cert_identity_mismatch` |
| 4 | 节点状态不是 `revoked` | `node_revoked` |
| 5 | CSR 签名有效（纯持有性证明） | `csr_invalid` |
| 6 | **CSR 公钥 ≠ 当前证书公钥（必须换钥）** | `same_key` |
| 7 | 签发新证书：同一 `node_id`、新序列号 | `sign_failed` |

对外一律 `INVALID_ARGUMENT "续期被拒绝"`；内部 reason **只入审计**。

### 3.3 成功路径

- **同一事务**写入：`cert_serial` → 新序列号，`pending_superseded_serial` → 旧序列号；
- 节点状态**不变**（续期不是状态迁移）；
- 写 `node.cert_renewed` 审计（`old_serial`、`new_serial`、`not_after`）。

### 3.4 旧证书：`superseded` 延迟吊销（**本轮核心设计决定**）

**旧证书在续期后不立即吊销。** 原因：吊销会把节点状态改为 `revoked`（终态）；
若续期响应丢失，节点会**卡在已吊销的证书上**，既不能继续工作也无法再续期。

| 步骤 | 行为 |
|---|---|
| 续期成功 | 旧序列号只写入 `pending_superseded_serial`，**不**入吊销表 |
| 节点仍用旧证书 | 旧证书**继续可用**（心跳正常） |
| 服务端收到**新序列号**的心跳 | 把旧序列号写入吊销表，`reason=superseded`；写 `node.cert_superseded`；**节点状态不变**；清空待确认字段 |

吊销表新增 `reason` 约束（`revoked` | `superseded`，见 §6 迁移）。
**关键区分**：`superseded` 只阻止旧证书继续使用，**不改节点状态**；
`revoked` 是终态（D3），两者不得混用。

### 3.5 节点侧调度（**工程默认，待确认**）

| 项 | 值 |
|---|---|
| 续期时机 | 有效期的 **50%**，抖动 **±10%**（相对触发点）⇒ 7 天有效期为 **[3.15 天, 3.85 天]** |
| 失败重试 | 指数退避：初值 **1 分钟**，上限 **1 小时** |
| 成功后 | 用 T2 的**原子写入**替换身份文件；后续连接使用新证书 |
| 到期提醒 | 剩余不足 **48 小时**未续期 → 服务端写 `node.cert_expiry_risk`，**每节点每 6 小时最多一条**；节点侧同时记 ERROR 日志 |

### 3.6 「±10% 抖动」的口径澄清

"续期时机为有效期的 50%，加减 10% 抖动"有两种读法：

- **采用**：相对触发点 ⇒ 比例 ∈ [0.45, 0.55] ⇒ 7 天为 [3.15d, 3.85d]；
- **不采用**：相对整个有效期 ⇒ 比例 ∈ [0.40, 0.60] ⇒ 7 天为 [2.8d, 4.2d]。

采用前者（与裁决 `[3.15 天, 3.85 天]` 一致）。**工程默认，待确认。**

---

## 4. 吊销后补发（T4，仅测试模式）

**补上 ADR-021 的"吊销是终态但没有恢复路径"缺口。**

| 项 | 内容 |
|---|---|
| 恢复语义 | 吊销是终态：恢复方式只有 **新 `node_id` + 新证书**，旧 `node_id` **永不复活** |
| 入口 | `IssueReissueToken(old_node_id, operator, reason, confirm=true)` |
| 模式 | **仅 `-mode=test` 可用**；生产模式返回 `ErrProdReissueUnimplemented`（**流程未设计**） |
| 前置 | 目标节点**必须**为 `revoked`；`confirm` 必须为 `true`；`operator` 必填 |
| 令牌 | 沿用 N6 规则：32 字节随机、只存 SHA-256、15 分钟、**单次消费**（原子 UPDATE + 影响行数） |
| 关联 | 令牌记录新增 `reissued_for_node_id`（迁移 002） |
| 注册 | 新节点获得**新** `node_id`；`node.enrolled` 审计带 `previous_node_id`；旧节点保持 `revoked` |
| 审计 | `node.reissue_token_issued`（`operator`、`old_node_id`、`reason`、`expires_at`），**不含令牌明文或哈希** |

---

## 5. 审计覆盖（T5）

节点域的**全部**状态迁移及其审计动作（`internal/nodesvc.NodeTransitions` 为单一事实来源）：

| 迁移 | 审计动作 | 是否改变节点状态 |
|---|---|---|
| 注册 | `node.enrolled` | 是（→ online） |
| online → offline | `node.offline` | 是 |
| offline → online | `node.online` | 是 |
| → revoked | `node.cert_revoked` | 是（终态） |
| 续期成功 | `node.cert_renewed` | **否** |
| 旧证书被取代 | `node.cert_superseded` | **否** |
| 补发令牌 | `node.reissue_token_issued` | **否**（旧节点保持 revoked） |
| 连续 replay 重置基线 | `node.clock_regression_reset` | **否** |
| 剩余有效期不足 48h | `node.cert_expiry_risk` | **否** |
| 续期被拒绝 | `node.renew_rejected` | **否** |
| 时钟偏差级别变化 | `node.clock_skew_warning` | **否** |
| 心跳被拒绝 | `node.heartbeat_rejected` | **否** |
| 注册被拒绝 | `node.enroll_rejected` | **否** |

`TestAuditCoverage_AllTransitions` 遍历该表，断言每种迁移至少一条审计、
"状态迁移类"恰好一条、且全部审计 `seq` 连续、总量与分项之和一致。

---

## 6. 数据库迁移（本 ADR 引入，均可回滚）

`internal/nodemigrate` 提供三条迁移，入口为 `nodesvc.EnsureSchema`（先建表、再迁移）：

| 版本 | 名称 | Up | Down |
|---|---|---|---|
| 1 | `revocations_reason_check` | 回填历史空 `reason` 为 `revoked`；加 CHECK `reason IN ('revoked','superseded')` | 删除 CHECK |
| 2 | `tokens_reissued_for_node_id` | 加列 `reissued_for_node_id` | 删列 |
| 3 | `nodes_pending_supersede_and_session` | 加列 `pending_superseded_serial`、`boot_session_id`、`session_sent_at` | 逆序删列 |

**Up 与 Down 均已由 `TestMigrationUpDownVerified` 验证**（含幂等：重复执行不报错；
`Down` 在"旧 schema 无迁移记录表"时也能正常执行）。
`reason` 列本身在第二十二轮已存在，迁移 1 只补约束与回填。

---

## 7. 与既有 ADR 的关系

| ADR | 本 ADR 的处理 |
|---|---|
| ADR-021 §1（sent_at 严格递增） | **修订**为"按会话递增 + 连续 3 次重置"（§1） |
| ADR-021 §6（证书仅内存、重启需重新注册） | **修订**为"state 目录持久化 + 复用"（§2） |
| ADR-021 §7 / ADR-020 §7（证书 7 天、吊销表） | **继续有效**；本 ADR 补充 `superseded` 语义（§3.4） |
| ADR-021 的"吊销是终态" | **继续有效**；本 ADR 补充补发路径（§4） |
| ADR-018 §4（not_executed 等计划终态） | 不涉及 |
| ADR-001 ~ ADR-020 其余条款 | **不修改** |

---

## 8. 未决事项（**不得以默认值实现**）

- **生产 CA**：来源、根信任分发、离线签名流程未定；`-mode=prod` 继续拒绝启动。
- **生产凭据存储**：state 目录的文件权限方案（0700/0600）在其上叠加
  TPM / keyring / 内存锁定即为生产形态，但**具体选型未定**。
- **生产补发流程**：审批、权限模型、令牌交付渠道均未设计（本轮仅测试模式入口）。
- **证书吊销的多控制面分发**：单控制面查表可用；多控制面需先解决分发。
- **真实身份提供商 / 真实 issuer 联调**：需提供脱敏令牌样本（须含 `exp`）。

---

> **修订说明（第二十四轮）**：本 ADR 的 §3.3（`pending_superseded_serial` 单值记录）、
> §3.5（到期提醒在心跳路径判定）、§1（连续 3 次 replay 即重置）**已被
> [ADR-023](ADR-023-证书状态机-服务端周期扫描-时钟回退重置加固与CI二进制SHA强制校验.md) 修订**；
> 本 ADR 其余条款继续有效。正文未作修改。
