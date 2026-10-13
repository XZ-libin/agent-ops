# ADR-021：心跳以接收时间为准、控制面唯一分配身份、证书 7 天 + 吊销表、引导信任与 ULID 库替换；开发与 CI 门禁解耦

- 状态：已接受
- 日期：2026-10-13
- 轮次：第二十二轮（D1–D5 修正 + N6–N8 补齐）
- 关系：**不修改 ADR-001 ~ ADR-019 的正文**；本 ADR **取代 ADR-020 的下列条款**（见 §7）；
  在 ADR-020 末尾追加一行指向本 ADR 的说明。

---

## 1. D1 心跳：以**接收时间**判定存活，`sent_at` 只用于防重放

**取代 ADR-020 §5 的"注册时刻锚点"。**

| 项 | 旧（ADR-020） | 新（本 ADR） |
|---|---|---|
| 存活判定依据 | 节点自报 `sent_at`（并锚定注册时刻） | **控制面 `received_at`** |
| `sent_at` 作用 | 兼作存活与顺序依据 | **只用于防重放**（严格递增） |
| 首个心跳 | `sent_at` 早于注册时刻 → 被拒 | **接受**（锚点已删除） |

- 同一节点内，`sent_at` 必须**严格大于**上一次被接受的 `sent_at`：
  - 小于 → 拒绝，`reason=replay`；
  - 等于 → 拒绝，`reason=duplicate`；
  - **拒绝时不刷新任何状态**（`last_received_at`、`last_sent_at`、`status` 均不变）。
- 时钟偏差 `skew = received_at − sent_at`：
  - `> warn`（**默认 5 秒**）→ 记录并写一条 `node.clock_skew_warning`；
  - `> alert`（**默认 30 秒**）→ 同样只告警；
  - **只记录和告警，不拒绝、不离线**；同一偏差级别只写一次（级别变化才写，避免刷屏）。
- **工程默认值，待运维确认**：5 秒 / 30 秒。

## 2. D2 身份：`node_id` **只由控制面分配**

**取代 ADR-020 §3 的"CSR 一致性与 declared_node_id"。**

- `node_id` 只在 `Enroll` 成功时由控制面分配，格式 `nod_<ULID>`。
- CSR 仅用于**证明私钥持有**（proof of possession）：
  - 签名必须有效；
  - **不得包含 CN、任何 SAN（DNS/IP/URI/Email）或任何扩展字段**，否则拒绝；
  - 对外**统一返回 `INVALID_ARGUMENT`，不说明具体是哪个字段**。
- `EnrollRequest.declared_node_id` → **`display_label`**（字段语义变更，编号不变 = 3）：
  降级为**展示标签**，**不参与身份与任何校验**；修改它不影响 `node_id`，也不影响证书内容。
- 签发证书的 **CN 与 SAN 都由控制面写入分配的 `node_id`**。

### contract diff（`proto/agent_ops/contract/v1/node.proto`）

| 位置 | 变更 |
|---|---|
| `EnrollRequest.display_label`（field 3） | 由 `declared_node_id` **改名 + 语义降级**（展示标签，不参与校验） |
| `EnrollRequest.csr_der`（field 2） | 注释明确：**纯持有性证明**，不得含 CN/SAN/扩展 |
| `EnrollResponse.node_id`（field 1） | 注释明确：**唯一**身份来源，节点不能自报 |
| `enum NodeStatus` | 新增 `NODE_STATUS_REVOKED = 3`（D3 吊销终态） |

字段编号未变 → **线格式兼容**；语义变更需两侧同步发版。

## 3. D3 证书：有效期 **7 天** + 吊销表

**取代 ADR-020 §7 的"30 天有效期、不实现吊销"。**

- 证书有效期**默认 7 天**（`nodeidentity.DefaultCertValidity`），由 **`CAConfig.Validity` 配置项指定**，
  **不得在签发路径硬编码**。**工程默认值，待安全团队确认。**
- 控制面维护吊销表 `test_cert_revocations(serial PK, node_id, revoked_at, reason)`。
- **每次 mTLS 连接（gRPC 一元拦截器）与每次心跳都检查证书 `serial`**：吊销后即使证书仍在有效期内也必须拒绝。
- 节点被吊销后 `test_nodes.status = revoked`；**`revoked` 不可恢复为 `online`**，只能重新注册并获得**新的 `node_id`**。
- 吊销入口本轮**只在测试模式提供**（内部函数 `nodesvc.RevokeCert` + 测试调用）。
  审计 `node.cert_revoked` 的 payload 含 `serial` 与 `node_id`，**不含证书 PEM**。
- **不实现 CRL / OCSP**：单控制面部署下，查表比 CRL/OCSP 简单且足够；**TODO：证书吊销在多控制面下的分发**。
- **Renew 不在本轮**（第二十三轮）：7 天内不续期则节点全部失联，**这是生产前的硬门禁**。

## 4. D4 引导信任：节点必须校验**服务端**证书

补上 ADR-020 的缺口（此前只规定了控制面校验节点，未规定节点校验控制面）。

- 控制面 gRPC 服务端证书由**同一测试 CA** 签发，SAN = `127.0.0.1` 与 `localhost`。
- 节点配置**必须**包含：CA 包（`-ca-file`，只信任它，**不信任系统根证书**）与期望的服务端名称（`-server-name`）。
- **注册令牌只有在服务端证书校验通过之后才发送**：`Dial` 强制完成 TLS 握手（等待连接 `READY`），
  握手失败即返回错误，此时令牌尚未离开本进程。
- 测试断言：冒充的服务端（其他 CA 签发 / 名称不匹配）**收到的注册请求数为 0**。
- 仓库级 **AST 守卫**：`node-agent` 中不得出现 `InsecureSkipVerify`、`grpc.WithInsecure`、
  `insecure.NewCredentials`、自定义 `VerifyPeerCertificate` 绕过链校验。

## 5. D5 `node_id` 生成：改用 `github.com/oklog/ulid/v2`

- **替换自实现 ULID**（自研标识符编码位序易错，不值得自研）。
- 固定版本：`github.com/oklog/ulid/v2 v2.1.2`（写入 `go.mod` 与 `docs/tooling.md` 依赖清单）。
- 保留既有测试向量，并补充**拒绝用例**：非法字符（I/L/O/U）、长度错误、缺少 `nod_` 前缀、大小写混合。
- 规范：ULID 主体必须为**大写** Crockford Base32（拒绝小写与混合写法，避免同一身份多种写法）。

## 6. N6 持久化与审计（本轮补齐）

- 三张 test 表（仅存在于 `test_run_*` schema）：
  `test_nodes`、`test_enroll_tokens`、`test_cert_revocations`。
- **令牌消费必须原子**：
  ```sql
  UPDATE test_enroll_tokens SET used_at=$now, used_by_node_id=$id
   WHERE token_hash=$h AND used_at IS NULL AND expires_at > $now
  ```
  检查影响行数；**禁止先查后写**。并发 10 个 `Enroll` → **恰好 1 个成功**。
- 审计动作：`node.enrolled`、`node.online`、`node.offline`、`node.clock_skew_warning`、
  `node.cert_revoked`、`node.enroll_rejected`、`node.heartbeat_rejected`。
  - actor：节点事件 = `node:<node_id>`；**拒绝事件 = `system`**。
  - payload **禁止**出现：令牌明文、令牌哈希、CSR PEM、证书 PEM、私钥（测试用正则扫描）。
- 控制面重启后从 PG 恢复节点状态与令牌已用状态。

## 7. 本 ADR **取代** ADR-020 的条款

| ADR-020 条款 | 处理 |
|---|---|
| §3 注册与身份（CSR 一致性校验、`declared_node_id` 参与校验） | **被 §2 取代** |
| §5 心跳锚点（以 `sent_at` + 注册时刻锚点判定存活） | **被 §1 取代** |
| §7 证书有效期 30 天、不实现吊销 | **被 §3 取代**（7 天 + 吊销表） |
| §1 CI 残留门禁修订（取消独立 job，合并进 `test` job） | **继续有效**（ADR-020 原文不改） |
| §2 gRPC 选型、§4 契约边界、§6 测试 CA 仅内存、§8 心跳 unary、§9 审计约定、§10 降级范围 | **继续有效** |

ADR-020 正文不改，仅在其末尾追加一行指向本 ADR。

## 8. 规则变更：**开发与 CI 门禁解耦**

- 旧规则："CI 不过就不能继续写下一轮"——这会让项目无限期停在推送代码之前。
- **新规则**：**开发可以继续；合并到主干前 CI 必须全绿**（由人工在 GitHub 确认）。
- 报告中的"通过"一律标注 **"本地通过，CI 未验证"**。
- 本变更**不放宽任何安全要求**，只改变门禁的**位置**：从"进入下一轮之前"移到"合并之前"。

## 9. 影响与风险

- `exp`/证书有效期收紧、`revoked` 不可恢复、`display_label` 语义变更——**下游（监控、运维流程）需同步**。
- 7 天有效期 + 无 Renew ⇒ **生产上线前必须完成 Renew**（第二十三轮）。
- 吊销表是单点：多控制面部署需先解决吊销分发。

## 10. 附：本轮范围与验证状态

- 范围：**D1–D5 修正 + N6–N8 补齐**（N8 为真实 gRPC mTLS + 真实 PG 的集成测试，未使用替身）。
- 第二十三轮：Renew 与证书持久化。
- **验证状态：全部结论为"本地通过，CI 未验证"**（CI 首次运行结果尚未提供）。

---

> **修订说明（第二十三轮）**：本 ADR 的 §1（`sent_at` 严格递增的防重放）、
> §6（证书仅存内存、重启需重新注册）**已被
> [ADR-022](ADR-022-时钟回退会话基线-证书续期协议-superseded延迟吊销-持久化与补发.md) 修订**；
> 本 ADR §7 的"吊销是终态"继续有效，缺口的恢复路径（补发）由 ADR-022 §4 补充。
> 正文未作修改。
