# 节点证书生命周期运维手册

> **第二十四轮：本地闭环；CI 未验证。**
> 本文档与代码的一致性由测试守护（`internal/nodesvc` 的 T1–T5 用例）。
> 首次 CI 运行的预期步骤与需回收的内容见 `docs/ops/first-ci-run.md`。

适用对象：Agent Ops 节点代理（`node-agent`）与其控制面（`control-plane` 的节点域）。

---

## 1. 一页速查

| 项 | 值 | 状态 |
|---|---|---|
| 证书有效期 | **7 天** | 工程默认，**待安全团队确认** |
| 续期时机 | 有效期的 **50%**，抖动 **±10%**（相对触发点）⇒ 7 天为 **[3.15d, 3.85d]** | 工程默认，**待确认** |
| 续期失败重试 | 指数退避：**1 分钟** → 2 → 4 → … → 上限 **1 小时** | 工程默认，**待确认** |
| 到期风险告警 | 剩余 **< 48 小时**未续期 | 工程默认，**待确认** |
| 告警节流 | 每节点每 **6 小时**最多一条 | 工程默认，**待确认** |
| 心跳间隔 | **10 秒** | 裁决值 |
| 离线判定 | 连续 **3 次**（30 秒）未收到心跳 | 裁决值 |
| 时钟偏差告警 | warn **5 秒** / alert **30 秒**（只告警，不拒绝、不离线） | 工程默认，**待确认** |
| 时钟回退重置 | 同会话连续 3 次 **replay** + **严格递增** + **接收跨度 ≥20 秒** 才重置基线 | 工程默认，**待确认** |
| 证书状态机 | `issued → active → superseded`；`revoked` 为终态；`superseded` 不改节点状态 | 第二十四轮 |
| 到期扫描 | 服务端**每 5 分钟**扫描（不依赖心跳）；剩余 <48h → 告警；`issued` >24h → 信息 | 工程默认，**待确认** |
| 扫描器单实例 | **禁止多实例**（尚无 lease 协调） | 硬性约束 |
| state 目录权限 | **0700** | 硬性要求 |
| 身份文件权限 | **0600** | 硬性要求 |

---

## 2. 身份与证书的存放位置

```
<state-dir>/                 ← 权限必须 0700（-state-dir 指定）
└── identity.pem             ← 权限必须 0600
    ├── EC PRIVATE KEY       ← 节点私钥（永不离开节点）
    ├── CERTIFICATE          ← 叶证书（CN 与 SAN 均为 node_id）
    ├── CERTIFICATE          ← CA 证书
    └── # node_id: nod_...   ← 便于人工核对（**不是**信任来源，加载时以证书为准）
```

**写入是原子的**：先写 `.identity-*.tmp`（0600）→ fsync → rename 覆盖。
因此目录里**可能残留** `.identity-*.tmp`——这是正常的，下次启动会被忽略，
**不需要手工清理**。若残留文件过多影响排查，可安全删除（不影响正式身份）。

---

## 3. 启动行为（三态，fail-closed）

节点启动时按以下顺序决策：

| 情况 | 行为 |
|---|---|
| 身份文件**有效** | **复用**：不注册、不消耗令牌、`node_id` 不变 |
| 身份文件**不存在** | **注册**：消耗一次性令牌，成功后原子保存身份，并**尽力删除**令牌文件 |
| 身份文件**存在但无效** | **拒绝启动**（绝不静默重新注册） |

"无效"包含：权限不是 0600、PEM 损坏、公私钥不匹配、**已过期**、CA 不匹配、
CN/SAN 与 `node_id` 不一致。错误信息会明确指出是哪一类，**不含任何密钥材料**。

> **注意**：令牌文件缺失**不阻止**启动（复用路径不需要令牌）。
> 但令牌文件权限过宽（非 0600）会**直接拒绝启动**——这类错误说明有人在动凭据，必须人工介入。

### 3.1 常见启动失败与处置

| 错误 | 原因 | 处置 |
|---|---|---|
| `state 目录权限必须为 0700` | 人为 `chmod` 或备份还原 | `chmod 700 <state-dir>` 后重启 |
| `身份文件权限必须为 0600` | 同上 | `chmod 600 <state-dir>/identity.pem` 后重启 |
| `身份文件损坏或结构不完整` | 磁盘损坏 / 手工编辑 | 删除该文件并重新注册（需新令牌） |
| `身份证书已过期` | 未及时续期（见 §4.3） | 删除该文件并重新注册，或走 §6 补发 |
| `注册令牌文件权限必须为 0600` | 令牌文件权限过宽 | `chmod 600 <token-file>` |

---

## 4. 续期（Renew）

### 4.1 正常流程

```
注册成功 → 证书有效期 7 天
   ↓  到达有效期的 50%±10%（约第 3.15~3.85 天）
节点生成**新密钥** + CSR(PEM) → Renew RPC（走 mTLS）
   ↓  服务端 7 步校验通过
新证书签发 → **证书状态机记 issued**（含未确认上限 5）→ 审计 node.cert_renewed
   ↓  节点用 T2 的原子写入替换身份文件，后续连接使用新证书
节点用**新序列号**心跳 → 状态机确认：issued → active（写 confirmed_at），
   **同节点更早的 issued/active 全部 → superseded**（写吊销表 reason=superseded）
   → 审计 node.cert_superseded（**节点状态不变**）
```

**证书状态机**（第二十四轮；每张证书一条记录，表 `test_node_certs`）：

| 状态 | 含义 | 进入方式 |
| --- | --- | --- |
| `issued` | 已签发、未被任何心跳确认（可能仍在路上或响应丢失） | Renew 成功 |
| `active` | 已被心跳确认，是节点当前实际使用的证书 | 心跳确认该序列号 |
| `superseded` | 被更新的证书取代（只失效证书，**不改节点状态**） | 心跳确认更新证书时批量收敛 |
| `revoked` | 被人工吊销（终态，节点同置 revoked） | RevokeCert |

**未确认上限**：同一节点 `issued` 数量 > **5** 时，Renew 被拒绝
（`reason=pending_limit` 只入审计）——防止"响应连续丢失"无限堆积，也防止无限
签发不被使用的证书。状态机以"每证书一条"取代第二十三轮的单个 `pending_superseded_serial`
列（后者在第二次续期时会覆盖第一次，导致旧证书永不被收敛——**安全缺口**）。

### 4.2 为什么续期必须换钥

服务端第 6 步拒绝"CSR 公钥 == 当前证书公钥"。理由：续期是**密钥轮换**的唯一机会；
允许同钥续期等同于让一把可能已泄露的私钥无限期使用。

### 4.3 续期失败

- 节点侧**指数退避**重试：1 分钟起，每次翻倍，上限 1 小时；
- **不改变节点状态**（服务端也不因续期失败改状态）；
- 每次失败写一条 `node.renew_rejected`（内部 reason 只入审计，对外统一拒绝）；
- 日志会记录失败原因（**不含密钥材料**），可用 `node.renew_rejected` 计数告警。

### 4.4 到期前的风险告警

剩余有效期 **< 48 小时**仍未续期时：

- 服务端写 `node.cert_expiry_risk`（**每节点每 6 小时最多一条**，避免刷屏）；
- 节点侧同时记录 **ERROR** 日志。

**建议告警规则**：`node.cert_expiry_risk` 出现即告警（说明续期已经出问题，
距失联最长还有 48 小时）。

---

## 5. 证书被取代（superseded）与吊销（revoked）的区别

| | `superseded` | `revoked` |
|---|---|---|
| 触发 | 续期后，服务端收到**新序列号**心跳 | 人工吊销（`RevokeCert`，仅测试模式） |
| 含义 | 旧证书**被新证书取代** | 节点身份**被撤销** |
| 被吊销的对象 | 旧证书（旧序列号） | 当前证书 |
| **节点状态** | **不变**（继续 online/offline） | 变为 `revoked`（**终态**） |
| 节点还能工作吗 | **能**（用新证书） | **不能**（心跳与续期都被拒） |
| 恢复方式 | 无需恢复 | 只有 **新 `node_id` + 新证书**（§6） |

**运维要点**：`superseded` 是**正常**现象（每次成功续期都会产生一条），
不需要任何动作；`revoked` 才需要人工介入。

**孤儿证书不需要人工处理**（第二十四轮裁决）：节点确认某个序列号后，同节点
更早签发且未确认的证书会被**一并 supersede**。证书生命周期最长 7 天，孤儿
自然过期——**不做人工对账**。

---

## 6. 吊销后补发（恢复路径）

吊销是**终态**：旧 `node_id` **永不复活**。恢复方式只有**新身份**。

### 6.1 流程

```
1. 确认节点状态为 revoked（其他状态不允许补发）
2. 调用 IssueReissueToken(old_node_id, operator, reason, confirm=true)
   → 仅 -mode=test 可用；返回**一次性令牌明文**（只在此刻可见）
   → 审计 node.reissue_token_issued（operator / old_node_id / reason）
3. 在目标机器上部署令牌文件（权限 0600）并设置 NODE_ENROLL_TOKEN_FILE
4. 启动节点 → 注册成功 → 获得**新 node_id**
   → 审计 node.enrolled 带 previous_node_id（指向旧节点）
5. 旧节点保持 revoked（不会被复活）
```

### 6.2 生产模式

**生产模式的补发流程未设计**：调用返回 `ErrProdReissueUnimplemented`，
`-mode=prod` 也**整体拒绝启动**（生产 CA 未定）。生产补发需要先确定：
审批链、操作者权限模型、令牌交付渠道（不得出现在日志/工单正文/IM 明文）。

---

## 7. 时钟回退（D6）

### 7.1 现象与修复

节点系统时钟回拨后，`sent_at` 会小于上一次的值，旧规则（ADR-021）会把它判为
`replay` 并**永久拒绝**，节点在时钟追平前**一直离线**。

D6 的修复：

- 防重放基线按 **(node_id, boot_session_id)** 维护（会话 = 节点进程启动一次）；
- **新会话**（节点重启）的首个心跳**不与旧会话比较**；
- 同会话内基线**重置**（到当前 `sent_at` 并接受）必须**同时满足三条件**（第二十四轮加固）：
  ① 连续 **3 次** replay；
  ② 这 3 个被拒的 `sent_at` **严格递增**（是一条正在前进的新时钟，而非随机低值）；
  ③ 这几次的**接收时间跨度 ≥ 20 秒**。
  满足后写 `node.clock_regression_reset` 审计。

> **为什么加固**：旧规则"连续 3 次即重置"条件过宽——攻击者或一次短时抖动能用
> 3 个随机低值触发重置，使 replay 检测在 3 个心跳窗口内失效。三条件把重置
> 限定为**确凿的时钟回拨**形态。注意：`sent_at` 防重放只是**纵深防御**
> （mTLS 已绑定会话，攻击者无法伪造合法会话的 sent_at）；它对抗的是
> "证书半途失窃、尚未被吊销"的极短窗口。

### 7.2 运维要点

- **重启节点**是最快的恢复手段（新会话直接切换基线）；
- 不重启也能自愈：连续 3 次心跳后自动重置（约 30 秒）；
- `node.clock_regression_reset` 出现 ⇒ **该节点时钟有问题**，应检查 NTP；
- 时钟偏差（skew）**只告警不拒绝**：warn > 5 秒、alert > 30 秒。
  `node.clock_skew_warning` 频繁出现说明节点时钟漂移严重。

---

## 8. 监控项与建议告警

| 审计动作 | 建议告警条件 | 说明 |
|---|---|---|
| `node.offline` | 立即告警 | 节点掉线 |
| `node.cert_revoked` | 立即告警 | 身份被撤销，需人工介入（§6） |
| `node.cert_expiry_risk` | 立即告警 | 距失联最长 48 小时（服务端周期扫描，不依赖心跳） |
| `node.cert_unconfirmed` | 通知（信息级） | 续期后 24 小时未被确认（响应可能丢失） |
| `node.renew_rejected` | 5 分钟内 ≥ 3 条 | 续期持续失败 |
| `node.clock_regression_reset` | 告警 | 节点时钟回退（需查 NTP） |
| `node.clock_skew_warning` | alert 级别出现即告警 | 时钟漂移 > 30 秒 |
| `node.cert_renewed` | 不告警 | 正常续期（每日每节点约 0～1 条） |
| `node.cert_superseded` | 不告警 | 续期的正常副产物 |
| `node.reissue_token_issued` | 通知（非告警） | 有人执行了补发，运维应知晓 |
| `node.heartbeat_rejected` | 突增时告警 | 可能为攻击或节点异常 |
| `node.enroll_rejected` | 突增时告警 | 可能为令牌猜测攻击 |

**需要同步更新的看板项**：

1. 证书**剩余有效期**分布（按节点），标出 < 48 小时的节点；
2. 续期**成功率**与**失败率**（`cert_renewed` vs `renew_rejected`）；
3. `superseded` 与 `revoked` **分列**（两者语义完全不同，合并会误判）；
4. 时钟偏差分布（按节点，标出 alert 级别）；
5. 审计 `seq` 连续性检查（缺口即审计链断裂）。

---

## 9. 处置速查

| 症状 | 处置 |
|---|---|
| 节点拒绝启动，提示权限 | 按 §3.1 修正权限（0700 / 0600） |
| 节点拒绝启动，提示已过期 | 删除身份文件 → 重新注册；若节点已 revoked 则走 §6 补发 |
| 证书即将到期（> 48h） | 通常无需动作（会自动续期）；持续观察 `renew_rejected` |
| 证书剩余 < 48h 且未续期 | 检查网络/控制面可用性；必要时人工重启节点触发续期 |
| 节点长期 offline | 检查节点进程、网络、`heartbeat_rejected` 计数 |
| 出现 `clock_regression_reset` | 检查该节点 NTP；确认是否发生时钟回拨 |
| 节点被误吊销 | 走 §6 补发（新身份）；旧 `node_id` 不可恢复 |
| 需要主动吊销节点 | 本轮**仅测试模式**提供入口；生产吊销流程待运维确认 |

---

## 10. 未完成项（上线前门禁）

- **生产 CA 未定** ⇒ `-mode=prod` 拒绝启动；
- **生产凭据存储未定**（TPM / keyring / 内存锁定选型）；
- **生产补发流程未定**（审批、权限、令牌交付）；
- **多控制面的吊销分发未定**（当前为单控制面查表）；
- **扫描器多实例 lease 协调未实现**：**多实例部署前必须先实现**（当前单实例是硬性约束）；
- **CI 的 kubectl/go linux/amd64 SHA-256 已回填**（2026-10-13 取自官方校验文件；
  实现侧已独立复核实测哈希，见 [ADR-023 §8](../adr/ADR-023-证书状态机-服务端周期扫描-时钟回退重置加固与CI二进制SHA强制校验.md)），
  `TestCI2_ToolingHasNoPendingSHAForCIBinaries` 的合并阻断条件已解除；
  仍留**人工复核**待办（§11 的命令）；
- **CI 首次运行未执行**（`make residual-check` / `gen-check` / `test` 尚未在 GitHub 上跑过）。

---

## 11. CI 侧外部二进制校验方式（第二十四轮 R4/T5）

流水线里**任何**下载外部二进制的步骤，都必须在使用前完成逐字节校验；校验值来自
`docs/tooling.md` 的登记表，而不是记忆或镜像站。

| 二进制 | 获取方式 | 校验方式 | 失败后果 |
| --- | --- | --- | --- |
| kubectl（linux/amd64） | `curl -fsSLo /tmp/kubectl https://dl.k8s.io/release/<ver>/bin/linux/amd64/kubectl` | 从 `docs/tooling.md` 平台相关条目表提取该行的 SHA-256，执行 `echo "<sha>  /tmp/kubectl" \| sha256sum -c -` | 提取为空或含"待人工提供"占位 → 脚本 `exit 1`；哈希不符 → `sha256sum -c` 非零退出。两者都**中止 test job**（fail-closed） |
| Go 工具链（linux/amd64） | `actions/setup-go`（按官方 `go.dev/dl` 清单下载） | setup-go 自身按官方清单校验校验和；登记表另存官方 `.sha256` 值供人工比对 | 校验不过则 setup-go 步骤失败 |
| kind / buf | `go install` / `go run`（Go module proxy，非二进制下载） | Go 校验和数据库（`go.sum` / sum.golang.org） | 校验和不匹配即构建失败 |

守卫（三条，`internal/repoguard/ci_sha_test.go`）：

- `TestCI1_EveryBinaryDownloadVerifiesSHA`：解析 `ci.yml`，每个 HTTP 下载步骤之后必须紧跟 `sha256sum -c`；
- `TestCI2_ToolingHasNoPendingSHAForCIBinaries`：CI 用到的二进制不得留"待回填"占位；
- `TestCI3_ToolingDocFormat`：登记条目必须齐五字段（名称/版本/平台/SHA-256/来源 URL）。

人工复核命令（与实现侧无关，任何人都可自行验证）：

```sh
# kubectl linux/amd64（应输出与 tooling.md 一致的单行哈希）
curl -fsS https://dl.k8s.io/release/v1.31.4/bin/linux/amd64/kubectl.sha256
# go 1.27.2 linux/amd64（官方发布站）
curl -fsS https://dl.google.com/go/go1.27.2.linux-amd64.tar.gz.sha256
# 或直接对产物求哈希（应与上面两个值一致）
curl -fsSL https://dl.k8s.io/release/v1.31.4/bin/linux/amd64/kubectl | shasum -a 256
curl -fsSL https://go.dev/dl/go1.27.2.linux-amd64.tar.gz          | shasum -a 256
```

> **第三方 Action 已钉到 commit SHA**（`actions/checkout@11d5960a…` # v4、
> `actions/setup-go@40f1582b…` # v5）。升级 tag 时必须重新用官方 API 解析
> `git/ref/tags/<tag>` 的 `object.sha` 并同步 `ci.yml` 顶部注释（复核记录见 ADR-023 §8）。
