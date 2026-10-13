# ADR-023：证书状态机、服务端周期扫描、时钟回退重置加固与 CI 二进制 SHA 强制校验

- 状态：已接受
- 日期：2026-10-13
- 轮次：第二十四轮（闭环轮：只修已知缺口，不新增功能）
- 关系：**不修改 ADR-001 ~ ADR-022 的正文**；ADR-022 末尾追加一行指向本 ADR。

> **第二十四轮：本地闭环；CI 已由 run 1–3 验证（2026-10-13 全部 success）。**
> 本行在第二十四/二十五轮期间写作"CI 未验证"——那是**推送之前**的状态，当时不得声称通过。
> 提交 `8e5f45d`/`03130ec`/`626ab5b` 推送后，GitHub Actions 三次运行
> `gen-check / build / test` 均 `completed/success`，且残留门禁步骤原文为
> `residual-check: OK (no leftovers)`（`--- PASS: TestNoLeftoversAfterSuite`，**不是 SKIP**）。
> 逐步骤证据见 `docs/ops/first-ci-run.md` §1A。

---

## 1. 缺口 1：证书状态机（每证书一条状态记录）

### 1.1 问题

第二十三轮用 `test_nodes.pending_superseded_serial`（**单个**字符串列）记录
"续期后待确认的旧证书"。第二次续期会**覆盖**第一次，于是**第一份旧证书永远不会
被 supersede**——它在 7 天有效期内持续有效。这是**安全缺口**（多份可用的未撤销证书）。

### 1.2 决定：`test_node_certs` 状态机

新增表（迁移 004，可回滚）：

| 列 | 含义 |
| --- | --- |
| `serial`（PK） | 证书序列号（`SerialNumber.String()`） |
| `node_id` | 所属节点 |
| `state` | `issued` / `active` / `superseded` / `revoked`（CHECK 约束） |
| `issued_at` | 签发时刻（"更早的证书"判定依据） |
| `not_after` | 到期时刻 |
| `confirmed_at` | 被心跳确认的时刻（仅 active） |

**迁移**：从 `test_nodes.cert_serial` 回填为 `active`；旧列保留、**停止写入**；
`down` 删表（可回滚）。

### 1.3 状态迁移规则

| 触发 | 规则 |
| --- | --- |
| Renew 成功 | 新序列号 → `issued`（**计入未确认上限**） |
| 心跳携带 S 为 `issued` | S → `active` + 写 `confirmed_at`；**同节点 `issued_at` 早于 S 的**所有 `issued`/`active` 证书 → `superseded`（写吊销表 `reason=superseded`） |
| 心跳携带 S 已 `active` | 无变化 |
| 心跳携带 S 为 `superseded` / `revoked` | **拒绝**（PermissionDenied），不改变任何状态 |

- **孤儿收敛**（裁决决定）：节点确认序列号 S 后，同节点更早签发且未确认的证书
  **一并 supersede**。证书生命周期最长 7 天，孤儿自然过期，**不需要人工对账**。
- **未确认上限**：同一节点 `issued` 数量 > 5（**工程默认，待确认**）时 Renew 拒绝，
  `reason=pending_limit`（只入审计）；同一事务内 count+insert 防止并发绕过。
- **状态分离**：证书状态与节点状态（online/offline/revoked）**完全独立**，
  `supersede` **不改变**节点状态（否则会把健康节点误打成 revoked 终态）。

### 1.4 为什么"心跳携带 superseded 先拒绝、后再按吊销表区分"

心跳的吊销表检查会把 superseded 也命中（superseded 的行在吊销表中）；但两者的
**运维处置不同**：

- `revoked`：节点身份被撤销 → 终止节点（置 revoked，不可恢复）；
- `superseded`：只是证书被取代 → **绝不**终止节点，仅拒绝该证书继续使用。

因此状态机先于吊销表判定，用 `ErrCertSuperseded`（不改节点状态）与
`ErrCertRevoked`（终止节点）区分。

---

## 2. 缺口 2：服务端周期扫描（到期提醒不再依赖心跳）

### 2.1 问题

第二十三轮的到期提醒只在**心跳到达时**判定。续期失败的节点恰恰是沉默的
（心跳不再到达），于是提醒**永远不会触发**，直到证书过期、节点彻底失联。

### 2.2 决定：`internal/nodesweep` 周期扫描器

| 项 | 值 | 状态 |
| --- | --- | --- |
| 扫描周期 | 默认 **5 分钟** | 工程默认，待确认 |
| 到期阈值 | active 证书剩余 **< 48 小时** | 工程默认，待确认 |
| 告警节流 | 同一节点每 **6 小时**最多一条 | 工程默认，待确认 |
| 未确认阈值 | `issued` 超过 **24 小时**未确认 → `node.cert_unconfirmed`（信息级） | 工程默认，待确认 |
| 附加条件 | 到期告警要求"自上次成功续期以来**没有新签发**"（有更新的证书 ⇒ 续期进行中，不告警） | — |

- **节流状态持久化**（`test_node_sweep_state`，迁移 005）：跨控制面重启有效。
- 扫描器**只写审计**，**不改变**节点状态、**不改变**证书状态（纯观察者）。
- 扫描器用**注入时钟 + tick**驱动，测试**禁止 sleep**。
- **单实例约束**：本实现无 lease 协调。多实例会把非节流事件（如
  `node.cert_unconfirmed`）重复写审计。**多实例部署前必须先实现 lease 协调**
  （代码注释与运行手册均已注明；本轮不实现，硬性约束 15）。

---

## 3. 缺口 3：时钟回退重置条件加固

### 3.1 问题

第二十三轮"D6"的规则是"同一会话内连续 3 次 replay 即重置基线"——条件过宽。
攻击者（或一次短时抖动）能用 3 个**随机低值**触发重置，使 replay 检测在
3 个心跳窗口内失效。

### 3.2 威胁分析（本 ADR 专节）

**sent_at 防重放的定位是"纵深防御"，不是第一道防线。**

真实的安全边界是三件套：

1. **mTLS 会话绑定**：节点持有 CA 签发的证书，服务端只接受该证书对应的连接；
   攻击者**无法伪造**一个合法会话的 `sent_at`——它要么没有证书（连接被拒），
   要么必须偷到证书（此时它能发一切有效心跳，重放攻击的额外收益为零）。
2. **吊销/状态机**：证书可被 superseded/revoked，偷到的证书会被迅速失效。
3. **sent_at 防重放**：在上述两者之间作为**纵深防御**，主要对抗"证书在半途失窃、
   尚未被吊销"的极短窗口——它阻止攻击者用**旧包重放**来搅乱存活判定。

**因此**，重置基线的成本（让 replay 检测短暂失效）必须**显著低于**永久失联的成本
（节点时钟回拨后一直 offline）。加固后的三条件把"重置"限定为**确凿的时钟回拨**形态。

### 3.3 决定：重置必须同时满足三条件

| # | 条件 | 值 | 状态 |
| --- | --- | --- | --- |
| ① | 连续 replay 次数 | ≥ 3 次 | 工程默认，待确认 |
| ② | 被拒的 `sent_at` 之间**严格递增** | 必须（一条正在前进的新时钟，而非随机低值） | — |
| ③ | 这几次的**接收时间跨度** | **≥ 20 秒**（默认） | 工程默认，待确认 |

**清晰化**：

- `duplicate` **不计入**连续 replay 计数（与基线相同不是"前进"）；
- **任一被接受的心跳**清零计数与候选序列；
- 历史"连续 3 次即重置"的语义作废，由本三条件取代。

**为什么是 20 秒**：约 2 个心跳周期。足以排除"一次网络抖动里连发 3 个伪造低值"
的廉价攻击，同时远小于节点时钟追平所需的时间（`sent_at` 重新超过旧基线通常需要
数分钟）。

---

## 4. 缺口 4：CI 外部二进制 SHA-256 强制校验

### 4.1 问题

`docs/tooling.md` 中 kubectl 与 Go 的 **linux/amd64** SHA-256 仍是"待回填"；
CI 若在未校验的情况下下载，就违反了**硬性约束 6**（外部二进制必须登记 SHA-256
后才能使用）。

### 4.2 决定

1. **`ci.yml` 的每个下载步骤必须在使用前 `sha256sum -c`**（或等价逐字节比对）；
   校验值来自 `docs/tooling.md`（**实现者不得自行填写**，只能由人工从官方校验文件确认）。
2. 守卫测试：
   - `TestCI1_EveryBinaryDownloadVerifiesSHA`：解析 `ci.yml`，断言 HTTP 下载步骤
     之后紧跟 `sha256sum -c`；
   - `TestCI2_ToolingHasNoPendingSHAForCIBinaries`：`docs/tooling.md` 中 CI 使用的
     二进制**不得为"待回填"**。**在用户回填之前该测试会失败——这是预期的合并阻断，
     不得放宽**；
   - `TestCI3_ToolingDocFormat`：登记项必须含**五字段**（名称 / 版本 / 平台 /
     SHA-256 / 来源 URL）。
3. `go` 由 `setup-go` 下载，其等价校验是**官方清单比对**（不适用 `sha256sum -c`），
   但 **TestCI2 仍要求它登记具体 SHA**（不得待回填）。
4. 本轮**不要求**把 actions 钉到 commit SHA（由用户完成）；报告列出所有 `uses:`
   引用形式：`actions/checkout@v4` ×3、`actions/setup-go@v5` ×3。
5. 不添加 `continue-on-error`，不移除/跳过校验步骤。

---

## 5. 与既有 ADR 的关系

| ADR | 本 ADR 的处理 |
| --- | --- |
| ADR-022 §3.3（`pending_superseded_serial` 单值） | **被 §1 取代**（证书状态机） |
| ADR-022 §3.5（到期提醒在心跳路径判定） | **被 §2 取代**（服务端周期扫描） |
| ADR-022 §1（连续 3 次 replay 即重置） | **被 §3 取代**（三条件加固） |
| ADR-021 §1（sent_at 严格递增防重放） | 语义保留，**叠加** §3 的加固条件 |
| ADR-020 §1（CI 残留门禁合并 test job） | 继续有效 |
| 第十四轮 H5（测试失败时**保留** run schema 供排查） | **被 §7 取代**（失败也删除，现场证据转日志） |
| 其余 ADR | 不修改 |

## 6. 未决事项（**不得以默认值实现**）

- **生产 CA**：来源、根信任分发、离线签名流程未定；`-mode=prod` 继续拒绝启动。
- **生产补发流程**：审批、权限、令牌交付未设计（本轮仍未实现）。
- **扫描器多实例 lease 协调**：未实现（单实例约束在手册中注明）。
- **CI 二进制 SHA 复核**：kubectl / go 的 linux/amd64 值已回填（`docs/tooling.md`
  平台相关条目表，2026-10-13 取自官方校验文件）；实现侧已独立复核实测哈希一致，
  仍建议人工按 `curl -fsS https://dl.k8s.io/release/v1.31.4/bin/linux/amd64/kubectl.sha256`
  复核一次（§8）。
- **darwin/arm64 登记值**：第二十四轮发现 `docs/tooling.md` 第 15、64 行登记的 kubectl
  darwin/arm64 SHA-256 与官方校验文件在第 27 位相差一个字符（登记 `…c370728a…`，
  官方 `…c371728a…`）→ **第二十五轮 T1 已修正**（官方 `.sha256` + 56,560,802 字节
  产物实测双重取值，见 §9.1）。
- **本机 kubectl 与登记版本不同**：PATH 上的 kubectl 是 Docker Desktop 自带的
  **v1.36.1**，登记的却是 v1.31.4 本机实测值。→ **第二十五轮 T2 已处置**：
  测试经 `internal/toolpin` 钉定登记版本，版本不符即失败、不静默退回（见 §9.2）。
  **遗留待确认**：`.tools/kubectl` 是否作为团队约定路径固化（它被 gitignore，
  新环境需自行放置或设 `AGENT_OPS_KUBECTL_BIN`）。
- **真实 issuer 联调**：需脱敏令牌样本（须含 `exp`）。

## 7. 测试 run schema 清理策略修订（R1c / R1d）

**原策略**（第十四轮 H5）：测试通过才删除 `test_run_*` schema，失败时保留供排查。

**矛盾**：`make residual-check` 断言 `test_run_*` schema 数量为 0。两条规则互斥——
**只要有一个用例失败，残留门禁必然失败**，于是"门禁是否通过"这一信号被测试失败
本身污染（第二十四轮 R0 实测：68 个残留 schema 全部来自失败用例的保留分支，
`runschema.go` 旧 `t.Cleanup` 的 `if t.Failed() { return }`）。

**修订**：通过/失败**都删除** schema；清理收敛为唯一入口
`testdb.CleanupRunSchema(ctx, baseDSN, name, failed, logf)`，删除前仍强制
`ValidateSchemaName`（非 `test_run_` 前缀一律拒绝，public 不可触碰）。
失败现场的证据形式由"数据库里的 schema"改为"测试日志里的 schema 名 + 断言输出"
——日志本来就在 `round24-*.log` 里，可归档、可比对，且不污染下一次运行的门禁。

**自证**：`TestCleanupRunsOnFailure`（`internal/testdb/cleanup_test.go`）真实创建
schema 后以 `failed=true` 调用清理入口，断言 schema 消失；并断言 `public`、
`information_schema`、`test_approvals`、`test_run_`、空名一律被拒绝。

## 8. 外部二进制与 Action 引用复核记录（第二十四轮 R0/R4）

| 项 | 登记值 | 独立复核方法与结果 | 判定 |
| --- | --- | --- | --- |
| kubectl v1.31.4 **linux/amd64** | `298e19e9…5620f` | ① 官方 `kubectl.sha256` 文本一致；② 本机下载该产物 56,381,592 字节，`shasum -a 256` = `298e19e9…5620f` | **一致** |
| go 1.27.2 **linux/amd64** | `ecbadb99…45fe5` | ① `https://dl.google.com/go/go1.27.2.linux-amd64.tar.gz.sha256` 一致；② 本机从 `go.dev/dl` 下载 70,590,635 字节（与登记 size 相同），实测哈希一致 | **一致** |
| `actions/checkout@11d5960a…` | 钉到 commit | `https://api.github.com/repos/actions/checkout/git/ref/tags/v4` → `object.sha = 11d5960a326750d5838078e36cf38b85af677262` | **与 v4 当前指向一致** |
| `actions/setup-go@40f1582b…` | 钉到 commit | `…/repos/actions/setup-go/git/ref/tags/v5` → `object.sha = 40f1582b2485089dde7abd97c1529aa768e1baff` | **与 v5 当前指向一致** |
| kubectl v1.31.4 **darwin/arm64** | `a756bb91…c370728a…` | 官方 `…/darwin/arm64/kubectl.sha256` = `…c371728a…`（第 27 位差一个字符） | **不一致，待人工裁决** |
| 本机 PATH kubectl | 登记 v1.31.4 实测 | 实际为 v1.36.1（Docker Desktop），哈希 `9ea693e3…` | **版本口径不一致，待人工裁决** |

> **note**：钉 Action 与回填 linux/amd64 SHA 在 `R0` 快照（20:21）之后由会话外写入
> （`ci.yml`、`docs/tooling.md` mtime 20:27）。本轮实现者未编辑这两个文件，
> 上表是对这两处改动的**独立复核**结论，而非对本轮改动的自我声明。

## 9. 第二十五轮补充（T1 登记值修正 / T2 工具版本钉定 / T3 本地保留开关）

### 9.1 T1：darwin/arm64 kubectl 登记值修正

`docs/tooling.md` 第 15、64 行登记的 kubectl v1.31.4 darwin/arm64 SHA 第 27 位写成 `0`
（`…c370728a…`），官方为 `1`（`…c371728a…`）。修正依据（两条互相独立，同日取值）：

- 官方校验文件：`https://dl.k8s.io/release/v1.31.4/bin/darwin/arm64/kubectl.sha256`；
- 产物实测：下载同 URL 二进制 **56,560,802 字节**，`shasum -a 256` 与官方值逐字符一致。

判定为**转写错误**而非上游重签名。CI 不消费 darwin 条目，故此前不影响流水线。
linux/amd64 的 kubectl（56,381,592 字节）与 Go（70,590,635 字节）按同一方法再核一次，
均与登记一致，**未回退为"待回填"**。

### 9.2 T2：测试外部工具版本钉定（新增 `internal/toolpin`）

**问题**：`internal/k8stest` 与 `adapters/kubernetes` 以"优先 PATH"定位 kubectl，
而本机 PATH 是 Docker Desktop 的 **v1.36.1**，登记（且 CI 安装）的是 **v1.31.4**——
受保护产物与被测试执行的二进制不是同一个。

**决定**：kubectl 一律经 `toolpin.PinnedKubectl()` 解析。期望版本取自 `docs/tooling.md`
的平台行（按 `GOOS/GOARCH`）；候选顺序 `AGENT_OPS_KUBECTL_BIN` → 仓库 `.tools/kubectl` → PATH；
候选存在后必须验证 `version --client` 的 `gitVersion` 等于登记值——
**版本不符即失败且不顺延到下一个候选**，只有"该来源不存在/不可执行"才继续下一个来源；
全部不可用则报错并给出修复方式。`nodemigrate` 校验、`TestCI1/CI2/CI3` 等既有守卫一律未放宽。

- `.tools/` 已加入 `.gitignore`：仓库不存二进制；CI 上没有 `.tools/kubectl`，
  因此走 PATH，而 CI 的 PATH 里是 `sha256sum -c` 校验过的 v1.31.4，语义一致。
- kind 未纳入闸门（本机 v0.30.0 与登记一致，无漂移）。
- 新守卫 `TestToolVersionMatchesRegistered`（`internal/repoguard`）：比对 `ci.yml` 的
  `GO/KUBECTL/BUF/KIND_VERSION` 与登记表版本，**只读文件、不执行任何二进制**。
- 证据：`env -i` 最小环境预演里 PATH 的 kubectl 仍是 v1.36.1，而
  `[T2] kubectl 已钉到登记版本 v1.31.4` 出现 4 次，
  `TestIntegrationReadOnlyAgainstKindCluster` 在 v1.31.4 下 PASS（61.43s）。
- **实现期间修掉的两个自身缺陷**：kubectl 的 `-o json` 把 `gitVersion` 嵌在
  `clientVersion` 里（顶层没有）；"环境自带"表的第二列是路径而非版本号——
  两个问题都由新增用例先跑出失败再修正，不是事后补解释。

### 9.3 T3：失败现场的本地补偿开关

R1c 取消"失败保留 schema"后失去 DB 现场，本轮补 `AGENT_OPS_KEEP_SCHEMA=1`：
**仅本地、仅失败用例**保留 run schema。

- `CI=true`/`CI=1` 或残留检查模式（`AGENT_OPS_RESIDUAL_CHECK=1`）下**启动即失败**
  ——在创建 schema 之前就拒绝，连一个残留都不留；它不能变成在 CI 里制造残留的后门；
- 残留门禁**不读**该开关（`internal/k8stest/residual_test.go` 只查 `pg_namespace`）；
- 通过用例一律删除；保留与否由纯函数 `ShouldRetainOnFailure(failed, keep)` 决定，
  真值表与"真实 schema 三分支"（通过→删 / 失败未开关→删 / 失败且开关→保留）均有测试。

### 9.4 T4：CI 首跑事实与本地预演

- **已观察到 CI 真实运行过**（公开 API，无凭据）：`XZ-libin/agent-ops` 为 public，
  run 1 = `8e5f45d`、run 2 = `03130ec`，两次 `gen-check / build / test` 均 `success`；
  run 2 的 `test` job 步骤 9「残留门禁（make residual-check）」`conclusion=success`。
  这两个提交都是**第 24 轮工作树**（其中 `03130ec` 把我的 §9.1 文档修正一并扫入提交，
  故 T1 已被 run 2 覆盖）；本轮 T2/T3 的**代码**改动仍未提交、不在任何 CI 记录里。
- 步骤日志正文需鉴权才能取，本轮未使用凭据，因此
  `residual-check: OK (no leftovers)` 那一行**原文仍未回收**（详见 `docs/ops/first-ci-run.md` §1）。
- 本地 `env -i` 预演（本轮改动之后）：`gen-check` exit 0 / 5s、`test-verbose` exit 0 / 181s、
  `residual-check` exit 0 / 6s（输出 `residual-check: OK (no leftovers)`）、`build` exit 0 / 4s，
  前后 `test_run_*` schema 与 kind 集群均为 0。

### 9.5 会话外改动追踪（本轮两次）

本工作树有两个写入者。R0 快照（`agent-ops-snapshot-20261013-202104.tar.gz`，
sha256 `dc0f17321c13d9c527d878a91bd6c9b6793d8067a5843255f5e7572eccf5819b`）之后，
会话外先后写入：

| 时间 | 文件 | 内容 | 本轮独立复核 |
| --- | --- | --- | --- |
| 20:27 | `docs/tooling.md` | 回填 kubectl/go 的 linux/amd64 SHA | 官方 `.sha256` + 产物实测均一致 |
| 20:27 | `.github/workflows/ci.yml` | actions 钉到 `checkout@11d5960…`(#v4) / `setup-go@40f1582b…`(#v5) | 官方 API tag→commit 一致 |
| 20:35 | `.gitignore` | 忽略 `.workbuddy-ai/` | 非代码改动，已接受（本轮另加 `.tools/` 一行） |
| 20:53 | `.github/workflows/ci.yml` | **升级并改钉** `checkout@3d3c42e…`(#v7.0.1) / `setup-go@b7ad1da…`(#v7.0.0)，并显式 `cache: true` | 官方 API tag→commit 一致；`go-version` 输入名在三处步骤保留 |

**本轮未编辑** `ci.yml`；对它的两次改动只做核验与记录。升级 action 大版本
（v4→v7、v5→v7）是会话外的决定，理由是 run 1 出现 "Node.js 20 is deprecated" 提示。