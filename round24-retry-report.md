# 第二十四轮（修复重入：审计 + 收敛）报告

执行时间：2026-10-13 20:21 – 20:5x（本机 darwin/arm64，Go 1.27.2，测试库 `agent_ops_test`@55432）
性质：R0 快照与来源核对 → R1 残留清理与根因 → R2 修复失败 → R3 public 防增长 → R4 文档核对 → R5 验证
本轮**未新增功能**，未做控制台/真实 issuer/凭据管理/生产补发。

---

## 0. 结论速览

| 门禁 | 本轮前（R0 快照） | 本轮后 | 判定 |
| --- | --- | --- | --- |
| 顶层用例 | 442 PASS / **4 FAIL** / 1 SKIP | **448 PASS / 0 FAIL / 1 SKIP** | 通过 |
| 有测试的包 | 36 | 36 | 不减 |
| `make gen-check` | OK | **OK**（EXIT=0） | 通过 |
| `make residual-check` | **FAILED（68 项残留）** | **连续两次 EXIT=0** | 通过 |
| `test_run_*` schema | 68 | 0（测试后仍为 0） | 通过 |
| `agent_ops_test.public` | 75 表 | 75 表（未增长、未删除） | 通过 |
| GitHub CI | 从未运行 | **CI 未验证**（无本地 git 仓库，仓库地址待确认） | 未完成 |

用例数账目（可核对）：`442 + 4（原失败转通过）+ 2（本轮新增）= 448`。

---

## 1. R0：快照与工作树来源核对

**快照**：`/Users/x/Documents/agent/agent-ops-snapshot-20261013-202104.tar.gz`
**sha256**：`dc0f17321c13d9c527d878a91bd6c9b6793d8067a5843255f5e7572eccf5819b`（389 个文件）

**无 git 历史**：本目录不是 git 仓库（`git rev-parse` → fatal，无 `.git`），因此
**无法自动审计本轮之前的任何改动**；来历未知的文件一律**只按内容审，不按作者信任**。

第二十四轮相关文件核对表（mtime 为快照前；行数为快照时值）：

| 路径 | mtime | 行数 | 对应任务 | 判定 |
| --- | --- | --- | --- | --- |
| `docs/adr/ADR-023-…SHA强制校验.md` | 19:51 | 179 | T0 | **存在且符合**（四项方案、威胁分析、默认/待确认标注齐；本轮追加 §7/§8） |
| `internal/nodecerts/state.go` | 19:18 | 389 | T1 | **存在且符合**（状态机 issued/active/superseded/revoked、`DefaultPendingLimit = 5` 在 :53） |
| `internal/nodesweep/sweeper.go` | 19:22 | 314 | T2 | **存在且符合**（tick 驱动、单实例注释 :17-21、常量 :34/:36/:38/:40） |
| `internal/nodehealth/tracker.go` | 19:24 | 636 | T3 | **存在且符合**（`resetEligible` 三条件；`DefaultReplayResetMinSpan = 20s` :68） |
| `internal/repoguard/ci_sha_test.go` | 19:46 | 255 | T4b/c/g | **存在且符合**（CI1/CI2/CI3 三条守卫） |
| `.github/workflows/ci.yml` | 19:35 | 137 | T4a | **存在且符合**（:99-121 从 tooling.md 取 SHA → `sha256sum -c`，占位即 `exit 1`，fail-closed） |
| `docs/ops/node-cert-lifecycle.md` | 19:52 | 258 | T5 | **存在但不符**：缺"CI 校验方式"一节 → 本轮补 §11 |
| `internal/nodemigrate/migrate.go` | 19:22 | 298 | T1b/T2b | **存在且符合**（5 条迁移，每条带 Down） |
| `internal/nodestore/store.go` | 19:20 | 526 | T1 | **存在但不符**：未暴露扫描状态表名（R2b 根因）→ 本轮补 |
| `internal/nodesvc/{u,s,r,n6,t5_audit,migrate}_test.go` | 19:0x-19:2x | — | T1/T2/T3 测试 | **存在且符合**，其中 3 条在 R0 时失败 |

**快照之后的会话外改动**（我用 `diff -rq` 对快照逐文件比对得出，共 2 个文件，**均非本轮实现者所改**）：

| 文件 | mtime | 改动内容 | 独立复核结论 |
| --- | --- | --- | --- |
| `docs/tooling.md` | 20:27 | 两处 `<<< 待人工提供 >>>` 占位被填为真实 SHA-256；状态由"待回填（合并阻断）"改为"已回填" | kubectl `298e19e9…5620f`、go `ecbadb99…45fe5` —— 与我本机实测产物哈希、官方 `.sha256` 三方一致（见 §5） |
| `.github/workflows/ci.yml` | 20:27 | `actions/checkout@v4`→`@11d5960a…`、`actions/setup-go@v5`→`@40f1582b…`（6 处 uses 钉 SHA + 顶部注释） | 官方 API `git/ref/tags/v4`、`/v5` 的 `object.sha` 与钉入值**完全一致**；无 `continue-on-error`、无条件跳过残留检查 |

> 说明：`R2d`/`T4f` 原本要求"本轮不填 SHA、不钉 Action"。这两项被会话外先行完成，
> 我没有回退（回退同样是修改），也**没有把它们记为本轮成果**；本报告只给出独立复核结论。
> 复核前 TestCI2 是"预期失败"，复核后它已转绿——合并阻断条件事实上已解除，
> **是否接受该回填由你确认**（约束 7：SHA 须人工确认）。

---

## 2. R1：残留清理与根因

**a. 名单与合法性**：68 个 `test_run_*` schema 已写入 `round24-residual-schemas-before.log`；
逐个校验 `^test_run_[0-9]+$` 全部匹配（非法名 0 个），且与 `public` 无重名（`nspname='public'` 计数 0）。

**b. 删除**：按名单逐个 `DROP SCHEMA … CASCADE`，已删除 68、拒绝 0；`public` 表数删除前后均为 75。

**c. 根因（不是"清空掩盖"，而是改策略）**：
`internal/testdb/runschema.go` 的旧 `t.Cleanup` 分支为
`if t.Failed() { 保留 schema; return }`（第十四轮 H5 的"失败保留现场"策略）。
而 `make residual-check` 断言 `test_run_*` 数量为 0。
**两条规则互斥：只要有一个用例失败，残留门禁必然失败。**
R0 实测的 68 个残留全部来自该分支（4 个失败用例 × 多轮重复运行累积）。
排除项：`alerts/internal/chain/executor_test.go:219-245` 的 `t.Failed()` 早退只是**跳过删除断言**，
它不创建 schema，不是泄漏源。

修法：清理收敛为唯一入口 `testdb.CleanupRunSchema(ctx, baseDSN, name, failed, logf)`，
**通过/失败都删除**；删除前仍强制 `ValidateSchemaName`（非 `test_run_` 前缀一律拒绝，public 碰不到）；
失败现场改留日志（schema 名 + 断言输出已在 `-v` 日志中，可归档）。策略变更记入 ADR-023 §7。

**d. 新增自证**：`internal/testdb/cleanup_test.go::TestCleanupRunsOnFailure` → **PASS**。
真实建 schema → 以 `failed=true` 调清理入口 → 断言已消失；并断言 `public`、`information_schema`、
`test_approvals`、`test_run_`、空名一律被拒。

**e. 验证**：`make residual-check` **连续两次 EXIT=0**（第 1 次、第 2 次均 `residual-check: OK`，非 SKIP）。

---

## 3. R2：失败项修复表

| # | 文件:行号 | 根因 | 旧值 | 新值 | 结果 |
| --- | --- | --- | --- | --- | --- |
| a | `internal/nodesvc/migrate_test.go:66-68` | v4（证书状态机表）+ v5（扫描状态表）使迁移数从 4 变 5，断言停留在 4 | `len(applied) != 4`，文案"第二十三轮 3 条 + 第二十四轮证书状态机表" | `len(applied) != 5`，文案补"+ 扫描状态表 005" | **PASS** |
| b | `internal/nodestore/store.go`（常量区、`Config`、`Store`、`New`、新增 `SweepStateTable()`、`AllTables`）+ `internal/nodesvc/u_test.go:297-300` + `internal/nodesvc/n6_test.go:96` + `internal/nodesvc/service.go:328,345,1010,1028` | `nodemigrate.New` 校验 5 个表名（含 `SweepState`），而 `Store.AllTables()` 只暴露 4 个 → 测试传入空名 → `ErrBadTable` | `AllTables() (nodes, tokens, revocations, certs)`；service 内硬编码 `nodemigrate.DefaultTables().SweepState`；包级 `sweepStateTableName()` | 新增 `DefaultSweepStateTable = "test_node_sweep_state"`、`Config.SweepStateTable`、`Store.SweepStateTable()`；`AllTables` 返回 5 个；service 的表名一律取自 Store（删除硬编码 helper） | **PASS** |
| c | `internal/nodesvc/t5_audit_test.go:86-107` | T3 收紧后，原注入方式把**同一个** sent_at 连发 3 次：等值属 `duplicate`，不计入 replay streak；且无严格递增 → 永不重置 → `node.clock_regression_reset` 审计 0 条 | 3 次心跳 `sent_at = base`（等值） | 3 次 `sent_at = base-10min+i·1s`（严格递增、均低于基线），每次 `advance(10s)` → 接收跨度 20s（≥20s） | **PASS**（`TestAuditCoverage_AllTransitions` 断言**未改**：仍要求恰好 1 条） |
| d | `internal/repoguard/ci_sha_test.go::TestCI2_…` | 预期失败＝合并阻断（占位符未回填） | — | 本轮**未修改该测试**；因 §1 所述会话外回填而转绿 | 状态见 §1，需你确认 |

**未放宽任何守卫**：`nodemigrate.New` 的 5 表名校验保持；`TestCI1/CI2/CI3` 逻辑未改；
`ci.yml` 无 `continue-on-error`、残留检查仍无条件在 test job 内执行。

---

## 4. R3：public 历史残留（只防增长，不删除）

**创建者查明**：`public` 的 72 张 `test_audit_events_* / test_approvals_*` 表，其表名时间戳换算后
全部落在 **2026-10-12 ~ 10-13 01:00**，即**第十四轮 H5 之前**——当时测试直接用基线 DSN
（无 `search_path`）在 public 建每轮独立表。H5 引入 `testdb.NewRunSchema`（`search_path=test_run_*`）后
该路径已收敛：现 17 个测试文件走 `NewRunSchema`，`internal/audit/audit_test.go:31`、
`gateway/internal/testwrite/integration_test.go:358` 等均取 `rs.Pool()`。
本轮两次全量 `go test ./...`（20:0x 与 20:4x）之后 public 计数 **75 → 75，零增长**，实证修复有效。

**守卫新增**：`internal/testdb/public_guard_test.go::TestPublicTableCountDoesNotGrow` → **PASS**。
基线常量 75；超出即失败并列出全部 public 表名与体积，提示"新表必须建在 run schema 内"。
低于基线时**告警不失败**（防有人未经授权删 public 表）。
**本轮未删除任何 public 表或审计记录**（硬性约束 3/5）。

**基线口径分两栏（自本轮起）**：
- 生产命名表 **3** 张：`approvals`、`audit_events`、`idempotency_keys`；
- 历史残留表 **72** 张：`test_audit_events_*`（含 `_grpc_/_itest_/_itest10_/_tamper_/_node_` 变体）与
  `test_approvals*` 系列，名单见 `round24-residual-schemas-before.log` 同批次的 public 查询结果，
  完整清单可用 `docker exec deploy-postgres-1 psql -U agent_ops -d agent_ops_test -tAc "select tablename from pg_tables where schemaname='public' order by 1"` 复现。

---

## 5. R4：常量与版本核对

**五个工程默认值（代码位置）**：

| 值 | 含义 | 文件:行号 | 状态 |
| --- | --- | --- | --- |
| 48 小时 | 到期风险阈值（剩余 <48h → `node.cert_expiry_risk`） | `internal/nodesweep/sweeper.go:36` `DefaultExpiryThreshold` | 工程默认，待确认 |
| 6 小时 | 同节点告警节流间隔 | `internal/nodesweep/sweeper.go:38` `DefaultThrottleGap` | 工程默认，待确认 |
| 24 小时 | `issued` 未确认判定 | `internal/nodesweep/sweeper.go:40` `DefaultUnconfirmedAge` | 工程默认，待确认 |
| 20 秒 | 时钟回退重置的最小接收跨度 | `internal/nodehealth/tracker.go:68` `DefaultReplayResetMinSpan` | 工程默认，待确认 |
| 5 个 | 同节点 `issued` 未确认上限（超限拒续期） | `internal/nodecerts/state.go:53` `DefaultPendingLimit` | 工程默认，待确认 |
| 5 分钟 | 扫描周期 | `internal/nodesweep/sweeper.go:34` `DefaultInterval` | 工程默认，待确认（补充项） |
| 3 次 | 连续 replay 阈值 | `internal/nodehealth/tracker.go:62` `DefaultReplayResetThreshold` | 工程默认，待确认（补充项） |

ADR-023 §1/§2/§3 已逐条标注"工程默认，待确认"（实测 8 处标注），本轮无缺失需补。

**版本一致性（`tooling.md` vs `ci.yml`）**：
- Go：`ci.yml:40 GO_VERSION: "1.27.2"` ↔ 登记 `go | 1.27.2 | linux/amd64` — **一致**；
- kubectl：`ci.yml:43 KUBECTL_VERSION: "v1.31.4"` ↔ 登记 `kubectl | v1.31.4 | linux/amd64` — **一致**；
- buf `v1.47.2`、kind `v0.30.0` — 与 Makefile 固定版本一致。

**两处不一致（按 R4c 只报告、不擅改）**：
1. `docs/tooling.md` 第 **15** 行与第 **64** 行登记的 kubectl **darwin/arm64** v1.31.4 SHA 与官方
   校验文件在第 27 位相差一个字符：登记 `…c111c370728a…`，官方
   `…c111c371728a…`（`curl -fsS https://dl.k8s.io/release/v1.31.4/bin/darwin/arm64/kubectl.sha256`）。
   CI 不消费该条目（CI 用 linux/amd64），故流水线不受影响；但按登记即校验的口径它是错的。
2. 本机 PATH 上的 kubectl 是 `/Users/x/.docker/bin/kubectl`，**Client Version v1.36.1**
   （哈希 `9ea693e3…aaef`），而登记的"本机实测"条目是 v1.31.4。即**集成测试实际执行的 kubectl
   与登记条目不是同一个二进制**（kind 夹具用 v1.31.0 节点镜像，属另一维度）。

**外部二进制独立复核（本机实测，不采信记忆）**：

| 项 | 官方来源 | 实测 | 判定 |
| --- | --- | --- | --- |
| kubectl linux/amd64 | `…/v1.31.4/bin/linux/amd64/kubectl.sha256` = `298e19e9…5620f` | 下载产物 56,381,592 字节，`shasum -a 256` = `298e19e9c6c17199011404278f0ff8168a7eca4217edad9097af577023a5620f` | **一致** |
| go 1.27.2 linux/amd64 | `https://dl.google.com/go/go1.27.2.linux-amd64.tar.gz.sha256` = `ecbadb99…45fe5` | 从 `go.dev/dl` 下载 70,590,635 字节，实测 `ecbadb99091a3f46e31f5f934b068b1864eafa7995211b39eaddf76996045fe5` | **一致** |
| `actions/checkout@11d5960a…` | API `repos/actions/checkout/git/ref/tags/v4` → `object.sha = 11d5960a326750d5838078e36cf38b85af677262` | 与钉入值相同 | **一致** |
| `actions/setup-go@40f1582b…` | API `repos/actions/setup-go/git/ref/tags/v5` → `object.sha = 40f1582b2485089dde7abd97c1529aa768e1baff` | 与钉入值相同 | **一致** |

> `docs/tooling.md` 新写的取值说明称"`dl.google.com` 在本机 TLS 握手不通"。
> 我这侧 `dl.google.com` 两次均 HTTP 200 且值一致，故该说明属**会话外环境差异**，不影响结论。

---

## 6. R5：验证与前后对比

| 指标 | R0 快照（本轮前） | 本轮后 | 差 |
| --- | --- | --- | --- |
| 顶层 PASS / FAIL / SKIP | 442 / 4 / 1 | **448 / 0 / 1** | +6 PASS，−4 FAIL |
| 有测试的包 / 无测试文件的包 | 36 / 19 | 36 / 19 | 0 |
| `make gen-check` | OK | OK | — |
| `make residual-check` | EXIT≠0（68 残留） | **EXIT=0 ×2** | 修复 |
| `test_run_*` schema | 68 | 0 | 清零 |
| public 表 / 行数 | 75 / 824（`n_live_tup` 估算） | 75 / 824 | 0（未删未增） |

日志：`round24-retry-test-output.log`（`go test ./... -v -count=1`，7 模块全跑）。

**唯一 SKIP**：`TestNoLeftoversAfterSuite`（`internal/k8stest`）——常规 `go test` 下未设
`AGENT_OPS_RESIDUAL_CHECK=1` 时按设计 SKIP；它由 `make residual-check` 强制执行且
**Makefile 把"被 SKIP"也判为失败**，两次 EXIT=0 已证明它真实执行并通过。SKIP 不计入通过。

**本轮改动文件清单**：

| 路径 | 用途 |
| --- | --- |
| `internal/testdb/runschema.go` | R1c：清理策略改为失败也删除；新增唯一入口 `CleanupRunSchema`；删除无调用者的 `Drop` |
| `internal/testdb/cleanup_test.go`（新） | R1d：`TestCleanupRunsOnFailure` + `adminPool`/`schemaExists` 辅助 |
| `internal/testdb/public_guard_test.go`（新） | R3c：`TestPublicTableCountDoesNotGrow`（基线 75） |
| `internal/nodestore/store.go` | R2b：`DefaultSweepStateTable`、`Config.SweepStateTable`、`Store.sweepState`、`SweepStateTable()`、`AllTables` 返回 5 项 |
| `internal/nodesvc/service.go` | R2b：节流状态表名改由 Store 提供（`SweepStateTable()`），删除硬编码 `sweepStateTableName()` |
| `internal/nodesvc/u_test.go` | R2b：`AllTables` 5 值解构并把 `SweepState` 传入 `nodemigrate.New` |
| `internal/nodesvc/n6_test.go` | R2b：`AllTables` 解构补一位（非断言改动） |
| `internal/nodesvc/migrate_test.go` | R2a：迁移条数断言 4 → 5 |
| `internal/nodesvc/t5_audit_test.go` | R2c：按 T3 三条件重造 replay 注入（断言未动） |
| `docs/adr/ADR-023-….md` | §5 关系表补 H5 取代行；§6 未决事项改写；新增 §7 清理策略修订、§8 外部二进制与 Action 复核记录 |
| `docs/ops/node-cert-lifecycle.md` | T5：新增 §11 CI 外部二进制校验方式（含人工复核命令、Action 钉 SHA 说明）；§10 的 SHA 待回填条目改为已回填+待复核 |
| `round24-residual-schemas-before.log`（新） | R1a：删除前的 68 个 schema 名单 |
| `round24-retry-test-output.log`（新） | R5a：全量 `-v` 输出 |

**被修改的既有断言（逐条，符合约束 14）**：仅 R2a 一处（`migrate_test.go:66` 的 4→5）。
R2b 的两处是**解构元数**适配（非断言），R2c **未改任何断言**。

---

## 7. 节点生命周期闭环清单

| 项 | 代码完成 | 测试覆盖 | 依赖用户输入 | 依赖 CI |
| --- | --- | --- | --- | --- |
| O1 续期（Renew） | 是 | 是（U1–U6 全 PASS） | — | 是（未验证） |
| O2 持久化（状态机 + 迁移可回滚） | 是 | 是（U5 回填与 down 回滚 PASS；迁移数断言修正） | — | 是 |
| O3 补发（reissue） | 是 | 是（X 系列 PASS） | 生产补发流程未定 | 是 |
| O4 时钟回退（会话基线 + 防重放） | 是 | 是（C1–C5、D6、T5 覆盖 PASS） | 20s/3 次为工程默认，待确认 | 是 |
| 缺口 1 证书状态机（多张未确认证书收敛） | 是 | 是（U1/U2/U3/U4/U6） | 上限 5 待确认 | 是 |
| 缺口 2 服务端周期扫描（不依赖心跳） | 是 | 是（S1–S5，tick 驱动无 sleep） | 48h/6h/24h/5min 待确认 | 是 |
| 缺口 3 时钟回退重置加固 | 是 | 是（C1–C5 + T5 审计覆盖） | 20s/3 次待确认 | 是 |
| 缺口 4 CI 二进制 SHA 强制校验 | 是（`sha256sum -c` fail-closed + 三守卫） | 是（CI1/CI2/CI3 PASS） | **SHA 与 Action 钉值请人工确认**；darwin 登记值疑误待裁决 | 是 |

---

## 8. 残留风险

1. **CI 未验证**：本轮全部结论来自本地。`gen-check / build / test / residual-check` 在
   GitHub runner 上从未跑过；`adapters/kubernetes` 依赖 kind 镜像缓存（本地 70s 通过，
   冷 runner 可能拉镜像超时），首次 CI 需盯这一项。
2. **仓库不存在**：本机无 `.git`、无 `gh` CLI，`XZ-libin/agent-ops` API 返回 404。
   因此"推送分支 / CI 结果 / 把 `test` 设为必需检查"三件事目前**无法执行**；
   分支保护需建仓后再设。
3. **合并阻断由会话外解除**：`TestCI2` 与 Action 钉 SHA 不是本轮实现者所为。
   若你不认可该回填，应把两处值改回占位并恢复阻断——这是你的决定，我未擅自回退。
4. **darwin/arm64 登记值有一位字符差**（§5），若将来有基于该条目的本机校验脚本会误报失败。
5. **本机 kubectl 版本口径不一致**（v1.36.1 vs 登记 v1.31.4）：测试结论对 kubectl 小版本
   的敏感度未被证明。
6. **public 72 张历史残留表仍在**（约束 3 不许删）。守卫只防增长；行数指标 824 由这些
   残留贡献，作为"数据量基线"意义有限，建议改看生产 3 表。
7. **`CleanupRunSchema` 的 CI 行为差异**：失败即删除意味着**失去 DB 现场**；
   排查依赖 `-v` 日志中的 schema 名与断言输出。若你需要 DB 现场，应改为
   "失败时 dump 到文件后再删除"（本轮未做，属功能新增）。
8. **扫描器仍单实例**（无 lease 协调），多副本控制面会重复写审计。
