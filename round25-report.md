# 第二十五轮报告（CI 预演与收口：审计 / 修正 / 预演，不新增功能）

执行：2026-10-13 20:48 – 21:5x，本机 darwin/arm64，Go 1.27.2，测试库 `agent_ops_test`@55432
快照：`../agent-ops-snapshot-20261013-202104.tar.gz`，sha256 `dc0f17321c13d9c527d878a91bd6c9b6793d8067a5843255f5e7572eccf5819b`（校验**匹配**）
本轮**未推送、未 commit、未 git init、未使用任何 GitHub 凭据**（写操作为 0；读取公开 API 见 T4）。

## 0. 结果速览

| 门禁 | 基线（本轮要求） | 本轮后 |
| --- | --- | --- |
| 顶层用例 | 448 PASS / 0 FAIL / 1 SKIP（36 包） | **459 PASS / 0 FAIL / 1 SKIP（37 包）** |
| `make gen-check` | OK | **OK**（exit 0） |
| `make residual-check` | 连续两次 0 | **连续两次 0**（`residual-check: OK (no leftovers)`） |
| `public` | 75 表 / 824 行 | 75 表 / 824 行 |
| `test_run_*` schema | 0 | 0 |

459 = 448 + **11 个新增用例**（无删除、无改名）；新增包 1 个：`internal/toolpin`。
唯一 SKIP：`TestNoLeftoversAfterSuite`（常规 `go test` 下未设 `AGENT_OPS_RESIDUAL_CHECK=1`，设计如此；
它在 `make residual-check` 步骤里真实执行并通过，Makefile 把 SKIP 判为失败）。

## 1. T0 改动审计

`diff -rq`（快照 → 当前，排除 `.git`）结果分类：

**本轮实现者改动（12 项，全部有任务号）**

| 路径 | 类型 | 任务 |
| --- | --- | --- |
| `docs/tooling.md` | 修改 | T1c（darwin 两处登记值 + 第二十五轮下载记录条目） |
| `.gitignore` | 修改 | T2b（新增 `.tools/` 一行） |
| `internal/toolpin/toolpin.go` | 新增 | T2b |
| `internal/toolpin/toolpin_test.go` | 新增 | T2b（7 用例） |
| `internal/repoguard/toolversion_test.go` | 新增 | T2c（1 用例） |
| `internal/k8stest/k8stest.go` | 修改 | T2b（`KubectlPinned`；`ResidualCheckEnv` 改引 testdb 常量） |
| `adapters/kubernetes/integration_test.go` | 修改 | T2b（两处 kubectl 解析改为钉版本） |
| `internal/testdb/runschema.go` | 修改 | T3a/b（开关 + fail-fast + 保留分支） |
| `internal/testdb/keep_test.go` | 新增 | T3d（3 用例） |
| `docs/ops/first-ci-run.md` | 新增 | T4f |
| `docs/adr/ADR-023-….md` | 修改 | T5 + §9（含 §6 结构修正：上一轮我把一条 §6 bullet 挤到了文件末尾，本轮归位） |
| `round25-test-output.log` / 本报告 | 新增 | T6 |

**会话外改动（4 项，快照之后写入，均非本轮所为）**

| 时间 | 文件 | 内容 | 处置 |
| --- | --- | --- | --- |
| 20:27 | `docs/tooling.md` | 回填 kubectl/go 的 linux/amd64 SHA | 保留 + 独立复核（T1e 一致） |
| 20:27 | `.github/workflows/ci.yml` | actions 钉 `11d5960…`(#v4) / `40f1582b…`(#v5) | 保留 + 官方 API 核验一致 |
| 20:35 | `.gitignore` | 忽略 `.workbuddy-ai/` | **T0c 之外的第三个会话外文件**：非代码、非 CI、非校验值 → 列入清单后继续，未回退 |
| 20:53 | `.github/workflows/ci.yml` | **升级并改钉** `3d3c42e…`(#v7.0.1) / `b7ad1da…`(#v7.0.0) + 显式 `cache: true` | 快照后再次漂移：官方 API 核验两个 tag→commit 一致；`go-version` 输入名三处保留；本轮未编辑该文件 |

> 会话外还做了 `git init` + 2 个提交 + 推送到 `github.com/XZ-libin/agent-ops`（public）。
> 本轮约束禁止这些操作，我**一个都没执行**，只做了只读取证（见 §5）。

## 2. T1 darwin/arm64 修正记录

| 项 | 值 |
| --- | --- |
| 旧值 | `a756bb911298a85af35c0111c370728a26c532d504fe8b534eb684501fcaf996` |
| 新值 | `a756bb911298a85af35c0111c371728a26c532d504fe8b534eb684501fcaf996` |
| 差异位置 | 第 **27** 位（0-based 26）：`0` → `1` |
| 来源 | `https://dl.k8s.io/release/v1.31.4/bin/darwin/arm64/kubectl.sha256`（官方） |
| 产物实测 | 下载 56,560,802 字节，`shasum -a 256` = 新值（逐字符一致） |
| 修正位置 | `docs/tooling.md` 第 15 行（已声明并校验表）与第 64 行（平台相关条目表），并追加第二十五轮下载记录 |
| 日期 | 2026-10-13 |
| 定性 | 转写错误（非上游重签名）；CI 不消费 darwin 条目，故未影响流水线 |

**T1e linux 复核**：kubectl `298e19e9…5620f`（官方 `.sha256` 一致；产物 56,381,592 字节实测一致）；
go `ecbadb99…45fe5`（`dl.google.com` 的 `.sha256` 一致；从 `go.dev/dl` 下载 70,590,635 字节实测一致）。
两个值均与登记**一致**，**未**回退为"待回填"。

## 3. T2 kubectl 调用检查与版本钉定

**a. 调用点（grep 全仓）**：
- 测试：`adapters/kubernetes/integration_test.go`（`toolPath(t,"kubectl")` ×2：`TestIntegrationReadOnlyAgainstKindCluster`、`TestIntegrationKindAvailabilityRecords`）、`internal/k8stest/k8stest.go`（`ToolPath(t,"kubectl")` ×2：外部 kubeconfig 复用路径与自建集群路径，`kubectlBin` 用于集群内建/删命名空间与只读查询）→ **参与测试**；
- `Makefile`、`deploy/`、`diagnostics/`、`web/`：**无 kubectl 调用**；
- `ci.yml`：安装步骤（下载 + `sha256sum -c` + `install`）与 `kubectl version --client`。
- `adapters/kubernetes/kubernetes_test.go` 里出现的 `kubectl` 字样是**注解键名**（`kubectl.kubernetes.io/last-applied-configuration`），不是命令调用。

**b. 改造**：新增 `internal/toolpin`，两个调用点改为 `KubectlPinned/pinnedKubectl`。
候选优先级 `AGENT_OPS_KUBECTL_BIN` → `.tools/kubectl` → PATH；
**版本不符即失败、不顺延**；只有"来源不存在/不可执行"才继续下一个来源；
找不到登记版本时错误里点名两条修复路径。本机 `.tools/kubectl` 放置的是 T1 实测过的 v1.31.4（`.tools/` 已 gitignore，仓库不存二进制）。
既有 skip 语义收窄：只有 **kind 缺失**才 skip（kubectl 问题不再可能被静默绕过）。

**c. 守卫**：`TestToolVersionMatchesRegistered`（`internal/repoguard/toolversion_test.go`）
只读比对 `ci.yml` 的 `GO_VERSION=1.27.2 / KUBECTL_VERSION=v1.31.4 / BUF_VERSION=v1.47.2 / KIND_VERSION=v0.30.0`
与 `docs/tooling.md` 登记版本 → 4 项一致，PASS。不执行任何二进制。

**d. 过程中修掉的两个自身缺陷**（都由新用例先失败暴露）：
1. `kubectl version --client -o json` 的 `gitVersion` 嵌在 `clientVersion` 下（顶层无）；
2. 表格解析把"使用但不由本项目下载"表的第二列（安装路径）当版本，导致"同一工具多版本"误报。

**e. 效果实证**：`env -i` 最小环境里 PATH 仍是 v1.36.1，日志出现
`[T2] kubectl 已钉到登记版本 v1.31.4` ×4，`TestIntegrationReadOnlyAgainstKindCluster` PASS（61.43s）。

## 4. T3 残留调试开关

- 开关 `AGENT_OPS_KEEP_SCHEMA=1`（`internal/testdb`）：**仅本地、仅失败用例**保留 run schema；
- fail-fast：`CI=true`/`CI=1` 或 `AGENT_OPS_RESIDUAL_CHECK=1` 时，在**创建 schema 之前**即 `t.Fatal`（一个残留都不留）；
- 残留门禁不读该开关（`residual_test.go` 只查 `pg_namespace`）；`ResidualCheckEnv` 常量改为单一来源（testdb → k8stest 引用）；
- 测试 3 个：`TestKeepSchemaRefusedInCI`（5 种禁止组合）、`TestKeepSchemaLocalOnly`（含非 "1" 取值不生效 + 真值表）、`TestKeepSchemaRetainsOnlyOnFailure`（真实 schema 三分支：通过→删、失败未开关→删、失败且开关→保留），全部 PASS。

## 5. T4 CI 预演

**执行方式**：`env -i HOME=… PATH=/usr/local/bin:/usr/bin:/bin:~/.local/bin:~/go/bin:~/.docker/bin AGENT_OPS_TEST_DATABASE_URL=postgres://agent_ops:agent_ops@localhost:55432/agent_ops_test?sslmode=disable`
（与 `ci.yml` 的 env 同名同值；最小环境自检：`go1.27.2 darwin/arm64`、`kind v0.30.0`、`GNU Make 3.81`、`Docker 29.8.2`）

| 步骤 | 命令 | 退出码 | 耗时 | 关键输出 |
| --- | --- | --- | --- | --- |
| job1 | `make gen-check` | **0** | 5s | `gen-check: OK` |
| job3 | `make test-verbose` | **0** | **181s** | 460 PASS / 0 FAIL / 1 SKIP（含 residual 步骤重复计入的包） |
| job3 | `make residual-check` | **0** | 6s | **`residual-check: OK (no leftovers)`**（不是 SKIP） |
| job2 | `make build` | **0** | 4s | 7 模块通过 |

前后残留：`test_run_*` schema **0 → 0**，`kind` 集群 **0 → 0**，agent-ops 标记容器 0。

**已观察到 CI 真实跑过**（读公开 API，未用凭据）：仓库 public，`main` 分支两个提交都已推送，
两次 workflow run 均 `completed/success`：

| run | 提交 | job 结论 |
| --- | --- | --- |
| 1 | `8e5f45d`（第 1–24 轮快照） | success |
| 2 | `03130ec`（action 升 v7 钉 SHA） | gen-check / build / test **均 success**；test job 步骤 6「安装并校验 kubectl（v1.31.4）」success、步骤 8 测试 143s success、步骤 9「残留门禁」success |

**但四点保留**：① 这两个 run 覆盖的主体是**第 24 轮工作树**；本轮 11 个新用例 + toolpin + keep 开关
**未提交、不在其中**；② 例外——会话外的提交 `03130ec`（20:53）**把我的 T1 修正扫了进去**
（`git show --stat 03130ec` 含 `docs/tooling.md | 23 ++++++`，且 diff 里有"第二十五轮 T1 修正"字样），
因此 **T1 的文档修正已被 run 2 覆盖**（run 2 的 test job 里 `TestCI2/TestCI3` 解析的正是修正后的表）；
③ `residual-check: OK (no leftovers)` 那一行**原文仍未回收**（日志端点需鉴权，本轮不用凭据）；
④ 我的 T2/T3/T5 改动全部仍在工作树未提交，**归属清晰但未经 CI**。
产出文档：`docs/ops/first-ci-run.md`。

**无法本地复现**：`actions/checkout`、`actions/setup-go`、service 容器初始化、
全新 runner 冷编译与模块缓存、kubectl 的下载+`sha256sum -c` 安装步（本地对应物是事先实测的 `.tools/kubectl`）。

## 6. T5 状态收口

`docs/adr/ADR-023-….md:8` 与 `docs/ops/node-cert-lifecycle.md:3` 的状态行已统一为
「**第二十四轮：本地闭环；CI 未验证**」，均未出现"已通过 CI"字样。
ADR-023 新增 §9（9.1 登记值修正 / 9.2 版本钉定 / 9.3 保留开关 / 9.4 CI 事实与预演 / 9.5 会话外改动追踪）。

## 7. 本地闭环状态表

| 项 | 代码完成 | 测试覆盖 | 依赖 CI | 依赖用户输入 |
| --- | --- | --- | --- | --- |
| O1 续期 Renew | 是 | 是（U1–U6） | 本轮改动未经 | — |
| O2 持久化（状态机 + 可回滚迁移） | 是 | 是（U5 + 迁移断言 5 条） | 是 | — |
| O3 补发 | 是 | 是（X1–X4） | 是 | 生产补发流程未定 |
| O4 时钟回退 | 是 | 是（C1–C5、D6、T5） | 是 | 20s / 3 次默认待确认 |
| 缺口 1 证书状态机 | 是 | 是 | 是 | 上限 5 待确认 |
| 缺口 2 服务端扫描 | 是 | 是（S1–S5） | 是 | 48h/6h/24h/5min 待确认 |
| 缺口 3 重置加固 | 是 | 是 | 是 | 20s/3 次待确认 |
| 缺口 4 CI SHA 校验 | 是 | 是（CI1/CI2/CI3 + T2c） | 是（本轮未重跑 CI） | **SHA 与 action 钉值的人工确认**（值本身已由我实测一致） |
| T1 darwin 登记修正 | 是 | 文档修正（无代码断言） | 不适用 | 是否接受"转写错误"定性 |
| T2 kubectl 版本钉定 | 是 | 是（8 用例：7 toolpin + 1 守卫） | **是**（CI 上 `.tools/` 不存在，依赖 PATH 的 v1.31.4 路径生效） | `.tools/` 或 `AGENT_OPS_KUBECTL_BIN` 是否作为团队约定 |
| T3 保留开关 | 是 | 是（3 用例） | 是 | 无 |

## 8. 被修改的既有断言

**无。** 本轮只改：既有 `toolPath(t,"kubectl")` 调用与 skip 条件（行为改造，非断言）、
`ResidualCheckEnv` 常量的定义来源（值不变）。既有测试断言一律未动，测试数只增不减。

## 9. 残留风险

1. **本轮改动未经 CI**：`internal/toolpin` 在 CI 上的路径是「无 `.tools/` → 取 PATH 上 `ci.yml` 装好的 v1.31.4」。
   这条路径逻辑上成立，但**从未在 runner 上执行过**；若 CI 的 `install` 位置或 PATH 顺序有变，
   k8s 集成测试会**失败（fail-closed）**而不是退回旧版本——这是设计意图，但首跑可能因此变红。
2. **并发写入者**：同一棵树上有第二个会话在改 `ci.yml`/`tooling.md` 并提交推送。
   本轮的 T2/T3 改动**尚未提交**，若对方下一次提交把这些一起带上车，CI 结果与改动归属会混淆。
3. `residual-check` 步骤日志正文未取回（需凭据）。
4. action 大版本被升到 v7（会话外决定）：`cache: true` 在 CI 上缓存 Go 模块，
   gen-check 的"逐字节比对"不因缓存变弱，但**缓存命中时的产物差异我未验证**。
5. public 的 72 张历史残留表仍在（约束不许删）；`824 行` 这一指标仍被它们主导。
6. `adapters/linux/linux_test.go` 自 10-12 起未 `gofmt`（快照里同样如此，非本轮引入）；
   跑 `make fmt` 会顺带改写它，故本轮未动。
7. kind 未纳入版本闸门（当前无漂移）。

## 10. 推送与 CI（轮末用户指示：推到 GitHub）

本轮原约束禁止 git 写操作；轮末用户明确指示推送，据此执行。

| 项 | 值 |
| --- | --- |
| 提交 | `626ab5b`（11 文件，+1069 / −20） |
| 推送 | `03130ec..626ab5b → origin/main`（HTTPS + askpass 读取 PAT；令牌未进命令行，临时脚本用后删除） |
| 未纳入提交 | `round24-retry-report.md`、`round25-report.md`（轮次工作记录留在工作树；`*.log`、`.tools/`、`.workbuddy-ai/` 均被 gitignore） |
| 推送前预检 | 逐文件核对暂存归属（避免串入并发会话的改动）；敏感串扫描（私钥 / `ghp_` / `github_pat_` / Slack token / AKIA / api_key）无命中；本次不含 `ci.yml`，故不涉及 Workflows 权限 |
| 远端返回提示 | `remote: Bypassed rule violations for refs/heads/main: Required status check "test" is expected.` |

**这条提示的含义值得单独记**：分支保护中的必需检查 `test` **不阻止直推 main**
（所有者/管理员可绕过），它只拦 PR 合并。因此"CI 绿"不是推送的前置闸门，
推送后必须回读 run 结果——本轮就是这么做的。

CI run 3（`sha=626ab5b`，2026-10-13 21:50–21:53 CST）：**`completed / success`**。

| job / 步骤 | 结果 |
| --- | --- |
| `gen-check` | success |
| `build` | success |
| `test` 步骤 6 安装并校验 kubectl | `/tmp/kubectl: OK`（`sha256sum -c` 通过） |
| `test` 步骤 8 单元与集成测试 | **顶层 459 PASS / 0 FAIL / 1 SKIP，37 个有测试的包** —— 与本地 `round25-test-output.log` 逐项相同 |
| `test` 步骤 8 中的 T2 闸门 | `[T2] kubectl 已钉到登记版本 v1.31.4（/usr/local/bin/kubectl）` ×4 |
| `test` 步骤 9 残留门禁 | `[残留检查] kind 集群 0、agent-ops.test=true 容器 0、test_run_* schema 0` → `--- PASS: TestNoLeftoversAfterSuite (0.05s)` → **`residual-check: OK (no leftovers)`** |
| annotation | 仅一条：`ubuntu-latest` 将于 2026-10-19 迁移到 Ubuntu 26（提醒，非失败） |

因此：**残留门禁是 PASS，不是 SKIP**；§9 残留风险第 1 条（CI 上无 `.tools/` 时走 PATH 的 v1.31.4）
已被真机验证；第 3 条（日志原文未回收）已消解。ADR-023 与运维手册的状态行相应更新，
并在文中保留"此前写作 CI 未验证"的时间线说明。

日志取回方法（供后续轮次复用）：`GET /repos/{o}/{r}/actions/runs/{id}/logs` 返回 302 → zip，
需 PAT；zip 内的步骤文件名含中文，`unzip` 会因文件名编码失败，须用 Python `zipfile` 读取。
