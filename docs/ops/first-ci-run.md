# 首次 CI 运行：预期、已观察到的结果与需回收的内容

> **第二十四轮 / 第二十五轮：本地闭环；CI 已由 run 1–3 验证（2026-10-13，全部 success）。**
> 说明：本行在第二十五轮 T5 时原写为"CI 未验证"——那是推送前的状态。
> 提交 `626ab5b`（含 T2/T3 代码）推送后 run 3 三 job 全绿，步骤级日志已回收，
> 故按事实更新；证据见 §1A。**在此之前不得声称 CI 通过。**

---

## 1A. run 3 = 提交 `626ab5b`（第二十五轮 T2/T3 改动第一次进 CI）

| 项 | 结果 |
| --- | --- |
| run | 3，`completed / success`，2026-10-13 13:50:11Z → 13:53:15Z（约 3 分钟） |
| job | `gen-check` success、`build` success、`test` success |
| 步骤 6 安装并校验 kubectl | `/tmp/kubectl: OK`（`echo "$expected  /tmp/kubectl" \| sha256sum -c -` 通过） |
| 步骤 8 单元与集成测试 | **顶层 459 PASS / 0 FAIL / 1 SKIP，37 个有测试的包，19 个无测试文件** —— 与本地 `round25-test-output.log` **逐项相同** |
| 步骤 8 中的 T2 闸门 | `[T2] kubectl 已钉到登记版本 v1.31.4（/usr/local/bin/kubectl）` 出现 **4 次** |
| 步骤 9 残留门禁原文 | `residual_test.go:97: [残留检查] kind 集群 0、agent-ops.test=true 容器 0、test_run_* schema 0`<br>`--- PASS: TestNoLeftoversAfterSuite (0.05s)`<br>`residual-check: OK (no leftovers)` |
| 唯一 SKIP | `TestNoLeftoversAfterSuite`（步骤 8 阶段，未设 `AGENT_OPS_RESIDUAL_CHECK=1`，设计如此；它在步骤 9 被真实执行并 PASS） |
| annotation（唯一一条） | `The ubuntu-latest label will migrate to Ubuntu 26 beginning October 19, 2026.` —— 迁移提醒，非失败 |

**结论：残留门禁那一行是 PASS，不是 SKIP。** 取到方式：公开 API 的
`/actions/runs/38408229682/logs`（302 → zip）需要鉴权，用本机 PAT 读取；
日志条目名含中文，`unzip` 会因文件名编码失败，需用 Python 的 `zipfile` 读取。
CI 上 `.tools/kubectl` 不存在（已 gitignore），`internal/toolpin` 因此走 PATH 上
由 `ci.yml` 下载并校验过的 v1.31.4 —— 与本地设计一致，本轮已在真机上验证成立。

## 1B. 此前两次运行（第 24 轮工作树）

已在 GitHub 公开 API 观察到的运行记录（无凭据读取）

仓库 `XZ-libin/agent-ops`（**public**，默认分支 `main`）有两个 workflow run：

| run | 提交 | 触发 | 状态 | 结论 | 时间（UTC / 本地 CST） |
| --- | --- | --- | --- | --- | --- |
| 1 | `8e5f45d`（init：第 1–24 轮工作树快照） | push | completed | **success** | 2026-10-13 12:46Z / 20:46 |
| 2 | `03130ec`（ci：Action 升至 node24 并钉 release SHA） | push | completed | **success** | 2026-10-13 13:33–13:36Z / 21:33–21:36 |

run 2 的三个 check run（对应 `ci.yml` 的三个 job）全部 `completed / success`：

| job | conclusion | job URL |
| --- | --- | --- |
| gen-check | success | `.../actions/runs/38400702220/job/115325408914` |
| build | success | `.../actions/runs/38400702220/job/115325344432` |
| test | success | `.../actions/runs/38400702220/job/115325341452` |

`test` job 的步骤级结果（公开 API 可读）：

| # | 步骤 | 结论 | 耗时 |
| --- | --- | --- | --- |
| 3 | Run actions/checkout@3d3c42e…（# v7.0.1） | success | 1s |
| 4 | Run actions/setup-go@b7ad1da…（# v7.0.0） | success | 13s |
| 5 | 安装 kind（v0.30.0） | success | 5s |
| 6 | **安装并校验 kubectl（v1.31.4）** | success | 1s |
| 7 | 等待 PostgreSQL 就绪 | success | <1s |
| 8 | 单元与集成测试（`make test-verbose`） | success | **143s** |
| 9 | **残留门禁（`make residual-check`）** | success | **<1s** |

**保留意见（已由 run 3 消解）：**

1. run 1/run 2 覆盖的是**第 24 轮工作树**（其中 `03130ec` 顺带把 T1 的 `tooling.md` 修正扫入提交）。
   本轮 T2/T3 代码在提交 `626ab5b` 推送后由 **run 3** 覆盖，结果见 §1A——三个 job 全绿，
   步骤 8 的用例统计与本地逐项一致。
2. `residual-check: OK (no leftovers)` 那一行**原文已回收**（用本机 PAT 读
   `/actions/runs/<id>/logs`，302 → zip；条目名含中文，须用 Python `zipfile` 而非 `unzip`）。
   在此之前它只是"步骤 conclusion=success + Makefile 把 SKIP 判为失败"的推理。

## 2. 每个 job 的预期步骤与预期结果（下一次推送时）

| job | 步骤顺序 | 预期结果 |
| --- | --- | --- |
| `gen-check` | checkout → setup-go(go 1.27.2) → `make gen-check` | 末行 `gen-check: OK`，exit 0 |
| `build` | checkout → setup-go → `make build` | 7 个模块全部编译通过，exit 0 |
| `test` | checkout → setup-go → 安装 kind → **下载并 `sha256sum -c` 校验 kubectl** → 等 PG 就绪 → `make test-verbose` → `make residual-check` | 测试无 FAIL；末行 `residual-check: OK (no leftovers)`；**不得出现 `--- SKIP: TestNoLeftoversAfterSuite`**（出现即该目标以非零退出、job 失败） |

`kubectl` 校验步骤的 fail-closed 行为（已在 `ci.yml:118-137` 实现，`TestCI1` 守卫）：
从 `docs/tooling.md` 的平台表提取 `linux/amd64` 的 SHA；提取为空或仍是"待人工提供"→ `exit 1`；
哈希不符 → `sha256sum -c` 非零退出。两者都会中止 `test` job。

## 3. 本地与 CI 的差异清单（无法本地复现 / 口径不同）

| 维度 | CI（ubuntu-latest） | 本地（macOS darwin/arm64） | 影响 |
| --- | --- | --- | --- |
| 平台 | linux/amd64 | darwin/arm64 | `docs/tooling.md` 需按平台分别登记（已登记 kubectl 两平台、go 仅 linux） |
| kubectl 来源 | `ci.yml` 下载到 `/usr/local/bin/kubectl`（v1.31.4，`sha256sum -c`） | `.tools/kubectl`（v1.31.4，本轮实测校验）；PATH 上的 Docker Desktop 版是 **v1.36.1** | 第二十五轮 T2 起：`internal/toolpin` 只接受登记版本，版本不符即失败，**不再静默用 PATH 版本**。`.tools/` 被 gitignore，故 CI 走 PATH（装的正是 v1.31.4） |
| Go 工具链 | setup-go 按官方清单下载 | 本机 1.27.2 | 版本一致（`TestToolVersionMatchesRegistered` 断言） |
| PostgreSQL | job 的 service 容器（`postgres:16-alpine`，55432） | 常驻容器 `deploy-postgres-1`（55432） | 连接串相同；本地库里另有 72 张历史残留表（CI 是干净库，**CI 不会复现"public 表数=75"这一基线**） |
| kind 节点镜像 | runner 需现拉 `kindest/node:v1.31.0`（约 1GB） | 本机已缓存 | CI 的 `test` job 时间主要花在这里；run 2 实测 143s 说明缓存/镜像可得 |
| Docker 守护进程 | runner 自带 | Docker Desktop | 等价 |
| 环境纯净度 | 全新 runner，无本地 env | 我使用 `env -i` + 最小 PATH 模拟 | 见 §5 预演结果 |
| Action 运行时 | checkout v7.0.1 / setup-go v7.0.0（node24） | 不适用 | 由会话外在 run 1 之后升级（原因：run 1 提示 Node.js 20 弃用）；两个钉值已用官方 API 核验 tag→commit 一致 |

## 4. 首跑后需要人工粘回的内容（run 3 已全部取得，留作复核口径）

1. 三个 job 的名字与状态：`gen-check` / `build` / `test` —— 已取，均 success；
2. `test` job 日志中这两行的**原文**：
   - `make test-verbose` 汇总：已取，**顶层 459 PASS / 0 FAIL / 1 SKIP，37 个有测试的包**；
   - 残留门禁：已取，`residual-check: OK (no leftovers)` +
     `--- PASS: TestNoLeftoversAfterSuite (0.05s)`（若出现 `residual-check: FAILED`
     或 `FAILED (gate test was SKIPPED - equals no check)` 则为失败）；
3. `安装并校验 kubectl` 步骤的 `sha256sum -c` 输出：已取，`/tmp/kubectl: OK`。

后续每次推送仍按同一口径回收这四项；`/logs` 端点需鉴权（本机 PAT 可用），
公开 API 只能拿到 job/step 的 `status` 与 `conclusion`。

## 5. 本地预演（T4a）结果

在本机用 `env -i HOME=$PATH_MIN` 的最小环境逐步执行 `ci.yml` 的三个 job
（`PATH_MIN=/usr/local/bin:/usr/bin:/bin:~/.local/bin:~/go/bin:~/.docker/bin`，
并注入 `AGENT_OPS_TEST_DATABASE_URL`，与 `ci.yml` 的 env 同名同值）。

| 步骤 | 命令 | 退出码 | 耗时 | 判定 |
| --- | --- | --- | --- | --- |
| job1 | `make gen-check` | 0 | 5s | 本地 PASS（末行 `gen-check: OK`） |
| job3-测试 | `make test-verbose` | 0 | **181s** | 460 PASS / 0 FAIL / 1 SKIP（38 个有测试的包） |
| job3-残留门禁 | `make residual-check` | 0 | 6s | **`residual-check: OK (no leftovers)`**（PASS，非 SKIP） |
| job2 | `make build` | 0 | 4s | 7 个模块编译通过 |

- 预演前后残留：`test_run_*` schema **0 → 0**，`kind` 集群 **0 → 0**；
- 最小环境里的工具版本与 CI 常量一致：`go1.27.2`、`kind v0.30.0`、`GNU Make 3.81`、
  `Docker 29.8.2`；
- 最小环境里 PATH 上的 kubectl 仍是 **v1.36.1**，而 `internal/toolpin` 四次把
  Kubernetes 集成测试钉到登记的 **v1.31.4**（`[T2] kubectl 已钉到登记版本 v1.31.4`），
  `TestIntegrationReadOnlyAgainstKindCluster` 在该版本下 PASS（61.43s）；
- 那唯一一条 `--- SKIP: TestNoLeftoversAfterSuite` 出现在 `make test-verbose` 阶段
  （未设 `AGENT_OPS_RESIDUAL_CHECK=1`，属设计行为）；随后的 `make residual-check`
  步骤里该用例是**执行并通过**的——若它被 SKIP，Makefile 会以非零码退出。

> **无法本地复现的项**：`actions/checkout`、`actions/setup-go`、service 容器初始化、
> 全新 runner 的冷启动与 Go 模块缓存、kubectl 的 `sha256sum -c` 安装步骤
> （本地对应物是 `.tools/kubectl` 的事先实测）。这些只能由真实 CI 验证。
