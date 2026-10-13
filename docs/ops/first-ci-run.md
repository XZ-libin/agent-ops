# 首次 CI 运行：预期、已观察到的结果与需回收的内容

> **第二十四轮：本地闭环；CI 未验证。**
> 本文档写于第二十五轮（T4 CI 预演）。第二十五轮的**代码**改动（T2 工具版本钉定、
> T3 保留开关、T2c 守卫）**尚未提交，不被任何 CI 记录覆盖**；
> 唯一例外是 T1 的 `docs/tooling.md` 修正被会话外的提交 `03130ec` 一并提交推送，
> 因而被 run 2 覆盖（该 run 的 test job 里 `TestCI2/TestCI3` 解析的正是修正后的登记表）。

---

## 1. 已在 GitHub 公开 API 观察到的运行记录（无凭据读取）

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

**两点必须说清楚的保留意见：**

1. 这两个 run 覆盖的是**第 24 轮工作树**，不是本轮改动。本轮结论仍是"CI 未验证"。
2. 步骤 9 的**日志正文**需要鉴权才能取（`/logs` 端点），本轮不使用任何 GitHub 凭据，
   因此**没有拿到 `residual-check: OK (no leftovers)` 那一行原文**。
   能证明的只有：该步骤 `conclusion=success`，且 `Makefile` 的 `residual-check` 目标在
   用例被 SKIP 时会以非零码退出（"SKIP 不计入通过"），所以 success 蕴含"门禁真实执行且未发现残留"；
   但这是**推理**，不是原文。请人工把日志里那一行贴回来确认（见 §4）。

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

## 4. 首跑后需要人工粘回的内容

1. 三个 job 的名字与状态（`gen-check` / `build` / `test`）；
2. `test` job 日志中这两行的**原文**：
   - `make test-verbose` 的汇总（各模块 `ok`/`FAIL`，或 `PASS` 总数）；
   - 残留门禁那一行：应为 `residual-check: OK (no leftovers)`，
     若出现 `residual-check: FAILED ...` 或 `residual-check: FAILED (gate test was SKIPPED - equals no check)` 则视为失败；
3. `安装并校验 kubectl` 步骤中 `sha256sum -c` 的输出行（应为 `/tmp/kubectl: OK`）。

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
