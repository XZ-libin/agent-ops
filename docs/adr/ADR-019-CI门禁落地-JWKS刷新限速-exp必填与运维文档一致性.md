# ADR-019：CI 门禁落地、JWKS 刷新限速、exp 必填与运维文档一致性

- 状态：已接受
- 日期：2026-10-13（第二十轮）
- 决策者：业务方裁决（本轮裁决 1–5）
- 关系：**不修改 ADR-001 至 ADR-017**。本 ADR：
  - **修订 ADR-018 §4** 的假设"`exp`/`nbf` 缺失时不做过期判定"——`exp` 改为**必填**
    （fail-closed）；ADR-018 的其余条款继续有效；
  - 把 ADR-018 §1（残留门禁）从 Makefile 约定**落地为 CI 流水线**；
  - 补齐 ADR-018 §4 中 OIDC 的两个可控硬化项（JWKS 刷新限速、一致性夹具）
    与 §2 的**下游运维口径文档**。
- 本轮**不引入新功能**（第二十轮范围裁决）：节点代理（注册、心跳、mTLS）
  推迟到第二十一轮。

## 背景

第十九轮落地 OIDC 生产认证与残留门禁后，评审指出四处问题：

1. **CI 载体缺失**：`.github/workflows/ci.yml` 只有一个 `verify` job 把
   `gen-check / build / test / residual-check` 串成步骤；"residual-check 不允许
   跳过"只是 Makefile 里的约定，无法在分支保护上单独设为必需检查。
2. **OIDC 与真实 issuer 的差异未覆盖**：本地 JWKS 只覆盖单密钥、无 `x5c`、
   `aud` 为字符串的形态；真实 issuer 常见多密钥、`kid` 轮换、`x5c`、`aud` 数组。
3. **未知 kid 可被放大**：每个未知 `kid` 都会触发一次外部 JWKS 请求；攻击者可用
   随机 `kid` 制造大量外部请求（打爆 issuer 端点 / 放大流量）。
4. **缺少 `exp` 的令牌被放行**：ADR-018 §4 的假设是"缺失时不做过期判定"，
   等于接受**永不失效**的令牌。
5. **终态语义切换没有下游口径**：`partial` 与 `not_executed` 拆分后，
   监控规则与看板若不同步更新，会把"根本没跑"误读为"部分成功"。

## 决策

### 1. CI 流水线（C1）

`.github/workflows/ci.yml` 拆为**四个独立 job**（可分别设为分支保护必需检查）：

| job | 命令 | 说明 |
| --- | --- | --- |
| `gen-check` | `make gen-check` | 生成代码一致性（ADR-002） |
| `build` | `make build` | 全模块编译 |
| `test` | `make test-verbose`（= `go test ./... -v -count=1`）+ `make residual-check` | 测试；末尾**同一 runner** 上做残留检查 |
| `residual-check` | `make residual-check` | 独立必选门禁 |

- **不得**设置 `continue on error` 语义的绕过开关；`residual-check` **不得**用
  `if` 条件跳过（由 `internal/repoguard` 的 `TestCIConfigGuards` 断言，见 §5）；
- 工具链版本**固定**：Go `1.27.2`、buf `v1.47.2`、kind `v0.30.0`、kubectl `v1.31.4`；
  来源与校验方式登记在 `docs/tooling.md`（kubectl 与 Go 采用"下载即校验"：
  分别比对官方 `.sha256` 与 setup-go 的官方清单）；
- **残留检查的两个位置**（重要）：
  1. `test` job 末尾：与测试同 runner，能看到本次测试**真实遗留**的
     kind 集群 / 测试容器 / `test_run_*` schema；
  2. 独立 `residual-check` job：作为分支保护必需检查。GitHub 托管 runner
     每个 job 环境全新，该 job **看不到** `test` job 的遗留——它验证的是
     "门禁本身可运行且 runner 干净"。真正的"测试后遗留检测"由 (1) 承担。

### 2. JWKS 刷新速率限制（O1）

- 未知 `kid` 触发的 JWKS 刷新，两次之间间隔**不得短于 30 秒**
  （`DefaultRefreshInterval`，经注入时钟控制）；
- 间隔不足时**直接拒绝该令牌且不发起任何外部请求**
  （`ErrOIDCRefreshRateLimited`）；
- **已知 `kid` 不受限速影响**（命中缓存，不触发刷新）；
- 限速闸门"先占位再请求"，避免并发请求同时通过；
- 启动期初始化刷新同样计入限速窗口（启动后 30 秒内的首个未知 `kid` 不会立刻
  触发第二次外部请求）。

### 3. `exp` 必填（O2，修订 ADR-018 §4）

- **缺少 `exp` 的令牌一律拒绝**（`ErrOIDCMissingExpiry`）；`exp ≤ 0` 同样拒绝；
- `nbf` **仍可选**：缺失（0）时不做未生效判定；
- 过期判定仍允许 ±60 秒时钟偏差（ADR-018 §4 不变）；
- **修订说明**：ADR-018 §4 曾假设"`exp`/`nbf` 缺失时不做过期/未生效判定"。
  该假设对 `exp` 是**放宽**（等价于接受永不失效的令牌），本轮改为 fail-closed；
  对 `nbf` 的假设保留（部分 issuer 不发 `nbf`）。

### 4. JWKS 一致性夹具（O3）

在 `gateway/internal/grpcwire/testdata/jwks/` 下新增**合成**样本，覆盖真实
issuer 的常见形态：

| 样本 | 覆盖形态 |
| --- | --- |
| `multi-key.jwks.json` + `multi-key.token.txt` | 3 个 RSA 公钥（不同 `kid`）；由第 2 把签发 |
| `kid-rotation.jwks.json` + 两个令牌 | 旧 `kid` 与新 `kid` **并存**（轮换过渡期） |
| `with-x5c.jwks.json` + 令牌 | 带 `x5c` / `x5t` 字段（**解析时忽略**，不影响校验） |
| `aud-array.jwks.json` + 令牌 | `aud` 为**数组** |

- **只含公开部分**：生成器（`testdata/jwks/gen/main.go`）只在内存中持有 RSA 私钥，
  落盘的只有 JWK 公开参数与已签名令牌；私钥随进程退出丢弃；
- 样本是**合成的**：`iss` 固定为 `https://fixtures.invalid/issuer`（保留域名），
  **不对应任何真实身份提供商**；生成过程见 `testdata/jwks/README.md`；
- 仓库级断言：`testdata` 中不得出现 PEM 私钥标记
  （`TestJWKSFixturesContainNoPrivateKeys` 与仓库级 `TestNoPrivateKeysCommittedInRepo`）。

### 5. 运维文档与代码一致性（O4）

- 新增 `docs/ops/terminal-states.md`：四种终态（`done` / `partial` /
  `not_executed` / `failed`）的含义、能力结果组合、建议告警条件（含阈值默认值）、
  需同步更新的监控项清单（8 项）、排查指引；
- **一致性由测试断言**（`alerts/internal/executor/terminal_doc_test.go`）：
  从代码读取终态常量（`executor.TerminalPlanStates()` / `PlanStateMeanings()`）
  与文档比对——文档漏写或多写终态即失败；终态表里不得出现非终态
  （`running` / `planned` / `no_rule`）；
- 文档必须明确区分 `partial`（部分成功）与 `not_executed`（一个能力都没执行），
  并引用 ADR-018 作为拆分依据。

### 6. CI 配置守卫（C1 的机器可检查化）

`internal/repoguard` 新增 `TestCIConfigGuards`，对 `.github/workflows/ci.yml` 断言：

1. 不出现 `continue on error` 语义的绕过开关；
2. `residual-check` job 不使用 `if` 跳过；
3. 四个独立 job 均存在；
4. `residual-check` 真正执行 `make residual-check`；
5. 工具链版本固定（不得出现浮动主版本的 `go-version`）。

## 影响

- `.github/workflows/ci.yml`：由单 job `verify` 改为四独立 job；
- `Makefile`：新增 `test-verbose`（`go test ./... -v -count=1`）；
- `docs/tooling.md`：新增"CI 使用的工具链"表（版本 + 获取方式 + 校验方式）；
- `internal/repoguard/ciworkflow_test.go`（新增）：CI 配置守卫；
- `gateway/internal/grpcwire/oidc.go`：新增 `DefaultRefreshInterval`、
  `OIDCConfig.RefreshInterval`、`allowRefresh`、`RefreshCount`、
  `ErrOIDCRefreshRateLimited`、`ErrOIDCMissingExpiry`；`exp` 改为必填；
- `gateway/internal/grpcwire/oidc_test.go`：新增 O1 ①②③④ 与 O2 ①②③；
  更新未知 `kid` 用例（先推进时钟越过限速窗口）；
- `gateway/internal/grpcwire/testdata/jwks/`（新增）：夹具 + 生成器 + README；
- `gateway/internal/grpcwire/fixtures_test.go`（新增）：夹具一致性测试；
- `alerts/internal/executor/executor.go`：新增 `TerminalPlanStates()` /
  `PlanStateMeanings()`；
- `alerts/internal/executor/terminal_doc_test.go`（新增）：文档一致性测试；
- `docs/ops/terminal-states.md`（新增）：运维文档；
- ADR-018 §4 关于 `exp` 缺失的假设以本 ADR 为准；其余条款继续有效。

## 未决 / TODO

- **真实 issuer 联调**：需要业务方提供测试 issuer 地址（issuer / audience /
  JWKS URL）；作为**上线前门禁**单独列出，本轮未完成；
- **GitHub 分支保护**：`gen-check` / `build` / `test` / `residual-check`
  四个 job 需人工在 GitHub 仓库设置中设为必需检查（代码无法代替）；
- **首次 CI 运行**：本轮仅在本地逐条模拟各 job 的命令序列，**未在 GitHub 上执行**；
  首次运行结果（含 linux/amd64 的 kubectl 与 Go 工具链 SHA-256 实测值）需回填
  `docs/tooling.md`；
- **JWKS 定时刷新**：当前仅"未知 `kid` 触发 + 30 秒限速"，未实现定时刷新与
  `Cache-Control` 遵从；
- **`x5c` 校验**：当前**忽略** `x5c`（只信 `n`/`e`）；若后续要求证书链校验，
  需另行记录；
- **节点代理（注册 / 心跳 / mTLS）**：第二十一轮范围。
