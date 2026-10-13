# 计划终态（terminal states）运维说明

适用范围：`alerts` 告警链路的**诊断计划**（表 `test_diagnosis_plans.status`）。

代码来源：`alerts/internal/executor`（终态常量与判定逻辑）。
**本文档与该代码的一致性由测试断言**（`TestTerminalStatesDocMatchesCode`）：
文档漏写或多写终态都会让测试失败。

相关决策：ADR-016 §4（终态判定）、ADR-018 §2（`not_executed` 与 `partial` 的拆分）、
ADR-017 §2 / ADR-018 §3（`interrupted` 归属 `failed`）。

---

## 1. 终态一览

| 终态 | 含义 | 能力结果组合 | 是否终态 | 是否可自动恢复 |
| --- | --- | --- | --- | --- |
| `done` | 全部能力执行成功 | 所有能力 `ok` | 是 | — |
| `partial` | **部分成功**：至少一个能力执行成功，且至少一个被拒绝或推迟 | `ok ≥ 1` 且 `denied + no_cluster_configured + deferred ≥ 1` | 是 | 否（需人工处置被拒项） |
| `not_executed` | **一个能力都没有执行** | `ok = 0` 且 `failed = 0`，全部为 `denied` / `no_cluster_configured` / `deferred` | 是 | 否（多为配置缺口，需人工修复） |
| `failed` | 任一能力执行失败（含 `interrupted`） | `failed ≥ 1` | 是 | 否（需人工重投或重新规划） |

### 非终态（不要按终态消费）

| 状态 | 含义 | 说明 |
| --- | --- | --- |
| `planned` | 已规划、待执行 | 等待 worker / 测试驱动执行 |
| `running` | 已被 CAS 抢占、尚未落终态 | **中间态**；正常路径下会很快落终态。长期停留 = 进程被强杀，由对账 `ReconcileRunning` 标记为 `failed(stale_running)`，**不自动重跑** |
| `no_rule` | 无匹配规则 | 规划器未生成能力清单，**不会被执行器抢占**（不产生结果行） |
| `deferred` | 全部能力被推迟 | 当前实现**无产生路径**（K8s 已改为真实执行，见 ADR-017），保留以备将来 |

---

## 2. 结果行状态（能力粒度）

计划终态由各能力的**结果行状态**汇总而来（表 `test_diagnosis_results.status`）：

| 结果状态 | 含义 |
| --- | --- |
| `ok` | 能力执行成功 |
| `denied` | 被拒绝（未声明能力 / 非只读 / 策略判定非 auto） |
| `no_cluster_configured` | 需要集群的能力在未配置集群时未执行（不静默降级） |
| `deferred` | 被推迟（当前无产生路径） |
| `failed` | 执行失败（含停止宽限期耗尽被取消） |

判定优先级：`failed` 最高；其次 `ok ≥ 1` → `done` 或 `partial`；
`ok = 0` → `not_executed`。

---

## 3. 建议的告警条件

> 阈值（N 分钟）为**工程默认值，待运维确认**。

| 终态 / 状态 | 建议告警 | 级别 | 建议条件（默认值） |
| --- | --- | --- | --- |
| `not_executed` | **应告警** | 警告 | 同一 `profile` 在 **N=15 分钟**内出现 ≥1 条 `not_executed`，或 `not_executed` 占比 > 50% |
| `not_executed`（原因含 `no_cluster_configured`） | **应告警** | 严重 | 出现即告警：说明集群未配置，该画像**完全没有诊断覆盖**（ADR-017 §1） |
| `failed`（原因含 `interrupted`） | **应告警** | 警告 | 5 分钟内 ≥3 条：说明收到停止信号且宽限期（30s）不够，需检查能力耗时 |
| `failed`（其他原因） | **应告警** | 严重 | 出现即告警：执行失败意味着诊断链路对该故障无效 |
| `partial` | **需关注，不建议直接告警** | 信息 | 建议做趋势看板；若同一 `profile` 的 `partial` 占比持续上升（> 30%）再告警 |
| `done` | 不告警 | — | 可作为"诊断链路健康"的基线指标 |
| `running` 长期停留 | **应告警** | 严重 | 停留 > 10 分钟：说明存在被强杀的残留，需人工确认后重新规划/重投 |
| `planned` 长期停留 | **应告警** | 警告 | 停留 > 15 分钟且无 `running`：说明 worker 未运行或已停止 |
| `no_rule` | 需关注 | 信息 | 占比持续升高说明规则表未覆盖该告警源（ADR-016 §1） |

---

## 4. 需要同步更新的监控项 / 看板

> **重要**：`partial` 与 `not_executed` 的语义在第十九轮发生拆分（ADR-018 §2）。
> 任何在第十九轮之前建立的监控规则/看板**必须**按下表核对更新，否则会把
> "根本没跑"（`not_executed`）误读为"部分成功"（`partial`）。

| # | 监控项 | 需要做什么 | 状态 |
| --- | --- | --- | --- |
| 1 | 计划终态分布面板（按 `status` 分组） | 新增 `not_executed` 序列；确认原有 `partial` 序列口径已收窄 | 待运维执行 |
| 2 | `partial` 告警规则 | 确认不再把"全部未执行"计入；如原规则是 `status = 'partial'`，需拆分 | 待运维执行 |
| 3 | 新增 `not_executed` 告警规则 | 按 §3 的阈值新增 | 待运维执行 |
| 4 | `interrupted` 专项计数 | 按 `reason LIKE 'interrupted%'` 建独立指标（与普通 `failed` 区分） | 待运维执行 |
| 5 | `running` 停留时长指标 | 新增（对账前的残留预警） | 待运维执行 |
| 6 | 能力粒度结果分布（`test_diagnosis_results.status`） | 新增 `no_cluster_configured` 序列 | 待运维执行 |
| 7 | 审计事件 `diagnosis.interrupted` 计数 | 新增（与 `diagnosis.executed` / `diagnosis.denied` / `diagnosis.no_cluster_configured` 并列） | 待运维执行 |
| 8 | 值班手册 / Runbook | 补充"`not_executed` 首要原因排查路径"（配置缺口 vs 策略拒绝） | 待运维执行 |

---

## 5. 排查指引（简版）

1. **看到 `not_executed`**：读 `reason` 的"首要原因"——
   - 含 `no_cluster_configured` → 检查 `AGENT_OPS_K8S_KUBECONFIG` 是否配置；
   - 含"被拒绝" → 读各能力结果行的 `reason`（未声明 / 非只读 / 策略非 auto）。
2. **看到 `failed` 且 `reason` 含 `interrupted`**：说明收到停止信号且当前能力在
   30 秒宽限期内未完成；检查该能力的实际耗时与 `CapabilityTimeout`。
3. **看到 `running` 长期停留**：进程被强杀。确认无存活 worker 后执行对账
   （`ReconcileRunning` → `failed(stale_running)`），再**人工**重新规划或重投
   （**不自动重跑**，见 ADR-018 §3）。
