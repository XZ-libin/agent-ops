# ADR-017：Kubernetes 只读执行边界与测试模式 worker 单实例锁

- 状态：已接受
- 日期：2026-10-13（第十八轮）
- 决策者：业务方裁决（本轮裁决 1–5）
- 关系：**不修改 ADR-001 至 ADR-015**；本 ADR **修订 ADR-016 §4** 中
  "kubernetes 能力记为 deferred（本轮不执行）"的决定——自本轮起 Kubernetes
  只读能力与 Linux / Docker 走同一条真实执行路径。ADR-016 的其余条款继续有效。

## 背景

第十七轮落地只读诊断执行器后，评审指出两处问题：

1. **Kubernetes 长期 deferred 不可接受**：`alertmanager` 画像的计划会永远停在
   `deferred`，K8s 类故障在告警链路中**没有诊断覆盖**，链路在该类故障上形同虚设。
2. **执行器循环未接入常驻进程**：consumer / planner / executor 只能由测试驱动，
   `cmd/alerts` 只跑 HTTP 入口，生产/准生产形态缺失。

另有一处残留：第十七轮开发期一次失败用例留下的 `test_run_*` schema（Q1 已清理）。

## 决策

### 1. Kubernetes 只读能力纳入执行器（修订 ADR-016 §4）

执行路径与 Linux / Docker **完全一致**：

```
CAS 抢占（planned → running）
  → 注册表存在性检查（未声明 → denied）
  → 只读性检查（非 read_only / destructive / test_only → denied）
  → **policy.Evaluate**（必须 auto 且 tier=read_only，否则 denied）
  → 集群配置检查（未配置 → no_cluster_configured）
  → 调用 kubernetes 适配器**只读方法**（Discover / Diagnose）
  → 写 test_diagnosis_results
  → 写审计（diagnosis.executed / diagnosis.denied / diagnosis.no_cluster_configured）
```

- **集群来源**：仅测试自建 kind 集群（名称 `agent-ops-itest-<纳秒>`），
  **自建自删**——测试结束（含失败）删除，并断言 `kind get clusters` 无
  `agent-ops-itest-*` 残留；允许用 `AGENT_OPS_K8S_KUBECONFIG` 复用外部集群
  （调试用，此时不负责删除）。不连接任何真实集群。
- **未配置集群**：`AGENT_OPS_K8S_KUBECONFIG` 未设置时，需要集群的能力记为
  结果状态 **`no_cluster_configured`**，原因写明缺少该环境变量；
  计划终态为 **`partial`**（**不得静默降级，也不得记为 `done`**）。
  该状态由 `CapEntry.RequiresCluster` + `Config.ClusterConfigured` 判定，
  判定发生在 **policy 闸门之后、适配器调用之前**，因此不会发出任何请求。
- **Secret 永不请求**（沿用 ADR-012）：
  1. 客户端对 `secrets?` 路径直接拒绝（白名单判定之前）；
  2. 新增**请求观测钩子** `kubernetes.Config.Observe(method, path)`：每次
     **真正发出** HTTP 请求之前回调（被拒绝的路径不触发）。测试用它做
     **HTTP 层计数**，断言 `/secrets` 请求数为 **0**。
- **屏蔽与第十三轮白名单一致**：结果中不得出现容器 `env` 值与注解原值
  （`last-applied-configuration` 整条删除、`managedFields` 删除）。

### 2. 测试模式 worker（新增，接入 `cmd/alerts`）

- 新增参数 **`-worker`**（布尔，默认关闭）；**仅 `-mode=test` 允许**，
  `mode=prod` 开启即**拒绝启动**；
- 循环顺序固定：**consumer → planner → executor**，每轮批量上限
  **consumer 100 / planner 50 / executor 50**，轮询间隔默认 **5s**，
  间隔与睡眠可注入（测试不真实等待）；
- **单实例**：启动时在**专用连接**上取 PostgreSQL advisory lock
  （`pg_try_advisory_lock`，固定键 `0x41474F5053574B31`，即 ASCII `AGOPSWK1`）；
  取不到锁 → **拒绝启动**（`ErrLockHeld`），**不允许并行处理**；
  advisory lock 是会话级的，因此必须由同一连接持有与释放（释放幂等）；
- **优雅停止**：收到 SIGINT / SIGTERM 后取消上下文；
  **不再进入下一阶段**，当前阶段用**与取消解耦的上下文**（`context.WithoutCancel`
  + 阶段超时）跑完，因此不会留下"CAS 已置 `running` 但无终态结果"的残留；
- **对账兜底**：强杀（SIGKILL）/ 崩溃等无法优雅停止的场景，由
  `executor.ReconcileRunning` 把 `running` 且结果未写齐的计划标记为
  `failed`（原因 `stale_running`）。宁可人工重新规划/重投，也不把不确定结果
  记为成功。

### 3. 新增状态与原因

| 名称 | 归属 | 含义 |
| --- | --- | --- |
| `no_cluster_configured` | 结果状态 | 需要集群的能力在未配置集群时未执行 |
| `diagnosis.no_cluster_configured` | 审计动作 | 对应审计事件 |
| `stale_running` | 计划原因 | 对账把残留 `running` 计划标记为 `failed` 的原因 |

计划终态补充规则：**全部能力为 `no_cluster_configured` → `partial`**
（明确区别于 `done`）。

### 4. 只读能力接线集中在 `alerts/internal/diagcaps`

- `diagcaps.Build` 是**唯一**的生产接线路径（worker 与集成测试共用），
  避免"生产一套、测试一套"；
- 只注册只读能力（`tier=read_only`、`destructive=false`、`test_only=false`）；
- **部分配置一律 fail-closed**：例如给了 SSH 地址却没给密钥 → `Build` 直接报错；
  配置了 kubeconfig 却没给命名空间 → 报错；
- 完全未配置的家族仍注册能力项（调用即报错），因此计划会**显式失败**，
  不会静默成功。

## 影响

- `alerts/internal/executor/executor.go`：删除 `k8s.* → deferred` 分支；
  新增 `CapEntry.RequiresCluster`、`Config.ClusterConfigured`、
  `StatusNoClusterConfigured`、`ActionNoClusterConfigured`、
  `ReasonNoClusterConfigured`、`ReasonStaleRunning`；
  新增 `RunOnceLimit`（批量上限）、`StaleRunning`、`ReconcileRunning`；
  结果表 CHECK 扩展为 `('ok','denied','deferred','failed','no_cluster_configured')`；
- `alerts/internal/diagcaps/`（新增）：linux / docker / kubernetes 只读能力接线；
- `alerts/internal/worker/`（新增）：测试模式 worker + advisory lock + 审计适配器；
- `alerts/cmd/alerts/main.go`：新增 `-worker` 与 `buildWorker`；
- `alerts/internal/{consumer,planner}`：新增 `RunOnceLimit`（默认值不变）；
- `adapters/kubernetes/client.go`：新增 `Config.Observe` 请求观测钩子（生产留空）；
- `internal/k8stest/`（新增）：kind 集群测试夹具（自建自删 + 残留断言）；
- `alerts/internal/chain/`：新增 W2 三类画像端到端集成用例；
- ADR-016 的其余条款（画像匹配、无损迁移、人工重投、执行器边界）继续有效。

## 未决 / TODO

- **worker 的生产形态**：生产（`-mode=prod`）下的 worker 需要独立的
  服务账号、连接池、限流与可观测性设计；本轮只在测试模式开启；
- **多实例横向扩展**：当前用 advisory lock 强制单实例；若未来需要多实例，
  需要按"计划分片"重新设计（并同步修订本 ADR）；
- **Kubernetes 生产连接**：`mode=prod` 的 ServiceAccount 连接与 CA 校验
  （ADR-012 已定边界，实现仍待排期）；
- **人工重投的生产流程**：`redrive` 目前仅测试模式（ADR-016 §3），
  生产重投的审批与权限模型待运维确认；
- **规则表内容**：R-001~R-007 仍为"最小心智模型"，具体能力组合待运维确认。
