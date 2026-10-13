# ADR-012：Kubernetes 只读适配器的安全边界

- 状态：已接受
- 日期：2026-10-13（第十三轮）
- 决策者：工程默认（待运维确认项已标注）

## 背景

第十三轮新增 `adapters/kubernetes`（Kubernetes 只读适配器）。Kubernetes API 的
能力面比 Docker 更大：同一套 API 既能读 Pod/Deployment，也能读 Secret、执行
`pods/exec`、端口转发、删除资源。Secret 一旦被读取，等于把集群里所有凭据暴露给
诊断链路——因此本 ADR 在 Docker 边界（ADR-011）之上追加一条**硬性规则**：
**永不读取 Secret**。

## 决策

### 1. 只读：客户端唯一出口 + 端点白名单

访问收敛到唯一出口 `Client.get`，发出请求前先过 `AllowedEndpoint(method, path)`：

| 允许的端点（仅 GET） | 用途 | 附加约束 |
| --- | --- | --- |
| `/version` | 集群版本（Discover/Health） | — |
| `/api/v1/namespaces/{ns}` | 命名空间读取 | 仅带测试标签的命名空间 |
| `/api/v1/namespaces/{ns}/pods` | Pod 列表 | 强制 `labelSelector=agent-ops.test=true` |
| `/api/v1/namespaces/{ns}/pods/{name}` | Pod 详情 | 仅限带测试标签的 Pod |
| `/apis/apps/v1/namespaces/{ns}/deployments` | Deployment 列表 | 强制同一标签选择器 |

- 命名空间名与对象名分别过 `validation.ValidK8sNamespace` / `ValidK8sName`
  （RFC 1123 子集），杜绝路径穿越与额外路径段；
- 其余路径一律拒绝（`/api/v1/nodes`、`/api/v1/namespaces`、configmaps、services、
  serviceaccounts、`pods/*/status`、`statefulsets`、`pods/{name}/log|exec|attach|portforward` 等）；
- 所有非 GET 方法一律拒绝（POST/PUT/PATCH/DELETE），且包内不存在写方法调用路径
  （由 `internal/repoguard` 仓库级守卫断言）。

### 2. 永不读取 Secret（硬性规则）

`secretPathPattern = (?i)/secrets?(/|$)` 命中即拒绝，且**优先于白名单判断**：
`/api/v1/secrets`、`/api/v1/namespaces/{ns}/secrets`、`/api/v1/namespaces/{ns}/secrets/{name}`
等一律在客户端内部拒绝，**不发往集群**（测试断言集群侧零请求）。
ServiceAccount token 相关路径（`serviceaccounts`、`token`）同样拒绝。

### 3. 屏蔽规则（纯函数，可单测）

| 对象 | 删除的字段 |
| --- | --- |
| Pod | `spec.containers[*].env`、`envFrom`；`spec.initContainers[*].env`、`envFrom`；`metadata.annotations` 中键名以 `secret`/`token`/`password`/`credential` 开头的项；`spec.volumes[*]` 中 `secret`/`configMap`/`projected`/`downwardAPI`/`csi`/`persistentVolumeClaim` 数据源（保留卷 `name` 与其余非数据源字段） |
| Deployment | 同上，作用于 `spec.template.spec` 与 `spec.template.metadata`（避免经 Deployment 泄露） |
| Namespace | `metadata.annotations` 中的凭据类键 |

**追加（集成测试发现，第十三轮）**：`kubectl.kubernetes.io/last-applied-configuration`
注解由 `kubectl apply` 写入，**内嵌完整清单 JSON**（含 env 取值与 secret 类注解
原值）。只按"键名前缀"删除会经它泄露——已在真实 kind 集群上复现并修复：
该注解（及任何键名含 `last-applied` 的注解）整条删除；
`metadata.managedFields` 一并删除（含 last-applied 字段路径与大量无关元数据，
诊断不需要；工程默认）。

### 4. 标签过滤与空列表语义

命名空间、Pod、Deployment 只返回带 `agent-ops.test=true` 标签的对象，
并对返回项**逐项复核**标签（不信任服务端是否真的过滤）。
过滤后为空 → `ErrNoLabelledObjects`（明确报错，不静默返回空列表）。

### 5. 连接方式与运行模式

| 模式 | 连接方式 | 说明 |
| --- | --- | --- |
| `test` | kubeconfig 文件路径 | 仅本地 kind 等测试集群；`insecure-skip-tls-verify` 仅此模式可达 |
| `prod` | ServiceAccount | 本轮**仅实现接口与配置校验**（APIServer 必须 https、TokenFile/CAFile 必填），**不做生产连接** |

模式必须显式指定（空串即拒绝）。

### 6. 资源上限与只读语义

10 秒超时、1MB 响应体上限（均可配）。5 个能力全部 `read_only`、
`rollbackable=false`、`destructive=false`：`k8s.version`、`k8s.namespace.get`、
`k8s.pod.list`、`k8s.pod.status`、`k8s.deployment.list`。
`Execute` 对只读能力直接拒绝并提示走 Diagnose/Health；`PlanRollback` 恒返回
`ErrNoRollbackNeeded`；诊断只接受预定义问题，自由文本一律拒绝。

### 7. 本轮不接入网关执行路径

与 Docker 适配器一致（D3）：只通过适配器接口自身的测试验证，
网关侧源码不得导入 `adapters/kubernetes`。

## 影响

- 新增 `adapters/kubernetes`（客户端、屏蔽规则、适配器、清单）与单元/集成测试；
- 集成测试使用本地 kind 集群（默认集群名 `agent-ops-itest`）+ 测试命名空间前缀
  `agent-ops-k8stest-<纳秒>`，只操作自己创建的资源；结束删除命名空间并断言删除成功；
  kind/kubectl 不可用时以"未验证"标记 skip（不计入通过）；
- `internal/validation` 新增 `ValidK8sNamespace` 与 `ValidK8sName`；
- 仓库级守卫（`internal/repoguard`）同时覆盖本包：只有
  `adapters/kubernetes/client.go` 可以出现集群 HTTP 调用，且只允许 GET。
