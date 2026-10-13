# ADR-011：Docker 只读适配器的安全边界

- 状态：已接受（第十三轮修订：/info 白名单化、仓库级守卫、生产连接限制、
  docker.image.list 生产未完成状态）
- 日期：2026-10-13（第十二轮；第十三轮 2026-10-13 修订）
- 决策者：工程默认（待运维确认项已标注）

## 背景

第十二轮新增 `adapters/docker`（Docker 主机只读适配器），通过 Docker Engine API
读取守护进程与容器信息。Docker API 的能力面远大于只读：同一套 API 既能创建/启动/
删除容器与镜像，也能读取容器环境变量、挂载的宿主机路径、Swarm 节点信息与各类
凭据形态的标签。若把"只读"寄托于调用方自觉（例如"适配器只会调只读方法"），
一旦后续有人新增一个方法就会静默越界。

因此需要一份**代码层面强制**的边界决策，超出 ADR-001~010 的范围，按约束新立本 ADR。

## 决策

### 1. 只读：客户端唯一出口 + 端点白名单（强制，不依赖调用方自觉）

`adapters/docker` 的 Docker API 访问收敛到唯一出口 `Client.get`，它在发出请求前
先过 `AllowedEndpoint(method, path)` 白名单校验：

| 允许的端点（仅 GET） | 用途 | 附加约束 |
| --- | --- | --- |
| `GET /version` | 引擎版本（Discover/Health） | — |
| `GET /info` | 引擎信息 | 输出经 `MaskInfo` 屏蔽 |
| `GET /containers/json` | 容器列表 | **强制**标签过滤 `agent-ops.test=true` |
| `GET /containers/{id}/json` | 容器详情 | 仅允许带测试标签的容器；`{id}` 过名称白名单 |
| `GET /images/json` | 镜像列表 | **强制**标签过滤 `agent-ops.test=true` |

- 其余路径一律拒绝（含 `/_ping`、`/secrets`、`/services`、`/nodes`、
  `/containers/{id}/logs`、`/containers/{id}/top` 等）；
- 所有非 GET 方法一律拒绝（POST/PUT/DELETE/PATCH），
  且**包内不存在任何写方法的调用路径**（源码守卫测试断言）；
- `{id}` 必须通过 `validation.ValidContainerID`（首字符字母数字、仅
  `[A-Za-z0-9_.-]`、长度 ≤128），杜绝路径穿越与额外路径段。

### 2. 标签过滤：只碰测试对象，空列表必须明确报错

容器与镜像列表一律下发 `filters={"label":["agent-ops.test=true"]}`，
并对返回项**逐项复核**标签（不信任守护进程是否真的过滤）。
过滤后为空时返回 `ErrNoLabelledObjects`——**明确报错而非静默返回空列表**；
生产模式下不存在该标签对象，因此列表能力在生产即表现为显式错误。

### 3. 字段屏蔽：三类字段绝不外泄

屏蔽实现为纯函数（`MaskContainerInspect` / `MaskInfo` / `MaskLabels`），
返回"副本 + 被屏蔽路径列表"，原数据不被修改：

| 对象 | 屏蔽字段 |
| --- | --- |
| 容器 inspect | `Config.Env`（全部环境变量）、`Mounts[*].Source`（宿主机路径）、`HostConfig.Binds`（宿主机路径）、`Config.Labels` 中的凭据类键、任意嵌套层级的凭据类键 |
| `/info` | `Swarm`（含节点 ID/地址/密钥）、`NodeID`、`NodeAddr`、`Name`（主机名）、任意嵌套层级的凭据类键 |
| 容器/镜像列表项 | `Labels` 中的凭据类键、任意嵌套层级的凭据类键 |

凭据类键 = 键名以 `secret` / `token` / `password` 开头（大小写不敏感）。

### 4. 资源上限

每个请求 10 秒超时（`DefaultTimeout`，可配）与 1MB 响应体上限
（`DefaultMaxBodyBytes`，可配）；超限即报错，超限内容不读入内存。

### 5. 能力面与只读语义

声明 5 个能力，全部 `read_only`、`rollbackable=false`、`destructive=false`：

`docker.version`、`docker.info`、`docker.container.list`、
`docker.container.inspect_status`、`docker.image.list`

与 Linux 适配器一致：`Execute` 对只读能力直接拒绝并提示走 Diagnose/Health；
`PlanRollback` 恒返回 `ErrNoRollbackNeeded`；诊断只接受预定义问题，
自由文本与非法容器 ID 一律拒绝。

### 6. 本轮不接入网关执行路径（D3）

第十二轮只通过适配器接口自身的测试验证，不注册进网关注册表、不改动执行链路。
网关侧源码不得导入 `adapters/docker`（由测试断言守卫）。

## 修订记录

### 第十三轮修订（2026-10-13）：/info 白名单化、仓库级守卫、生产连接限制

**1. `/info` 由"删除式屏蔽"改为白名单（F1）。** 原实现删除已知敏感字段
（Swarm/NodeID/NodeAddr/Name），依赖字段清单与 Docker 版本同步——Docker 升级
新增敏感字段会直接泄露。现改为只返回以下 11 个明确字段，其余一律不返回：

`ServerVersion`、`OperatingSystem`、`Architecture`、`NCPU`、`MemTotal`、
`Containers`、`ContainersRunning`、`ContainersPaused`、`ContainersStopped`、
`Images`、`KernelVersion`

实现为纯函数 `WhitelistInfo`（返回裁剪副本 + 被裁剪字段名列表），
测试覆盖"注入未知敏感字段（Swarm.NodeAddr、Name）与白名单外普通字段
（Driver、RegistryConfig）都必须不出现"。

**2. 源码守卫由包内改为仓库级（F2）。** 原守卫只扫 `adapters/docker` 非测试文件，
把 Docker 调用搬到别的包即可绕过。现由 `internal/repoguard` 扫描**全仓**非测试
Go 文件（跳过生成代码与守卫自身）：

- 只有 `adapters/docker/client.go` 与 `adapters/kubernetes/client.go` 可以出现
  后端 HTTP 调用；
- 白名单文件内只允许 GET；
- 全仓禁止写方法常量/字面量与越界路径字面量（`/containers/create`、
  `/containers/start`、`/containers/exec`、`/secrets`、`/services`、`/nodes`、
  `/api/v1/secrets`、`serviceaccounts`、`portforward`、`pods/log`、`pods/exec` 等，
  一律带引号形式以避免误报）。

守卫本身由测试夹具验证有效（临时目录写入违规文件时必须报错）。

**3. 生产模式禁止直接使用 Docker unix socket（F3）。** socket 等价 root 权限，
直接挂载在生产不可接受。`mode=prod` 时：

- **只接受 TCP** 地址，且必须显式声明 `ReadOnlyProxy=true`（确认对端是仅开放
  GET 端点的只读代理，如 docker-socket-proxy）；
- 直接使用 unix socket 一律**拒绝启动**，错误信息说明原因（等价 root 权限、
  必须经只读代理）；
- `mode=test` 允许 unix socket 直连（本地容器/测试环境）。

**4. `docker.image.list` 在生产环境未完成（F4，标记为未完成）。**
当前实现按镜像标签 `agent-ops.test=true` 过滤；生产环境需要的是**基于镜像仓库
白名单**的方案（按 registry/repository 授权），而不是依赖镜像标签。
该方案留待后续批次，在此之前该能力在生产环境始终返回显式错误（不静默）。

## 影响

- 新增 `adapters/docker`（客户端、屏蔽规则、适配器、清单）与对应单元/集成测试；
- 集成测试使用**固定版本**小镜像（`busybox:1.36`）与唯一前缀的测试容器名
  （`agent-ops-dockertest-<纳秒>`），只创建/删除自己创建的容器；
  结束即删除并断言删除成功；Docker 不可用时 skip 并输出原因；
- 测试夹具的容器创建/删除使用 docker CLI（argv 形式）——适配器代码本身
  只发白名单 GET，两者的边界由源码守卫测试固定；
- `internal/validation` 新增 `ValidContainerID`（容器标识唯一校验来源）；
- 本机其他项目的容器与镜像一律不读取、不列出（标签过滤 + 逐项复核）；
- 第十三轮新增：`internal/repoguard`（仓库级守卫）、`internal/validation.ValidContainerID`；
  `/info` 白名单函数 `WhitelistInfo` 取代 `MaskInfo`；`Config.Mode`（必填）与
  `Config.ReadOnlyProxy`（prod 必填）为新增配置项。
