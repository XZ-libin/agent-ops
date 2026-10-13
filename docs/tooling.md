# 外部二进制与工具来源记录（docs/tooling.md）

本文件记录本项目使用/下载的**外部二进制**：名称、版本、下载 URL、SHA-256 与用途。
规则（第十四轮 H3 裁决）：

1. 任何外部二进制**必须先记录**（名称、版本、URL、SHA-256）**再使用**；
2. 下载后必须校验 SHA-256，校验失败即停止，不得使用；
3. 未经本文件声明的下载一律不允许。

## 已声明并校验

| 名称 | 版本 | 来源 URL | SHA-256 | 用途 | 校验记录 |
| --- | --- | --- | --- | --- | --- |
| kind | v0.30.0 (go1.27.2 darwin/arm64) | 经 Go module proxy：`go install sigs.k8s.io/kind@v0.30.0`（模块代理 `proxy.golang.org`） | `1f9b705cd82503f3cd8176022325cb469290dfbd589785b101fc9739a8c66c8e` | Kubernetes 集成测试：创建/删除临时 kind 集群 | 第十四轮记录（构建自模块源码，非二进制下载；SHA-256 为本机产物实测值） |
| kubectl | v1.31.4 (darwin/arm64) | `https://dl.k8s.io/release/v1.31.4/bin/darwin/arm64/kubectl` | `a756bb911298a85af35c0111c371728a26c532d504fe8b534eb684501fcaf996` | Kubernetes 集成测试夹具：创建/删除测试命名空间与 Pod | 第十四轮补录（第十三轮下载时未记录，属流程缺陷，已按裁决补录并加入本表）；**第二十五轮 T1 修正**：原登记值第 27 位为 `0`（`…c370728a…`），官方校验文件与产物实测均为 `1`（`…c371728a…`） |
| buf | v1.47.2 | 经 Go module proxy：`go install github.com/bufbuild/buf/cmd/buf@v1.47.2` | `a71f9500cc4bb7db592a46f4b2718ac849c3a604fa3324004bdb60b40d670f83` | protobuf 代码生成与 lint/breaking 检查（`make gen`） | 第十四轮记录（构建自模块源码） |

## CI 使用的工具链（第二十轮 C1；第二十四轮 T4 改为五字段登记 + 强制校验）

CI（`.github/workflows/ci.yml`）固定使用下列版本。**未引入任何新的本地下载。**

### 登记格式（每个条目必须包含五个字段）

| 字段 | 含义 |
| --- | --- |
| **名称** | 工具名（与 `ci.yml` 中的引用一致） |
| **版本** | 固定版本（不得为 `latest`） |
| **平台** | `darwin/arm64`、`linux/amd64` 等；跨平台条目需分别登记 |
| **SHA-256** | **二进制本身**的校验值（64 位十六进制）；模块代理获取的条目标注获取方式 |
| **来源 URL** | 下载地址（或模块路径） |

> **规则（硬性约束 6）**：CI 中**每个下载外部二进制的步骤**都必须在使用前执行
> `sha256sum -c`（或等价的逐字节比对），校验值取本表。**实现者不得自行填写 SHA 值**——
> 只能来自官方校验文件并由人工确认。

### 平台相关条目（CI 使用 linux/amd64）

| 名称 | 版本 | 平台 | SHA-256 | 来源 URL |
| --- | --- | --- | --- | --- |
| kubectl | v1.31.4 | linux/amd64 | `298e19e9c6c17199011404278f0ff8168a7eca4217edad9097af577023a5620f` | `https://dl.k8s.io/release/v1.31.4/bin/linux/amd64/kubectl` |
| go | 1.27.2 | linux/amd64 | `ecbadb99091a3f46e31f5f934b068b1864eafa7995211b39eaddf76996045fe5` | `https://go.dev/dl/go1.27.2.linux-amd64.tar.gz` |

> **状态：已回填（2026-10-13，按人工指示从官方校验文件取值）**。取值来源与方法：
>
> - `kubectl`：官方同目录校验文件明文单行
>   `curl -fsS https://dl.k8s.io/release/v1.31.4/bin/linux/amd64/kubectl.sha256`；
> - `go`：官方下载清单 `https://go.dev/dl/?mode=json`（golang.org 发布数据）中
>   `go1.27.2` 的 `files[].sha256`（`filename=go1.27.2.linux-amd64.tar.gz`，
>   size=70590635），**间隔重取两次结果一致**。
>   说明：`https://go.dev/dl/go1.27.2.linux-amd64.tar.gz.sha256sum` 直链返回的是
>   HTML 重定向页而非纯文本，`dl.google.com` 在本机 TLS 握手不通，故采用官方 JSON 清单；
>   CI 侧 `setup-go` 另有官方清单校验兜底。
>
> 守卫测试 `TestCI2_ToolingHasNoPendingSHAForCIBinaries` 自此转绿。
> **人工确认待办**：值由助手按指示从官方文件抓取，仍建议复核一次
> （复核命令：`curl -fsS https://dl.k8s.io/release/v1.31.4/bin/linux/amd64/kubectl.sha256`）。
> 本机为 darwin/arm64，无法离线推导 linux/amd64 的哈希值。

### 非平台相关条目（本地开发与构建）

| 名称 | 版本 | 平台 | SHA-256 | 来源 URL |
| --- | --- | --- | --- | --- |
| kind | v0.30.0 | darwin/arm64（本机实测） | `1f9b705cd82503f3cd8176022325cb469290dfbd589785b101fc9739a8c66c8e` | 模块代理：`sigs.k8s.io/kind@v0.30.0`（`go install`） |
| kubectl | v1.31.4 | darwin/arm64（本机实测） | `a756bb911298a85af35c0111c371728a26c532d504fe8b534eb684501fcaf996` | `https://dl.k8s.io/release/v1.31.4/bin/darwin/arm64/kubectl` |
| buf | v1.47.2 | 模块（跨平台） | `a71f9500cc4bb7db592a46f4b2718ac849c3a604fa3324004bdb60b40d670f83` | 模块代理：`github.com/bufbuild/buf/cmd/buf@v1.47.2`（`go run`） |
| protoc-gen-go | v1.36.1 | 模块（跨平台） | 经 Go module 校验和数据库（`go.sum`） | `google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.1` |
| protoc-gen-go-grpc | v1.5.1 | 模块（跨平台） | 经 Go module 校验和数据库（`go.sum`） | `google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.5.1` |

**模块代理获取的条目**（kind / buf / protoc-gen-*）：不经 HTTP 下载二进制，
其完整性由 Go module 校验和数据库（`go.sum` + `sum.golang.org`）保证，
因此在 CI 中**不需要**额外的 `sha256sum -c` 步骤（守卫测试按"来源 URL 含
`dl.k8s.io`/`go.dev` 等 HTTP 下载地址"识别需要校验的条目）。

**postgres**（`postgres:16-alpine` 容器镜像）：由 GitHub Actions `services` 拉取，
镜像摘要由 registry 提供，非二进制下载，本表规则不适用。

## 使用但不由本项目下载（环境自带）## 使用但不由本项目下载（环境自带）

| 名称 | 来源 | 用途 | 说明 |
| --- | --- | --- | --- |
| docker CLI | Docker Desktop 自带（`/Applications/Docker.app/Contents/Resources/bin/docker`） | 本地容器夹具（sshd 测试容器、Docker 适配器测试容器）与镜像预载 | 环境自带，不由本项目下载 |
| go toolchain | `/Users/x/.local/go/bin/go`（1.27.x） | 构建与测试 | 环境自带 |
| protoc-gen-go / protoc-gen-go-grpc | 经 Go module proxy：`google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.1`、`google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.5.1` | protobuf 代码生成插件 | 构建自模块源码 |

## 下载记录

### 第二十七轮：**本轮无新外部二进制；新增一个 Go 依赖（守卫用）**

- 控制台只读 API 的契约一致性守卫需要解析 `openapi/console.yaml`，因此根模块新增依赖
  `gopkg.in/yaml.v3 v3.0.1` —— 与 `adapters` 模块**同一固定版本**（第二十二轮起已在用），
  经 Go module proxy 获取、由 `go.sum`/sum.golang.org 校验，**不是二进制下载**，本表规则按
  第二十二轮 `oklog/ulid` 的先例登记；本机 module cache 已有该版本，本轮未产生新的网络下载；
- 证书与令牌全部使用 Go 标准库（`crypto/rsa`、`crypto/sha256`、`encoding/base64`、
  `encoding/json`），**未引入任何第三方 JWT/JWKS 库**（沿用 ADR-019 的裁决）；
- 测试夹具的 RSA 密钥与 JWKS **运行时生成、仅存内存**，不落盘、不入数据库；
- 未新增任何外部二进制：`kubectl`/`kind`/`buf`/`go` 版本与校验值全部沿用本表既有登记。

### 第二十五轮（T1）：**修正登记值，无新增外部二进制。**

- **darwin/arm64 kubectl v1.31.4 的 SHA-256 登记错误已修正**：
  - 旧值：`a756bb911298a85af35c0111c370728a26c532d504fe8b534eb684501fcaf996`
  - 新值：`a756bb911298a85af35c0111c371728a26c532d504fe8b534eb684501fcaf996`
  - 差异位置：**第 27 位**（十六进制串内 0-based 索引 26）旧 `0` → 新 `1`；
  - 来源：官方校验文件 `https://dl.k8s.io/release/v1.31.4/bin/darwin/arm64/kubectl.sha256`；
  - 实测：下载 `https://dl.k8s.io/release/v1.31.4/bin/darwin/arm64/kubectl`
    共 **56,560,802 字节**，`shasum -a 256` 与官方值逐字符一致；
  - 取值日期：2026-10-13；修正位置：本表"已声明并校验"行与"平台相关条目"表各一处；
  - 性质：**转写错误**（单字符），非上游重签名（同一 URL 的产物哈希与官方校验文件一致）。
- **linux/amd64 两值再次核对**（T1e，方法同上）：
  - kubectl `298e19e9…5620f` ↔ 官方 `.sha256` 一致，产物实测 56,381,592 字节一致；
  - go 1.27.2 `ecbadb99…45fe5` ↔ `https://dl.google.com/go/go1.27.2.linux-amd64.tar.gz.sha256`
    一致，产物实测 70,590,635 字节一致（本机 `dl.google.com` TLS 可达，与第二十四轮
    会话外说明"本机握手不通"不同，属环境差异，不影响取值）。
- 本轮**未新下载任何未在表内登记的二进制**；darwin 版 kubectl 仅为本轮校验用途，
  临时产物置于 `/tmp`，不进入仓库、不参与构建。

### 第二十四轮：**本轮无新外部二进制。**

- 第二十四轮（证书状态机 + 周期扫描 + 时钟回退加固 + CI 校验）未下载任何新二进制；
- 新增的 `test_node_certs` 与 `test_node_sweep_state` 两张表由 PostgreSQL DDL 创建
  （`internal/nodemigrate` 迁移 004/005），不涉及外部工具；
- **CI 的 kubectl 与 Go 的 linux/amd64 SHA-256 已回填**（见上文"平台相关条目"，
  2026-10-13 按人工指示取自官方校验文件），`TestCI2_ToolingHasNoPendingSHAForCIBinaries`
  的合并阻断条件已解除。

### 第二十三轮：**本轮无新外部二进制。**

- 第二十三轮（D6 + 持久化 + Renew + 补发 + 审计覆盖）未下载任何新二进制，
  也未引入新的 Go 依赖：证书/CSR/密钥全部使用 Go 标准库
  （`crypto/ecdsa`、`crypto/x509`、`crypto/tls`、`encoding/pem`），
  ULID 沿用第二十二轮已登记的 `github.com/oklog/ulid/v2 v2.1.2`；
- 测试 CA、节点密钥与令牌**运行时生成、仅存内存**（`identity.pem` 只在测试临时目录）；
- 新增迁移只使用 PostgreSQL DDL（`ALTER TABLE ... ADD/DROP COLUMN`、`CHECK`），
  不涉及外部工具。

### 第二十二轮：**本轮无新的本地下载。**

- 第二十二轮（D1–D5 修正 + N6–N8 补齐）未下载任何新二进制；
- **新增一个 Go 依赖**（以固定版本写入 `go.mod`，经 Go module proxy 获取，非"二进制下载"）：
  `github.com/oklog/ulid/v2 v2.1.2` —— 用于 `node_id`（`nod_<ULID>`）生成，
  替换此前自实现的 ULID 编码（D5：标识符不自研）；
- 证书与 CA 全部使用 Go 标准库（`crypto/ecdsa`、`crypto/x509`、`crypto/rand`、`crypto/tls`），
  **未引入任何第三方证书/JWT 库**；测试 CA 与节点私钥**运行时生成、仅存内存**。

### 第二十一轮：**本轮无新的本地下载。**

- 第二十一轮为设计 + 纯单元范围（CI 前置条件未满足，见 ADR-020 §10），
  未在本地下载任何新二进制；
- 节点侧协议为 gRPC（`google.golang.org/grpc` 已在 contract 模块依赖中），
  **未引入任何第三方 JWT / 证书库**——CA 与证书全部使用 Go 标准库
  （`crypto/ecdsa`、`crypto/x509`、`crypto/rand`、`encoding/pem`）；
- 测试 CA 与节点密钥**运行时生成、仅存内存**，不落盘、不提交。

### 第二十轮：**本轮无新的本地下载。**

- 第二十轮只新增 CI 配置（`.github/workflows/ci.yml`）与文档，未在本地下载任何
  新二进制；CI 期获取的工具链版本、来源与校验方式见上文"CI 使用的工具链"表；
- 唯一的"新增获取项"是 CI 期下载的 **kubectl linux/amd64** 与 **Go linux/amd64
  工具链**——两者均为**下载即校验**（比对官方 `.sha256` / setup-go 官方清单），
  具体 SHA-256 值待首次 CI 运行成功后回填（本机为 darwin/arm64，无法离线推导）。

### 第十九轮：**本轮无新下载。**

- 第十九轮未引入任何新的外部二进制；OIDC 的 JWKS/JWT 校验**只用 Go 标准库**
  （`crypto/rsa`、`crypto/sha256`、`encoding/base64`、`encoding/json`、`net/http`），
  未引入任何第三方 JWT/JWKS 库；
- 测试密钥在运行时生成（RSA 2048），JWKS 由本地 httptest 提供，不落盘、不入库。

### 第十八轮：**本轮无新下载。**

- 第十八轮未引入任何新的外部二进制；Kubernetes 集成测试复用第十四轮已登记的
  kind v0.30.0（本机 `~/go/bin/kind`）、kubectl（本机 PATH：
  `/Users/x/.docker/bin/kubectl`，v1.36.1）与本地已缓存的
  `kindest/node:v1.31.0` 节点镜像；
- 另复用环境自带的 docker CLI 与 `busybox:1.36` 镜像（Docker 只读适配器测试容器）。

### 第十七轮：**本轮无新下载。**

- 第十七轮未引入任何新的外部二进制；仅复用已登记的 docker CLI（环境自带）、
  sshd 测试容器与本地 Docker 守护进程。

### 第十六轮：**本轮无新下载。**

### 第十四轮：**本轮无新下载。**

- kind / kubectl 为第十三轮安装，第十四轮仅**补录**来源与 SHA-256；
- 第十四轮与第十六轮均未引入任何新的外部二进制。

## 校验方法

```sh
# 二进制文件（本机已存在的产物）
shasum -a 256 <path-to-binary>

# 与官方发布校验和比对（下载式二进制，以 kubectl 为例）
curl -fsSL https://dl.k8s.io/release/v1.31.4/bin/darwin/arm64/kubectl.sha256
```

校验失败即停止使用并报告；不得"先跑通再补记录"。
