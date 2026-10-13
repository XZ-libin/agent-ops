# JWKS 一致性测试夹具（合成样本）

本目录存放 OIDC 校验的**合成**测试样本，用于覆盖真实 issuer 的常见形态差异
（多密钥、`kid` 轮换、`x5c` 字段、`aud` 数组）。

## 重要声明

- **全部样本都是合成的**，`iss` 固定为 `https://fixtures.invalid/issuer`
  （`.invalid` 是保留域名，**不对应任何真实身份提供商**）；
- **本目录不含任何私钥**：生成器只在内存中持有 RSA 私钥，进程退出即丢弃；
  落盘的只有 JWK 的公开参数（`n` / `e`）与已签名令牌；
- 令牌是**合成令牌**，不对应任何真实主体，也不含任何真实凭据；
- 有测试断言本目录不出现 PEM 私钥标记（`TestJWKSFixturesContainNoPrivateKeys`
  与仓库级 `TestNoPrivateKeysCommittedInRepo`）。

## 样本清单

| 文件 | 覆盖形态 | 预期 |
| --- | --- | --- |
| `multi-key.jwks.json` | 3 个 RSA 公钥，kid 分别为 `mk-1` / `mk-2` / `mk-3` | 解析出 3 个 kid；每个 kid 都能取到公钥 |
| `multi-key.token.txt` | 由 `mk-2` 签发的令牌 | 验签通过（证明"多密钥中正确的那一把被选中"） |
| `kid-rotation.jwks.json` | 旧 kid `rot-old` 与新 kid `rot-new` **并存** | 两个 kid 都能解析、都能验签（轮换过渡期） |
| `kid-rotation.old.token.txt` | 由 `rot-old` 签发 | 通过 |
| `kid-rotation.new.token.txt` | 由 `rot-new` 签发 | 通过 |
| `with-x5c.jwks.json` | 同一公钥额外带 `x5c`（合成占位串）与 `x5t` | 解析时**忽略** `x5c`，仍能取到 RSA 公钥 |
| `with-x5c.token.txt` | 由 `x5c-1` 签发 | 通过（`x5c` 不影响校验） |
| `aud-array.jwks.json` | 单密钥，kid `aud-arr-1` | 解析通过 |
| `aud-array.token.txt` | 载荷 `aud` 为**数组** `["other-service","agent-ops-gateway"]` | 数组内含配置的 audience → 通过 |

## 生成过程（可复现）

生成器源码：`gen/main.go`（同目录下的 `gen/` 子包）。它位于 `testdata/` 之下，
因此 `go build ./...` 与 `go test ./...` 的包匹配不会包含它。

```sh
# 在仓库根目录执行（会覆盖本目录下的样本文件）
go run ./gateway/internal/grpcwire/testdata/jwks/gen
```

生成器行为：

1. 用 `crypto/rand` 生成若干把 **RSA 2048** 私钥（仅内存）；
2. 把每把公钥按 JWK（`kty=RSA`、`alg=RS256`、`use=sig`、`n`、`e`）写入
   `*.jwks.json`——**只写公开参数**；
3. 用 `crypto/sha256` + `rsa.SignPKCS1v15` 签发 RS256 令牌，写入 `*.token.txt`；
4. 固定声明：`iss=https://fixtures.invalid/issuer`、`sub=fixture-operator`、
   `nbf=1700000000`（2023-11-14）、`exp=2000000000`（2033-05-18），
   保证在任何合理的测试时钟下都有效；
5. 进程退出，私钥随内存丢弃——**不落盘、不入库、不进版本库**。

> 重新生成会得到**全新的密钥与令牌**，测试断言与样本内容无关（只依赖形态与预期
> 结果），因此重跑生成器不会破坏测试；但会让 `git diff` 出现变化。

## 测试如何消费这些样本

`fixtures_test.go`（同包）用固定时钟读取本目录样本：

- `OIDCAuth` 的 `JWKSFetcher` 指向样本文件（`NewFileJWKSFetcher`），
  因此走的是**真实解析 + 真实验签**路径，而不是替身；
- 令牌从 `*.token.txt` 读取后放入 `authorization: Bearer` metadata，
  经 `Authenticate` 完整校验；
- 断言失败即测试失败（不会因样本变化而静默通过）。
