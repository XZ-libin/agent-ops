# ADR-009：幂等哈希的 JSON 规范化规则

- 状态：已接受
- 日期：2026-10-12（第九轮，R5）
- 决策者：工程默认（跨语言互操作为目标，黄金测试钉死实现）

## 背景

第八轮网关以「请求内容的规范化 JSON → sha256 hex」作为幂等判断与审批记录绑定
的哈希输入。该哈希将被 TypeScript 客户端与 Python 客户端复算（同键不同内容
→ 422 的判定依赖三方哈希一致），必须有一份跨语言可对齐的规范化规则。

## 决策

### 哈希输入（域）

网关执行请求的以下字段按表定顺序构成一个 JSON 对象：

| 序 | 键 | 取值 |
| --- | --- | --- |
| 1 | `actor` | 操作人字符串 |
| 2 | `key` | 幂等键字符串 |
| 3 | `capability` | 能力名字符串 |
| 4 | `params` | 请求参数独立 JSON 对象（见下），无参数时为 `null` |
| 5 | `asset_id` | 目标资产 ID 字符串，无目标时为 `""` |
| 6 | `access` | 接入方式枚举名（如 `ACCESS_SSH`），未指定为 `""` |
| 7 | `environment` | 环境枚举名（如 `ENVIRONMENT_TEST`），未指定为 `""` |
| 8 | `impact_scope` | `Action.impact_scope` 原文，缺失为 `""` |
| 9 | `freeze_window` | 布尔 |

**凭据引用（CredentialRef）不参与哈希，也不进入任何存储与审计 payload。**

### 规范化规则

1. 编码：RFC 8259 JSON，紧凑无空白，输出字节 UTF-8。
2. 键序：固定字段按上表顺序；嵌套对象（`params` 及其内层对象）的键按 Unicode
   码点升序排序（等于对 ASCII 的字典序）。
3. 字符串转义：仅 `"` `\` 与控制字符（`\b \f \n \r \t`，其余 <0x20 以 `\u00XX`
   小写十六进制）。`<` `>` `&` 与非 ASCII 字符**不转义**、原样 UTF-8 输出
   （与 JSON.stringify 一致；Go 端须等价于 `json.Encoder`+`SetEscapeHTML(false)`，
   Python 端 `ensure_ascii=False`）。
4. 数字：JSON number 的最短往返表示；整数值不带小数点（`2.0` → `2`）。
5. 空值：缺失的可选字段为 `null`；空对象 `{}`、空数组 `[]`；布尔小写
   `true`/`false`。
6. 指纹：`sha256(规范化字节)` 的 64 位小写 hex。

### 黄金测试与附录

黄金哈希钉在 `TestCanonicalRequestHashGolden`（gateway/internal/gateway）：

- 规范化 JSON：
  `{"actor":"ops-lead","key":"golden-key-1","capability":"diagnose.service_state","params":{"count":2,"flag":true,"note":"a<b","unit":"nginx"},"asset_id":"ast_01HX","access":"ACCESS_SSH","environment":"ENVIRONMENT_TEST","impact_scope":"single","freeze_window":true}`
- sha256 黄金值：
  `759950041a723c4af52ac3deb7d140c331e252d3d0296331b7bc7dffdf746893`

后续 TS / Python 客户端实现幂等哈希时，须以上述规范化 JSON 为输入、黄金值为
验收基准。

## 影响

- gateway/internal/gateway/requtil.go 的 canonicalJSON 是 Go 侧唯一实现；
- 任何对规范化规则的修改必须先改本 ADR 并更新黄金测试。