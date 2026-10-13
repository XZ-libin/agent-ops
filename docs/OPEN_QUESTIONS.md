# 待决策问题清单

整理时间：2026-10-12（第二轮答复后更新）。
原则：未确认事项不自行决定；已答复条目分别落实为「决策」或「工程默认值」，
工程默认值在代码注释中以「默认值，待运维确认」标注。

## 一、已决策（2026-10-12 答复）

- **Q1** ADR-001 已按指示写入 docs/adr/。
- **Q2 契约唯一源**：protobuf 为唯一源；OpenAPI 由 proto 生成，手写定义已删除（api/ 只存生成产物）。生成管道接入列入第四节待办。
- **Q3 诊断服务接入方式**：诊断服务作为 outbox 事件消费者，控制层不直接调用诊断服务（ADR-003）。

## 二、工程默认值（已按默认执行，标注「默认值，待运维确认」）

| 编号 | 事项 | 工程默认值 | 标注位置 |
| --- | --- | --- | --- |
| Q4 | 网关/节点 Agent 通道参数 | 心跳周期 30s；连续 3 次未心跳判离线；指令签名 Ed25519（双向流消息形状随执行通道批次定义） | gateway.proto、gateway/internal/agent |
| Q10 | 幂等键有效期 | 24 小时 | ADR-002、deploy/migrations |
| Q11 | 对象存储 | S3 兼容存储；本地开发/测试用 MinIO，以 Object Lock 实现 WORM；生产平台待运维确认 | ADR-005 |
| Q14 | 模型网关 | 自研薄封装（脱敏 → 托管 API → 用量与延迟记录），不引入现成网关 | ADR-004、diagnostics |
| Q15 | 诊断会话上限 | 单次 ≤ 50 步；总耗时 ≤ 30 分钟；单资产并发诊断 ≤ 2 | ADR-004、diagnostics |
| Q16 | 资产摘要字段与健康状态取值 | 占位字段集 id/asset_type/environment/status；status ∈ healthy/degraded/unhealthy | capability.proto、gateway.proto |
| Q17 | outbox 运行参数 | 轮询间隔 1s；事件保留 30 天 | ADR-003、internal/event |
| Q18 | TS/Python 生成链路接入时机 | 下一批次接入（web/ diagnostics 开始消费生成类型时），本批次仅打通 Go | ci.yml、diagnostics/pyproject.toml |

## 三、保持 TODO（不自行决定）

- **Q5** 首批数据库种类：公司实际使用哪几种数据库——决定首批公共组件适配器范围。
- **Q6** 低风险自动执行清单逐条确认（含无状态 Pod 重启的 10% 副本比例）。
- **Q7** 审批超时（候选：默认 30 分钟，生产高风险 2 小时）与能力超时（候选：只读 60s、执行类 300s）。
- **Q8** 审计与录像保留期限（候选：审计 ≥1 年；录像 90 天、>30 天转冷存储）——以安全与合规确认为准。
- **Q9** 各环境变更冻结窗口、审批人名单；成功标准数值（建议两周基线后定目标）。
- **Q12** 公司是否已有云厂商 KMS：有则优先复用，否则部署 Vault。
- **Q13** 历史故障评测样本由谁提供与维护；脱敏字段清单。

## 四、由上述决策引入的后续批次待办

1. OpenAPI 生成管道接入：gateway.proto 补 HTTP 注解，接入 proto→OpenAPI 插件，gen-check 覆盖生成的 OpenAPI（Q2）。
2. TS（openapi-typescript）/ Python（datamodel-code-generator）生成接入 Makefile 与 CI（Q18）。
3. 控制层↔网关双向流消息形状定义：指令/回执/心跳（Q4）。
4. 诊断服务 outbox 消费者实现（Q3）。