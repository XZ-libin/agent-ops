# deploy/migrations

PostgreSQL 迁移占位。随各模块实现批次落地：

- `idempotency_keys` 表（ADR-002：按「操作人 + 接口 + key」隔离，有效期 24 小时——工程默认值，待运维确认）；
- outbox 表（ADR-003：轮询间隔 1s、事件保留 30 天——工程默认值，待运维确认）；
- 审计独立 schema、独立角色（仅 INSERT）与禁止 UPDATE/DELETE 的触发器（ADR-005）；
- 主库业务表（ADR-001）。

本阶段不写入任何 schema，避免与待确认参数绑定（docs/OPEN_QUESTIONS.md）。