// Package audit 是审计模块的骨架占位（ADR-005）：
// 只追加、独立 schema 与角色（仅 INSERT）、触发器禁止 UPDATE/DELETE、
// 哈希链 + 外部对象锁锚点。
package audit
