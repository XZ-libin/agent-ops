-- 0002_alerts_fingerprint_pk.up.sql（第十六轮 R4；第十七轮 P2 改为**无损**）
--
-- 目的：把 test_alerts 从"每次告警一行（id 主键、received_at）"升级为
--       "每个 fingerprint 一行（fingerprint 主键、window_start、upsert 计数）"。
--
-- 无损保证（第十七轮 P2）：
--   1. 修改前先把 test_alerts **完整复制**到备份表 test_alerts_pre_0002
--      （结构相同：自带 id 序列、主键与索引；数据逐行复制）；
--   2. 若备份表已存在，脚本**立即失败**（防止覆盖既有备份）；
--   3. down 脚本从备份表原样恢复，因此本迁移是**可逆**的。
--
-- 约束：本脚本使用**未限定表名**，作用于当前 search_path 指向的 schema。
--       迁移测试在独立 run schema 中执行；**不得**对 public 模式执行。
--       生产环境仍必须先做全量备份（见运维手册），这一条不因脚本自带备份而豁免。

BEGIN;

-- 0) 备份表必须不存在（否则立即失败，不覆盖既有备份）。
DO $$
BEGIN
    IF to_regclass('test_alerts_pre_0002') IS NOT NULL THEN
        RAISE EXCEPTION '备份表 test_alerts_pre_0002 已存在：拒绝执行迁移（请先人工确认并清理）';
    END IF;
END $$;

-- 1) 复制旧表结构与数据到备份表（结构与旧表一致：自带序列、主键、索引）。
CREATE TABLE test_alerts_pre_0002 (
    id          bigserial   PRIMARY KEY,
    source      text        NOT NULL,
    severity    text        NOT NULL CHECK (severity IN ('info','warning','critical')),
    asset_id    text        NOT NULL,
    fingerprint text        NOT NULL,
    summary     text        NOT NULL DEFAULT '',
    received_at timestamptz NOT NULL,
    count       bigint      NOT NULL DEFAULT 1,
    first_seen  timestamptz NOT NULL,
    last_seen   timestamptz NOT NULL
);

CREATE INDEX test_alerts_pre_0002_fingerprint_idx
    ON test_alerts_pre_0002 (fingerprint, received_at DESC);

INSERT INTO test_alerts_pre_0002
    (id, source, severity, asset_id, fingerprint, summary, received_at, count, first_seen, last_seen)
SELECT id, source, severity, asset_id, fingerprint, summary, received_at, count, first_seen, last_seen
FROM test_alerts;

-- 备份表的 id 序列推进到与数据一致（后续插入不冲突）。
SELECT setval(pg_get_serial_sequence('test_alerts_pre_0002', 'id'),
              GREATEST((SELECT COALESCE(MAX(id), 0) FROM test_alerts_pre_0002), 1));

-- 2) 新结构（临时名）+ 按 fingerprint 聚合旧数据。
CREATE TABLE test_alerts_new (
    fingerprint  text        PRIMARY KEY,
    source       text        NOT NULL,
    severity     text        NOT NULL CHECK (severity IN ('info','warning','critical')),
    asset_id     text        NOT NULL,
    summary      text        NOT NULL DEFAULT '',
    count        bigint      NOT NULL DEFAULT 1,
    window_start timestamptz NOT NULL,
    first_seen   timestamptz NOT NULL,
    last_seen    timestamptz NOT NULL
);

INSERT INTO test_alerts_new
    (fingerprint, source, severity, asset_id, summary, count, window_start, first_seen, last_seen)
SELECT
    fingerprint,
    (array_agg(source   ORDER BY last_seen DESC))[1],
    (array_agg(severity ORDER BY last_seen DESC))[1],
    (array_agg(asset_id ORDER BY last_seen DESC))[1],
    (array_agg(summary  ORDER BY last_seen DESC))[1],
    SUM(count),
    MIN(first_seen),
    MIN(first_seen),
    MAX(last_seen)
FROM test_alerts
GROUP BY fingerprint;

-- 3) 替换旧表（备份表已保留原始数据）。
DROP TABLE test_alerts;
ALTER TABLE test_alerts_new RENAME TO test_alerts;

COMMIT;
