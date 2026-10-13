-- 0002_alerts_fingerprint_pk.down.sql（第十六轮 R4；第十七轮 P2 改为**无损**）
--
-- 目的：回到旧结构（id 主键、received_at、每次告警一行）。
--
-- 无损恢复（第十七轮 P2）：
--   本脚本从 up 脚本创建的备份表 test_alerts_pre_0002 **原样恢复**：
--   删除聚合后的表，把备份表改名为 test_alerts（结构与数据均为原始状态，
--   行与行逐列相等），并恢复序列名。备份表在恢复后**删除**。
--
--   备份表缺失时脚本立即失败（说明 up 未执行或备份被人工删除）。
--
-- 约束：同 up 脚本，作用于当前 search_path 指向的 schema；不得对 public 执行。

BEGIN;

-- 0) 备份表必须存在（否则无法无损恢复）。
DO $$
BEGIN
    IF to_regclass('test_alerts_pre_0002') IS NULL THEN
        RAISE EXCEPTION '备份表 test_alerts_pre_0002 不存在：无法无损恢复（up 是否已执行？）';
    END IF;
END $$;

-- 1) 删除聚合后的表（数据由备份表恢复）。
DROP TABLE test_alerts;

-- 2) 备份表原样恢复为 test_alerts（结构与数据均为原始状态）。
ALTER TABLE test_alerts_pre_0002 RENAME TO test_alerts;

-- 3) 序列与索引改名，恢复旧结构的命名。
ALTER SEQUENCE test_alerts_pre_0002_id_seq RENAME TO test_alerts_id_seq;
ALTER SEQUENCE test_alerts_id_seq OWNED BY test_alerts.id;
ALTER INDEX test_alerts_pre_0002_fingerprint_idx RENAME TO test_alerts_fingerprint_idx;

COMMIT;
