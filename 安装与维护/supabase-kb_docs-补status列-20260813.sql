-- 纳川云同步：kb_docs 补 status 列（2026-08-13 企业级知识库升级配套）
-- ★何时才需要：仅当你启用纳川云同步时才需要执行。2026-08-13 实测本机
--   云同步未启用、未配置（load_cfg: enabled=False, 无 url/key），不启用则本脚本无需执行。
-- 背景：启用后客户端会在同步载荷里带 status 字段；远端缺列时 PostgREST 返回 400，
-- kb_docs 推送会静默丢批（其他表不受影响）。
-- 用法：Supabase 仪表盘 → 左侧 SQL Editor → New query → 粘贴本文件全部内容 → Run。
-- 安全性：只加列带默认值，不动存量数据，可反复执行（IF NOT EXISTS 幂等）。

ALTER TABLE public.kb_docs ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'active';

-- 验证（应返回 1 行：status | text | active）：
SELECT column_name, data_type, column_default
FROM information_schema.columns
WHERE table_name = 'kb_docs' AND column_name = 'status';
