-- Motion ページ並び順（#3）用マイグレーション
-- 適用前バックアップ: ~/backups/motion_db-20261103-sortorder.sql
-- 既存データがあるため IF NOT EXISTS で安全に追加する。
ALTER TABLE pages ADD COLUMN IF NOT EXISTS sort_order INTEGER NOT NULL DEFAULT 0;
-- 既存行の初期順序：親ごとに created_at 順で 0,1,2,... を振る
-- （新規行は API 側で末尾に自動配置されるため、この初期化は一度きりでよい）
WITH ranked AS (
  SELECT id, ROW_NUMBER() OVER (PARTITION BY user_id, parent_id ORDER BY created_at ASC, id ASC) - 1 AS rn
  FROM pages
)
UPDATE pages p SET sort_order = r.rn FROM ranked r WHERE p.id = r.id;
CREATE INDEX IF NOT EXISTS pages_user_parent_sort_idx ON pages (user_id, parent_id, sort_order);
