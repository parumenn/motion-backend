-- Motion 楽観ロックの同一ミリ秒ウィンドウ解消（R2-9）用マイグレーション
-- 適用前バックアップ: ~/backups/motion_db-20261103-revision.sql
-- pages に更新回数カウンタを追加し、PUT の競合判定を整数比較で行う。
-- 既存行は 0 で初期化する（初回保存で 1 になる）。
ALTER TABLE pages ADD COLUMN IF NOT EXISTS revision INTEGER NOT NULL DEFAULT 0;
