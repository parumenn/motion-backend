-- Motion 設定の端末間同期（R2-8）用マイグレーション
-- 適用前バックアップ: ~/backups/motion_db-20261103-prefs.sql
-- users に設定 JSON を持たせる。既存行は空オブジェクトで初期化する。
ALTER TABLE users ADD COLUMN IF NOT EXISTS prefs JSONB NOT NULL DEFAULT '{}'::jsonb;
