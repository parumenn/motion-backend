-- Motion ゴミ箱機能（#1）用マイグレーション
-- 適用済み: 2026-11-03（本番 DB へ直接適用）
-- 既存データがあるため IF NOT EXISTS で安全に追加する。
ALTER TABLE pages ADD COLUMN IF NOT EXISTS deleted_at timestamptz DEFAULT NULL;
