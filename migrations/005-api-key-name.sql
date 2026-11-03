-- Motion 設定モーダルからの APIキー発行機能用マイグレーション
-- 適用前バックアップ: ~/backups/motion_db-20261103-apikey.sql（適用時に取得）
-- api_keys に表示名（どのエージェント／用途向けか）を保持するカラムを追加する。
-- 既存行は NULL（UI では「名称未設定」と表示する）。
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS name VARCHAR(100);
