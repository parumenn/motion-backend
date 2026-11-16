-- シークレット暗号化／復号モーダル用のユーザ鍵（2026-11-17）
-- 鍵はユーザ単位にランダムな 256bit を払い出し、base64 で保管する。
-- 暗号文そのものはサーバに保存しない（エンドポイントは変換のみを行う）。
CREATE TABLE IF NOT EXISTS user_secret_keys (
    user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    key_b64 text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
