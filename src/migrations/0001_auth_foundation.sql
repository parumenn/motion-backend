-- Motion 認証基盤（マイボード踏襲, 2026-11-16）
-- パスキー / メール認証シーケンス / JWT 失効 / step-up の土台を作る。
-- 既存ユーザー（approved）は移行でメール確認済みに倒し、ロックアウトを防ぐ。

-- 1) users 拡張
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified_at timestamptz;
ALTER TABLE users ADD COLUMN IF NOT EXISTS token_version integer NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_stepup_at timestamptz;
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_login_disabled boolean NOT NULL DEFAULT false;

-- 既存の承認済みユーザーはメール所有確認済みとして扱う（FUJIWARA 本人の移行）
UPDATE users SET email_verified_at = COALESCE(email_verified_at, created_at, now())
 WHERE status = 'approved';

-- 2) メールトークン（本人確認 / パスワードリセット）
CREATE TABLE IF NOT EXISTS email_tokens (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind text NOT NULL CHECK (kind IN ('verify', 'reset')),
    token_hash text NOT NULL,
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    request_ip text,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_email_tokens_token_hash ON email_tokens (token_hash);

-- 3) メール outbox（マイボード mail.ts 方式）
CREATE TABLE IF NOT EXISTS mail_outbox (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    to_email text NOT NULL,
    kind text NOT NULL CHECK (kind IN ('verify', 'reset', 'reset_done', 'password_changed', 'passkey_added', 'passkey_removed')),
    payload jsonb,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'sent', 'failed')),
    attempts int NOT NULL DEFAULT 0,
    next_attempt_at timestamptz,
    sent_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_mail_outbox_status_next ON mail_outbox (status, next_attempt_at);

-- 4) パスキー（マイボード passkeys テーブル + Backup 状態保存）
CREATE TABLE IF NOT EXISTS passkeys (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id text UNIQUE NOT NULL,
    public_key text NOT NULL,
    name text NOT NULL,
    sign_count bigint NOT NULL DEFAULT 0,
    credential_device_type text,
    backed_up boolean,
    last_used_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- 5) WebAuthn チャレンジ（単回消費・期限付き）
--    token_fingerprint は発行元 JWT の SHA-256。登録系・step-up 系は発行セッション
--    （= JWT）に紐付け、ログイン前（auth）は NULL のまま使う（マイボードの session_id 相当）。
CREATE TABLE IF NOT EXISTS webauthn_challenges (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid REFERENCES users(id) ON DELETE CASCADE,
    challenge text NOT NULL,
    kind text NOT NULL CHECK (kind IN ('register', 'auth', 'stepup')),
    token_fingerprint text,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_user ON webauthn_challenges (user_id, kind, expires_at);
