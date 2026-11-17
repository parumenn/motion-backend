-- step-up 再認証をユーザ単位からトークン（セッション）単位へ紐付ける
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_stepup_token_fp text;
