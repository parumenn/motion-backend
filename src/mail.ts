import nodemailer from 'nodemailer';
import { pool} from './db';

// マイボード mail.ts の移植: outbox テーブルに積んでワーカーが SMTP 送信する方式。
// 送信基盤はマイボードと同一の Resend SMTP を共有する（認証情報は k8s Secret 経由）。
type Queryable = { query: (text: string, params?: any[]) => Promise<any>};

export const mailConfig = {
smtpHost: process.env.SMTP_HOST || '',
smtpPort: Number(process.env.SMTP_PORT || 465),
smtpUser: process.env.SMTP_USER || '',
smtpPass: process.env.SMTP_PASS || '',
mailFrom: process.env.MAIL_FROM || 'no-reply@parumenn.com',
publicBaseUrl: (process.env.PUBLIC_BASE_URL || 'https://motion.parumenn.com').replace(/\/$/, ''),
};

export async function enqueueMail(db: Queryable, to: string, kind: string, payload: unknown): Promise<void> {
await db.query(
`INSERT INTO mail_outbox (to_email, kind, payload, status) VALUES ($1, $2, $3, 'pending')`,
[to, kind, JSON.stringify(payload)]
);
}

function renderMail(kind: string, payload: any): { subject: string; text: string} {
switch (kind) {
case 'verify':
return {
subject: '本人確認のお願い',
text: `Motion へのご登録ありがとうございます。\n以下のURLにアクセスして本人確認を完了し、パスワードを設定してください（1時間有効）。\n\n${payload.url}\n\n心当たりがない場合は、このメールを破棄してください。`,
};
case 'reset':
return {
subject: 'パスワード再設定のご案内',
text: `パスワードの再設定がリクエストされました。\n以下のURLから再設定を行ってください（30分間有効）。\n\n${payload.url}\n\n再設定を完了すると、すべてのセッション（ログイン中の端末）とパスキーが無効化されます。APIキーは無効化されません。\n心当たりがない場合は、このメールを破棄してください（何も変更されません）。`,
};
case 'reset_done': {
const inv = payload.invalidated || {};
return {
subject: 'パスワード再設定完了のお知らせ',
text: `パスワードの再設定が完了しました。セキュリティのため、以下を無効化しました。\n\n- すべてのセッション（再ログインが必要です）\n- パスキー: ${inv.passkeys || 0}件（再登録が必要です）\n\nAPIキーは無効化していません。心当たりがない場合は、至急パスワード再設定を行ってください。`,
};
}
case 'password_changed':
return {
subject: 'パスワード変更完了のお知らせ',
text: 'パスワードの変更が完了しました。他のすべてのセッションはログアウトされました。APIキーは無効化していません。\n心当たりがない場合は、パスワード再設定からアカウントを保護してください。',
};
case 'passkey_added':
return {
subject: 'パスキー登録のお知らせ',
text: `パスキー「${payload.name || ''}」が登録されました。\n心当たりがない場合は、至急パスワード再設定を行ってください。`,
};
case 'passkey_removed':
return {
subject: 'パスキー削除のお知らせ',
text: 'パスキーが削除されました。\n心当たりがない場合は、至急パスワード再設定を行ってください。',
};
default:
return { subject: 'お知らせ', text: 'Motion からの通知です。'};
}
}

export async function processOutboxOnce(): Promise<number> {
if (!mailConfig.smtpHost) return 0;

// 送信対象を「リース」方式で確保する（next_attempt_at を先に進めて重複送信を防ぐ）
const { rows} = await pool.query(`
UPDATE mail_outbox
SET next_attempt_at = now() + interval '5 minutes'
WHERE id IN (
SELECT id FROM mail_outbox
WHERE status = 'pending'
AND (next_attempt_at IS NULL OR next_attempt_at <= now())
ORDER BY created_at ASC
LIMIT 20
)
RETURNING id, to_email, kind, payload, attempts
`);
if (rows.length === 0) return 0;

const transporter = nodemailer.createTransport({
host: mailConfig.smtpHost,
port: mailConfig.smtpPort,
secure: mailConfig.smtpPort === 465,
...(mailConfig.smtpUser && mailConfig.smtpPass
? { auth: { user: mailConfig.smtpUser, pass: mailConfig.smtpPass}}
: {}),
});

let sentCount = 0;
for (const row of rows) {
const { subject, text} = renderMail(row.kind, row.payload?? {});
try {
await transporter.sendMail({ from: mailConfig.mailFrom, to: row.to_email, subject, text});
await pool.query(`UPDATE mail_outbox SET status = 'sent', sent_at = now() WHERE id = $1`, [row.id]);
sentCount++;
} catch (err) {
console.error(`Mail send error for id ${row.id}:`, err);
const nextAttempts = row.attempts + 1;
if (nextAttempts >= 5) {
await pool.query(`UPDATE mail_outbox SET status = 'failed', attempts = $1 WHERE id = $2`, [nextAttempts, row.id]);
} else {
await pool.query(
`UPDATE mail_outbox SET attempts = $1, next_attempt_at = now() + interval '${nextAttempts * 5} minutes' WHERE id = $2`,
[nextAttempts, row.id]
);
}
}
}
return sentCount;
}

export function startMailWorker(): NodeJS.Timeout {
const timer = setInterval(async () => {
try {
await processOutboxOnce();
} catch (err) {
console.error('Mail worker error:', err);
}
}, 15000);
timer.unref();
return timer;
}
