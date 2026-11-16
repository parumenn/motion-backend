import crypto from 'node:crypto';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { pool } from '../db';

// マイボード auth-utils.ts の Motion（JWT 方式）版。
// Motion にはセッション表が無いため、step-up 状態は users.last_stepup_at に持ち、
// JWT 認証のたびに DB の現在値と照合する（クライアント申告だけにしない）。

export function randomToken(bytes = 32): string {
  return crypto.randomBytes(bytes).toString('base64url');
}

export function sha256hex(input: string): string {
  return crypto.createHash('sha256').update(input).digest('hex');
}

export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, 10);
}

export async function verifyPassword(hashStr: string, password: string): Promise<boolean> {
  try {
    return await bcrypt.compare(password, hashStr);
  } catch {
    return false;
  }
}

export const PASSWORD_MIN_LENGTH = 12;
export const PASSWORD_MAX_LENGTH = 64;

export function validatePassword(password: unknown): string | null {
  if (typeof password !== 'string' || password.length < PASSWORD_MIN_LENGTH || password.length > PASSWORD_MAX_LENGTH) {
    return `パスワードは${PASSWORD_MIN_LENGTH}文字以上${PASSWORD_MAX_LENGTH}文字以内で設定してください`;
  }
  return null;
}

export function validateEmail(email: unknown): string | null {
  if (typeof email !== 'string' || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
    return 'メールアドレスの形式が正しくありません';
  }
  return null;
}

export function normalizeEmail(email: unknown): string {
  return typeof email === 'string' ? email.trim().toLowerCase() : '';
}

// JWT 発行。token_version (tv) を含め、DB 側の version と一致しない JWT を失効扱いにする。
export async function issueTokenForUser(user: { id: string; email: string; role: string }): Promise<{ token: string; user: any }> {
  const { rows } = await pool.query(
    `SELECT id, email, role, status, token_version FROM users WHERE id = $1`,
    [user.id]
  );
  const u = rows[0] ?? { ...user, status: 'approved', token_version: 0 };
  const token = jwt.sign(
    { userId: u.id, email: u.email, role: u.role, tv: Number(u.token_version) },
    process.env.JWT_SECRET as string,
    { expiresIn: '7d' }
  );
  return {
    token,
    user: { id: u.id, email: u.email, role: u.role, status: u.status },
  };
}

// 全セッション失効: token_version を上げることで既存 JWT をすべて無効化する
export async function bumpTokenVersion(userId: string): Promise<void> {
  await pool.query(`UPDATE users SET token_version = token_version + 1 WHERE id = $1`, [userId]);
}

// ---- step-up 認証（マイボード assertStepUp / markStepUp 相当） ----
export const STEP_UP_WINDOW_MS = 5 * 60 * 1000;

export async function isStepUpFresh(userId: string): Promise<boolean> {
  const { rows } = await pool.query(`SELECT last_stepup_at FROM users WHERE id = $1`, [userId]);
  if (rows.length === 0 || !rows[0].last_stepup_at) return false;
  return Date.now() - new Date(rows[0].last_stepup_at).getTime() <= STEP_UP_WINDOW_MS;
}

export async function markStepUp(userId: string): Promise<void> {
  await pool.query(`UPDATE users SET last_stepup_at = now() WHERE id = $1`, [userId]);
}

// JWT の指紋（チャレンジの発行元セッション紐付け用。マイボードの session_id 相当）
export function tokenFingerprint(req: any): string {
  const authHeader = req.headers?.['authorization'] as string | undefined;
  const token = authHeader && authHeader.split(' ')[1];
  return sha256hex(token || '');
}
