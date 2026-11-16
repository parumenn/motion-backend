import express from 'express';
import crypto from 'crypto';
import { pool } from '../db';
import { authenticateToken, requireWriteAccess, requireStepUp } from '../middleware/auth';

const router = express.Router();

// シークレット暗号化／復号は「人間のログインセッション（JWT）」専用にする。
// APIキーでは使わせない（apiKeys ルートと同じ方針）。
// 復号は平文を取り出す操作なので、ルート側で step-up 認証（直近5分以内の
// 再認証）を必須とする。暗号化は平文を預けるだけなので step-up は不要。
router.use(authenticateToken, requireWriteAccess);

// 暗号文フォーマット: "mv1:" + base64(nonce(12) || ciphertext || authTag(16))
// 鍵はユーザ単位の 256bit。暗号文はサーバに保存せず、変換のみを行う。
// 平文・暗号文は絶対にログへ出さないこと。
const FORMAT_PREFIX = 'mv1:';
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const MAX_PLAINTEXT_CHARS = 4096;
const MAX_CIPHERTEXT_CHARS = 16384;

// ユーザ鍵を取得する。無ければランダムに生成して登録する（初回利用時の遅延払い出し）。
// 同時リクエストでも競合しないよう INSERT ... ON CONFLICT DO NOTHING の後に再 SELECT する。
async function getOrCreateUserKey(userId: string): Promise<Buffer> {
  const existing = await pool.query('SELECT key_b64 FROM user_secret_keys WHERE user_id = $1', [userId]);
  if (existing.rows.length > 0) {
    return Buffer.from(existing.rows[0].key_b64, 'base64');
  }
  const key = crypto.randomBytes(32);
  await pool.query(
    'INSERT INTO user_secret_keys (user_id, key_b64) VALUES ($1, $2) ON CONFLICT (user_id) DO NOTHING',
    [userId, key.toString('base64')]
  );
  const created = await pool.query('SELECT key_b64 FROM user_secret_keys WHERE user_id = $1', [userId]);
  return Buffer.from(created.rows[0].key_b64, 'base64');
}

// 復号失敗のレート制限（auth.ts のログイン制限と同じインメモリ方式）
// ・ユーザごと：15分あたり失敗20回まで（他人の暗号文の総当たり・タグ検証の試行を抑止）
// ・プロセス全体：15分あたり失敗200回まで
// ・成功時はそのユーザのカウンタを消去する
// ・複数 Pod では Pod ごとにカウンタを持つため実効上限は Pod 数倍になるが、
//   総当たりの抑止としては十分な水準（ログイン制限と同じ割り切り）。
const DECRYPT_WINDOW_MS = 15 * 60 * 1000;
const MAX_FAILED_PER_USER = 20;
const MAX_FAILED_GLOBAL = 200;

type FailedBucket = { count: number; resetAt: number };
const failedByUser = new Map<string, FailedBucket>();
let globalFailed: FailedBucket = { count: 0, resetAt: 0 };

function pruneExpiredBuckets(now: number): void {
  if (globalFailed.resetAt !== 0 && now >= globalFailed.resetAt) {
    globalFailed = { count: 0, resetAt: 0 };
  }
  for (const [key, bucket] of failedByUser) {
    if (now >= bucket.resetAt) failedByUser.delete(key);
  }
}

function isDecryptLimited(userId: string, now: number): boolean {
  pruneExpiredBuckets(now);
  const perUser = failedByUser.get(userId);
  if (perUser && perUser.count >= MAX_FAILED_PER_USER) return true;
  if (globalFailed.count >= MAX_FAILED_GLOBAL) return true;
  return false;
}

function recordDecryptFailure(userId: string, now: number): void {
  pruneExpiredBuckets(now);
  const perUser = failedByUser.get(userId);
  if (perUser) {
    perUser.count += 1;
  } else {
    failedByUser.set(userId, { count: 1, resetAt: now + DECRYPT_WINDOW_MS });
  }
  if (globalFailed.resetAt === 0) globalFailed.resetAt = now + DECRYPT_WINDOW_MS;
  globalFailed.count += 1;
}

function clearDecryptFailures(userId: string): void {
  failedByUser.delete(userId);
}

// 暗号化 (POST /api/secrets/encrypt)
// 平文を受け取り暗号文を返す。どちらもサーバには保存しない。
router.post('/encrypt', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  try {
    const userId = (req as any).user.userId;
    const plaintext = (req.body as any)?.plaintext;
    if (typeof plaintext !== 'string' || plaintext.length === 0) {
      return res.status(400).json({ error: '暗号化するテキストを入力してください' });
    }
    if (plaintext.length > MAX_PLAINTEXT_CHARS) {
      return res.status(400).json({ error: `テキストは${MAX_PLAINTEXT_CHARS}文字以内で入力してください` });
    }

    const key = await getOrCreateUserKey(userId);
    const nonce = crypto.randomBytes(NONCE_BYTES);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
    const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    const ciphertext = FORMAT_PREFIX + Buffer.concat([nonce, encrypted, tag]).toString('base64');
    return res.json({ ciphertext });
  } catch (error) {
    console.error('シークレット暗号化エラー:', error);
    return res.status(500).json({ error: '暗号化中にエラーが発生しました' });
  }
});

// 復号 (POST /api/secrets/decrypt)
// step-up 認証必須。暗号文を受け取り平文を返す。どちらもサーバには保存しない。
// 失敗理由（形式不正・他ユーザの鍵・改ざん）は区別せず、同じ文言で返す。
router.post('/decrypt', requireStepUp, async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const userId = (req as any).user.userId;
  try {
    if (isDecryptLimited(userId, Date.now())) {
      return res.status(429).json({ error: '復号の失敗が多すぎます。しばらくしてから再度お試しください' });
    }

    const input = (req.body as any)?.ciphertext;
    if (typeof input !== 'string' || input.length === 0 || input.length > MAX_CIPHERTEXT_CHARS || !input.startsWith(FORMAT_PREFIX)) {
      recordDecryptFailure(userId, Date.now());
      return res.status(400).json({ error: '暗号文の形式が正しくないか、復号できませんでした' });
    }

    const key = await getOrCreateUserKey(userId);
    let plaintext: string;
    try {
      const raw = Buffer.from(input.slice(FORMAT_PREFIX.length), 'base64');
      if (raw.length < NONCE_BYTES + TAG_BYTES + 1) throw new Error('too short');
      const nonce = raw.subarray(0, NONCE_BYTES);
      const tag = raw.subarray(raw.length - TAG_BYTES);
      const data = raw.subarray(NONCE_BYTES, raw.length - TAG_BYTES);
      const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce);
      decipher.setAuthTag(tag);
      plaintext = Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8');
    } catch {
      recordDecryptFailure(userId, Date.now());
      return res.status(400).json({ error: '暗号文の形式が正しくないか、復号できませんでした' });
    }

    clearDecryptFailures(userId);
    return res.json({ plaintext });
  } catch (error) {
    console.error('シークレット復号エラー:', error);
    return res.status(500).json({ error: '復号中にエラーが発生しました' });
  }
});

export default router;
