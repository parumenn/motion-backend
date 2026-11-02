import express from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { pool } from '../db';
import { authenticateToken, requireWriteAccess } from '../middleware/auth';

const router = express.Router();

// ログイン試行のレート制限（新規依存なしのインメモリ実装）
// ・メールアドレスごと：15分あたり失敗10回まで（総当たりで1アカウントを狙う試行を抑止）
// ・プロセス全体：15分あたり失敗200回まで（多数のアカウントを狙う分散気味の試行にも上限を設ける）
// ・成功時はそのメールのカウンタを消去するので、正しいログインは制限されない
// ・制限中は 429 を返す（401 と区別し、成功・失敗の有無を漏らさない文言にする）
// ・注意：Express は trust proxy 未設定のため req.ip は ingress 経由で共有され得るため、
//   IP 単位の制限は採用せず、メール単位＋全体単位とした。複数 Pod では Pod ごとに
//   カウンタを持つため実効上限は Pod 数倍になる（現行 2 Pod なら約2倍）が、
//   総当たりの抑止としては十分な水準。
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const MAX_FAILED_PER_EMAIL = 10;
const MAX_FAILED_GLOBAL = 200;

type FailedBucket = { count: number; resetAt: number };
const failedByEmail = new Map<string, FailedBucket>();
let globalFailed: FailedBucket = { count: 0, resetAt: 0 };

function normalizeLoginEmail(email: unknown): string {
  return typeof email === 'string' ? email.trim().toLowerCase() : '';
}

function pruneExpiredBuckets(now: number): void {
  if (globalFailed.resetAt !== 0 && now >= globalFailed.resetAt) {
    globalFailed = { count: 0, resetAt: 0 };
  }
  for (const [key, bucket] of failedByEmail) {
    if (now >= bucket.resetAt) failedByEmail.delete(key);
  }
}

function isLoginLimited(emailKey: string, now: number): boolean {
  pruneExpiredBuckets(now);
  const perEmail = failedByEmail.get(emailKey);
  if (perEmail && perEmail.count >= MAX_FAILED_PER_EMAIL) return true;
  if (globalFailed.count >= MAX_FAILED_GLOBAL) return true;
  return false;
}

function recordLoginFailure(emailKey: string, now: number): void {
  pruneExpiredBuckets(now);
  const perEmail = failedByEmail.get(emailKey);
  if (perEmail) {
    perEmail.count += 1;
  } else if (emailKey) {
    failedByEmail.set(emailKey, { count: 1, resetAt: now + LOGIN_WINDOW_MS });
  }
  if (globalFailed.resetAt === 0) globalFailed.resetAt = now + LOGIN_WINDOW_MS;
  globalFailed.count += 1;
}

function clearLoginFailures(emailKey: string): void {
  if (emailKey) failedByEmail.delete(emailKey);
}

// 1. アカウント作成API (POST /api/auth/register)
router.post('/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // すでに登録されているかチェック
    const userCheck = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userCheck.rows.length > 0) {
      return res.status(400).json({ error: 'このメールアドレスは既に登録されています' });
    }

    // パスワードを暗号化 (ハッシュ化)
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // 管理者（thonglo02cocoa@gmail.com）の場合は最初から承認済みとする
    const status = email === 'thonglo02cocoa@gmail.com' ? 'approved' : 'pending';
    const role = email === 'thonglo02cocoa@gmail.com' ? 'admin' : 'user';

    // データベースに保存
    const result = await pool.query(
      'INSERT INTO users (email, password_hash, status, role) VALUES ($1, $2, $3, $4) RETURNING id, email, status, role',
      [email, hashedPassword, status, role]
    );

    res.status(201).json({ message: 'アカウントを作成しました', user: result.rows[0] });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'サーバーエラーが発生しました' });
  }
});

// 2. ログインAPI (POST /api/auth/login)
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const emailKey = normalizeLoginEmail(email);

    // 制限に達している場合は認証処理に入らず 429 を返す
    if (isLoginLimited(emailKey, Date.now())) {
      return res.status(429).json({ error: 'ログイン試行が多すぎます。しばらくしてから再度お試しください' });
    }

    // ユーザーを検索
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];

    // ユーザーが存在しない、またはパスワードが一致しない場合
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      recordLoginFailure(emailKey, Date.now());
      return res.status(401).json({ error: 'メールアドレスまたはパスワードが間違っています' });
    }

    // 承認ステータスのチェック（フロントエンドの仕様に合わせる）
    if (user.status !== 'approved') {
      return res.status(403).json({ error: 'アカウントは現在管理者の承認待ちです' });
    }

    // JWT(JSON Web Token)を発行してログイン状態を証明する
    const token = jwt.sign(
      { userId: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET as string,
      { expiresIn: '7d' } // 7日間有効
    );

    // ログイン成功時は失敗カウンタを消去する
    clearLoginFailures(emailKey);

    res.json({
      message: 'ログイン成功',
      token, 
      user: { id: user.id, email: user.email, role: user.role } 
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'サーバーエラーが発生しました' });
  }
});

// 3. 設定の端末間同期 API (GET/PUT /api/auth/prefs) — R2-8
// フロントの savePrefs が扱うキーだけを許可する。
// 未知キーを黙って捨てると将来の不整合の原因になるため、未知キーがあれば 400 を返す。
// JWT のみ（requireWriteAccess が APIキーを 403 で弾く）。PUT はキー単位マージで、
// 片方の端末だけが送ったキーが他方のキーで上書き消去されないようにする。
const PREF_KEYS = ['theme', 'image_quality', 'show_locked', 'search_locked'] as const;

router.get('/prefs', authenticateToken, requireWriteAccess, async (req, res) => {
  try {
    const userId = (req as any).user.userId;
    const result = await pool.query('SELECT prefs FROM users WHERE id = $1', [userId]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'ユーザーが見つかりません' });
    }
    res.json({ prefs: result.rows[0].prefs || {} });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'サーバーエラーが発生しました' });
  }
});

router.put('/prefs', authenticateToken, requireWriteAccess, async (req, res) => {
  try {
    const userId = (req as any).user.userId;
    const incoming = req.body?.prefs;
    if (!incoming || typeof incoming !== 'object' || Array.isArray(incoming)) {
      return res.status(400).json({ error: 'prefs オブジェクトを指定してください' });
    }
    const updates: Record<string, string> = {};
    for (const key of Object.keys(incoming)) {
      if (!(PREF_KEYS as readonly string[]).includes(key)) {
        return res.status(400).json({ error: `未知の設定キーです: ${key}` });
      }
      const value = incoming[key];
      if (typeof value !== 'string' || value.length > 100) {
        return res.status(400).json({ error: `設定値が不正です: ${key}` });
      }
      updates[key] = value;
    }
    const result = await pool.query(
      'UPDATE users SET prefs = COALESCE(prefs, \'{}\'::jsonb) || $2::jsonb WHERE id = $1 RETURNING prefs',
      [userId, JSON.stringify(updates)]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'ユーザーが見つかりません' });
    }
    res.json({ prefs: result.rows[0].prefs });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'サーバーエラーが発生しました' });
  }
});

export default router;