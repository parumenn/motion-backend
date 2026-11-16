import express from 'express';
import { pool } from '../db';
import { authenticateToken, requireWriteAccess, requireStepUp } from '../middleware/auth';
import { enqueueMail, mailConfig } from '../mail';
import {
  hashPassword,
  verifyPassword,
  randomToken,
  sha256hex,
  validateEmail,
  validatePassword,
  normalizeEmail,
  issueTokenForUser,
  bumpTokenVersion,
  markStepUp,
} from '../utils/authHelpers';

const router = express.Router();

// 管理者メール（環境変数で上書き可。従来のハードコード値をデフォルトとして維持）
const ADMIN_EMAIL = normalizeEmail(process.env.ADMIN_EMAIL || 'thonglo02cocoa@gmail.com');

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
// マイボード方式: 常に同じ 202 応答を返し（登録有無を漏らさない）、
// 確認メール内のトークンで本登録（パスワード設定）するまでアカウントは有効化されない。
// パスワードは本登録時に受け取るため、この段階では受け取らない（後方互換のため
// フィールドが送られてきても無視する）。
router.post('/register', async (req, res) => {
  const email = normalizeEmail(req.body?.email);
  if (validateEmail(email)) {
    return res.status(400).json({ error: 'メールアドレスの形式が正しくありません' });
  }
  res.status(202).json({ ok: true, message: '確認メールを送信しました。メール内のリンクから本登録を完了してください。' });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows: existing } = await client.query(
      `SELECT id, email_verified_at FROM users WHERE email = $1`,
      [email]
    );
    let userId: string | null = null;
    if (existing.length > 0) {
      if (existing[0].email_verified_at !== null) {
        // 確認済みの既存アカウント: 存在を漏らさず何もしない（マイボードと同じ）
        await client.query('ROLLBACK');
        return;
      }
      userId = existing[0].id; // 未確認の再送ケース
    } else {
      const role = email === ADMIN_EMAIL ? 'admin' : 'user';
      const { rows: uRows } = await client.query(
        `INSERT INTO users (email, password_hash, status, role)
         VALUES ($1, $2, 'pending', $3) RETURNING id`,
        // 本登録までは使えないランダムパスワードのハッシュを入れておく
        [email, await hashPassword(randomToken()), role]
      );
      userId = uRows[0].id;
    }

    const token = randomToken();
    await client.query(
      `INSERT INTO email_tokens (user_id, kind, token_hash, expires_at, request_ip)
       VALUES ($1, 'verify', $2, now() + interval '1 hour', $3)`,
      [userId, sha256hex(token), req.ip]
    );
    await enqueueMail(client, email, 'verify', { url: `${mailConfig.publicBaseUrl}/?token=${token}` });
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    console.error('register error:', err);
  } finally {
    client.release();
  }
});

// 1b. 本登録API (POST /api/auth/verify) — 確認メールのトークンでパスワードを設定し有効化する
router.post('/verify', async (req, res) => {
  try {
    const token = typeof req.body?.token === 'string' ? req.body.token : '';
    const pwError = validatePassword(req.body?.password);
    if (pwError) return res.status(400).json({ error: pwError });

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const { rows: tRows } = await client.query(
        `SELECT id, user_id FROM email_tokens
          WHERE token_hash = $1 AND kind = 'verify' AND used_at IS NULL AND expires_at > now()`,
        [sha256hex(token)]
      );
      if (tRows.length === 0) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: '確認リンクが無効か、期限切れです' });
      }
      const userId: string = tRows[0].user_id;
      await client.query(
        `UPDATE users SET password_hash = $1, email_verified_at = now(), status = 'approved' WHERE id = $2`,
        [await hashPassword(req.body.password), userId]
      );
      await client.query(`UPDATE email_tokens SET used_at = now() WHERE id = $1`, [tRows[0].id]);
      await client.query('COMMIT');
      return res.json({ ok: true, message: '本登録が完了しました。ログインしてください。' });
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      throw err;
    } finally {
      client.release();
    }
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'サーバーエラーが発生しました' });
  }
});

// 2. ログインAPI (POST /api/auth/login)
router.post('/login', async (req, res) => {
  try {
    const email = normalizeEmail(req.body?.email);
    const password = typeof req.body?.password === 'string' ? req.body.password : '';

    // 制限に達している場合は認証処理に入らず 429 を返す
    if (isLoginLimited(email, Date.now())) {
      return res.status(429).json({ error: 'ログイン試行が多すぎます。しばらくしてから再度お試しください' });
    }

    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];

    // ユーザーが存在しない、またはパスワードが一致しない場合（文言は統一）
    if (!user || !(await verifyPassword(user.password_hash, password))) {
      recordLoginFailure(email, Date.now());
      return res.status(401).json({ error: 'メールアドレスまたはパスワードが間違っています' });
    }

    // パスワードログイン無効化中（パスキーのみ許可。マイボードと同じ扱い）
    if (user.password_login_disabled) {
      return res.status(401).json({ error: 'メールアドレスまたはパスワードが間違っています' });
    }

    // メール確認・有効化のチェック
    if (user.email_verified_at === null || user.status !== 'approved') {
      return res.status(403).json({ error: 'メール確認が完了していません。受信メールのリンクから本登録を完了してください', code: 'email_unverified' });
    }

    const { token, user: safeUser } = await issueTokenForUser(user);
    clearLoginFailures(email);

    res.json({ message: 'ログイン成功', token, user: safeUser });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'サーバーエラーが発生しました' });
  }
});

// 2b. 自分の情報 (GET /api/auth/me)
router.get('/me', authenticateToken, requireWriteAccess, async (req, res) => {
  try {
    const userId = (req as any).user.userId;
    const { rows } = await pool.query(
      `SELECT id, email, role, status, password_login_disabled,
              (SELECT count(*)::int FROM passkeys WHERE user_id = $1) AS passkey_count
         FROM users WHERE id = $1`,
      [userId]
    );
    if (rows.length === 0) return res.status(404).json({ error: 'ユーザーが見つかりません' });
    res.json(rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'サーバーエラーが発生しました' });
  }
});

// 3. パスワード変更 (POST /api/auth/password/change)
// 現在のパスワード確認必須。成功時は token_version を上げて他の全セッションを失効させ、
// この端末用に新しい JWT を返してログイン状態を維持する（マイボードの
// 「現セッションだけ残して他を失効」と等価）。APIキーは失効させない。
router.post('/password/change', authenticateToken, requireWriteAccess, async (req, res) => {
  try {
    const userId = (req as any).user.userId;
    const currentPassword = typeof req.body?.current_password === 'string' ? req.body.current_password : '';
    const pwError = validatePassword(req.body?.new_password);
    if (pwError) return res.status(400).json({ error: pwError });

    const { rows } = await pool.query(`SELECT email, password_hash, password_login_disabled FROM users WHERE id = $1`, [userId]);
    if (rows.length === 0) return res.status(404).json({ error: 'ユーザーが見つかりません' });
    const user = rows[0];
    if (user.password_login_disabled) {
      return res.status(400).json({ error: 'パスワードログインが無効化されているため、パスワード変更はできません。先にパスキーでログインし直し、パスワードログインを有効化してください', code: 'password_login_disabled' });
    }
    if (!(await verifyPassword(user.password_hash, currentPassword))) {
      return res.status(400).json({ error: '現在のパスワードが正しくありません' });
    }

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(`UPDATE users SET password_hash = $1 WHERE id = $2`, [await hashPassword(req.body.new_password), userId]);
      await client.query(`UPDATE users SET token_version = token_version + 1 WHERE id = $1`, [userId]);
      await enqueueMail(client, user.email, 'password_changed', {});
      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      throw err;
    } finally {
      client.release();
    }

    const { token } = await issueTokenForUser({ id: userId, email: user.email, role: (req as any).user.role });
    await markStepUp(userId);
    return res.json({ ok: true, token });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'サーバーエラーが発生しました' });
  }
});

// 4. パスワードリセット申請 (POST /api/auth/password/reset-request)
// 常に同じ 202 応答（存在を漏らさない）。確認済み・有効なユーザーにだけメールを送る。
router.post('/password/reset-request', async (req, res) => {
  const email = normalizeEmail(req.body?.email);
  res.status(202).json({ ok: true, message: '再設定メールを送信しました（登録がある場合）。' });
  if (validateEmail(email)) return;

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows } = await client.query(
      `SELECT id, email_verified_at, status FROM users WHERE email = $1`,
      [email]
    );
    if (rows.length > 0 && rows[0].email_verified_at && rows[0].status === 'approved') {
      const token = randomToken();
      await client.query(
        `INSERT INTO email_tokens (user_id, kind, token_hash, expires_at, request_ip)
         VALUES ($1, 'reset', $2, now() + interval '30 minutes', $3)`,
        [rows[0].id, sha256hex(token), req.ip]
      );
      await enqueueMail(client, email, 'reset', { url: `${mailConfig.publicBaseUrl}/?mode=reset&token=${token}` });
    }
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    console.error('reset-request error:', err);
  } finally {
    client.release();
  }
});

// 4b. パスワードリセット実行 (POST /api/auth/password/reset)
// 完了時: (a) token_version を上げて全 JWT を失効 (b) パスキー全削除
// (c) password_login_disabled を戻す。APIキーは FUJIWARA が日常使用中のため
// 失効させない（マイボードとの意図的な差分。変更があった旨はメールで通知する）。
router.post('/password/reset', async (req, res) => {
  try {
    const token = typeof req.body?.token === 'string' ? req.body.token : '';
    const pwError = validatePassword(req.body?.new_password);
    if (pwError) return res.status(400).json({ error: pwError });

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const { rows: tRows } = await client.query(
        `SELECT id, user_id FROM email_tokens
          WHERE token_hash = $1 AND kind = 'reset' AND used_at IS NULL AND expires_at > now()`,
        [sha256hex(token)]
      );
      if (tRows.length === 0) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: '再設定リンクが無効か、期限切れです' });
      }
      const userId: string = tRows[0].user_id;
      const { rows: uRows } = await client.query(`SELECT email FROM users WHERE id = $1`, [userId]);
      const email: string = uRows[0].email;

      await client.query(
        `UPDATE users SET password_hash = $1, token_version = token_version + 1, password_login_disabled = false WHERE id = $2`,
        [await hashPassword(req.body.new_password), userId]
      );
      await client.query(`UPDATE email_tokens SET used_at = now() WHERE id = $1`, [tRows[0].id]);
      const { rowCount: passkeyCount } = await client.query(`DELETE FROM passkeys WHERE user_id = $1`, [userId]);
      const invalidated = { passkeys: passkeyCount ?? 0 };
      await enqueueMail(client, email, 'reset_done', { invalidated });
      await client.query('COMMIT');
      return res.json({ ok: true, invalidated });
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      throw err;
    } finally {
      client.release();
    }
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'サーバーエラーが発生しました' });
  }
});

// 5. step-up 認証（パスワード再入力） (POST /api/auth/stepup/password)
// パスキー方式の step-up は passkeys ルート側にある（マイボードと同じ配置）。
router.post('/stepup/password', authenticateToken, requireWriteAccess, async (req, res) => {
  try {
    const userId = (req as any).user.userId;
    const password = typeof req.body?.password === 'string' ? req.body.password : '';
    const { rows } = await pool.query(`SELECT email, password_hash, password_login_disabled FROM users WHERE id = $1`, [userId]);
    if (rows.length === 0) return res.status(404).json({ error: 'ユーザーが見つかりません' });
    if (rows[0].password_login_disabled) {
      return res.status(400).json({ error: 'パスワードログインが無効化されています。パスキーで再認証してください', code: 'step_up_password_unavailable' });
    }
    if (!(await verifyPassword(rows[0].password_hash, password))) {
      return res.status(401).json({ error: '現在のパスワードが正しくありません' });
    }
    await markStepUp(userId);
    return res.json({ ok: true });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'サーバーエラーが発生しました' });
  }
});

// 6. 全セッション失効 (POST /api/auth/revoke-sessions)
// step-up 必須。token_version を上げ、操作した本人の新しい JWT だけを返す。
router.post('/revoke-sessions', authenticateToken, requireWriteAccess, requireStepUp, async (req, res) => {
  try {
    const userId = (req as any).user.userId;
    await bumpTokenVersion(userId);
    const { rows } = await pool.query(`SELECT email, role FROM users WHERE id = $1`, [userId]);
    const { token } = await issueTokenForUser({ id: userId, email: rows[0].email, role: rows[0].role });
    return res.json({ ok: true, token });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'サーバーエラーが発生しました' });
  }
});

// 7. 設定の端末間同期 API (GET/PUT /api/auth/prefs) — R2-8
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
