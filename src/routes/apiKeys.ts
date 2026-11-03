import express from 'express';
import crypto from 'crypto';
import { pool } from '../db';
import { authenticateToken, requireWriteAccess } from '../middleware/auth';

const router = express.Router();

// APIキー管理は「人間のログインセッション（JWT）」専用にする。
// authenticateToken で認証し、requireWriteAccess で APIキーによる呼び出しを 403 にする
// （APIキー自身にキーの発行・失効をさせない）。
router.use(authenticateToken, requireWriteAccess);

// 発行するキーに付与するスコープ（発行スクリプト scripts/generate-api-key.ts と同一）
const DEFAULT_SCOPES = ['read:pages', 'write:pages'];
const MAX_NAME_LENGTH = 100;

// 自分のAPIキー一覧（平文・ハッシュは絶対に返さない）
router.get('/', async (req, res) => {
  try {
    const userId = (req as any).user.userId;
    const result = await pool.query(
      `SELECT id, name, scopes, created_at, last_used_at, revoked_at
         FROM api_keys
        WHERE user_id = $1
        ORDER BY created_at DESC, id DESC`,
      [userId]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('APIキー一覧エラー:', error);
    res.status(500).json({ error: 'APIキーの取得中にエラーが発生しました' });
  }
});

// 新しいAPIキーを発行する。平文キーはこのレスポンスで一度だけ返す
// （サーバーには SHA-256 ハッシュしか保存されないため再表示は不可能）。
router.post('/', async (req, res) => {
  try {
    const userId = (req as any).user.userId;
    const rawName = (req.body as any)?.name;
    const name = typeof rawName === 'string' ? rawName.trim() : '';
    if (name.length > MAX_NAME_LENGTH) {
      return res.status(400).json({ error: `名前は${MAX_NAME_LENGTH}文字以内で入力してください` });
    }

    // 発行スクリプトと同一形式: motion_live_<ランダム文字列>
    const randomPart = crypto.randomBytes(32).toString('base64url').replace(/[^a-zA-Z0-9]/g, '');
    const apiKey = `motion_live_${randomPart}`;
    const keyHash = crypto.createHash('sha256').update(apiKey).digest('hex');

    const result = await pool.query(
      'INSERT INTO api_keys (user_id, key_hash, scopes, name) VALUES ($1, $2, $3, $4) RETURNING id, name, scopes, created_at',
      [userId, keyHash, DEFAULT_SCOPES, name || null]
    );

    res.status(201).json({ ...result.rows[0], apiKey });
  } catch (error) {
    console.error('APIキー発行エラー:', error);
    res.status(500).json({ error: 'APIキーの発行中にエラーが発生しました' });
  }
});

// APIキーを失効させる（削除はせず revoked_at を立てる。冪等）
router.post('/:id/revoke', async (req, res) => {
  try {
    const userId = (req as any).user.userId;
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) {
      return res.status(400).json({ error: 'キーIDが不正です' });
    }

    const existing = await pool.query(
      'SELECT id, revoked_at FROM api_keys WHERE id = $1 AND user_id = $2',
      [id, userId]
    );
    if (existing.rows.length === 0) {
      return res.status(404).json({ error: 'APIキーが見つかりません' });
    }
    if (existing.rows[0].revoked_at !== null) {
      return res.json({ id, revoked_at: existing.rows[0].revoked_at, alreadyRevoked: true });
    }

    const result = await pool.query(
      'UPDATE api_keys SET revoked_at = CURRENT_TIMESTAMP WHERE id = $1 AND user_id = $2 RETURNING revoked_at',
      [id, userId]
    );
    res.json({ id, revoked_at: result.rows[0].revoked_at });
  } catch (error) {
    console.error('APIキー失効エラー:', error);
    res.status(500).json({ error: 'APIキーの失効中にエラーが発生しました' });
  }
});

export default router;
