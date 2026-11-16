import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { pool } from '../db';
import { isStepUpFresh } from '../utils/authHelpers';

// ログイン状態を確認する関所（ミドルウェア）
export const authenticateToken = async (req: Request, res: Response, next: NextFunction) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // "Bearer トークン文字列" から抽出

  if (!token) {
    return res.status(401).json({ error: '認証トークンがありません' });
  }

  // APIキー認証 (motion_ で始まる場合)
  if (token.startsWith('motion_')) {
    try {
      // 渡されたトークンをハッシュ化してDBと照合
      const keyHash = crypto.createHash('sha256').update(token).digest('hex');
      const result = await pool.query(
        'SELECT user_id, scopes, revoked_at FROM api_keys WHERE key_hash = $1',
        [keyHash]
      );

      if (result.rows.length === 0) {
        return res.status(403).json({ error: '無効なAPIキーです' });
      }

      const apiKeyData = result.rows[0];

      // 失効チェック
      if (apiKeyData.revoked_at !== null) {
        return res.status(403).json({ error: 'このAPIキーは失効しています' });
      }

      // 最終利用日時の更新 (バックグラウンドで実行)
      pool.query('UPDATE api_keys SET last_used_at = CURRENT_TIMESTAMP WHERE key_hash = $1', [keyHash]).catch(err => {
        console.error('last_used_atの更新に失敗しました:', err);
      });

      // JWT利用時と形式を合わせつつ、APIキーであるフラグとスコープを付与
      (req as any).user = {
        userId: apiKeyData.user_id,
        isApiKey: true,
        scopes: apiKeyData.scopes || []
      };

      return next();
    } catch (error) {
      console.error('APIキー認証エラー:', error);
      return res.status(500).json({ error: '認証処理中にエラーが発生しました' });
    }
  }

  // JWT認証
  // ・無効/期限切れは 401 に統一する（旧実装は 403 で、フロントの再ログイン導線と噛み合っていなかった）
  // ・token_version (tv) を DB の現在値と照合し、パスワード変更/リセット等で
  //   version が上がった JWT は失効として 401 を返す
  let payload: any;
  try {
    payload = jwt.verify(token, process.env.JWT_SECRET as string);
  } catch {
    return res.status(401).json({ error: 'トークンが無効または期限切れです', code: 'invalid_token' });
  }

  try {
    const result = await pool.query(
      'SELECT token_version, status FROM users WHERE id = $1',
      [payload.userId]
    );
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'トークンが無効または期限切れです', code: 'invalid_token' });
    }
    const current = result.rows[0];
    // 移行前に発行された JWT（tv を含まない）は tv=0 として扱い、既存セッションを切らない
    const tokenTv = typeof payload.tv === 'number' ? payload.tv : 0;
    if (tokenTv !== Number(current.token_version)) {
      return res.status(401).json({ error: 'セッションが無効になりました。再度ログインしてください', code: 'session_revoked' });
    }
    if (current.status !== 'approved') {
      return res.status(403).json({ error: 'アカウントが有効ではありません', code: 'account_inactive' });
    }
  } catch (error) {
    console.error('JWT照合エラー:', error);
    return res.status(500).json({ error: '認証処理中にエラーが発生しました' });
  }

  (req as any).user = payload;
  next();
};

// APIキーによるアクセスを全面的に禁止する関所 (DELETE や uploads 用)
export const requireWriteAccess = (req: Request, res: Response, next: NextFunction) => {
  const user = (req as any).user;
  if (user && user.isApiKey) {
    return res.status(403).json({ error: 'APIキーではこの操作を実行する権限がありません' });
  }
  next();
};

// APIキーに特定のスコープを要求する関所 (POST, PUT用)
export const requireScope = (requiredScope: string) => {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = (req as any).user;
    // APIキーの場合のみスコープを検証 (JWTの場合は常に許可)
    if (user && user.isApiKey) {
      if (!user.scopes || !user.scopes.includes(requiredScope)) {
        return res.status(403).json({ error: `${requiredScope} スコープが許可されていません` });
      }
    }
    next();
  };
};

// step-up 認証（再認証）を要求する関所（マイボード assertStepUp 相当）
// パスキー追加/削除・APIキー発行/失効など、永続的なアクセス手段を操作する前に
// 直近5分以内の再認証（パスワード再入力 or 既存パスキー）を必須とする。
// 状態は users.last_stepup_at（サーバ側）で判定し、クライアント申告は使わない。
export const requireStepUp = async (req: Request, res: Response, next: NextFunction) => {
  const user = (req as any).user;
  if (!user || user.isApiKey) {
    return res.status(403).json({ error: 'この操作はログインセッションからのみ実行できます', code: 'step_up_required' });
  }
  try {
    if (await isStepUpFresh(user.userId)) return next();
  } catch (error) {
    console.error('step-up照合エラー:', error);
    return res.status(500).json({ error: '認証処理中にエラーが発生しました' });
  }
  return res.status(403).json({
    error: 'この操作には再認証が必要です。再度本人確認を行ってください',
    code: 'step_up_required',
  });
};
