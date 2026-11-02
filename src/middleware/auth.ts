import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { pool } from '../db';

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

  // 従来のJWT認証
  jwt.verify(token, process.env.JWT_SECRET as string, (err, user) => {
    if (err) return res.status(403).json({ error: 'トークンが無効または期限切れです' });
    
    // リクエスト情報にユーザー情報を付与して次の処理へ進む
    (req as any).user = user;
    next();
  });
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

