import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

// ログイン状態を確認する関所（ミドルウェア）
export const authenticateToken = (req: Request, res: Response, next: NextFunction) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // "Bearer トークン文字列" から抽出

  if (!token) {
    return res.status(401).json({ error: '認証トークンがありません' });
  }

  jwt.verify(token, process.env.JWT_SECRET as string, (err, user) => {
    if (err) return res.status(403).json({ error: 'トークンが無効または期限切れです' });
    
    // リクエスト情報にユーザー情報を付与して次の処理へ進む
    (req as any).user = user;
    next();
  });
};