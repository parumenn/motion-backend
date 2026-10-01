import express from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { pool } from '../db';

const router = express.Router();

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

    // ユーザーを検索
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];

    // ユーザーが存在しない、またはパスワードが一致しない場合
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
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

export default router;