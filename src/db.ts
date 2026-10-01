import { Pool } from 'pg';
import dotenv from 'dotenv';

dotenv.config();

// PostgreSQLへの接続プールを作成
export const pool = new Pool({
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

// 起動時に接続テストを実行
pool.query('SELECT NOW()', (err, res) => {
  if (err) {
    console.error('❌ データベース接続エラー:', err.message);
  } else {
    console.log('✅ データベース接続成功! 現在時刻:', res.rows[0].now);
  }
});