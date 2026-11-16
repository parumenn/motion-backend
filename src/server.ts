import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import './db';
import authRoutes from './routes/auth';
import pageRoutes from './routes/pages'; // ★追加
import uploadRoutes from './routes/uploads'; // ★追加
import apiKeyRoutes from './routes/apiKeys';
import passkeyRoutes from './routes/passkeys';
import { runMigrations } from './migrate';
import { startMailWorker, mailConfig } from './mail';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// CORS は自サイトのみに絞る（従来は無制限だった。APIキー利用はサーバ間通信で
// CORS の影響を受けないため、ブラウザ経由の利用だけを許可すれば足りる）
app.use(cors({ origin: mailConfig.publicBaseUrl }));
app.use(express.json());
app.use('/uploads', express.static('uploads'));

app.use('/api/auth', authRoutes);
app.use('/api/auth', passkeyRoutes);
app.use('/api/pages', pageRoutes); // ★追加
app.use('/api/uploads', uploadRoutes); // ★追加
app.use('/api/api-keys', apiKeyRoutes);

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', message: 'Motion Backend is running!' });
});

async function start() {
  try {
    const applied = await runMigrations();
    if (applied.length > 0) console.log('📦 マイグレーション適用:', applied.join(', '));
  } catch (err) {
    console.error('❌ マイグレーション失敗:', err);
    process.exit(1);
  }
  startMailWorker();
  app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
  });
}

start();
