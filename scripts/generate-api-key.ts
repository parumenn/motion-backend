import crypto from 'crypto';
import { pool } from '../src/db';

async function generateApiKey() {
  try {
    // 1. api_keys テーブルの作成 (users.id が UUID である前提)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS api_keys (
        id SERIAL PRIMARY KEY,
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        key_hash VARCHAR(64) NOT NULL UNIQUE,
        scopes VARCHAR(255)[],
        last_used_at TIMESTAMP,
        revoked_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // 2. 管理者ユーザーの取得
    const adminResult = await pool.query("SELECT id FROM users WHERE role = 'admin' LIMIT 1");
    if (adminResult.rows.length === 0) {
      console.error('❌ エラー: role = "admin" のユーザーが見つかりません。先に管理者を登録してください。');
      process.exit(1);
    }
    const adminUserId = adminResult.rows[0].id;

    // 3. APIキーの生成
    const randomBytes = crypto.randomBytes(32).toString('base64url').replace(/[^a-zA-Z0-9]/g, '');
    const apiKey = `motion_live_${randomBytes}`;
    
    // 4. ハッシュ化とデータベース登録 (read:pages と write:pages の両方を付与)
    const keyHash = crypto.createHash('sha256').update(apiKey).digest('hex');
    const scopes = ['read:pages', 'write:pages'];

    await pool.query(
      'INSERT INTO api_keys (user_id, key_hash, scopes) VALUES ($1, $2, $3)',
      [adminUserId, keyHash, scopes]
    );

    // 5. 結果の出力
    console.log('✅ APIキーの発行に成功しました！');
    console.log('=====================================================');
    console.log('API Key (Museに登録してください):');
    console.log(apiKey);
    console.log('=====================================================');
    console.log('⚠️ このキーは二度と表示されません。平文で保存されることはないため、必ず今コピーしてください。');
    
    process.exit(0);
  } catch (error) {
    console.error('❌ 実行エラー:', error);
    process.exit(1);
  }
}

generateApiKey();

