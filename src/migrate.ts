import fs from 'node:fs/promises';
import path from 'node:path';
import { pool } from './db';

// マイボード migrate.ts と同方式: migrations/*.sql を名前順に一度だけ適用する。
// 適用記録は schema_migrations に残し、advisory lock で多重起動時の競合を防ぐ。
// ディレクトリ解決は tsx の実行形態（CJS/ESM）に依存しないよう候補を順に探す。
function migrationsDir(): string {
  const candidates = [
    typeof __dirname !== 'undefined' ? path.join(__dirname, 'migrations') : '',
    path.join(process.cwd(), 'src', 'migrations'),
    path.join(process.cwd(), 'migrations'),
  ].filter(Boolean);
  return candidates[0] ?? path.join(process.cwd(), 'src', 'migrations');
}

export async function runMigrations(): Promise<string[]> {
  const dir = migrationsDir();
  const client = await pool.connect();
  const applied: string[] = [];
  try {
    await client.query('SELECT pg_advisory_lock(727273)');
    await client.query(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        name text PRIMARY KEY,
        applied_at timestamptz NOT NULL DEFAULT now()
      )
    `);
    let files: string[] = [];
    try {
      files = (await fs.readdir(dir)).filter((f) => f.endsWith('.sql')).sort();
    } catch {
      return applied; // migrations ディレクトリが無い場合は何もしない
    }
    for (const file of files) {
      const { rows } = await client.query('SELECT 1 FROM schema_migrations WHERE name = $1', [file]);
      if (rows.length > 0) continue;
      const sql = await fs.readFile(path.join(dir, file), 'utf-8');
      await client.query('BEGIN');
      try {
        await client.query(sql);
        await client.query('INSERT INTO schema_migrations (name) VALUES ($1)', [file]);
        await client.query('COMMIT');
      } catch (err) {
        await client.query('ROLLBACK');
        throw err;
      }
      applied.push(file);
    }
    return applied;
  } finally {
    try { await client.query('SELECT pg_advisory_unlock(727273)'); } catch { /* ignore */ }
    client.release();
  }
}
