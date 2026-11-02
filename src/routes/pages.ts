import express from 'express';
import { pool } from '../db';
import { authenticateToken, requireWriteAccess, requireScope } from '../middleware/auth';
import { convertBlocksToMarkdown } from '../utils/markdown';

const router = express.Router();

// すべてのページを取得 (サイドバーツリー用)
router.get('/', authenticateToken, async (req, res) => {
  try {
    const user = (req as any).user;
    
    // APIキーの場合はスコープを確認
    if (user.isApiKey && (!user.scopes || !user.scopes.includes('read:pages'))) {
      return res.status(403).json({ error: 'read:pages スコープが許可されていません' });
    }

    const userId = user.userId;
    // blocks（中身）は重いのでここでは取得しない
    const result = await pool.query(
      'SELECT id, parent_id, title, is_locked, password_hash FROM pages WHERE user_id = $1',
      [userId]
    );

    let pages = result.rows;

    // APIキー経由のアクセスなら、全ページのパスワードハッシュを除外
    if (user.isApiKey) {
      pages = pages.map(page => {
        const { password_hash, ...safePage } = page;
        return safePage;
      });
    }

    res.json(pages);
  } catch (error) {
    res.status(500).json({ error: 'データ取得エラー' });
  }
});

// ページ詳細の取得 (エディタを開いたとき用)
router.get('/:id', authenticateToken, async (req, res) => {
  try {
    const user = (req as any).user;
    
    // APIキーの場合はスコープを確認
    if (user.isApiKey && (!user.scopes || !user.scopes.includes('read:pages'))) {
      return res.status(403).json({ error: 'read:pages スコープが許可されていません' });
    }

    const userId = user.userId;
    const result = await pool.query(
      'SELECT * FROM pages WHERE id = $1 AND user_id = $2',
      [req.params.id, userId]
    );
    
    if (result.rows.length === 0) return res.status(404).json({ error: 'ページが見つかりません' });
    
    let page = result.rows[0];

    // body_markdown を生成して追加（API/JWT問わず提供。ロック中でも提供）
    let parsedBlocks = [];
    if (typeof page.blocks === 'string') {
      try {
        parsedBlocks = JSON.parse(page.blocks);
      } catch (e) {
        // パース失敗時は空配列として扱う
      }
    } else if (Array.isArray(page.blocks)) {
      parsedBlocks = page.blocks;
    }
    
    page.body_markdown = convertBlocksToMarkdown(parsedBlocks);

    // APIキー経由のアクセスなら、パスワードハッシュを除外
    if (user.isApiKey) {
      delete page.password_hash;
    }

    res.json(page);
  } catch (error) {
    res.status(500).json({ error: 'データ取得エラー' });
  }
});

// ページの新規作成 (APIキーは write:pages スコープが必要)
router.post('/', authenticateToken, requireScope('write:pages'), async (req, res) => {
  try {
    const userId = (req as any).user.userId;
    const { id, title, parentId, blocks, isLocked, passwordHash } = req.body;
    
    const result = await pool.query(
      'INSERT INTO pages (id, user_id, parent_id, title, blocks, is_locked, password_hash) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *',
      [id, userId, parentId, title, JSON.stringify(blocks || []), isLocked, passwordHash]
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: '作成エラー' });
  }
});

// ページの更新 (自動保存用 / APIキーは write:pages スコープが必要)
router.put('/:id', authenticateToken, requireScope('write:pages'), async (req, res) => {
  try {
    const userId = (req as any).user.userId;
    const { title, parentId, blocks, isLocked, passwordHash } = req.body;
    
    const result = await pool.query(
      'UPDATE pages SET title = $1, parent_id = $2, blocks = $3, is_locked = $4, password_hash = $5, updated_at = CURRENT_TIMESTAMP WHERE id = $6 AND user_id = $7 RETURNING *',
      [title, parentId, JSON.stringify(blocks), isLocked, passwordHash, req.params.id, userId]
    );
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: '更新エラー' });
  }
});

// ページの削除 (APIキー不可)
router.delete('/:id', authenticateToken, requireWriteAccess, async (req, res) => {
  try {
    const userId = (req as any).user.userId;
    await pool.query('DELETE FROM pages WHERE id = $1 AND user_id = $2', [req.params.id, userId]);
    res.json({ message: '削除しました' });
  } catch (error) {
    res.status(500).json({ error: '削除エラー' });
  }
});

export default router;

