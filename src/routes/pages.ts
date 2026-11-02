import express from 'express';
import { pool } from '../db';
import { authenticateToken, requireWriteAccess, requireScope } from '../middleware/auth';
import { convertBlocksToMarkdown } from '../utils/markdown';

const router = express.Router();

// すべてのページを取得 (サイドバーツリー用)
// デフォルトではゴミ箱のページを除外する。?includeDeleted=true の場合のみ含める。
router.get('/', authenticateToken, async (req, res) => {
  try {
    const user = (req as any).user;

    // APIキーの場合はスコープを確認
    if (user.isApiKey && (!user.scopes || !user.scopes.includes('read:pages'))) {
      return res.status(403).json({ error: 'read:pages スコープが許可されていません' });
    }

    const userId = user.userId;
    const includeDeleted = req.query.includeDeleted === 'true';
    // blocks（中身）は重いのでここでは取得しない
    const result = includeDeleted
      ? await pool.query(
          'SELECT id, parent_id, title, is_locked, password_hash, deleted_at FROM pages WHERE user_id = $1',
          [userId]
        )
      : await pool.query(
          'SELECT id, parent_id, title, is_locked, password_hash FROM pages WHERE user_id = $1 AND deleted_at IS NULL',
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
// ゴミ箱内のページは ?includeDeleted=true がない限り 404 とする。
router.get('/:id', authenticateToken, async (req, res) => {
  try {
    const user = (req as any).user;

    // APIキーの場合はスコープを確認
    if (user.isApiKey && (!user.scopes || !user.scopes.includes('read:pages'))) {
      return res.status(403).json({ error: 'read:pages スコープが許可されていません' });
    }

    const userId = user.userId;
    const includeDeleted = req.query.includeDeleted === 'true';
    const result = includeDeleted
      ? await pool.query(
          'SELECT * FROM pages WHERE id = $1 AND user_id = $2',
          [req.params.id, userId]
        )
      : await pool.query(
          'SELECT * FROM pages WHERE id = $1 AND user_id = $2 AND deleted_at IS NULL',
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
// ゴミ箱内のページへの更新は 410 とし、自動保存がゴミ箱ページを蘇らせないようにする。
router.put('/:id', authenticateToken, requireScope('write:pages'), async (req, res) => {
  try {
    const userId = (req as any).user.userId;
    const { title, parentId, blocks, isLocked, passwordHash } = req.body;

    const result = await pool.query(
      'UPDATE pages SET title = $1, parent_id = $2, blocks = $3, is_locked = $4, password_hash = $5, updated_at = CURRENT_TIMESTAMP WHERE id = $6 AND user_id = $7 AND deleted_at IS NULL RETURNING *',
      [title, parentId, JSON.stringify(blocks), isLocked, passwordHash, req.params.id, userId]
    );
    if (result.rows.length > 0) return res.json(result.rows[0]);

    // 更新対象がない場合：ゴミ箱内なら 410、それ以外は 404（フロントは新規作成へ進む）
    const existing = await pool.query(
      'SELECT deleted_at FROM pages WHERE id = $1 AND user_id = $2',
      [req.params.id, userId]
    );
    if (existing.rows.length > 0 && existing.rows[0].deleted_at !== null) {
      return res.status(410).json({ error: 'このページはゴミ箱にあります' });
    }
    return res.status(404).json({ error: 'ページが見つかりません' });
  } catch (error) {
    res.status(500).json({ error: '更新エラー' });
  }
});

// ページのゴミ箱への移動 (APIキー不可)
// 対象ページとその子孫ページすべてに deleted_at を設定する（完全消去はしない）。
router.delete('/:id', authenticateToken, requireWriteAccess, async (req, res) => {
  try {
    const userId = (req as any).user.userId;
    const result = await pool.query(
      `WITH RECURSIVE subtree AS (
         SELECT id FROM pages WHERE id = $1 AND user_id = $2 AND deleted_at IS NULL
         UNION ALL
         SELECT p.id FROM pages p JOIN subtree s ON p.parent_id = s.id
         WHERE p.user_id = $2 AND p.deleted_at IS NULL
       )
       UPDATE pages SET deleted_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
       WHERE id IN (SELECT id FROM subtree) AND user_id = $2`,
      [req.params.id, userId]
    );
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'ページが見つかりません' });
    }
    res.json({ message: 'ゴミ箱に移動しました' });
  } catch (error) {
    res.status(500).json({ error: '削除エラー' });
  }
});

// ゴミ箱からの復元 (APIキー不可)
// 対象ページとその子孫を復元する。親がゴミ箱内に残っている場合は孤立を避けるため
// 祖先チェーンも一緒に復元する。
router.post('/:id/restore', authenticateToken, requireWriteAccess, async (req, res) => {
  try {
    const userId = (req as any).user.userId;
    const result = await pool.query(
      `WITH RECURSIVE ancestors AS (
         SELECT id, parent_id FROM pages WHERE id = $1 AND user_id = $2 AND deleted_at IS NOT NULL
         UNION ALL
         SELECT p.id, p.parent_id FROM pages p JOIN ancestors a ON p.id = a.parent_id
         WHERE p.user_id = $2 AND p.deleted_at IS NOT NULL
       ),
       subtree AS (
         SELECT id FROM pages WHERE id = $1 AND user_id = $2 AND deleted_at IS NOT NULL
         UNION ALL
         SELECT p.id FROM pages p JOIN subtree s ON p.parent_id = s.id WHERE p.user_id = $2
       )
       UPDATE pages SET deleted_at = NULL, updated_at = CURRENT_TIMESTAMP
       WHERE id IN (SELECT id FROM ancestors UNION SELECT id FROM subtree) AND user_id = $2`,
      [req.params.id, userId]
    );
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'ゴミ箱にページが見つかりません' });
    }
    res.json({ message: '復元しました' });
  } catch (error) {
    res.status(500).json({ error: '復元エラー' });
  }
});

// ゴミ箱からの完全削除 (APIキー不可)
// 対象ページとその子孫を完全に DELETE する。通常ページ（ゴミ箱外）の完全消去はできない。
router.delete('/:id/permanent', authenticateToken, requireWriteAccess, async (req, res) => {
  try {
    const userId = (req as any).user.userId;
    const result = await pool.query(
      `WITH RECURSIVE subtree AS (
         SELECT id FROM pages WHERE id = $1 AND user_id = $2 AND deleted_at IS NOT NULL
         UNION ALL
         SELECT p.id FROM pages p JOIN subtree s ON p.parent_id = s.id WHERE p.user_id = $2
       )
       DELETE FROM pages WHERE id IN (SELECT id FROM subtree) AND user_id = $2`,
      [req.params.id, userId]
    );
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'ゴミ箱にページが見つかりません' });
    }
    res.json({ message: '完全に削除しました' });
  } catch (error) {
    res.status(500).json({ error: '削除エラー' });
  }
});

export default router;
