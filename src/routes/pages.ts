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
    // 並び順は sort_order 順（同値の場合は作成順で安定させる）
    const result = includeDeleted
      ? await pool.query(
          'SELECT id, parent_id, title, is_locked, password_hash, deleted_at, sort_order FROM pages WHERE user_id = $1 ORDER BY sort_order ASC, created_at ASC',
          [userId]
        )
      : await pool.query(
          'SELECT id, parent_id, title, is_locked, password_hash, sort_order FROM pages WHERE user_id = $1 AND deleted_at IS NULL ORDER BY sort_order ASC, created_at ASC',
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

// 全文検索 (R2-2)：一覧 API は blocks を含まないため、未読込ページの本文は
// フロントの検索で拾えない。タイトル＋blocks 全文をサーバー側で検索する。
// '/:id' より前に登録すること（'/search' が id='search' と解釈されるのを防ぐ）。
router.get('/search', authenticateToken, async (req, res) => {
  try {
    const user = (req as any).user;

    // APIキーの場合はスコープを確認
    if (user.isApiKey && (!user.scopes || !user.scopes.includes('read:pages'))) {
      return res.status(403).json({ error: 'read:pages スコープが許可されていません' });
    }

    const q = String(req.query.q || '').trim();
    if (!q) return res.json([]);

    // ILIKE のワイルドカード文字をエスケープ
    const escaped = q.replace(/\\/g, '\\\\').replace(/%/g, '\\%').replace(/_/g, '\\_');
    const pattern = `%${escaped}%`;

    const result = await pool.query(
      `SELECT id, parent_id, title, is_locked, blocks FROM pages
       WHERE user_id = $1 AND deleted_at IS NULL
       AND (title ILIKE $2 ESCAPE '\\' OR blocks::text ILIKE $2 ESCAPE '\\')
       ORDER BY sort_order ASC, created_at ASC LIMIT 50`,
      [user.userId, pattern]
    );

    res.json(result.rows.map((row: any) => {
      let blocks = row.blocks;
      if (typeof blocks === 'string') {
        try { blocks = JSON.parse(blocks); } catch (e) { blocks = []; }
      }
      return {
        id: row.id,
        parent_id: row.parent_id,
        title: row.title,
        is_locked: row.is_locked,
        blocks: Array.isArray(blocks) ? blocks : [],
      };
    }));
  } catch (error) {
    res.status(500).json({ error: '検索エラー' });
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
// sortOrder を省略した場合は同じ親の中の末尾に自動配置する。
// ※ 末尾番号の算出と INSERT を分けているのは、同一パラメータを
//   複数箇所で使うと Postgres が型推論で 42P08 を返すため。
router.post('/', authenticateToken, requireScope('write:pages'), async (req, res) => {
  try {
    const userId = (req as any).user.userId;
    const { id, title, parentId, blocks, isLocked, passwordHash, sortOrder } = req.body;

    let order = sortOrder ?? null;
    if (order === null || order === undefined) {
      const maxResult = await pool.query(
        'SELECT COALESCE(MAX(sort_order), -1) + 1 AS next_order FROM pages WHERE user_id = $1 AND parent_id IS NOT DISTINCT FROM $2 AND deleted_at IS NULL',
        [userId, parentId]
      );
      order = maxResult.rows[0].next_order;
    }

    const result = await pool.query(
      'INSERT INTO pages (id, user_id, parent_id, title, blocks, is_locked, password_hash, sort_order) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *',
      [id, userId, parentId, title, JSON.stringify(blocks || []), isLocked, passwordHash, order]
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Create page error:', error);
    res.status(500).json({ error: '作成エラー' });
  }
});

// 兄弟ページの並び替え（ドラッグ＆ドロップ／上下移動用）。
// body: { parentId: string | null, orderedIds: string[] }（兄弟全員の順序）。
// 対象がすべて同一ユーザ・同一親・ゴミ箱外であることを検証してから一括更新する。
router.post('/reorder', authenticateToken, requireScope('write:pages'), async (req, res) => {
  const userId = (req as any).user.userId;
  const { parentId, orderedIds } = req.body;
  if (!Array.isArray(orderedIds)) {
    return res.status(400).json({ error: 'orderedIds が必要です' });
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const found = await client.query(
      'SELECT id, parent_id FROM pages WHERE user_id = $1 AND id = ANY($2) AND deleted_at IS NULL',
      [userId, orderedIds]
    );
    const sameParent = (p: string | null) =>
      parentId === null || parentId === undefined ? p === null : p === parentId;
    if (found.rows.length !== orderedIds.length || !found.rows.every(r => sameParent(r.parent_id))) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: '並び替え対象が不正です' });
    }
    for (let i = 0; i < orderedIds.length; i++) {
      await client.query(
        'UPDATE pages SET sort_order = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 AND user_id = $3',
        [i, orderedIds[i], userId]
      );
    }
    await client.query('COMMIT');
    res.json({ ok: true });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Reorder error:', error);
    res.status(500).json({ error: '並び替えエラー' });
  } finally {
    client.release();
  }
});

// ページの更新 (自動保存用 / APIキーは write:pages スコープが必要)
// ゴミ箱内のページへの更新は 410 とし、自動保存がゴミ箱ページを蘇らせないようにする。
// 楽観ロック (#5)：フロントが expectedUpdatedAt（ページ読込時の updated_at）を送った場合、
// それと一致する行だけ更新する。一致しない場合は上書きせず 409 を返し、現在の updated_at
// を currentUpdatedAt として返す。expectedUpdatedAt を省略したクライアント（APIキー経由の
// 既存ツール等）は従来どおり無条件で更新する（後方互換）。
router.put('/:id', authenticateToken, requireScope('write:pages'), async (req, res) => {
  try {
    const userId = (req as any).user.userId;
    const { title, parentId, blocks, isLocked, passwordHash, sortOrder, expectedUpdatedAt } = req.body;

    // sortOrder を省略した場合は既存値を維持する（自動保存の PUT で順序が初期化されないように）。
    // ※ DB の updated_at はマイクロ秒精度だが、JS の Date / JSON 経由ではミリ秒に
    //   切り捨てられるため、両辺をミリ秒に切り捨てて比較する（同一ミリ秒内の
    //   連続更新という極めて狭い競合ウィンドウは残るが、実用上は無視できる）。
    const result = expectedUpdatedAt
      ? await pool.query(
          "UPDATE pages SET title = $1, parent_id = $2, blocks = $3, is_locked = $4, password_hash = $5, sort_order = COALESCE($6, sort_order), updated_at = CURRENT_TIMESTAMP WHERE id = $7 AND user_id = $8 AND deleted_at IS NULL AND date_trunc('milliseconds', updated_at) = date_trunc('milliseconds', $9::timestamptz) RETURNING *",
          [title, parentId, JSON.stringify(blocks), isLocked, passwordHash, sortOrder ?? null, req.params.id, userId, expectedUpdatedAt]
        )
      : await pool.query(
          'UPDATE pages SET title = $1, parent_id = $2, blocks = $3, is_locked = $4, password_hash = $5, sort_order = COALESCE($6, sort_order), updated_at = CURRENT_TIMESTAMP WHERE id = $7 AND user_id = $8 AND deleted_at IS NULL RETURNING *',
          [title, parentId, JSON.stringify(blocks), isLocked, passwordHash, sortOrder ?? null, req.params.id, userId]
        );
    if (result.rows.length > 0) return res.json(result.rows[0]);

    // 更新対象がない場合：ゴミ箱内なら 410、楽観ロックの不一致なら 409、
    // それ以外は 404（フロントは新規作成へ進む）
    const existing = await pool.query(
      'SELECT deleted_at, updated_at FROM pages WHERE id = $1 AND user_id = $2',
      [req.params.id, userId]
    );
    if (existing.rows.length > 0 && existing.rows[0].deleted_at !== null) {
      return res.status(410).json({ error: 'このページはゴミ箱にあります' });
    }
    if (expectedUpdatedAt && existing.rows.length > 0) {
      return res.status(409).json({
        error: '競合：他の端末で更新されました。上書きせず保存を中断しました',
        currentUpdatedAt: existing.rows[0].updated_at,
      });
    }
    return res.status(404).json({ error: 'ページが見つかりません' });
  } catch (error) {
    console.error('Update page error:', error);
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
