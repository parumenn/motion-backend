import express from 'express';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import { authenticateToken } from '../middleware/auth';

const router = express.Router();

// 画像の保存先フォルダを確保
const uploadDir = path.join(__dirname, '../../uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Multer (ファイル受け取りツール) の設定
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, 'img_' + uniqueSuffix + path.extname(file.originalname));
  }
});
const upload = multer({ storage, limits: { fileSize: 500 * 1024 * 1024 } }); // 500MB上限

// 画像アップロード
router.post('/', authenticateToken, upload.single('image'), (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'ファイルがありません' });
    
    // フロントエンドからアクセスできる画像URLを組み立てて返す
    const fileUrl = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
    res.status(201).json({ url: fileUrl, fileId: req.file.filename });
  } catch (error) {
    res.status(500).json({ error: 'アップロードエラー' });
  }
});

// 画像削除
router.delete('/:filename', authenticateToken, (req, res) => {
  try {
    const filePath = path.join(uploadDir, req.params.filename);
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }
    res.json({ message: '画像を削除しました' });
  } catch (error) {
    res.status(500).json({ error: '削除エラー' });
  }
});

export default router;