import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import './db'; 
import authRoutes from './routes/auth';
import pageRoutes from './routes/pages'; // ★追加
import uploadRoutes from './routes/uploads'; // ★追加

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use('/uploads', express.static('uploads'));

app.use('/api/auth', authRoutes);
app.use('/api/pages', pageRoutes); // ★追加
app.use('/api/uploads', uploadRoutes); // ★追加

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', message: 'Motion Backend is running!' });
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});