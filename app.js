import express, { response } from 'express';
import morgan from 'morgan';
import cookieParser from 'cookie-parser';
import authRoutes from './routes/auth.routes.js'
import { PORT } from './config.js';
import { connectDB } from './db.js';
import cors from 'cors'

const app = express();

app.use(cors({
    origin: ['https://lovemaster.app', 'http://localhost:5173'],
    credentials: true
}));
app.use(morgan('dev'));
app.use(express.json());
app.use(cookieParser());
app.use('/api', authRoutes);

connectDB();

app.listen(PORT, () => {
    console.log(`Servidor HTTPS en ejecución en el puerto ${PORT}`);
  });

export default app;
