import express from 'express';
import cookieParser from 'cookie-parser';
import 'dotenv/config.js'
import { connectDB } from './db/connectDB.js';

import authRoutes from './routes/auth.route.js'

const app = express();

const PORT = process.env.PORT || 5000;

app.use(express.json());

app.use(cookieParser());

app.use("/api/auth",authRoutes)

app.listen(PORT,()=>{
    connectDB()
    console.log(`Server is running on port ${PORT}`);
})