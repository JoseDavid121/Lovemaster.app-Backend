import mongoose from "mongoose";
import { DB_PASS, DB_USER } from './config.js';

export const connectDB = async () => {
    try {
        await mongoose.connect(`mongodb://${DB_USER}:${DB_PASS}@127.0.0.1:27017/lovemaster`, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
        });
        
        console.log("DATABASE CONNECTED");
    } catch (error) {
        console.error("Error connecting to database:", error.message);
        throw error;
    }

    mongoose.connection.on('connected', () => {
        console.log('Mongoose connected to database');
    });
    
    mongoose.connection.on('error', (err) => {
        console.error('Mongoose connection error:', err);
    });
    
    mongoose.connection.on('disconnected', () => {
        console.log('Mongoose disconnected');
    });
    
    process.on('SIGINT', async () => {
        await mongoose.connection.close();
        process.exit(0);
    });
    
}