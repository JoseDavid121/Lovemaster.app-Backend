import { config } from "dotenv";

config();

export const DB_USER = process.env.DB_USER;
export const DB_PASS = process.env.DB_PASS;

export const PORT = process.env.PORT || 5000;
export const HOST = '68.178.205.47:' + PORT;

export const TOKEN_SECRET = process.env.TOKEN_SECRET;