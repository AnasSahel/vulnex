import { createDb } from "@vulnex/db";

export const db = createDb(process.env.DATABASE_URL!);
