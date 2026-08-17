/**
 * lib/db.ts
 * Prisma client singleton for Next.js + Prisma v7 with SQLite driver adapter.
 *
 * Prisma v7 requires an explicit driver adapter.
 * For dev (SQLite): uses @prisma/adapter-better-sqlite3
 * For prod (PostgreSQL): replace adapter with @prisma/adapter-pg
 *
 * Avoids multiple instances in Next.js dev hot-reload.
 * https://www.prisma.io/docs/guides/performance-and-optimization/connection-management
 */

import { PrismaClient } from "@prisma/client";
import { PrismaBetterSqlite3 } from "@prisma/adapter-better-sqlite3";

function createPrismaClient(): PrismaClient {
  const dbUrl = process.env.DATABASE_URL;
  if (!dbUrl) throw new Error("DATABASE_URL is not set");

  // PrismaBetterSqlite3 takes { url } config object and creates the Database internally
  const adapter = new PrismaBetterSqlite3({ url: dbUrl });

  return new PrismaClient({
    adapter,
    log:
      process.env.NODE_ENV === "development"
        ? ["error", "warn"]
        : ["error"],
  });
}

const globalForPrisma = globalThis as unknown as {
  prisma: PrismaClient | undefined;
};

export const prisma = globalForPrisma.prisma ?? createPrismaClient();

if (process.env.NODE_ENV !== "production") {
  globalForPrisma.prisma = prisma;
}
