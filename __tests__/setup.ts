/**
 * __tests__/setup.ts
 * Global test setup and teardown.
 * Copies the freshly synced SQLite dev database to test.db for test isolation.
 */

import fs from "fs";
import path from "path";
import { afterAll, beforeAll } from "vitest";
import { prisma } from "../lib/db";

beforeAll(async () => {
  try {
    const devDbPath = path.resolve(__dirname, "../prisma/dev.db");
    const testDbPath = path.resolve(__dirname, "../prisma/test.db");
    if (fs.existsSync(devDbPath)) {
      fs.copyFileSync(devDbPath, testDbPath);
    }
  } catch (err) {
    console.error("Test setup database copy error:", err);
  }
});

afterAll(async () => {
  await prisma.$disconnect();
});
