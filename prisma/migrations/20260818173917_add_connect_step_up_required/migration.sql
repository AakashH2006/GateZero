-- RedefineTables
PRAGMA defer_foreign_keys=ON;
PRAGMA foreign_keys=OFF;
CREATE TABLE "new_Session" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "userId" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'PENDING_MFA',
    "ipAddress" TEXT NOT NULL,
    "userAgent" TEXT NOT NULL,
    "mfaToken" TEXT,
    "mfaExpiry" DATETIME,
    "connectStepUpRequired" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" DATETIME NOT NULL,
    "revokedAt" DATETIME,
    CONSTRAINT "Session_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);
INSERT INTO "new_Session" ("createdAt", "expiresAt", "id", "ipAddress", "mfaExpiry", "mfaToken", "revokedAt", "status", "userAgent", "userId") SELECT "createdAt", "expiresAt", "id", "ipAddress", "mfaExpiry", "mfaToken", "revokedAt", "status", "userAgent", "userId" FROM "Session";
DROP TABLE "Session";
ALTER TABLE "new_Session" RENAME TO "Session";
CREATE INDEX "Session_userId_idx" ON "Session"("userId");
CREATE INDEX "Session_status_idx" ON "Session"("status");
PRAGMA foreign_keys=ON;
PRAGMA defer_foreign_keys=OFF;
