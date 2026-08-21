-- RedefineTables
PRAGMA defer_foreign_keys=ON;
PRAGMA foreign_keys=OFF;
CREATE TABLE "new_DeskSession" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "userId" TEXT NOT NULL,
    "deviceCredentialId" TEXT NOT NULL,
    "authzTokenId" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'ACTIVE',
    "ipAddress" TEXT NOT NULL,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastActivityAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "absoluteExpiresAt" DATETIME NOT NULL,
    "deviceVerifiedAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "revokedAt" DATETIME,
    "revokedReason" TEXT,
    "rotatedFromId" TEXT,
    CONSTRAINT "DeskSession_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "DeskSession_deviceCredentialId_fkey" FOREIGN KEY ("deviceCredentialId") REFERENCES "DeviceCredential" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "DeskSession_authzTokenId_fkey" FOREIGN KEY ("authzTokenId") REFERENCES "AuthorizationToken" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);
INSERT INTO "new_DeskSession" ("absoluteExpiresAt", "authzTokenId", "createdAt", "deviceCredentialId", "id", "ipAddress", "lastActivityAt", "revokedAt", "revokedReason", "rotatedFromId", "status", "userId") SELECT "absoluteExpiresAt", "authzTokenId", "createdAt", "deviceCredentialId", "id", "ipAddress", "lastActivityAt", "revokedAt", "revokedReason", "rotatedFromId", "status", "userId" FROM "DeskSession";
DROP TABLE "DeskSession";
ALTER TABLE "new_DeskSession" RENAME TO "DeskSession";
CREATE UNIQUE INDEX "DeskSession_authzTokenId_key" ON "DeskSession"("authzTokenId");
CREATE INDEX "DeskSession_userId_idx" ON "DeskSession"("userId");
CREATE INDEX "DeskSession_status_idx" ON "DeskSession"("status");
CREATE INDEX "DeskSession_deviceCredentialId_idx" ON "DeskSession"("deviceCredentialId");
PRAGMA foreign_keys=ON;
PRAGMA defer_foreign_keys=OFF;
