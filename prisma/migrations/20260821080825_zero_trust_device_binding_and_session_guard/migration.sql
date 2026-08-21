/*
  Warnings:

  - Added the required column `seq` to the `AuditLog` table without a default value. This is not possible if the table is not empty.

*/
-- CreateTable
CREATE TABLE "DeviceCredential" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "userId" TEXT NOT NULL,
    "label" TEXT NOT NULL,
    "publicKeySpki" TEXT NOT NULL,
    "algorithm" TEXT NOT NULL DEFAULT 'ES256',
    "hardwareBacked" BOOLEAN NOT NULL DEFAULT false,
    "assurance" TEXT NOT NULL DEFAULT 'LOW',
    "status" TEXT NOT NULL DEFAULT 'PENDING_APPROVAL',
    "approvedByAdminId" TEXT,
    "approvedAt" DATETIME,
    "lastAttestedAt" DATETIME,
    "rotationDueAt" DATETIME NOT NULL,
    "graceExpiresAt" DATETIME NOT NULL,
    "replacesId" TEXT,
    "revokedAt" DATETIME,
    "revokedReason" TEXT,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL,
    CONSTRAINT "DeviceCredential_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

-- CreateTable
CREATE TABLE "DeviceChallenge" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "nonce" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "deviceCredentialId" TEXT,
    "purpose" TEXT NOT NULL,
    "issuer" TEXT NOT NULL DEFAULT 'website-1',
    "expiresAt" DATETIME NOT NULL,
    "consumedAt" DATETIME,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- CreateTable
CREATE TABLE "DeskSession" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "userId" TEXT NOT NULL,
    "deviceCredentialId" TEXT NOT NULL,
    "authzTokenId" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'ACTIVE',
    "ipAddress" TEXT NOT NULL,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastActivityAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "absoluteExpiresAt" DATETIME NOT NULL,
    "revokedAt" DATETIME,
    "revokedReason" TEXT,
    "rotatedFromId" TEXT,
    CONSTRAINT "DeskSession_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "DeskSession_deviceCredentialId_fkey" FOREIGN KEY ("deviceCredentialId") REFERENCES "DeviceCredential" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "DeskSession_authzTokenId_fkey" FOREIGN KEY ("authzTokenId") REFERENCES "AuthorizationToken" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

-- CreateTable
CREATE TABLE "SecurityEvent" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "eventId" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "payload" TEXT NOT NULL,
    "signature" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'PENDING',
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "lastAttemptAt" DATETIME,
    "lastError" TEXT,
    "deliveredAt" DATETIME,
    "ackedAt" DATETIME,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- CreateTable
CREATE TABLE "ProcessedSecurityEvent" (
    "eventId" TEXT NOT NULL PRIMARY KEY,
    "type" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "result" TEXT NOT NULL,
    "processedAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- CreateTable
CREATE TABLE "ComponentHealth" (
    "component" TEXT NOT NULL PRIMARY KEY,
    "state" TEXT NOT NULL DEFAULT 'HEALTHY',
    "consecutiveFailures" INTEGER NOT NULL DEFAULT 0,
    "consecutiveSuccesses" INTEGER NOT NULL DEFAULT 0,
    "lastCheckAt" DATETIME,
    "lastSuccessAt" DATETIME,
    "firstFailureAt" DATETIME,
    "confirmedOutageAt" DATETIME,
    "humanConfirmedByAdminId" TEXT,
    "humanConfirmedAt" DATETIME,
    "humanConfirmExpiresAt" DATETIME,
    "updatedAt" DATETIME NOT NULL
);

-- CreateTable
CREATE TABLE "AdminStepUp" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "adminUserId" TEXT NOT NULL,
    "action" TEXT NOT NULL,
    "targetUserId" TEXT,
    "reason" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'ISSUED',
    "issuedAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" DATETIME NOT NULL,
    "consumedAt" DATETIME
);

-- CreateTable
CREATE TABLE "DeviceRecoveryRequest" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "userId" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'PENDING',
    "reason" TEXT NOT NULL,
    "requestedAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "ipAddress" TEXT NOT NULL,
    "userAgent" TEXT NOT NULL,
    "humanVerifiedByAdminId" TEXT,
    "humanVerifiedAt" DATETIME,
    "verificationMethod" TEXT,
    "approvedAt" DATETIME,
    "completedAt" DATETIME,
    "newCredentialId" TEXT,
    CONSTRAINT "DeviceRecoveryRequest_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

-- CreateTable
CREATE TABLE "NotificationLog" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "userId" TEXT NOT NULL,
    "channel" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "severity" TEXT NOT NULL DEFAULT 'INFO',
    "status" TEXT NOT NULL,
    "detail" TEXT NOT NULL,
    "sentAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "NotificationLog_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

-- RedefineTables
PRAGMA defer_foreign_keys=ON;
PRAGMA foreign_keys=OFF;
CREATE TABLE "new_AuditLog" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "stream" TEXT NOT NULL,
    "eventType" TEXT NOT NULL,
    "userId" TEXT,
    "sessionId" TEXT,
    "authzId" TEXT,
    "ipAddress" TEXT NOT NULL,
    "userAgent" TEXT NOT NULL,
    "outcome" TEXT NOT NULL,
    "severity" TEXT NOT NULL DEFAULT 'INFO',
    "metadata" TEXT NOT NULL,
    "seq" INTEGER NOT NULL,
    "prevHash" TEXT,
    "hash" TEXT,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "AuditLog_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User" ("id") ON DELETE SET NULL ON UPDATE CASCADE
);
INSERT INTO "new_AuditLog" ("authzId", "createdAt", "eventType", "id", "ipAddress", "metadata", "outcome", "sessionId", "stream", "userAgent", "userId") SELECT "authzId", "createdAt", "eventType", "id", "ipAddress", "metadata", "outcome", "sessionId", "stream", "userAgent", "userId" FROM "AuditLog";
DROP TABLE "AuditLog";
ALTER TABLE "new_AuditLog" RENAME TO "AuditLog";
CREATE UNIQUE INDEX "AuditLog_seq_key" ON "AuditLog"("seq");
CREATE INDEX "AuditLog_stream_idx" ON "AuditLog"("stream");
CREATE INDEX "AuditLog_userId_idx" ON "AuditLog"("userId");
CREATE INDEX "AuditLog_createdAt_idx" ON "AuditLog"("createdAt");
CREATE INDEX "AuditLog_severity_idx" ON "AuditLog"("severity");
CREATE TABLE "new_AuthorizationToken" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "userId" TEXT NOT NULL,
    "sessionId" TEXT NOT NULL,
    "tokenHash" TEXT NOT NULL,
    "ipAddress" TEXT NOT NULL,
    "userAgent" TEXT NOT NULL,
    "deviceCredentialId" TEXT,
    "bindingNonce" TEXT,
    "targetApp" TEXT NOT NULL DEFAULT 'operations-desk',
    "consumedAt" DATETIME,
    "emergency" BOOLEAN NOT NULL DEFAULT false,
    "issuedByAdminId" TEXT,
    "status" TEXT NOT NULL DEFAULT 'ACTIVE',
    "issuedAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" DATETIME NOT NULL,
    "revokedAt" DATETIME,
    CONSTRAINT "AuthorizationToken_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "AuthorizationToken_sessionId_fkey" FOREIGN KEY ("sessionId") REFERENCES "Session" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);
INSERT INTO "new_AuthorizationToken" ("expiresAt", "id", "ipAddress", "issuedAt", "revokedAt", "sessionId", "status", "tokenHash", "userAgent", "userId") SELECT "expiresAt", "id", "ipAddress", "issuedAt", "revokedAt", "sessionId", "status", "tokenHash", "userAgent", "userId" FROM "AuthorizationToken";
DROP TABLE "AuthorizationToken";
ALTER TABLE "new_AuthorizationToken" RENAME TO "AuthorizationToken";
CREATE UNIQUE INDEX "AuthorizationToken_tokenHash_key" ON "AuthorizationToken"("tokenHash");
CREATE INDEX "AuthorizationToken_sessionId_idx" ON "AuthorizationToken"("sessionId");
CREATE INDEX "AuthorizationToken_userId_idx" ON "AuthorizationToken"("userId");
CREATE INDEX "AuthorizationToken_tokenHash_idx" ON "AuthorizationToken"("tokenHash");
CREATE INDEX "AuthorizationToken_deviceCredentialId_idx" ON "AuthorizationToken"("deviceCredentialId");
CREATE TABLE "new_Session" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "userId" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'PENDING_MFA',
    "ipAddress" TEXT NOT NULL,
    "userAgent" TEXT NOT NULL,
    "mfaToken" TEXT,
    "mfaExpiry" DATETIME,
    "connectStepUpRequired" BOOLEAN NOT NULL DEFAULT false,
    "mfaOverridden" BOOLEAN NOT NULL DEFAULT false,
    "mfaOverrideAdminId" TEXT,
    "connectCooldownUntil" DATETIME,
    "deviceCredentialId" TEXT,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" DATETIME NOT NULL,
    "revokedAt" DATETIME,
    CONSTRAINT "Session_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);
INSERT INTO "new_Session" ("connectStepUpRequired", "createdAt", "expiresAt", "id", "ipAddress", "mfaExpiry", "mfaToken", "revokedAt", "status", "userAgent", "userId") SELECT "connectStepUpRequired", "createdAt", "expiresAt", "id", "ipAddress", "mfaExpiry", "mfaToken", "revokedAt", "status", "userAgent", "userId" FROM "Session";
DROP TABLE "Session";
ALTER TABLE "new_Session" RENAME TO "Session";
CREATE INDEX "Session_userId_idx" ON "Session"("userId");
CREATE INDEX "Session_status_idx" ON "Session"("status");
CREATE TABLE "new_User" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "email" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "role" TEXT NOT NULL DEFAULT 'EMPLOYEE',
    "idpSubject" TEXT NOT NULL,
    "passwordHash" TEXT,
    "passwordChangedAt" DATETIME,
    "recoveryEmail" TEXT,
    "secondaryChannel" TEXT,
    "accessRevoked" BOOLEAN NOT NULL DEFAULT false,
    "accessRevokedAt" DATETIME,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL
);
INSERT INTO "new_User" ("createdAt", "email", "id", "idpSubject", "name", "role", "updatedAt") SELECT "createdAt", "email", "id", "idpSubject", "name", "role", "updatedAt" FROM "User";
DROP TABLE "User";
ALTER TABLE "new_User" RENAME TO "User";
CREATE UNIQUE INDEX "User_email_key" ON "User"("email");
CREATE UNIQUE INDEX "User_idpSubject_key" ON "User"("idpSubject");
PRAGMA foreign_keys=ON;
PRAGMA defer_foreign_keys=OFF;

-- CreateIndex
CREATE INDEX "DeviceCredential_userId_idx" ON "DeviceCredential"("userId");

-- CreateIndex
CREATE INDEX "DeviceCredential_status_idx" ON "DeviceCredential"("status");

-- CreateIndex
CREATE INDEX "DeviceCredential_publicKeySpki_idx" ON "DeviceCredential"("publicKeySpki");

-- CreateIndex
CREATE UNIQUE INDEX "DeviceChallenge_nonce_key" ON "DeviceChallenge"("nonce");

-- CreateIndex
CREATE INDEX "DeviceChallenge_userId_purpose_idx" ON "DeviceChallenge"("userId", "purpose");

-- CreateIndex
CREATE INDEX "DeviceChallenge_expiresAt_idx" ON "DeviceChallenge"("expiresAt");

-- CreateIndex
CREATE UNIQUE INDEX "DeskSession_authzTokenId_key" ON "DeskSession"("authzTokenId");

-- CreateIndex
CREATE INDEX "DeskSession_userId_idx" ON "DeskSession"("userId");

-- CreateIndex
CREATE INDEX "DeskSession_status_idx" ON "DeskSession"("status");

-- CreateIndex
CREATE INDEX "DeskSession_deviceCredentialId_idx" ON "DeskSession"("deviceCredentialId");

-- CreateIndex
CREATE UNIQUE INDEX "SecurityEvent_eventId_key" ON "SecurityEvent"("eventId");

-- CreateIndex
CREATE INDEX "SecurityEvent_status_idx" ON "SecurityEvent"("status");

-- CreateIndex
CREATE INDEX "SecurityEvent_userId_idx" ON "SecurityEvent"("userId");

-- CreateIndex
CREATE INDEX "ProcessedSecurityEvent_userId_idx" ON "ProcessedSecurityEvent"("userId");

-- CreateIndex
CREATE INDEX "AdminStepUp_adminUserId_status_idx" ON "AdminStepUp"("adminUserId", "status");

-- CreateIndex
CREATE INDEX "DeviceRecoveryRequest_userId_status_idx" ON "DeviceRecoveryRequest"("userId", "status");

-- CreateIndex
CREATE INDEX "NotificationLog_userId_idx" ON "NotificationLog"("userId");

-- CreateIndex
CREATE INDEX "NotificationLog_sentAt_idx" ON "NotificationLog"("sentAt");
