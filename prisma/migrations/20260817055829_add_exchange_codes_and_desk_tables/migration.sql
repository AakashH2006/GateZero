-- CreateTable
CREATE TABLE "AuthExchangeCode" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "code" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "sessionId" TEXT NOT NULL,
    "targetApp" TEXT NOT NULL,
    "ipAddress" TEXT NOT NULL,
    "userAgent" TEXT NOT NULL,
    "used" BOOLEAN NOT NULL DEFAULT false,
    "expiresAt" DATETIME NOT NULL,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- CreateTable
CREATE TABLE "Assignment" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "title" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "department" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'TODO',
    "priority" TEXT NOT NULL DEFAULT 'STANDARD',
    "assigneeName" TEXT NOT NULL,
    "assigneeEmail" TEXT NOT NULL,
    "deadline" TEXT NOT NULL,
    "rotation" REAL NOT NULL DEFAULT 0.0,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL
);

-- CreateTable
CREATE TABLE "WireBulletin" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "timestamp" TEXT NOT NULL,
    "category" TEXT NOT NULL,
    "headline" TEXT NOT NULL,
    "body" TEXT NOT NULL,
    "urgency" TEXT NOT NULL DEFAULT 'NORMAL',
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- CreateTable
CREATE TABLE "StaffMember" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "name" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "role" TEXT NOT NULL,
    "department" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'ON_DUTY',
    "deskLocation" TEXT NOT NULL,
    "extension" TEXT NOT NULL,
    "avatarUrl" TEXT,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL
);

-- CreateTable
CREATE TABLE "LedgerRecord" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "refNumber" TEXT NOT NULL,
    "entryDate" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "category" TEXT NOT NULL,
    "amount" REAL NOT NULL,
    "type" TEXT NOT NULL DEFAULT 'DEBIT',
    "authorizedBy" TEXT NOT NULL,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- CreateTable
CREATE TABLE "ArchiveRecord" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "recordNumber" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "department" TEXT NOT NULL,
    "filingDate" TEXT NOT NULL,
    "summary" TEXT NOT NULL,
    "tags" TEXT NOT NULL,
    "filedBy" TEXT NOT NULL,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- CreateTable
CREATE TABLE "DeskMessage" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "senderName" TEXT NOT NULL,
    "senderEmail" TEXT NOT NULL,
    "recipientEmail" TEXT NOT NULL,
    "subject" TEXT NOT NULL,
    "content" TEXT NOT NULL,
    "urgent" BOOLEAN NOT NULL DEFAULT false,
    "read" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- CreateTable
CREATE TABLE "CalendarShift" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "title" TEXT NOT NULL,
    "date" TEXT NOT NULL,
    "startTime" TEXT NOT NULL,
    "endTime" TEXT NOT NULL,
    "shiftType" TEXT NOT NULL,
    "assignedStaff" TEXT NOT NULL,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- CreateIndex
CREATE UNIQUE INDEX "AuthExchangeCode_code_key" ON "AuthExchangeCode"("code");

-- CreateIndex
CREATE INDEX "AuthExchangeCode_code_idx" ON "AuthExchangeCode"("code");

-- CreateIndex
CREATE INDEX "AuthExchangeCode_userId_idx" ON "AuthExchangeCode"("userId");

-- CreateIndex
CREATE INDEX "Assignment_status_idx" ON "Assignment"("status");

-- CreateIndex
CREATE INDEX "Assignment_department_idx" ON "Assignment"("department");

-- CreateIndex
CREATE INDEX "WireBulletin_createdAt_idx" ON "WireBulletin"("createdAt");

-- CreateIndex
CREATE INDEX "WireBulletin_category_idx" ON "WireBulletin"("category");

-- CreateIndex
CREATE UNIQUE INDEX "StaffMember_email_key" ON "StaffMember"("email");

-- CreateIndex
CREATE INDEX "StaffMember_department_idx" ON "StaffMember"("department");

-- CreateIndex
CREATE INDEX "StaffMember_status_idx" ON "StaffMember"("status");

-- CreateIndex
CREATE UNIQUE INDEX "LedgerRecord_refNumber_key" ON "LedgerRecord"("refNumber");

-- CreateIndex
CREATE INDEX "LedgerRecord_category_idx" ON "LedgerRecord"("category");

-- CreateIndex
CREATE INDEX "LedgerRecord_entryDate_idx" ON "LedgerRecord"("entryDate");

-- CreateIndex
CREATE UNIQUE INDEX "ArchiveRecord_recordNumber_key" ON "ArchiveRecord"("recordNumber");

-- CreateIndex
CREATE INDEX "ArchiveRecord_department_idx" ON "ArchiveRecord"("department");

-- CreateIndex
CREATE INDEX "DeskMessage_recipientEmail_idx" ON "DeskMessage"("recipientEmail");

-- CreateIndex
CREATE INDEX "DeskMessage_createdAt_idx" ON "DeskMessage"("createdAt");

-- CreateIndex
CREATE INDEX "CalendarShift_date_idx" ON "CalendarShift"("date");
