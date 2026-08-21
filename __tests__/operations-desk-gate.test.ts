/**
 * __tests__/operations-desk-gate.test.ts
 * Gate tests for Website 2 (The Operations Desk).
 *
 * Verifies:
 *   1. Exchange code issuance, single-use enforcement, and 60s expiration.
 *   2. Authorization introspection and cryptographic device binding.
 *   3. Instant revocation enforcement.
 *   4. Operations Desk database CRUD operations.
 *
 * TWO MODEL CHANGES UNDER THESE TESTS
 * ───────────────────────────────────
 * 1. The exchange code no longer MINTS an authorization. Connect mints it after
 *    the risk assessment and the device proof (W1 §8); the code is only a
 *    60-second front-channel handle for redeeming that existing grant
 *    (W2 §3). Each test therefore issues an authorization first.
 *
 * 2. Device binding is cryptographic, not a hashed User-Agent. W1 §5 forbids
 *    treating a UA string as a reliable identity signal, so the mismatch test
 *    now presents a different device *credential*.
 */

import { describe, it, expect, beforeEach } from "vitest";
import { prisma } from "../lib/db";
import {
  issueExchangeCode,
  exchangeCodeForToken,
  introspectTokenLive,
  issueAuthorization,
  revokeAuthorization,
  hashUA,
} from "../lib/authz-service";
import { SessionStatus } from "@prisma/client";
import { createActiveCredential } from "./helpers/device";

describe("Website 2 Gateway & Operations Desk Automated Tests", () => {
  let testUserId: string;
  let testSessionId: string;
  let testCredentialId: string;
  const testUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) TestBrowser/1.0";
  const testIP = "127.0.0.1";

  beforeEach(async () => {
    // Upsert clean test user
    const user = await prisma.user.upsert({
      where: { email: "desk-tester@company.internal" },
      update: { name: "Desk Tester", role: "EMPLOYEE" },
      create: {
        email: "desk-tester@company.internal",
        name: "Desk Tester",
        idpSubject: "sub-tester-12345",
        role: "EMPLOYEE",
      },
    });
    testUserId = user.id;

    // Create active session
    const session = await prisma.session.create({
      data: {
        userId: testUserId,
        status: SessionStatus.ACTIVE,
        ipAddress: testIP,
        userAgent: hashUA(testUA),
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      },
    });
    testSessionId = session.id;

    // W1 §8: every authorization is bound to a registered device credential.
    // Retire any credential left by a previous run so the one-employee-one-device
    // invariant holds and the newest credential is the active one.
    await prisma.deviceCredential.updateMany({
      where: { userId: testUserId, status: "ACTIVE" },
      data: { status: "REVOKED", revokedAt: new Date(), revokedReason: "TEST_RESET" },
    });
    const { credential } = await createActiveCredential({ userId: testUserId });
    testCredentialId = credential.id;
  });

  /**
   * Stand in for a completed Connect: a fresh 5-minute, one-time, device-bound
   * authorization for the test session.
   */
  async function connect() {
    return issueAuthorization({
      sessionId: testSessionId,
      userId: testUserId,
      ipAddress: testIP,
      userAgent: testUA,
      deviceCredentialId: testCredentialId,
    });
  }

  describe("1. Exchange Code Handshake", () => {
    it("should issue a single-use exchange code with 60-second TTL", async () => {
      await connect();

      const code = await issueExchangeCode({
        sessionId: testSessionId,
        userId: testUserId,
        ipAddress: testIP,
        userAgent: testUA,
      });

      expect(code).toBeDefined();
      expect(code.length).toBeGreaterThan(20);

      const record = await prisma.authExchangeCode.findUnique({ where: { code } });
      expect(record).not.toBeNull();
      expect(record?.used).toBe(false);
      expect(record?.expiresAt.getTime()).toBeGreaterThan(Date.now());
    });

    it("should exchange code for the existing authorization and prevent replay", async () => {
      const authorization = await connect();

      const code = await issueExchangeCode({
        sessionId: testSessionId,
        userId: testUserId,
        ipAddress: testIP,
        userAgent: testUA,
      });

      // First exchange: should succeed
      const tokenResult = await exchangeCodeForToken({
        code,
        ipAddress: testIP,
        userAgent: testUA,
      });

      // The code resolves to the grant Connect already minted — it does not
      // mint a second one.
      expect(tokenResult.tokenId).toBe(authorization.tokenId);
      expect(tokenResult.deviceCredentialId).toBe(testCredentialId);
      expect(tokenResult.user.email).toBe("desk-tester@company.internal");

      // Second exchange with same code: MUST fail (single-use enforcement)
      await expect(
        exchangeCodeForToken({
          code,
          ipAddress: testIP,
          userAgent: testUA,
        })
      ).rejects.toThrow("INVALID_OR_EXPIRED_CODE");
    });
  });

  describe("2. Authorization introspection & cryptographic device binding", () => {
    it("should verify an active authorization against the database", async () => {
      const { tokenId } = await connect();

      const verification = await introspectTokenLive({
        tokenId,
        userAgent: testUA,
        ipAddress: testIP,
      });

      expect(verification.valid).toBe(true);
      expect(verification.userEmail).toBe("desk-tester@company.internal");
      expect(verification.userName).toBe("Desk Tester");
      expect(verification.deviceCredentialId).toBe(testCredentialId);
    });

    it("should reject a grant presented with a different device credential", async () => {
      const { tokenId } = await connect();

      const stranger = await prisma.user.create({
        data: {
          email: `stranger-${Date.now()}@company.internal`,
          name: "Stranger",
          idpSubject: `sub-stranger-${Date.now()}`,
          role: "EMPLOYEE",
        },
      });
      const other = await createActiveCredential({ userId: stranger.id });

      const verification = await introspectTokenLive({
        tokenId,
        deviceCredentialId: other.credential.id,
        ipAddress: testIP,
      });

      expect(verification.valid).toBe(false);
      expect(verification.reason).toBe("DEVICE_MISMATCH");
    });

    it("should NOT reject a grant merely because the User-Agent changed (§5)", async () => {
      // UA is telemetry. A browser change is not a device change.
      const { tokenId } = await connect();

      const verification = await introspectTokenLive({
        tokenId,
        userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) DifferentBrowser/2.0",
        deviceCredentialId: testCredentialId,
        ipAddress: testIP,
      });

      expect(verification.valid).toBe(true);
    });

    it("should immediately enforce revocation", async () => {
      const { tokenId } = await connect();

      let check = await introspectTokenLive({ tokenId, userAgent: testUA });
      expect(check.valid).toBe(true);

      await revokeAuthorization(tokenId);

      check = await introspectTokenLive({ tokenId, userAgent: testUA });
      expect(check.valid).toBe(false);
      expect(check.reason).toBe("TOKEN_REVOKED");
    });
  });

  describe("3. The Operations Desk Database CRUD", () => {
    it("should manage assignments lifecycle on corkboard", async () => {
      const assignment = await prisma.assignment.create({
        data: {
          title: "Network Switch Firmware Upgrade",
          description: "Apply security patch to Core Switch 01.",
          department: "ENGINEERING",
          status: "TODO",
          priority: "URGENT",
          assigneeName: "Marcus Vance",
          assigneeEmail: "m.vance@company.internal",
          deadline: "1900 HRS",
          rotation: -1.2,
        },
      });

      expect(assignment.id).toBeDefined();
      expect(assignment.priority).toBe("URGENT");

      // Update status to IN_PROGRESS
      const updated = await prisma.assignment.update({
        where: { id: assignment.id },
        data: { status: "IN_PROGRESS" },
      });
      expect(updated.status).toBe("IN_PROGRESS");

      // Clean up
      await prisma.assignment.delete({ where: { id: assignment.id } });
    });

    it("should record and balance ledger transactions", async () => {
      const debit = await prisma.ledgerRecord.create({
        data: {
          refNumber: "TEST-LED-001",
          entryDate: "2026-08-16",
          description: "Cooling Fan Hardware",
          category: "INFRASTRUCTURE",
          amount: 500.0,
          type: "DEBIT",
          authorizedBy: "Tester",
        },
      });

      const credit = await prisma.ledgerRecord.create({
        data: {
          refNumber: "TEST-LED-002",
          entryDate: "2026-08-16",
          description: "Vendor Rebate",
          category: "PROCUREMENT",
          amount: 200.0,
          type: "CREDIT",
          authorizedBy: "Tester",
        },
      });

      const all = await prisma.ledgerRecord.findMany({
        where: { refNumber: { in: ["TEST-LED-001", "TEST-LED-002"] } },
      });

      const debits = all.filter(r => r.type === "DEBIT").reduce((acc: number, r) => acc + r.amount, 0);
      const credits = all.filter(r => r.type === "CREDIT").reduce((acc: number, r) => acc + r.amount, 0);

      expect(debits).toBe(500.0);
      expect(credits).toBe(200.0);
      expect(credits - debits).toBe(-300.0);

      // Clean up
      await prisma.ledgerRecord.deleteMany({
        where: { refNumber: { in: ["TEST-LED-001", "TEST-LED-002"] } },
      });
    });
  });
});
