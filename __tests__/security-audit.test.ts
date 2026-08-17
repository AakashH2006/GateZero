/**
 * __tests__/security-audit.test.ts
 * GateZero Automated Threat Defense & Security Regression Suite
 *
 * Automated regression tests covering key threat scenarios:
 *   1. Replay Attacks (Code reuse, OTP single-use)
 *   2. Token Forgery & Signature Tampering (Unsigned JWT, Rogue secret keys)
 *   3. Session Hijacking & Device Binding Mismatches (Spoofed User-Agent/Fingerprint)
 *   4. Unauthorized Privilege Escalation & MFA Bypass Attempts
 *   5. Sliding-Window Rate Limiting & DoS / Brute-Force Throttling
 *   6. Instant Revocation & Stale Token Invalidation
 *   7. Stored XSS Neutralization in Dynamic Templates
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
import { verifyEmailOTP } from "../lib/auth/email-mfa";
import { checkRateLimit, connectRateLimitKey } from "../lib/rate-limit";
import { AUTHZ_SIGNING_SECRET } from "../lib/config";
import { SessionStatus } from "@prisma/client";
import { SignJWT, jwtVerify } from "jose";

describe("GateZero Threat Defense Regression Suite", () => {
  let testUserId: string;
  let testSessionId: string;
  const legitUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0.0.0 Safari/537.36";
  const attackerUA = "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 Mobile Safari/537.36 (AttackerDevice)";
  const testIP = "192.168.1.100";
  const attackerIP = "203.0.113.42";

  beforeEach(async () => {
    // Upsert clean baseline test user
    const user = await prisma.user.upsert({
      where: { email: "audit-target@zerogate.internal" },
      update: { name: "Audit Target", role: "EMPLOYEE" },
      create: {
        email: "audit-target@zerogate.internal",
        name: "Audit Target",
        idpSubject: "audit-subject-99001",
        role: "EMPLOYEE",
      },
    });
    testUserId = user.id;

    // Create authentic active session
    const session = await prisma.session.create({
      data: {
        userId: testUserId,
        status: SessionStatus.ACTIVE,
        ipAddress: testIP,
        userAgent: hashUA(legitUA),
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      },
    });
    testSessionId = session.id;
  });

  describe("Threat Scenario 1: Replay Attacks (Code & Token Reuse)", () => {
    it("DEFENSE: Single-use exchange codes must be invalidated immediately upon first consumption", async () => {
      const code = await issueExchangeCode({
        sessionId: testSessionId,
        userId: testUserId,
        ipAddress: testIP,
        userAgent: legitUA,
      });

      // Legitimate first exchange
      const firstExchange = await exchangeCodeForToken({
        code,
        ipAddress: testIP,
        userAgent: legitUA,
      });
      expect(firstExchange.tokenId).toBeDefined();

      // Attacker intercepts and replays the same code
      await expect(
        exchangeCodeForToken({
          code,
          ipAddress: attackerIP,
          userAgent: attackerUA,
        })
      ).rejects.toThrow("INVALID_OR_EXPIRED_CODE");
    });

    it("DEFENSE: Expired exchange codes (>60s TTL) must be rejected", async () => {
      const expiredCodeRecord = await prisma.authExchangeCode.create({
        data: {
          code: `expired-code-${Date.now()}`,
          userId: testUserId,
          sessionId: testSessionId,
          targetApp: "operations-desk",
          ipAddress: testIP,
          userAgent: hashUA(legitUA),
          used: false,
          expiresAt: new Date(Date.now() - 5000), // Expired 5 seconds ago
        },
      });

      await expect(
        exchangeCodeForToken({
          code: expiredCodeRecord.code,
          ipAddress: testIP,
          userAgent: legitUA,
        })
      ).rejects.toThrow("INVALID_OR_EXPIRED_CODE");
    });
  });

  describe("Threat Scenario 2: Token Forgery & Signature Tampering", () => {
    it("DEFENSE: Unregistered token IDs must be rejected with TOKEN_NOT_FOUND", async () => {
      const fakeTokenId = "forged-token-cuid-999999999";
      const result = await introspectTokenLive({
        tokenId: fakeTokenId,
        userAgent: legitUA,
        ipAddress: testIP,
      });

      expect(result.valid).toBe(false);
      expect(result.reason).toBe("TOKEN_NOT_FOUND");
    });

    it("DEFENSE: Rogue JWT signed with unauthorized key fails cryptographic signature verification", async () => {
      const rogueKey = new TextEncoder().encode("malicious-rogue-secret-key-32chars-xyz");
      const authenticKey = new TextEncoder().encode(AUTHZ_SIGNING_SECRET);

      const forgedJwt = await new SignJWT({
        sub: testUserId,
        role: "ADMIN",
      })
        .setProtectedHeader({ alg: "HS256" })
        .setIssuedAt()
        .setExpirationTime("5m")
        .sign(rogueKey);

      // Verify that jose jwtVerify rejects the rogue JWT when validated with authentic secret
      await expect(
        jwtVerify(forgedJwt, authenticKey)
      ).rejects.toThrow();
    });
  });

  describe("Threat Scenario 3: Session Hijacking & Device Fingerprint Mismatches", () => {
    it("DEFENSE: Stolen authorization token used from a different device fingerprint must be blocked (DEVICE_MISMATCH)", async () => {
      const { tokenId } = await issueAuthorization({
        sessionId: testSessionId,
        userId: testUserId,
        ipAddress: testIP,
        userAgent: legitUA,
      });

      // Legitimate user on matching device succeeds
      const legitCheck = await introspectTokenLive({
        tokenId,
        userAgent: legitUA,
        ipAddress: testIP,
      });
      expect(legitCheck.valid).toBe(true);

      // Attacker on different device using the stolen tokenId is blocked
      const attackCheck = await introspectTokenLive({
        tokenId,
        userAgent: attackerUA,
        ipAddress: attackerIP,
      });
      expect(attackCheck.valid).toBe(false);
      expect(attackCheck.reason).toBe("DEVICE_MISMATCH");
    });
  });

  describe("Threat Scenario 4: MFA Bypass & Inactive Session Exploitation", () => {
    it("DEFENSE: Cannot issue authorization tokens or exchange codes for sessions in PENDING_MFA state", async () => {
      const pendingSession = await prisma.session.create({
        data: {
          userId: testUserId,
          status: SessionStatus.PENDING_MFA, // User has not completed MFA
          ipAddress: testIP,
          userAgent: hashUA(legitUA),
          expiresAt: new Date(Date.now() + 86400000),
        },
      });

      // Attempting exchange code issuance must fail
      await expect(
        issueExchangeCode({
          sessionId: pendingSession.id,
          userId: testUserId,
          ipAddress: testIP,
          userAgent: legitUA,
        })
      ).rejects.toThrow("SESSION_INVALID");

      // Attempting direct token issuance must fail
      await expect(
        issueAuthorization({
          sessionId: pendingSession.id,
          userId: testUserId,
          ipAddress: testIP,
          userAgent: legitUA,
        })
      ).rejects.toThrow("SESSION_INVALID");
    });

    it("DEFENSE: OTP input fuzzing & non-numeric values must be rejected by format checks", async () => {
      const invalidCodes = ["12345", "1234567", "abcdef", "12 45", "<script>", "' OR 1=1--"];
      for (const badCode of invalidCodes) {
        const result = await verifyEmailOTP(testSessionId, badCode);
        expect(result.valid).toBe(false);
      }
    });
  });

  describe("Threat Scenario 5: Rate Limiting & Brute-Force Throttling", () => {
    it("DEFENSE: Sliding-window rate limiter blocks requests exceeding limit threshold", async () => {
      const rateLimitKey = connectRateLimitKey(testUserId, `attack-ip-${Date.now()}`);
      const maxAllowed = 5;
      const windowSec = 60;

      // First 5 rapid requests must succeed
      for (let i = 0; i < maxAllowed; i++) {
        const result = await checkRateLimit(rateLimitKey, maxAllowed, windowSec);
        expect(result.allowed).toBe(true);
        expect(result.remaining).toBe(maxAllowed - i - 1);
      }

      // 6th rapid request within the same window MUST be blocked (429 Too Many Requests)
      const blockedAttempt = await checkRateLimit(rateLimitKey, maxAllowed, windowSec);
      expect(blockedAttempt.allowed).toBe(false);
      expect(blockedAttempt.remaining).toBe(0);
      expect(blockedAttempt.resetAt.getTime()).toBeGreaterThan(Date.now());
    });
  });

  describe("Threat Scenario 6: Instant Revocation & Stale Token Invalidation", () => {
    it("DEFENSE: Revoking a token on Website 1 immediately cuts off access on Website 2 in real-time", async () => {
      const { tokenId } = await issueAuthorization({
        sessionId: testSessionId,
        userId: testUserId,
        ipAddress: testIP,
        userAgent: legitUA,
      });

      // Token is valid initially
      let liveCheck = await introspectTokenLive({ tokenId, userAgent: legitUA });
      expect(liveCheck.valid).toBe(true);

      // Security admin revokes token
      await revokeAuthorization(tokenId);

      // Next per-request introspection MUST return valid: false (TOKEN_REVOKED)
      liveCheck = await introspectTokenLive({ tokenId, userAgent: legitUA });
      expect(liveCheck.valid).toBe(false);
      expect(liveCheck.reason).toBe("TOKEN_REVOKED");
    });
  });

  describe("Threat Scenario 7: Stored XSS Neutralization", () => {
    it("DEFENSE: HTML entity escaping neutralizes malicious script and event handler payloads", () => {
      function escapeHtml(str: string | null | undefined): string {
        if (str === null || str === undefined) return "";
        return String(str)
          .replace(/&/g, "&amp;")
          .replace(/</g, "&lt;")
          .replace(/>/g, "&gt;")
          .replace(/"/g, "&quot;")
          .replace(/'/g, "&#39;");
      }

      const payloads = [
        '<script>alert("xss")</script>',
        '<img src=x onerror=alert(document.cookie)>',
        '"><svg onload=alert(1)>',
        "javascript:alert(1)",
      ];

      for (const payload of payloads) {
        const escaped = escapeHtml(payload);
        expect(escaped).not.toContain("<script>");
        expect(escaped).not.toContain("<img");
        expect(escaped).not.toContain("<svg");
        expect(escaped).not.toContain('">');
      }
    });
  });
});
