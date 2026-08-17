/**
 * __tests__/authz-service.test.ts
 * Tests for the Mock Authorization Service and Gateway integration.
 *
 * Covers:
 *   1. Session alone cannot grant gateway access (no authorization token = 404)
 *   2. Connect fails gracefully when session is expired
 *   3. Rate limiting triggers after N requests in the window
 *   4. Revocation immediately blocks the mock gateway
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { prisma } from "../lib/db";
import { issueAuthorization, verifyAuthorization, revokeAuthorization } from "../lib/authz-service";
import { checkRateLimit, connectRateLimitKey } from "../lib/rate-limit";
import { SessionStatus, UserRole, AuthzStatus } from "@prisma/client";

// ── Test fixtures ──────────────────────────────────────────────────────────────

async function createTestUser(suffix: string = "") {
  return prisma.user.create({
    data: {
      idpSubject: `test-idp|user-${suffix}-${Date.now()}`,
      email: `test-${suffix}-${Date.now()}@zerogate.test`,
      name: `Test User ${suffix}`,
      role: UserRole.EMPLOYEE,
    },
  });
}

async function createTestSession(
  userId: string,
  status: SessionStatus = SessionStatus.ACTIVE,
  expiresAt?: Date
) {
  return prisma.session.create({
    data: {
      userId,
      status,
      ipAddress: "127.0.0.1",
      userAgent: "test-ua-hash",
      expiresAt: expiresAt ?? new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    },
  });
}

// ── Test: Session alone cannot access internal site ───────────────────────────

describe("Gateway access control", () => {
  it("verifyAuthorization returns invalid for unknown tokenId", async () => {
    const result = await verifyAuthorization({
      tokenId: "non-existent-token-id",
      sessionId: "any-session",
      userAgent: "test-ua",
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("TOKEN_NOT_FOUND");
  });

  it("session alone (no authorization token) produces TOKEN_NOT_FOUND", async () => {
    const user = await createTestUser("no-authz");
    const session = await createTestSession(user.id);

    // Try to access without ever calling Connect
    const result = await verifyAuthorization({
      tokenId: "i-never-called-connect",
      sessionId: session.id,
      userAgent: "test-ua",
    });

    expect(result.valid).toBe(false);
    expect(result.reason).toBe("TOKEN_NOT_FOUND");
  });
});

// ── Test: Connect fails when session is expired ────────────────────────────────

describe("Connect with expired session", () => {
  it("issueAuthorization throws SESSION_INVALID for expired session", async () => {
    const user = await createTestUser("expired");
    // Create session that expired 1 second ago
    const session = await createTestSession(
      user.id,
      SessionStatus.ACTIVE,
      new Date(Date.now() - 1000)
    );

    await expect(
      issueAuthorization({
        sessionId: session.id,
        userId: user.id,
        ipAddress: "127.0.0.1",
        userAgent: "test-ua",
      })
    ).rejects.toThrow("SESSION_INVALID");
  });

  it("issueAuthorization throws SESSION_INVALID for REVOKED session", async () => {
    const user = await createTestUser("revoked-sess");
    const session = await createTestSession(user.id, SessionStatus.REVOKED);

    await expect(
      issueAuthorization({
        sessionId: session.id,
        userId: user.id,
        ipAddress: "127.0.0.1",
        userAgent: "test-ua",
      })
    ).rejects.toThrow("SESSION_INVALID");
  });

  it("issueAuthorization throws SESSION_INVALID for PENDING_MFA session", async () => {
    const user = await createTestUser("pending-mfa");
    const session = await createTestSession(user.id, SessionStatus.PENDING_MFA);

    await expect(
      issueAuthorization({
        sessionId: session.id,
        userId: user.id,
        ipAddress: "127.0.0.1",
        userAgent: "test-ua",
      })
    ).rejects.toThrow("SESSION_INVALID");
  });
});

// ── Test: Rate limiting ────────────────────────────────────────────────────────

describe("Rate limiting", () => {
  it("allows requests under the limit and blocks when exceeded", async () => {
    const key = `test-rate-limit-${Date.now()}`;
    const max = 3;
    const windowSeconds = 60;

    // First 3 should be allowed
    for (let i = 0; i < max; i++) {
      const result = await checkRateLimit(key, max, windowSeconds);
      expect(result.allowed).toBe(true);
    }

    // 4th should be blocked
    const blocked = await checkRateLimit(key, max, windowSeconds);
    expect(blocked.allowed).toBe(false);
    expect(blocked.remaining).toBe(0);
  });

  it("different keys have independent limits", async () => {
    const key1 = `test-rl-a-${Date.now()}`;
    const key2 = `test-rl-b-${Date.now()}`;
    const max = 2;

    await checkRateLimit(key1, max, 60);
    await checkRateLimit(key1, max, 60);
    const blockedKey1 = await checkRateLimit(key1, max, 60);
    expect(blockedKey1.allowed).toBe(false);

    // key2 should be unaffected
    const okKey2 = await checkRateLimit(key2, max, 60);
    expect(okKey2.allowed).toBe(true);
  });
});

// ── Test: Revocation immediately blocks gateway ────────────────────────────────

describe("Authorization revocation", () => {
  it("revoked token immediately fails gateway check", async () => {
    const user = await createTestUser("revoke-test");
    const session = await createTestSession(user.id);

    // Issue authorization
    const authResult = await issueAuthorization({
      sessionId: session.id,
      userId: user.id,
      ipAddress: "127.0.0.1",
      userAgent: "test-ua",
    });

    // Should be valid before revocation
    const before = await verifyAuthorization({
      tokenId: authResult.tokenId,
      sessionId: session.id,
      userAgent: "test-ua",
    });
    expect(before.valid).toBe(true);

    // Revoke
    await revokeAuthorization(authResult.tokenId);

    // Should be invalid immediately after revocation
    const after = await verifyAuthorization({
      tokenId: authResult.tokenId,
      sessionId: session.id,
      userAgent: "test-ua",
    });
    expect(after.valid).toBe(false);
    expect(after.reason).toBe("TOKEN_REVOKED");
  });

  it("expired token is rejected with TOKEN_EXPIRED", async () => {
    const user = await createTestUser("expired-token");
    const session = await createTestSession(user.id);

    // Directly create a token record with past expiry
    const expiredToken = await prisma.authorizationToken.create({
      data: {
        userId: user.id,
        sessionId: session.id,
        tokenHash: `test-hash-${Date.now()}`,
        ipAddress: "127.0.0.1",
        userAgent: "test-ua-hash",
        status: AuthzStatus.ACTIVE,
        expiresAt: new Date(Date.now() - 1000), // already expired
      },
    });

    const result = await verifyAuthorization({
      tokenId: expiredToken.id,
      sessionId: session.id,
      userAgent: "test-ua",
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("TOKEN_EXPIRED");
  });

  it("device mismatch is rejected", async () => {
    const user = await createTestUser("device-check");
    const session = await createTestSession(user.id);

    const authResult = await issueAuthorization({
      sessionId: session.id,
      userId: user.id,
      ipAddress: "127.0.0.1",
      userAgent: "original-browser",
    });

    // Try with different user agent
    const result = await verifyAuthorization({
      tokenId: authResult.tokenId,
      sessionId: session.id,
      userAgent: "different-browser",
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("DEVICE_MISMATCH");
  });

  it("session mismatch is rejected", async () => {
    const user = await createTestUser("session-mismatch");
    const session = await createTestSession(user.id);
    const otherSession = await createTestSession(user.id);

    const authResult = await issueAuthorization({
      sessionId: session.id,
      userId: user.id,
      ipAddress: "127.0.0.1",
      userAgent: "test-ua",
    });

    // Try with different session ID
    const result = await verifyAuthorization({
      tokenId: authResult.tokenId,
      sessionId: otherSession.id,  // wrong session
      userAgent: "test-ua",
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("SESSION_MISMATCH");
  });
});
