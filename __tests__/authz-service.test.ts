/**
 * __tests__/authz-service.test.ts
 * Authorization Service and Gateway integration.
 *
 * Covers:
 *   1. A session alone grants no gateway access
 *   2. Authorization is refused for an expired or non-active session
 *   3. Rate limiting triggers after N requests in the window
 *   4. Revocation blocks immediately
 *
 * NOTE ON DEVICE IDENTITY
 * ───────────────────────
 * Device binding is now cryptographic (website-1-defense.md §8): the grant is
 * bound to a registered public-key credential, not to a hashed User-Agent.
 * §5 is explicit that UA strings must not be treated as a reliable identity
 * signal, so the old "different User-Agent is a device mismatch" assertion has
 * been replaced with one that presents a different device *credential*.
 * The full one-time/device-binding matrix lives in
 * authorization-lifecycle.test.ts.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { prisma } from "../lib/db";
import { issueAuthorization, verifyAuthorization, revokeAuthorization } from "../lib/authz-service";
import { checkRateLimit, connectRateLimitKey } from "../lib/rate-limit";
import { SessionStatus, UserRole, AuthzStatus } from "@prisma/client";
import { createActiveCredential } from "./helpers/device";
import { CLOCK_SKEW_TOLERANCE_MS } from "../lib/config";

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
        deviceCredentialId: (await createActiveCredential({ userId: user.id })).credential.id,
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
        deviceCredentialId: (await createActiveCredential({ userId: user.id })).credential.id,
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
        deviceCredentialId: (await createActiveCredential({ userId: user.id })).credential.id,
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

    const { credential } = await createActiveCredential({ userId: user.id });

    const authResult = await issueAuthorization({
      sessionId: session.id,
      userId: user.id,
      ipAddress: "127.0.0.1",
      userAgent: "test-ua",
      deviceCredentialId: credential.id,
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

    const expiredToken = await prisma.authorizationToken.create({
      data: {
        userId: user.id,
        sessionId: session.id,
        tokenHash: `test-hash-${Date.now()}-${Math.random()}`,
        ipAddress: "127.0.0.1",
        userAgent: "test-ua-hash",
        status: AuthzStatus.ACTIVE,
        // Well past the permitted clock-skew tolerance.
        expiresAt: new Date(Date.now() - CLOCK_SKEW_TOLERANCE_MS - 60_000),
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

  it("honours the agreed clock-skew tolerance, and no more", async () => {
    // The 5-minute window is enforced by three components against three clocks
    // (W1 §23 open item). A bounded, explicit tolerance is the point — an
    // unbounded one would silently extend every grant.
    const user = await createTestUser("skew");
    const session = await createTestSession(user.id);

    const withinSkew = await prisma.authorizationToken.create({
      data: {
        userId: user.id,
        sessionId: session.id,
        tokenHash: `skew-in-${Date.now()}-${Math.random()}`,
        ipAddress: "127.0.0.1",
        userAgent: "test-ua-hash",
        status: AuthzStatus.ACTIVE,
        expiresAt: new Date(Date.now() - Math.floor(CLOCK_SKEW_TOLERANCE_MS / 2)),
      },
    });

    const beyondSkew = await prisma.authorizationToken.create({
      data: {
        userId: user.id,
        sessionId: session.id,
        tokenHash: `skew-out-${Date.now()}-${Math.random()}`,
        ipAddress: "127.0.0.1",
        userAgent: "test-ua-hash",
        status: AuthzStatus.ACTIVE,
        expiresAt: new Date(Date.now() - CLOCK_SKEW_TOLERANCE_MS * 3),
      },
    });

    const tolerated = await verifyAuthorization({
      tokenId: withinSkew.id,
      sessionId: session.id,
    });
    const rejected = await verifyAuthorization({
      tokenId: beyondSkew.id,
      sessionId: session.id,
    });

    expect(tolerated.valid).toBe(true);
    expect(rejected.valid).toBe(false);
    expect(rejected.reason).toBe("TOKEN_EXPIRED");
  });

  it("a different device credential is rejected (§8)", async () => {
    const user = await createTestUser("device-check");
    const session = await createTestSession(user.id);
    const { credential } = await createActiveCredential({ userId: user.id });

    const authResult = await issueAuthorization({
      sessionId: session.id,
      userId: user.id,
      ipAddress: "127.0.0.1",
      userAgent: "original-browser",
      deviceCredentialId: credential.id,
    });

    const other = await createTestUser("device-check-other");
    const otherCredential = (await createActiveCredential({ userId: other.id })).credential;

    const result = await verifyAuthorization({
      tokenId: authResult.tokenId,
      sessionId: session.id,
      deviceCredentialId: otherCredential.id,
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("DEVICE_MISMATCH");
  });

  it("a changed User-Agent alone is NOT a device mismatch (§5)", async () => {
    // UA is telemetry. Treating it as identity would log employees out for
    // switching browsers, which §5 explicitly rules out.
    const user = await createTestUser("ua-not-identity");
    const session = await createTestSession(user.id);
    const { credential } = await createActiveCredential({ userId: user.id });

    const authResult = await issueAuthorization({
      sessionId: session.id,
      userId: user.id,
      ipAddress: "127.0.0.1",
      userAgent: "original-browser",
      deviceCredentialId: credential.id,
    });

    const result = await verifyAuthorization({
      tokenId: authResult.tokenId,
      sessionId: session.id,
      userAgent: "a-completely-different-browser",
      deviceCredentialId: credential.id,
    });
    expect(result.valid).toBe(true);
  });

  it("session mismatch is rejected", async () => {
    const user = await createTestUser("session-mismatch");
    const session = await createTestSession(user.id);
    const otherSession = await createTestSession(user.id);

    const { credential } = await createActiveCredential({ userId: user.id });

    const authResult = await issueAuthorization({
      sessionId: session.id,
      userId: user.id,
      ipAddress: "127.0.0.1",
      userAgent: "test-ua",
      deviceCredentialId: credential.id,
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
