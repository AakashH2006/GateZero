/**
 * lib/authz-service/index.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * AUTHORIZATION & GATEWAY SERVICE
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * Provides:
 *   1. Single-use Authorization Exchange Codes (60s TTL) for OIDC-style handshakes
 *   2. Token issuance bound to session and device fingerprint
 *   3. Live token introspection / verification on every request (instant revocation)
 *   4. Token revocation support
 */

import { SignJWT } from "jose";
import crypto from "crypto";
import { prisma } from "../db";
import { AUTHZ_SIGNING_SECRET, AUTHZ_TTL_SECONDS } from "../config";
import { AuthzStatus } from "@prisma/client";

// ── Internal types ─────────────────────────────────────────────────────────────

export interface AuthorizationRequest {
  sessionId: string;
  userId: string;
  ipAddress: string;
  userAgent: string;
}

export interface AuthorizationResult {
  tokenId: string;
  tokenJwt?: string;
  expiresAt: Date;
  ttlSeconds: number;
}

export interface AuthorizationVerification {
  valid: boolean;
  userId?: string;
  userEmail?: string;
  userName?: string;
  userRole?: string;
  sessionId?: string;
  expiresAt?: Date;
  reason?: string;
}

// ── Internals ─────────────────────────────────────────────────────────────────

function getSigningKey(): Uint8Array {
  return new TextEncoder().encode(AUTHZ_SIGNING_SECRET);
}

export function hashUA(userAgent: string): string {
  return crypto.createHash("sha256").update(userAgent || "unknown-ua").digest("hex").slice(0, 16);
}

function hashToken(token: string): string {
  return crypto.createHash("sha256").update(token).digest("hex");
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * 1. Issue a single-use exchange code for an active session (60s TTL).
 * Passed in redirect URL to Website 2 (e.g. ?code=...).
 */
export async function issueExchangeCode(params: {
  sessionId: string;
  userId: string;
  ipAddress: string;
  userAgent: string;
  targetApp?: string;
}): Promise<string> {
  const session = await prisma.session.findUnique({
    where: { id: params.sessionId },
  });

  if (!session || session.status !== "ACTIVE" || session.expiresAt < new Date()) {
    throw new Error("SESSION_INVALID");
  }

  const code = crypto.randomBytes(24).toString("hex");
  const expiresAt = new Date(Date.now() + 60 * 1000); // 60s TTL

  await prisma.authExchangeCode.create({
    data: {
      code,
      userId: params.userId,
      sessionId: params.sessionId,
      targetApp: params.targetApp ?? "operations-desk",
      ipAddress: params.ipAddress,
      userAgent: hashUA(params.userAgent),
      used: false,
      expiresAt,
    },
  });

  return code;
}

/**
 * 2. Back-channel exchange: Website 2 exchanges the code for an Authorization Token.
 */
export async function exchangeCodeForToken(params: {
  code: string;
  ipAddress: string;
  userAgent: string;
}): Promise<AuthorizationResult & { user: { id: string; name: string; email: string; role: string } }> {
  const record = await prisma.authExchangeCode.findUnique({
    where: { code: params.code },
  });

  if (!record || record.used || record.expiresAt < new Date()) {
    throw new Error("INVALID_OR_EXPIRED_CODE");
  }

  // Mark code as used immediately (single-use enforcement)
  await prisma.authExchangeCode.update({
    where: { id: record.id },
    data: { used: true },
  });

  // Verify session is still active
  const session = await prisma.session.findUnique({
    where: { id: record.sessionId },
    include: { user: true },
  });

  if (!session || session.status !== "ACTIVE" || session.expiresAt < new Date()) {
    throw new Error("SESSION_EXPIRED");
  }

  // Issue Authorization Token
  const expiresAt = new Date(Date.now() + AUTHZ_TTL_SECONDS * 1000);
  const uaHash = hashUA(params.userAgent);

  const tokenJwt = await new SignJWT({
    sub: session.userId,
    email: session.user.email,
    name: session.user.name,
    role: session.user.role,
    sid: session.id,
    uah: uaHash,
    ip: params.ipAddress,
  })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime(expiresAt)
    .setIssuer("zerogate-authz-service")
    .setAudience("operations-desk")
    .sign(getSigningKey());

  const tokenHash = hashToken(tokenJwt);

  const authzRecord = await prisma.authorizationToken.create({
    data: {
      userId: session.userId,
      sessionId: session.id,
      tokenHash,
      ipAddress: params.ipAddress,
      userAgent: uaHash,
      status: AuthzStatus.ACTIVE,
      expiresAt,
    },
  });

  return {
    tokenId: authzRecord.id,
    tokenJwt,
    expiresAt,
    ttlSeconds: AUTHZ_TTL_SECONDS,
    user: {
      id: session.user.id,
      name: session.user.name,
      email: session.user.email,
      role: session.user.role,
    },
  };
}

/**
 * 3. Live per-request token verification / introspection.
 * Called by Website 2 on EVERY request to enforce immediate revocation.
 */
export async function introspectTokenLive(params: {
  tokenId: string;
  userAgent: string;
  ipAddress?: string;
}): Promise<AuthorizationVerification> {
  const record = await prisma.authorizationToken.findUnique({
    where: { id: params.tokenId },
    include: {
      session: true,
      user: true,
    },
  });

  if (!record) {
    return { valid: false, reason: "TOKEN_NOT_FOUND" };
  }

  if (record.status === AuthzStatus.REVOKED) {
    return { valid: false, reason: "TOKEN_REVOKED" };
  }

  if (record.expiresAt < new Date()) {
    await prisma.authorizationToken
      .update({ where: { id: record.id }, data: { status: AuthzStatus.EXPIRED } })
      .catch(() => {});
    return { valid: false, reason: "TOKEN_EXPIRED" };
  }

  // Verify device binding (hashed UA)
  const expectedUAHash = hashUA(params.userAgent);
  if (record.userAgent !== expectedUAHash) {
    return { valid: false, reason: "DEVICE_MISMATCH" };
  }

  // Verify session is still active
  if (record.session.status !== "ACTIVE" || record.session.expiresAt < new Date()) {
    return { valid: false, reason: "SESSION_EXPIRED" };
  }

  return {
    valid: true,
    userId: record.userId,
    userEmail: record.user.email,
    userName: record.user.name,
    userRole: record.user.role,
    sessionId: record.sessionId,
    expiresAt: record.expiresAt,
  };
}

/**
 * Verify an authorization token by its DB record ID and session binding (for legacy gateway verification).
 */
export async function verifyAuthorization(params: {
  tokenId: string;
  sessionId: string;
  userAgent: string;
}): Promise<AuthorizationVerification> {
  const result = await introspectTokenLive({
    tokenId: params.tokenId,
    userAgent: params.userAgent,
  });

  if (!result.valid) return result;

  if (result.sessionId !== params.sessionId) {
    return { valid: false, reason: "SESSION_MISMATCH" };
  }

  return result;
}

/**
 * Issue a new short-lived authorization token directly.
 */
export async function issueAuthorization(
  req: AuthorizationRequest
): Promise<AuthorizationResult> {
  const session = await prisma.session.findUnique({
    where: { id: req.sessionId },
  });

  if (!session || session.status !== "ACTIVE" || session.expiresAt < new Date()) {
    throw new Error("SESSION_INVALID");
  }

  const expiresAt = new Date(Date.now() + AUTHZ_TTL_SECONDS * 1000);
  const uaHash = hashUA(req.userAgent);

  const token = await new SignJWT({
    sub: req.userId,
    sid: req.sessionId,
    uah: uaHash,
    ip: req.ipAddress,
  })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime(expiresAt)
    .setIssuer("zerogate-authz-service")
    .setAudience("zerogate-gateway")
    .sign(getSigningKey());

  const tokenHash = hashToken(token);

  const record = await prisma.authorizationToken.create({
    data: {
      userId: req.userId,
      sessionId: req.sessionId,
      tokenHash,
      ipAddress: req.ipAddress,
      userAgent: uaHash,
      status: AuthzStatus.ACTIVE,
      expiresAt,
    },
  });

  return {
    tokenId: record.id,
    expiresAt,
    ttlSeconds: AUTHZ_TTL_SECONDS,
  };
}

/**
 * Revoke an authorization token immediately.
 */
export async function revokeAuthorization(tokenId: string): Promise<void> {
  await prisma.authorizationToken.update({
    where: { id: tokenId },
    data: { status: AuthzStatus.REVOKED, revokedAt: new Date() },
  });
}

/**
 * Get active authorization for a session.
 */
export async function getActiveAuthorization(
  sessionId: string
): Promise<{ tokenId: string; expiresAt: Date; ttlSeconds: number } | null> {
  const now = new Date();
  const record = await prisma.authorizationToken.findFirst({
    where: {
      sessionId,
      status: AuthzStatus.ACTIVE,
      expiresAt: { gt: now },
    },
    orderBy: { issuedAt: "desc" },
  });

  if (!record) return null;

  const remainingMs = record.expiresAt.getTime() - now.getTime();
  return {
    tokenId: record.id,
    expiresAt: record.expiresAt,
    ttlSeconds: Math.floor(remainingMs / 1000),
  };
}
