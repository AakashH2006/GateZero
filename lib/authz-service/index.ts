/**
 * lib/authz-service/index.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * AUTHORIZATION SERVICE
 * website-1-defense.md §8, §9, §16 / website-2-defense.md §3, §15, §24
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * The Authorization Service is the only component that decides whether access
 * to Website 2 may be granted, and the only one that mints Gateway
 * authorizations. Website 1 asks; it does not decide, and it never learns where
 * Website 2 lives (W1 §4, §9).
 *
 * PROPERTIES OF AN AUTHORIZATION (W1 §8, W2 §3)
 * ─────────────────────────────────────────────
 *   employee-specific  bound to one named user
 *   device-bound       bound to a device public-key credential; the private key
 *                      never leaves the device, so a copied grant cannot be
 *                      redeemed elsewhere
 *   one-time           consumed at first successful use, never replayable (§24)
 *   short-lived        5 minutes, enforced independently by every validator
 *   context-bound      tied to the W1 session and target application
 *
 * The 7-day Website 1 session is never itself a Website 2 credential (W1 §21).
 *
 * FAILURE POSTURE (W1 §19)
 * ────────────────────────
 * Every path here fails closed. An error, an unknown state, or an unreachable
 * dependency denies the authorization; nothing is granted "because the check
 * could not be completed".
 *
 * REJECTION DETAIL (W2 §15)
 * ─────────────────────────
 * Reason codes returned by this module are INTERNAL. Callers log them and
 * answer the client generically — the Gateway must not tell an attacker whether
 * a grant was expired, already consumed, or bound to another device.
 */

import { SignJWT } from "jose";
import crypto from "crypto";
import { prisma } from "../db";
import {
  AUTHZ_SIGNING_SECRET,
  AUTHZ_TTL_SECONDS,
  CLOCK_SKEW_TOLERANCE_MS,
} from "../config";
import { AuthzStatus, DeviceCredentialStatus } from "@prisma/client";
import { credentialUsability } from "../device";

// ── Internal types ─────────────────────────────────────────────────────────────

export interface AuthorizationRequest {
  sessionId: string;
  userId: string;
  ipAddress: string;
  userAgent: string;
  /** §8: the device credential this grant is cryptographically bound to. */
  deviceCredentialId: string;
  /** Nonce of the device challenge that was proved to obtain this grant. */
  bindingNonce?: string;
  targetApp?: string;
  /** §16: set for administrative emergency authorizations. */
  emergency?: boolean;
  issuedByAdminId?: string;
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
  deviceCredentialId?: string;
  expiresAt?: Date;
  emergency?: boolean;
  /** INTERNAL only — never returned to an unauthenticated client verbatim. */
  reason?: string;
}

// ── Internals ─────────────────────────────────────────────────────────────────

function getSigningKey(): Uint8Array {
  return new TextEncoder().encode(AUTHZ_SIGNING_SECRET);
}

/**
 * Hashed User-Agent.
 *
 * TELEMETRY ONLY. W1 §5 is explicit that UA strings are trivially spoofed and
 * must not be treated as device identity; that role belongs to the device
 * credential. This value is recorded for correlation and risk input, and is
 * never on its own a reason to allow or deny.
 */
export function hashUA(userAgent: string): string {
  return crypto.createHash("sha256").update(userAgent || "unknown-ua").digest("hex").slice(0, 16);
}

function hashToken(token: string): string {
  return crypto.createHash("sha256").update(token).digest("hex");
}

/**
 * Expiry check with the single agreed skew tolerance.
 *
 * Three components enforce the same 5-minute window against three clocks
 * (W1 §23 open item). Server time is authoritative everywhere and client
 * timestamps are never consulted (W2 §3); this is the only slack permitted.
 */
function isExpired(expiresAt: Date, now: Date = new Date()): boolean {
  return expiresAt.getTime() + CLOCK_SKEW_TOLERANCE_MS < now.getTime();
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * 1. Issue a single-use exchange code for an already-issued authorization.
 *
 * The code is a front-channel handle only — it carries no authority of its own,
 * and it can only be exchanged for the authorization it names. It is bound to
 * the same session and device as that authorization.
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
 * 2. Back-channel exchange: Website 2 redeems the code for the authorization
 *    that was already minted at Connect time.
 *
 * The code is claimed with a conditional update on `used: false`, so two
 * concurrent redemptions cannot both succeed. This does NOT consume the
 * authorization — that happens only once Website 2 has independently verified
 * the device (§8.1) and actually established a session, so a failed handshake
 * does not burn the employee's grant.
 */
export async function exchangeCodeForToken(params: {
  code: string;
  ipAddress: string;
  userAgent: string;
}): Promise<
  AuthorizationResult & {
    deviceCredentialId: string | null;
    emergency: boolean;
    user: { id: string; name: string; email: string; role: string };
  }
> {
  const record = await prisma.authExchangeCode.findUnique({
    where: { code: params.code },
  });

  if (!record || record.used || record.expiresAt < new Date()) {
    throw new Error("INVALID_OR_EXPIRED_CODE");
  }

  const claimed = await prisma.authExchangeCode.updateMany({
    where: { id: record.id, used: false },
    data: { used: true },
  });
  if (claimed.count !== 1) throw new Error("INVALID_OR_EXPIRED_CODE");

  const session = await prisma.session.findUnique({
    where: { id: record.sessionId },
    include: { user: true },
  });

  if (!session || session.status !== "ACTIVE" || session.expiresAt < new Date()) {
    throw new Error("SESSION_EXPIRED");
  }

  // W2 §22: an administratively revoked employee gets nothing, even holding a
  // valid code.
  if (session.user.accessRevoked) throw new Error("ACCESS_REVOKED");

  // The authorization already exists — Connect minted it after the risk
  // assessment and the device proof. The code does not mint a second one.
  const authz = await prisma.authorizationToken.findFirst({
    where: {
      sessionId: record.sessionId,
      userId: record.userId,
      status: AuthzStatus.ACTIVE,
      consumedAt: null,
      targetApp: record.targetApp,
      expiresAt: { gt: new Date() },
    },
    orderBy: { issuedAt: "desc" },
  });

  if (!authz) throw new Error("NO_ACTIVE_AUTHORIZATION");

  return {
    tokenId: authz.id,
    expiresAt: authz.expiresAt,
    ttlSeconds: Math.max(0, Math.floor((authz.expiresAt.getTime() - Date.now()) / 1000)),
    deviceCredentialId: authz.deviceCredentialId,
    emergency: authz.emergency,
    user: {
      id: session.user.id,
      name: session.user.name,
      email: session.user.email,
      role: session.user.role,
    },
  };
}

/**
 * 3. Introspection.
 *
 * Called by the Gateway before allowing a session to be established. It
 * verifies state and binding but does not consume — consumption is a separate,
 * explicit step so that a check can never accidentally spend a grant.
 */
export async function introspectTokenLive(params: {
  tokenId: string;
  /** Telemetry only. Never a pass/fail input on its own. */
  userAgent?: string;
  ipAddress?: string;
  /** §8: the device that is actually presenting the grant. */
  deviceCredentialId?: string;
}): Promise<AuthorizationVerification> {
  const record = await prisma.authorizationToken.findUnique({
    where: { id: params.tokenId },
    include: { session: true, user: true },
  });

  if (!record) return { valid: false, reason: "TOKEN_NOT_FOUND" };
  if (record.status === AuthzStatus.REVOKED) return { valid: false, reason: "TOKEN_REVOKED" };

  // §24: one-time. A consumed grant is dead, and asking again is a replay.
  if (record.status === AuthzStatus.CONSUMED || record.consumedAt) {
    return { valid: false, reason: "TOKEN_ALREADY_CONSUMED" };
  }

  if (isExpired(record.expiresAt)) {
    await prisma.authorizationToken
      .updateMany({
        where: { id: record.id, status: AuthzStatus.ACTIVE },
        data: { status: AuthzStatus.EXPIRED },
      })
      .catch(() => {});
    return { valid: false, reason: "TOKEN_EXPIRED" };
  }

  // §8: cryptographic device binding. The caller must already have verified a
  // device proof and pass the resulting credential id here.
  if (params.deviceCredentialId && record.deviceCredentialId !== params.deviceCredentialId) {
    return { valid: false, reason: "DEVICE_MISMATCH" };
  }

  if (record.deviceCredentialId) {
    const credential = await prisma.deviceCredential.findUnique({
      where: { id: record.deviceCredentialId },
    });
    if (!credential || credential.status !== DeviceCredentialStatus.ACTIVE) {
      return { valid: false, reason: "DEVICE_CREDENTIAL_REVOKED" };
    }
    const usability = credentialUsability(credential);
    if (!usability.usable) return { valid: false, reason: usability.reason };
  }

  if (record.user.accessRevoked) return { valid: false, reason: "ACCESS_REVOKED" };

  // An emergency authorization is issued while Website 1 is down, so it
  // deliberately does not require a live, healthy W1 session behind it.
  if (!record.emergency) {
    if (record.session.status !== "ACTIVE" || record.session.expiresAt < new Date()) {
      return { valid: false, reason: "SESSION_EXPIRED" };
    }
  }

  return {
    valid: true,
    userId: record.userId,
    userEmail: record.user.email,
    userName: record.user.name,
    userRole: record.user.role,
    sessionId: record.sessionId,
    deviceCredentialId: record.deviceCredentialId ?? undefined,
    expiresAt: record.expiresAt,
    emergency: record.emergency,
  };
}

/**
 * Consume an authorization (W1 §8, W2 §3 step 9, §24).
 *
 * The conditional update on `consumedAt: null` is the actual one-time
 * enforcement: two devices redeeming the same grant simultaneously produce one
 * winner and one `TOKEN_ALREADY_CONSUMED`. A read-then-write would let both in.
 */
export async function consumeAuthorization(params: {
  tokenId: string;
  deviceCredentialId: string;
}): Promise<{ ok: boolean; reason?: string }> {
  const verification = await introspectTokenLive({
    tokenId: params.tokenId,
    deviceCredentialId: params.deviceCredentialId,
  });
  if (!verification.valid) return { ok: false, reason: verification.reason };

  const claimed = await prisma.authorizationToken.updateMany({
    where: { id: params.tokenId, consumedAt: null, status: AuthzStatus.ACTIVE },
    data: { status: AuthzStatus.CONSUMED, consumedAt: new Date() },
  });

  if (claimed.count !== 1) return { ok: false, reason: "TOKEN_ALREADY_CONSUMED" };
  return { ok: true };
}

/**
 * Verify an authorization against its originating Website 1 session.
 * Used where the caller can prove the session context as well.
 */
export async function verifyAuthorization(params: {
  tokenId: string;
  sessionId: string;
  userAgent?: string;
  deviceCredentialId?: string;
}): Promise<AuthorizationVerification> {
  const result = await introspectTokenLive({
    tokenId: params.tokenId,
    userAgent: params.userAgent,
    deviceCredentialId: params.deviceCredentialId,
  });

  if (!result.valid) return result;

  if (result.sessionId !== params.sessionId) {
    return { valid: false, reason: "SESSION_MISMATCH" };
  }

  return result;
}

/**
 * Issue a fresh 5-minute Gateway authorization.
 *
 * Callers must have already run the Connect-time risk assessment and verified
 * a device proof; this function enforces the invariants that must hold
 * regardless of who is calling.
 */
export async function issueAuthorization(
  req: AuthorizationRequest
): Promise<AuthorizationResult> {
  const session = await prisma.session.findUnique({
    where: { id: req.sessionId },
    include: { user: true },
  });

  if (!session) throw new Error("SESSION_INVALID");

  // Emergency authorizations are issued precisely when Website 1 is
  // unavailable, so they are exempt from the *live-session* requirement — but
  // from nothing else: employee-specific, device-bound, one-time, 5 minutes.
  if (!req.emergency) {
    if (session.status !== "ACTIVE" || session.expiresAt < new Date()) {
      throw new Error("SESSION_INVALID");
    }
  }

  if (session.user.accessRevoked) throw new Error("ACCESS_REVOKED");

  // §8: no device binding, no authorization. Refusing here is what keeps a
  // caller from quietly minting an unbound, freely-copyable grant.
  const credential = await prisma.deviceCredential.findUnique({
    where: { id: req.deviceCredentialId },
  });
  if (!credential || credential.userId !== req.userId) {
    throw new Error("DEVICE_CREDENTIAL_INVALID");
  }
  const usability = credentialUsability(credential);
  if (!usability.usable) throw new Error(usability.reason ?? "DEVICE_CREDENTIAL_INVALID");

  const expiresAt = new Date(Date.now() + AUTHZ_TTL_SECONDS * 1000);
  const uaHash = hashUA(req.userAgent);

  // The JWT is for the Gateway's own validation. It is never handed to the
  // browser: the client only ever sees the opaque token id.
  //
  // `jti` is not decoration. Every other claim is identical for two grants
  // minted for the same employee, session and device, and `iat` only has
  // one-second resolution — so without a per-grant nonce, two Connects inside
  // the same second would produce byte-identical tokens. That would collide on
  // the unique tokenHash, and worse, would make two distinct authorizations
  // indistinguishable from one another.
  const token = await new SignJWT({
    sub: req.userId,
    sid: req.sessionId,
    dcid: req.deviceCredentialId,
    uah: uaHash,
    ip: req.ipAddress,
    emg: req.emergency ?? false,
  })
    .setProtectedHeader({ alg: "HS256" })
    .setJti(crypto.randomUUID())
    .setIssuedAt()
    .setExpirationTime(expiresAt)
    .setIssuer("zerogate-authz-service")
    .setAudience("zerogate-gateway")
    .sign(getSigningKey());

  const record = await prisma.authorizationToken.create({
    data: {
      userId: req.userId,
      sessionId: req.sessionId,
      tokenHash: hashToken(token),
      ipAddress: req.ipAddress,
      userAgent: uaHash,
      deviceCredentialId: req.deviceCredentialId,
      bindingNonce: req.bindingNonce ?? null,
      targetApp: req.targetApp ?? "operations-desk",
      emergency: req.emergency ?? false,
      issuedByAdminId: req.issuedByAdminId ?? null,
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

/** Revoke an authorization immediately. */
export async function revokeAuthorization(tokenId: string): Promise<void> {
  await prisma.authorizationToken.updateMany({
    where: { id: tokenId, status: { notIn: [AuthzStatus.REVOKED] } },
    data: { status: AuthzStatus.REVOKED, revokedAt: new Date() },
  });
}

/** Revoke every outstanding authorization for an employee (§21, §22). */
export async function revokeAllAuthorizationsForUser(userId: string): Promise<number> {
  const result = await prisma.authorizationToken.updateMany({
    where: { userId, status: AuthzStatus.ACTIVE },
    data: { status: AuthzStatus.REVOKED, revokedAt: new Date() },
  });
  return result.count;
}

/** The session's outstanding, unconsumed authorization, if any. */
export async function getActiveAuthorization(
  sessionId: string
): Promise<{ tokenId: string; expiresAt: Date; ttlSeconds: number } | null> {
  const now = new Date();
  const record = await prisma.authorizationToken.findFirst({
    where: {
      sessionId,
      status: AuthzStatus.ACTIVE,
      consumedAt: null,
      expiresAt: { gt: now },
    },
    orderBy: { issuedAt: "desc" },
  });

  if (!record) return null;

  return {
    tokenId: record.id,
    expiresAt: record.expiresAt,
    ttlSeconds: Math.floor((record.expiresAt.getTime() - now.getTime()) / 1000),
  };
}
