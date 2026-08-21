/**
 * lib/desk-session/index.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * WEBSITE 2 SESSION GUARD
 * website-2-defense.md §10-§20 / website-1-defense.md §6 (scope boundary), §22.1
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * The Session Guard is Website 2's own detection and lifecycle layer. It is
 * explicitly NOT the Mini EDR: the Mini EDR watches Website 1 login, MFA, and
 * Connect and never sees Website 2 activity (W1 §6). The two layers are
 * independent and neither covers the other's domain.
 *
 * The defining property of a Website 2 session is independence (§35, W1 §22.1):
 * once established, its validity is decided here, from local state. It does not
 * call Website 1 or the Gateway on each request, and it does not end merely
 * because they are unreachable (§26). What crosses the boundary is a small set
 * of critical events, pulled and applied asynchronously (§21).
 *
 * WHY A SESSION, NOT THE AUTHORIZATION
 * ────────────────────────────────────
 * The Gateway authorization is consumed at establishment and never becomes a
 * standing credential (§3, §24). This session record is the thing that lives
 * on — with its own expiry rules, its own revocation, and its own device
 * binding, re-proved cryptographically rather than inherited from the Gateway's
 * say-so (§8.1).
 */

import crypto from "crypto";
import { prisma } from "../db";
import { deskSessionLimits, DESK_DEVICE_REVERIFY_MS } from "../config";
import { DeskSessionStatus, type DeskSession } from "@prisma/client";

export interface SessionValidation {
  valid: boolean;
  session?: DeskSession;
  /** Internal reason — callers answer the client generically (§15). */
  reason?: string;
  /**
   * §14: the session is otherwise valid but its device proof has gone stale.
   * The caller must obtain a fresh proof before serving the request. This is
   * NOT a denial — the session survives; it just has to re-prove itself.
   */
  deviceReverificationRequired?: boolean;
}

/**
 * Endpoints that count as meaningful application activity for the inactivity
 * timer (§17). Everything else — status polls, the wire feed refresh, health
 * pings — reads session state without extending its life, so an abandoned
 * browser tab left polling cannot keep a session alive indefinitely.
 */
const BACKGROUND_POLL_PATHS = [
  "/api/desk/stats",
  "/api/desk/wire",
  "/api/desk/session",
  "/api/health",
];

export function isMeaningfulActivity(method: string, path: string): boolean {
  if (method.toUpperCase() !== "GET") return true;
  return !BACKGROUND_POLL_PATHS.some((p) => path === p || path.startsWith(`${p}?`));
}

// ── Establishment (§10, §11, §12) ─────────────────────────────────────────────

export interface EstablishResult {
  session: DeskSession;
  /** Sessions revoked to honour the single-active-session rule (§11). */
  replacedSessionIds: string[];
}

/**
 * Create a Website 2 session from a successfully redeemed authorization.
 *
 * The previous session is revoked HERE, at the end of a fully successful
 * establishment — never earlier. §11 is explicit that a second device must not
 * be able to kill the incumbent session merely by *attempting* authorization,
 * so every failure path in the caller must return before reaching this call.
 */
export async function establishDeskSession(params: {
  userId: string;
  deviceCredentialId: string;
  authzTokenId: string;
  ipAddress: string;
}): Promise<EstablishResult> {
  const limits = deskSessionLimits();
  const now = new Date();

  const incumbents = await prisma.deskSession.findMany({
    where: { userId: params.userId, status: DeskSessionStatus.ACTIVE },
    select: { id: true },
  });

  const [, session] = await prisma.$transaction([
    prisma.deskSession.updateMany({
      where: { userId: params.userId, status: DeskSessionStatus.ACTIVE },
      data: {
        status: DeskSessionStatus.REVOKED,
        revokedAt: now,
        revokedReason: "REPLACED_BY_NEW_SESSION",
      },
    }),
    prisma.deskSession.create({
      data: {
        userId: params.userId,
        deviceCredentialId: params.deviceCredentialId,
        authzTokenId: params.authzTokenId,
        ipAddress: params.ipAddress,
        status: DeskSessionStatus.ACTIVE,
        lastActivityAt: now,
        absoluteExpiresAt: new Date(now.getTime() + limits.absoluteMs),
      },
    }),
  ]);

  return { session, replacedSessionIds: incumbents.map((s) => s.id) };
}

// ── Validation (§13, §14, §17, §18) ───────────────────────────────────────────

/**
 * Validate a session identifier for one request.
 *
 * Server time is authoritative for every expiry decision (§3): nothing the
 * client sends influences the outcome. Expiry is evaluated on read rather than
 * by a sweeper, so a session cannot outlive its limits just because no
 * background job happened to run.
 */
export async function validateDeskSession(params: {
  sessionId: string;
  /** When supplied, the session's bound credential must match (§14). */
  deviceCredentialId?: string;
  now?: Date;
}): Promise<SessionValidation> {
  const now = params.now ?? new Date();
  const limits = deskSessionLimits();

  const session = await prisma.deskSession.findUnique({
    where: { id: params.sessionId },
  });

  if (!session) return { valid: false, reason: "SESSION_NOT_FOUND" };
  if (session.status === DeskSessionStatus.REVOKED) {
    return { valid: false, reason: session.revokedReason ?? "SESSION_REVOKED" };
  }
  if (session.status === DeskSessionStatus.EXPIRED) {
    return { valid: false, reason: "SESSION_EXPIRED" };
  }

  // §18: absolute lifetime, regardless of activity.
  if (session.absoluteExpiresAt <= now) {
    await expireSession(session.id, "ABSOLUTE_LIFETIME_REACHED");
    return { valid: false, reason: "SESSION_EXPIRED" };
  }

  // §17: inactivity ceiling.
  if (now.getTime() - session.lastActivityAt.getTime() > limits.inactivityMs) {
    await expireSession(session.id, "INACTIVITY_TIMEOUT");
    return { valid: false, reason: "SESSION_EXPIRED" };
  }

  // §5, §14: the session belongs to one device credential. A stolen session
  // identifier presented from anywhere else does not resolve.
  if (params.deviceCredentialId && session.deviceCredentialId !== params.deviceCredentialId) {
    return { valid: false, reason: "DEVICE_MISMATCH" };
  }

  // §9: a session outlives neither its credential's revocation nor its expiry.
  const credential = await prisma.deviceCredential.findUnique({
    where: { id: session.deviceCredentialId },
    select: { status: true },
  });
  if (!credential || credential.status !== "ACTIVE") {
    await revokeDeskSession(session.id, "DEVICE_CREDENTIAL_REVOKED");
    return { valid: false, reason: "DEVICE_CREDENTIAL_REVOKED" };
  }

  // §14: the session identifier alone must never be enough. Once the last
  // device proof is stale, the caller has to present a fresh one before the
  // request is served. Someone holding a stolen cookie cannot produce it,
  // because producing it requires the private key that never left the device.
  if (now.getTime() - session.deviceVerifiedAt.getTime() > DESK_DEVICE_REVERIFY_MS) {
    return { valid: true, session, deviceReverificationRequired: true };
  }

  return { valid: true, session };
}

/**
 * §14: record a successful device re-proof, restarting the verification window.
 *
 * The caller MUST have verified a fresh signature against the session's bound
 * credential before calling — this function records, it does not verify.
 */
export async function recordDeviceVerification(sessionId: string): Promise<void> {
  await prisma.deskSession
    .update({ where: { id: sessionId }, data: { deviceVerifiedAt: new Date() } })
    .catch(() => {});
}

/** §17: extend the inactivity window. Only ever called for meaningful activity. */
export async function touchDeskSession(sessionId: string): Promise<void> {
  await prisma.deskSession
    .update({ where: { id: sessionId }, data: { lastActivityAt: new Date() } })
    .catch(() => {});
}

async function expireSession(sessionId: string, reason: string): Promise<void> {
  await prisma.deskSession
    .updateMany({
      where: { id: sessionId, status: DeskSessionStatus.ACTIVE },
      data: { status: DeskSessionStatus.EXPIRED, revokedAt: new Date(), revokedReason: reason },
    })
    .catch(() => {});
}

// ── Revocation (§9, §19, §20, §22, §26) ───────────────────────────────────────

export async function revokeDeskSession(sessionId: string, reason: string): Promise<void> {
  const now = new Date();
  const session = await prisma.deskSession.findUnique({ where: { id: sessionId } });
  if (!session) return;

  await prisma.$transaction([
    prisma.deskSession.updateMany({
      where: { id: sessionId, status: DeskSessionStatus.ACTIVE },
      data: { status: DeskSessionStatus.REVOKED, revokedAt: now, revokedReason: reason },
    }),
    // §19/§20: the authorization behind the session is invalidated with it, so
    // an already-consumed grant can never be resurrected.
    prisma.authorizationToken.updateMany({
      where: { id: session.authzTokenId, status: { not: "REVOKED" } },
      data: { status: "REVOKED", revokedAt: now },
    }),
  ]);
}

/**
 * Revoke active sessions for an employee.
 *
 * `options.except` exists for the new-device case (§11, W1 §22.3): the session
 * that just replaced the others must survive the very sweep it triggered.
 *
 * `options.deviceCredentialIds` narrows the sweep to sessions bound to specific
 * credentials, for device replacement and revocation (§7, §9).
 *
 * SCOPE APPLIES TO PENDING AUTHORIZATIONS TOO
 * ───────────────────────────────────────────
 * §21 requires pending authorizations to die alongside the sessions, or a
 * password change would leave a live 5-minute grant able to open a fresh
 * session. But that sweep has to honour the SAME narrowing as the session
 * sweep. Revoking every grant on a credential-scoped call breaks device
 * replacement: the employee enrols a new device, the DEVICE_REVOKED event for
 * the OLD credential arrives moments later, and it kills the grant the new
 * device just obtained — Connect appears to succeed and then dies at the
 * handoff.
 *
 * So: an unscoped call (password change, access revocation, administrator
 * termination) revokes everything, which is the intent. A scoped call revokes
 * only what it named.
 */
export async function revokeAllForUser(
  userId: string,
  reason: string,
  options: { except?: string; deviceCredentialIds?: string[] } = {}
): Promise<string[]> {
  const scopedToCredentials = Boolean(options.deviceCredentialIds?.length);

  const targets = await prisma.deskSession.findMany({
    where: {
      userId,
      status: DeskSessionStatus.ACTIVE,
      ...(options.except ? { id: { not: options.except } } : {}),
      ...(scopedToCredentials
        ? { deviceCredentialId: { in: options.deviceCredentialIds } }
        : {}),
    },
    select: { id: true },
  });

  for (const target of targets) {
    await revokeDeskSession(target.id, reason);
  }

  await prisma.authorizationToken
    .updateMany({
      where: {
        userId,
        status: "ACTIVE",
        ...(scopedToCredentials
          ? { deviceCredentialId: { in: options.deviceCredentialIds } }
          : {}),
      },
      data: { status: "REVOKED", revokedAt: new Date() },
    })
    .catch(() => {});

  return targets.map((t) => t.id);
}

/**
 * §16: rotate the session identifier, invalidating the previous one.
 *
 * Implemented as a primary-key change on the existing row rather than
 * revoke-and-recreate. The authorization is one-to-one with a session, so a
 * second row could not carry the same grant forward; more importantly, moving
 * the identifier guarantees the old one resolves to nothing at all rather than
 * to a revoked-but-present record.
 *
 * Lifetime is deliberately not reset: rotation is a hygiene measure against
 * leaked identifiers, not a way to extend a session past its §18 ceiling.
 */
export async function rotateDeskSessionId(sessionId: string): Promise<DeskSession | null> {
  const current = await prisma.deskSession.findUnique({ where: { id: sessionId } });
  if (!current || current.status !== DeskSessionStatus.ACTIVE) return null;

  return prisma.deskSession.update({
    where: { id: current.id },
    data: {
      id: crypto.randomUUID(),
      rotatedFromId: current.id,
      lastActivityAt: new Date(),
    },
  });
}

export async function getActiveDeskSession(userId: string): Promise<DeskSession | null> {
  return prisma.deskSession.findFirst({
    where: { userId, status: DeskSessionStatus.ACTIVE },
    orderBy: { createdAt: "desc" },
  });
}
