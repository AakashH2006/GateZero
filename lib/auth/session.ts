/**
 * lib/auth/session.ts
 * Server-side session management for GateZero Portal.
 *
 * Architecture:
 * ─────────────
 * - A signed httpOnly cookie (iron-session) holds ONLY the session ID.
 * - The actual session record lives in the DB (Session table).
 * - Sessions are revocable server-side by deleting/revoking the DB record.
 * - Sensitive claims are NEVER stored in the cookie or localStorage.
 *
 * Session lifecycle:
 *   1. SSO callback → createPendingSession() — status=PENDING_MFA
 *   2. MFA success  → activateSession()      — status=ACTIVE
 *   3. Logout       → destroySession()        — deletes DB record + clears cookie
 *   4. Admin revoke → revokeSession()         — status=REVOKED (preserved for audit)
 *   5. TTL expiry   → checked on every getValidSession() call
 */

import { getIronSession, IronSession } from "iron-session";
import { cookies } from "next/headers";
import { prisma } from "../db";
import {
  IRON_SESSION_OPTIONS,
  SESSION_TTL_MS,
  MFA_OVERRIDE_SESSION_TTL_MS,
  CONNECT_COOLDOWN_SECONDS,
} from "../config";
import { SessionStatus, User, Session } from "@prisma/client";
import crypto from "crypto";

// ── Iron-session data shape ────────────────────────────────────────────────────
// Only the session ID is stored in the cookie — nothing sensitive.
export interface SessionData {
  sessionId?: string;
}

// ── Helpers ────────────────────────────────────────────────────────────────────

export async function getIronSessionStore(): Promise<IronSession<SessionData>> {
  const cookieStore = await cookies();
  return getIronSession<SessionData>(cookieStore, IRON_SESSION_OPTIONS);
}

/** Hash a user-agent string so we don't store PII verbatim */
function hashUA(userAgent: string): string {
  return crypto.createHash("sha256").update(userAgent).digest("hex").slice(0, 16);
}

// ── Session creation (PENDING_MFA — after SSO, before MFA) ────────────────────

export async function createPendingSession(params: {
  userId: string;
  ipAddress: string;
  userAgent: string;
}): Promise<Session> {
  const expiresAt = new Date(Date.now() + SESSION_TTL_MS);

  const session = await prisma.session.create({
    data: {
      userId: params.userId,
      status: SessionStatus.PENDING_MFA,
      ipAddress: params.ipAddress,
      userAgent: hashUA(params.userAgent),
      expiresAt,
    },
  });

  // Write session ID to signed httpOnly cookie
  const ironSession = await getIronSessionStore();
  ironSession.sessionId = session.id;
  await ironSession.save();

  return session;
}

// ── Activate session after successful MFA ──────────────────────────────────────
//
// SECURITY: Session ID rotation.
// The PENDING_MFA session ID was minted *before* the user proved themselves
// with a second factor. If that ID was ever captured (log line, proxy,
// referrer leak, shoulder-surfed QR/link) during the login window, it must
// not remain valid for the full 7-day lifetime. On successful MFA we retire
// the pre-MFA session row and issue a brand new ACTIVE session ID, then
// rewrite the cookie. Anyone holding only the old ID gets a REVOKED session.

export async function activateSession(params: {
  sessionId: string;
  ipAddress: string;
  userAgent: string;
}): Promise<Session> {
  const pending = await prisma.session.findUnique({ where: { id: params.sessionId } });
  if (!pending) {
    throw new Error("SESSION_NOT_FOUND");
  }

  const expiresAt = new Date(Date.now() + SESSION_TTL_MS);

  const [, newSession] = await prisma.$transaction([
    // Retire the pre-MFA session ID — it must never be reusable post-rotation.
    prisma.session.update({
      where: { id: pending.id },
      data: { status: SessionStatus.REVOKED, revokedAt: new Date() },
    }),
    // Mint the real, post-MFA 7-day session under a fresh ID.
    prisma.session.create({
      data: {
        userId: pending.userId,
        status: SessionStatus.ACTIVE,
        ipAddress: params.ipAddress,
        userAgent: hashUA(params.userAgent),
        expiresAt,
      },
    }),
  ]);

  const ironSession = await getIronSessionStore();
  ironSession.sessionId = newSession.id;
  await ironSession.save();

  return newSession;
}

// ── Get and validate the current session from the cookie ──────────────────────

export type ValidSession = Session & { user: User };

export async function getValidSession(): Promise<ValidSession | null> {
  const ironSession = await getIronSessionStore();
  if (!ironSession.sessionId) return null;

  const session = await prisma.session.findUnique({
    where: { id: ironSession.sessionId },
    include: { user: true },
  });

  if (!session) return null;

  // Check revocation
  if (session.status === SessionStatus.REVOKED) return null;

  // Check expiry
  if (session.expiresAt < new Date()) {
    // Mark expired for audit purposes but don't block the check
    await prisma.session.update({
      where: { id: session.id },
      data: { status: SessionStatus.EXPIRED },
    }).catch(() => {}); // best-effort
    return null;
  }

  // Must be fully authenticated (not just PENDING_MFA)
  if (session.status !== SessionStatus.ACTIVE) return null;

  return session;
}

/** Get session including PENDING_MFA status (for MFA page) */
export async function getPendingOrActiveSession(): Promise<(Session & { user: User }) | null> {
  const ironSession = await getIronSessionStore();
  if (!ironSession.sessionId) return null;

  const session = await prisma.session.findUnique({
    where: { id: ironSession.sessionId },
    include: { user: true },
  });

  if (!session) return null;
  if (session.status === SessionStatus.REVOKED) return null;
  if (session.expiresAt < new Date()) return null;

  return session;
}

// ── Destroy session (logout) ───────────────────────────────────────────────────

export async function destroySession(): Promise<void> {
  const ironSession = await getIronSessionStore();
  const sessionId = ironSession.sessionId;

  ironSession.destroy();
  await ironSession.save();

  if (sessionId) {
    await prisma.session.delete({ where: { id: sessionId } }).catch(() => {});
  }
}

// ── Admin: revoke session ──────────────────────────────────────────────────────

export async function revokeSession(sessionId: string): Promise<void> {
  await prisma.session.update({
    where: { id: sessionId },
    data: { status: SessionStatus.REVOKED, revokedAt: new Date() },
  });
}

// ── Mini EDR (§6-7): Connect-scoped step-up gate ───────────────────────────────
//
// A MEDIUM risk assessment on Connect must block further Connect attempts and
// require fresh MFA, but must NOT revoke the 7-day Website 1 session — the
// employee can keep browsing the portal, they just can't Connect until they
// step up. This is a narrower gate than session revocation and is
// intentionally independent of the PENDING_MFA/ACTIVE login state machine.

/** Flag a session as requiring a fresh MFA step-up before Connect will succeed again. */
export async function flagStepUpRequired(sessionId: string): Promise<void> {
  await prisma.session.update({
    where: { id: sessionId },
    data: { connectStepUpRequired: true },
  });
}

/** Clear the step-up gate after the employee completes a fresh MFA challenge. */
export async function clearStepUpRequired(sessionId: string): Promise<void> {
  await prisma.session.update({
    where: { id: sessionId },
    data: { connectStepUpRequired: false },
  });
}

// ── §15: administrative MFA override ──────────────────────────────────────────
//
// An override must never quietly produce an ordinary 7-day session. The session
// minted here is flagged, given a much shorter lifetime, and pre-gated so the
// employee has to complete real MFA before Connect will work — regardless of
// how much of that shortened lifetime remains.

export async function createMfaOverriddenSession(params: {
  userId: string;
  adminUserId: string;
  ipAddress: string;
  userAgent: string;
}): Promise<Session> {
  return prisma.session.create({
    data: {
      userId: params.userId,
      status: SessionStatus.ACTIVE,
      ipAddress: params.ipAddress,
      userAgent: hashUA(params.userAgent),
      expiresAt: new Date(Date.now() + MFA_OVERRIDE_SESSION_TTL_MS),
      mfaOverridden: true,
      mfaOverrideAdminId: params.adminUserId,
      // §15: "the employee must complete fresh MFA at the next Connect attempt".
      connectStepUpRequired: true,
    },
  });
}

// ── §12 / §22: bulk session invalidation ──────────────────────────────────────

/**
 * Revoke every Website 1 session for an employee.
 *
 * §12: after a password reset this is what stops an attacker holding a
 * previously stolen 7-day session from carrying on. `except` exists so the
 * session performing the reset can survive its own sweep.
 */
export async function revokeAllSessionsForUser(
  userId: string,
  options: { except?: string } = {}
): Promise<number> {
  const result = await prisma.session.updateMany({
    where: {
      userId,
      status: { in: [SessionStatus.ACTIVE, SessionStatus.PENDING_MFA] },
      ...(options.except ? { id: { not: options.except } } : {}),
    },
    data: { status: SessionStatus.REVOKED, revokedAt: new Date() },
  });
  return result.count;
}

// ── §10: Connect abuse cooldown ───────────────────────────────────────────────
//
// Distinct from the sliding-window rate limit: that throttles bursts, this is
// the longer freeze applied once an account accumulates repeated *failures*.

export async function applyConnectCooldown(sessionId: string): Promise<Date> {
  const until = new Date(Date.now() + CONNECT_COOLDOWN_SECONDS * 1000);
  await prisma.session.update({
    where: { id: sessionId },
    data: { connectCooldownUntil: until },
  });
  return until;
}

export function connectCooldownRemainingMs(
  session: Pick<Session, "connectCooldownUntil">,
  now: Date = new Date()
): number {
  if (!session.connectCooldownUntil) return 0;
  return Math.max(0, session.connectCooldownUntil.getTime() - now.getTime());
}

/** Record which device credential a session most recently connected with (§5). */
export async function bindSessionDevice(
  sessionId: string,
  deviceCredentialId: string
): Promise<void> {
  await prisma.session
    .update({ where: { id: sessionId }, data: { deviceCredentialId } })
    .catch(() => {});
}
