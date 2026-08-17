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
import { IRON_SESSION_OPTIONS, SESSION_TTL_MS } from "../config";
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

export async function activateSession(sessionId: string): Promise<Session> {
  return prisma.session.update({
    where: { id: sessionId },
    data: { status: SessionStatus.ACTIVE, mfaToken: null, mfaExpiry: null },
  });
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
