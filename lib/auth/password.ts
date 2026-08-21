/**
 * lib/auth/password.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Password reset — website-1-defense.md §12
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * §12's opening line sets the constraint: "Password reset must not become an
 * alternative authentication path." So a reset is not a way *in* — it is only
 * available to someone who has already proved themselves with MFA.
 *
 * Reset tokens are single-use, short-lived, invalidated immediately on use,
 * generated from a CSPRNG, and never logged. Only the hash is stored, so a read
 * of the token store yields nothing usable.
 *
 * Hashing uses scrypt with a per-password salt. Verification is constant-time.
 *
 * SSO DEPLOYMENTS
 * ───────────────
 * Where the IdP owns the password, this local flow is unused and the same
 * downstream consequences (session invalidation, cross-boundary propagation)
 * are triggered by `applyPasswordChangeConsequences()` from an IdP webhook
 * instead. Both entry points converge on that one function so the security
 * consequences of a password change cannot drift apart between them.
 */

import crypto from "crypto";
import { prisma } from "../db";
import { revokeAllSessionsForUser } from "./session";
import { revokeAllAuthorizationsForUser } from "../authz-service";
import { enqueueSecurityEvent } from "../security-events";
import { notifyEmployeeById } from "../notify";

const SCRYPT_KEYLEN = 64;
const RESET_TOKEN_TTL_MS = 15 * 60 * 1000;

/** In-memory reset-token store: hash → record. Never holds the token itself. */
const resetTokens = new Map<
  string,
  { userId: string; expiresAt: Date; usedAt?: Date }
>();

function hashToken(token: string): string {
  return crypto.createHash("sha256").update(token).digest("hex");
}

// ── Password hashing ──────────────────────────────────────────────────────────

export function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16);
  const derived = crypto.scryptSync(password, salt, SCRYPT_KEYLEN);
  return `scrypt$${salt.toString("hex")}$${derived.toString("hex")}`;
}

export function verifyPassword(password: string, stored: string | null): boolean {
  if (!stored) return false;
  const [scheme, saltHex, hashHex] = stored.split("$");
  if (scheme !== "scrypt" || !saltHex || !hashHex) return false;

  try {
    const derived = crypto.scryptSync(password, Buffer.from(saltHex, "hex"), SCRYPT_KEYLEN);
    const expected = Buffer.from(hashHex, "hex");
    if (expected.length !== derived.length) return false;
    return crypto.timingSafeEqual(expected, derived);
  } catch {
    return false;
  }
}

/** Minimum acceptable password. Deliberately length-led rather than composition-led. */
export function passwordPolicyError(password: string): string | null {
  if (password.length < 12) return "Password must be at least 12 characters";
  if (password.length > 200) return "Password is too long";
  if (/^\s|\s$/.test(password)) return "Password must not start or end with whitespace";
  return null;
}

// ── Reset tokens (§12 "Reset Token Security") ─────────────────────────────────

/**
 * Issue a reset token. The caller MUST have verified MFA first — this function
 * mints, it does not authenticate.
 */
export function issueResetToken(userId: string): { token: string; expiresAt: Date } {
  const token = crypto.randomBytes(32).toString("base64url");
  const expiresAt = new Date(Date.now() + RESET_TOKEN_TTL_MS);
  resetTokens.set(hashToken(token), { userId, expiresAt });
  return { token, expiresAt };
}

export interface ResetTokenCheck {
  valid: boolean;
  userId?: string;
  reason?: string;
}

/**
 * Redeem a reset token. Single-use: the entry is deleted on the way through, so
 * a second presentation of the same token finds nothing regardless of outcome.
 */
export function consumeResetToken(token: string): ResetTokenCheck {
  const key = hashToken(token);
  const record = resetTokens.get(key);

  if (!record) return { valid: false, reason: "TOKEN_NOT_FOUND" };

  // Deleted first: even a failed redemption burns the token, which denies an
  // attacker repeated attempts against one live token.
  resetTokens.delete(key);

  if (record.usedAt) return { valid: false, reason: "TOKEN_ALREADY_USED" };
  if (record.expiresAt < new Date()) return { valid: false, reason: "TOKEN_EXPIRED" };

  return { valid: true, userId: record.userId };
}

// ── Consequences (§12 "Session Invalidation", §22.4, W2 §21) ──────────────────

export interface PasswordChangeResult {
  revokedSessions: number;
  revokedAuthorizations: number;
  eventId: string;
}

/**
 * Apply every downstream consequence of a password change.
 *
 * Both halves matter and neither is sufficient alone:
 *
 *   - Website 1 sessions are revoked, so an attacker holding a stolen 7-day
 *     session cannot keep using it after the legitimate employee resets (§12).
 *   - A critical event propagates to Website 2, so a live Website 2 session
 *     cannot survive the reset either (§12 closing note, §22.4, W2 §21).
 *     Without the second, the reset would look effective while the attacker
 *     carried on working inside Website 2.
 */
export async function applyPasswordChangeConsequences(params: {
  userId: string;
  reason: string;
  /** Session performing the reset, exempted from the sweep. */
  exceptSessionId?: string;
}): Promise<PasswordChangeResult> {
  await prisma.user.update({
    where: { id: params.userId },
    data: { passwordChangedAt: new Date() },
  });

  const revokedSessions = await revokeAllSessionsForUser(params.userId, {
    except: params.exceptSessionId,
  });
  const revokedAuthorizations = await revokeAllAuthorizationsForUser(params.userId);

  const eventId = await enqueueSecurityEvent({
    type: "PASSWORD_CHANGED",
    userId: params.userId,
    reason: params.reason,
  });

  void notifyEmployeeById(params.userId, "PASSWORD_CHANGED");

  return { revokedSessions, revokedAuthorizations, eventId };
}
