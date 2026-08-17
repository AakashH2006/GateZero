/**
 * lib/auth/mfa.ts
 * MFA (Multi-Factor Authentication) state management.
 *
 * In DEV_MODE:
 *   - "Simulate approve" flow: sets a short-lived DB flag on the session
 *   - 6-digit code: accepts ANY valid 6-digit numeric string
 *
 * In PRODUCTION (DEV_MODE=false):
 *   - This module would call out to a real MFA provider (e.g. Duo, Okta Verify)
 *   - The "simulatePushApprove" path would be gated out entirely
 *   - TOTP verification would use a real TOTP library (e.g. otplib) against
 *     a per-user secret stored in a secure vault
 *
 * MOCK BOUNDARY:
 * Replace the bodies of verifyTOTP() and triggerPushNotification() with real
 * provider calls without touching the session or audit logic around them.
 */

import crypto from "crypto";
import { prisma } from "../db";
import { DEV_MODE } from "../config";
import { SessionStatus } from "@prisma/client";

// MFA challenge is valid for 10 minutes
const MFA_TTL_MS = 10 * 60 * 1000;

/**
 * Begin an MFA challenge for a pending session.
 * Stores a signed challenge token in the session record.
 * Returns the token (used by the MFA status-check endpoint).
 */
export async function beginMFAChallenge(sessionId: string): Promise<{ mfaToken: string }> {
  const mfaToken = crypto.randomBytes(24).toString("hex");
  const mfaExpiry = new Date(Date.now() + MFA_TTL_MS);

  await prisma.session.update({
    where: { id: sessionId },
    data: { mfaToken, mfaExpiry },
  });

  if (DEV_MODE) {
    console.log(`[DEV_MODE] MFA challenge started for session ${sessionId}`);
  }

  return { mfaToken };
}

/**
 * DEV_MODE ONLY: Simulate a push notification approval.
 * In real systems this would come from a webhook from the MFA provider.
 */
export async function simulatePushApprove(sessionId: string): Promise<{ approved: boolean }> {
  if (!DEV_MODE) {
    throw new Error("simulatePushApprove is only available in DEV_MODE");
  }

  const session = await prisma.session.findUnique({ where: { id: sessionId } });
  if (!session || session.status !== SessionStatus.PENDING_MFA) {
    return { approved: false };
  }
  if (!session.mfaExpiry || session.mfaExpiry < new Date()) {
    return { approved: false };
  }

  // Mark MFA as approved by setting a magic sentinel in mfaToken
  await prisma.session.update({
    where: { id: sessionId },
    data: { mfaToken: `APPROVED:${session.mfaToken}` },
  });

  return { approved: true };
}

/**
 * Check if push approval has been simulated (dev) or confirmed (prod).
 */
export async function checkPushStatus(
  sessionId: string
): Promise<{ approved: boolean }> {
  const session = await prisma.session.findUnique({ where: { id: sessionId } });
  if (!session) return { approved: false };
  if (!session.mfaToken?.startsWith("APPROVED:")) return { approved: false };
  return { approved: true };
}

/**
 * Verify a TOTP/OTP code.
 * DEV_MODE: accepts any 6-digit numeric string.
 * Production: validate against a real TOTP secret with otplib or similar.
 */
export async function verifyOTPCode(
  sessionId: string,
  code: string
): Promise<{ valid: boolean; reason?: string }> {
  // Validate format first
  if (!/^\d{6}$/.test(code)) {
    return { valid: false, reason: "Code must be exactly 6 digits" };
  }

  const session = await prisma.session.findUnique({ where: { id: sessionId } });
  if (!session) return { valid: false, reason: "Session not found" };
  if (session.status !== SessionStatus.PENDING_MFA) {
    return { valid: false, reason: "Session is not awaiting MFA" };
  }
  if (!session.mfaExpiry || session.mfaExpiry < new Date()) {
    return { valid: false, reason: "MFA challenge expired" };
  }

  if (DEV_MODE) {
    // Accept any 6-digit code in dev mode
    console.log(`[DEV_MODE] Accepting OTP code ${code} for session ${sessionId}`);
    return { valid: true };
  }

  // ── PRODUCTION: integrate real TOTP verification here ─────────────────────
  // Example with otplib:
  //   const user = await prisma.user.findUnique({ where: { id: session.userId } });
  //   const secret = await vault.getSecret(`mfa/${user.id}`);
  //   return { valid: authenticator.check(code, secret) };
  // ──────────────────────────────────────────────────────────────────────────
  return { valid: false, reason: "MFA not configured in production mode" };
}
