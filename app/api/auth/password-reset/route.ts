/**
 * app/api/auth/password-reset/route.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Password reset — website-1-defense.md §12 / website-2-defense.md §21
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * POST /api/auth/password-reset
 *   { step: "send" }                  — dispatch an MFA code
 *   { step: "verify", code }          — verify MFA, receive a single-use token
 *   { step: "reset", token, password} — set the new password
 *
 * §12: "A password reset is permitted only after successful MFA verification."
 * The flow is ordered so that is structurally true — the token that authorizes
 * step three is only minted by step two, and step two requires a valid MFA
 * code. There is no path to step three without passing step two.
 *
 * This is deliberately NOT a "forgot password" flow. It requires an existing
 * authenticated session, because §12's constraint is that reset must not become
 * an alternative *authentication* path. An unauthenticated recovery flow is a
 * separate design problem that this section does not open.
 *
 * On success, every Website 1 session is invalidated and a critical event
 * propagates to Website 2 so no session survives on either side.
 */

import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { getValidSession } from "@/lib/auth/session";
import { sendEmailOTP, verifyEmailOTP } from "@/lib/auth/email-mfa";
import {
  hashPassword,
  passwordPolicyError,
  issueResetToken,
  consumeResetToken,
  applyPasswordChangeConsequences,
} from "@/lib/auth/password";
import { CSRF_HEADER, verifyCsrfToken } from "@/lib/auth/csrf";
import { checkRateLimit } from "@/lib/rate-limit";
import { auditLogin, getClientIP, getClientUA } from "@/lib/audit";
import { prisma } from "@/lib/db";
import {
  unauthorized,
  forbidden,
  badRequest,
  validationError,
  tooManyRequests,
  safeHandler,
} from "@/lib/errors";

const schema = z.discriminatedUnion("step", [
  z.object({ step: z.literal("send") }),
  z.object({ step: z.literal("verify"), code: z.string().regex(/^\d{6}$/) }),
  z.object({
    step: z.literal("reset"),
    token: z.string().min(20),
    password: z.string().min(1),
  }),
]);

function otpKey(sessionId: string): string {
  return `password-reset:${sessionId}`;
}

export async function POST(request: NextRequest): Promise<NextResponse> {
  return safeHandler(async () => {
    const ip = getClientIP(request);
    const ua = getClientUA(request);

    const session = await getValidSession();
    if (!session) return unauthorized("Valid session required");

    if (!verifyCsrfToken(session.id, request.headers.get(CSRF_HEADER))) {
      return forbidden("Missing or invalid CSRF token");
    }

    const rate = await checkRateLimit(`password-reset:${session.userId}`, 8, 900);
    if (!rate.allowed) {
      void auditLogin({
        eventType: "PASSWORD_RESET_RATE_LIMITED",
        userId: session.userId,
        sessionId: session.id,
        ipAddress: ip,
        userAgent: ua,
        outcome: "DENIED",
        severity: "WARNING",
        metadata: {},
      });
      return tooManyRequests(rate.resetAt);
    }

    const parsed = schema.safeParse(await request.json().catch(() => ({})));
    if (!parsed.success) return validationError(parsed.error);

    // ── Step 1: MFA challenge ───────────────────────────────────────────────
    if (parsed.data.step === "send") {
      const result = await sendEmailOTP(otpKey(session.id), session.user.email);

      void auditLogin({
        eventType: "PASSWORD_RESET_MFA_SENT",
        userId: session.userId,
        sessionId: session.id,
        ipAddress: ip,
        userAgent: ua,
        outcome: result.success ? "SUCCESS" : "FAILURE",
        severity: "NOTICE",
        metadata: {},
      });

      return NextResponse.json({ success: result.success, step: "verify" });
    }

    // ── Step 2: MFA verification mints the single-use reset token ───────────
    if (parsed.data.step === "verify") {
      const { valid, reason } = await verifyEmailOTP(otpKey(session.id), parsed.data.code);

      if (!valid) {
        void auditLogin({
          eventType: "PASSWORD_RESET_MFA_FAILED",
          userId: session.userId,
          sessionId: session.id,
          ipAddress: ip,
          userAgent: ua,
          outcome: "FAILURE",
          severity: "WARNING",
          metadata: { reason },
        });
        return badRequest(reason ?? "Invalid code", "MFA_FAILED");
      }

      const { token, expiresAt } = issueResetToken(session.userId);

      void auditLogin({
        eventType: "PASSWORD_RESET_AUTHORIZED",
        userId: session.userId,
        sessionId: session.id,
        ipAddress: ip,
        userAgent: ua,
        outcome: "SUCCESS",
        severity: "HIGH",
        // The token itself is never logged (§12) — only that one was issued.
        metadata: { expiresAt },
      });

      return NextResponse.json({ success: true, step: "reset", token, expiresAt });
    }

    // ── Step 3: redeem the token and set the password ──────────────────────
    const policyError = passwordPolicyError(parsed.data.password);
    if (policyError) return badRequest(policyError, "PASSWORD_POLICY");

    const check = consumeResetToken(parsed.data.token);
    if (!check.valid || !check.userId) {
      void auditLogin({
        eventType: "PASSWORD_RESET_TOKEN_REJECTED",
        userId: session.userId,
        sessionId: session.id,
        ipAddress: ip,
        userAgent: ua,
        outcome: "DENIED",
        severity: "HIGH",
        metadata: { reason: check.reason },
      });
      return badRequest("Reset token is invalid or expired", "RESET_TOKEN_INVALID");
    }

    // The token is bound to the user who obtained it. A token minted for one
    // account must not be spendable from another's session.
    if (check.userId !== session.userId) {
      void auditLogin({
        eventType: "PASSWORD_RESET_TOKEN_USER_MISMATCH",
        userId: session.userId,
        sessionId: session.id,
        ipAddress: ip,
        userAgent: ua,
        outcome: "DENIED",
        severity: "CRITICAL",
        metadata: {},
      });
      return badRequest("Reset token is invalid or expired", "RESET_TOKEN_INVALID");
    }

    await prisma.user.update({
      where: { id: session.userId },
      data: { passwordHash: hashPassword(parsed.data.password) },
    });

    // §12 + §22.4: invalidate Website 1 sessions AND propagate to Website 2, so
    // neither a stolen portal session nor a live Website 2 session survives.
    // The session performing the reset is deliberately not exempted — §12's
    // diagram ends at "Fresh authentication required".
    const consequences = await applyPasswordChangeConsequences({
      userId: session.userId,
      reason: "PASSWORD_RESET",
    });

    void auditLogin({
      eventType: "PASSWORD_RESET_COMPLETED",
      userId: session.userId,
      sessionId: session.id,
      ipAddress: ip,
      userAgent: ua,
      outcome: "SUCCESS",
      severity: "CRITICAL",
      metadata: {
        revokedSessions: consequences.revokedSessions,
        revokedAuthorizations: consequences.revokedAuthorizations,
        eventId: consequences.eventId,
      },
    });

    return NextResponse.json({
      success: true,
      message: "Password changed. All sessions were signed out — please sign in again.",
      revokedSessions: consequences.revokedSessions,
    });
  });
}
