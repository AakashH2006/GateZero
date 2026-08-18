/**
 * app/api/auth/step-up/route.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Step-up MFA — clears the Mini EDR MEDIUM-risk Connect gate (§6-7)
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * POST /api/auth/step-up
 * Body: { action: "send" }              — dispatch a fresh email OTP
 * Body: { code: string }                — verify the OTP and clear the gate
 *
 * This is intentionally SEPARATE from /api/auth/mfa (the login MFA route),
 * which is tied to the PENDING_MFA -> ACTIVE session-rotation flow (§3) and
 * is not touched here. Step-up operates on an already-ACTIVE, unrevoked
 * session — it only gates the Connect endpoint (via
 * session.connectStepUpRequired), never the session itself.
 */

import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { getValidSession, clearStepUpRequired } from "@/lib/auth/session";
import { sendEmailOTP, verifyEmailOTP } from "@/lib/auth/email-mfa";
import { auditLogin, getClientIP, getClientUA } from "@/lib/audit";
import { badRequest, unauthorized, validationError, safeHandler } from "@/lib/errors";

const sendSchema = z.object({ action: z.literal("send") });
const verifySchema = z.object({ code: z.string() });

export async function POST(request: NextRequest): Promise<NextResponse> {
  return safeHandler(async () => {
    const ip = getClientIP(request);
    const ua = getClientUA(request);

    // Step-up requires an already fully-authenticated, unrevoked session.
    // This session is NEVER revoked by the step-up flow itself.
    const session = await getValidSession();
    if (!session) {
      return unauthorized("Valid session required");
    }

    if (!session.connectStepUpRequired) {
      return badRequest("No step-up MFA is pending for this session", "NO_STEP_UP_PENDING");
    }

    const body = await request.json();

    if (body.action) {
      const parsed = sendSchema.safeParse(body);
      if (!parsed.success) return validationError(parsed.error);

      const result = await sendEmailOTP(session.id, session.user.email);
      void auditLogin({
        eventType: "STEP_UP_MFA_SENT",
        userId: session.userId,
        sessionId: session.id,
        ipAddress: ip,
        userAgent: ua,
        outcome: result.success ? "SUCCESS" : "FAILURE",
        metadata: { email: session.user.email },
      });

      return NextResponse.json({ success: result.success, email: session.user.email });
    }

    const parsed = verifySchema.safeParse(body);
    if (!parsed.success) return validationError(parsed.error);

    const { valid, reason } = await verifyEmailOTP(session.id, parsed.data.code);
    if (!valid) {
      void auditLogin({
        eventType: "STEP_UP_MFA_FAILED",
        userId: session.userId,
        sessionId: session.id,
        ipAddress: ip,
        userAgent: ua,
        outcome: "FAILURE",
        metadata: { reason },
      });
      return NextResponse.json(
        { success: false, error: reason ?? "Invalid code" },
        { status: 400 }
      );
    }

    // Fresh MFA proven — clear the Connect gate. Session id/status untouched.
    await clearStepUpRequired(session.id);

    void auditLogin({
      eventType: "STEP_UP_MFA_VERIFIED",
      userId: session.userId,
      sessionId: session.id,
      ipAddress: ip,
      userAgent: ua,
      outcome: "SUCCESS",
      metadata: {},
    });

    return NextResponse.json({ success: true });
  });
}
