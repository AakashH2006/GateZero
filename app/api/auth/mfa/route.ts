/**
 * app/api/auth/mfa/route.ts
 * MFA verification endpoint supporting Email OTP and TOTP.
 *
 * POST /api/auth/mfa
 * Body: { method: "totp" | "email", code?: string }
 * Body: { action: "send_email" }
 */

import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { getPendingOrActiveSession, activateSession } from "@/lib/auth/session";
import { verifyOTPCode } from "@/lib/auth/mfa";
import { sendEmailOTP, verifyEmailOTP } from "@/lib/auth/email-mfa";
import { auditLogin, getClientIP, getClientUA } from "@/lib/audit";
import {
  badRequest,
  unauthorized,
  validationError,
  safeHandler,
} from "@/lib/errors";
import { SessionStatus } from "@prisma/client";

const mfaSchema = z.object({
  method: z.enum(["totp", "email"]),
  code: z.string().optional(),
});

const actionSchema = z.object({
  action: z.enum(["send_email"]),
});

export async function POST(request: NextRequest): Promise<NextResponse> {
  return safeHandler(async () => {
    const ip = getClientIP(request);
    const ua = getClientUA(request);

    const session = await getPendingOrActiveSession();
    if (!session) {
      return unauthorized("No active session");
    }

    const body = await request.json();

    // Action handler: send_email
    if (body.action) {
      const parsed = actionSchema.safeParse(body);
      if (!parsed.success) return validationError(parsed.error);

      if (parsed.data.action === "send_email") {
        const result = await sendEmailOTP(session.id, session.user.email);
        void auditLogin({
          eventType: "MFA_PUSH_APPROVED",
          userId: session.userId,
          sessionId: session.id,
          ipAddress: ip,
          userAgent: ua,
          outcome: "SUCCESS",
          metadata: { method: "email_otp_sent", email: session.user.email },
        });

        return NextResponse.json({
          success: true,
          email: session.user.email,
        });
      }
    }

    if (session.status === SessionStatus.ACTIVE) {
      return NextResponse.json({ success: true, redirect: "/dashboard" });
    }

    if (session.status !== SessionStatus.PENDING_MFA) {
      return unauthorized("Session is not awaiting MFA");
    }

    const parsed = mfaSchema.safeParse(body);
    if (!parsed.success) return validationError(parsed.error);

    const { method, code } = parsed.data;

    // Method 1: Email OTP
    if (method === "email") {
      if (!code) return badRequest("code is required for Email method");

      const { valid, reason } = await verifyEmailOTP(session.id, code);
      if (!valid) {
        void auditLogin({
          eventType: "MFA_TOTP_FAILED",
          userId: session.userId,
          sessionId: session.id,
          ipAddress: ip,
          userAgent: ua,
          outcome: "FAILURE",
          metadata: { method: "email", reason },
        });
        return NextResponse.json(
          { success: false, error: reason ?? "Invalid Email OTP" },
          { status: 400 }
        );
      }

      await activateSession(session.id);

      void auditLogin({
        eventType: "MFA_TOTP_APPROVED",
        userId: session.userId,
        sessionId: session.id,
        ipAddress: ip,
        userAgent: ua,
        outcome: "SUCCESS",
        metadata: { method: "email" },
      });

      return NextResponse.json({ success: true, redirect: "/dashboard" });
    }

    // Method 2: TOTP / 6-digit code
    if (method === "totp") {
      if (!code) return badRequest("code is required for TOTP method");

      const { valid, reason } = await verifyOTPCode(session.id, code);
      if (!valid) {
        void auditLogin({
          eventType: "MFA_TOTP_FAILED",
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

      await activateSession(session.id);

      void auditLogin({
        eventType: "MFA_TOTP_APPROVED",
        userId: session.userId,
        sessionId: session.id,
        ipAddress: ip,
        userAgent: ua,
        outcome: "SUCCESS",
        metadata: { method: "totp" },
      });

      return NextResponse.json({ success: true, redirect: "/dashboard" });
    }

    return badRequest("Invalid MFA method");
  });
}
