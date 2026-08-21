/**
 * app/api/admin/step-up/route.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Administrator re-authentication — website-1-defense.md §14
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * POST /api/admin/step-up
 *   { action: "send" }                              — dispatch a fresh admin OTP
 *   { code, privilegedAction, targetUserId?, reason } — verify and mint a grant
 *
 * §14: "Admin login does not equal permanent administrative authorization.
 * Every privileged action requires fresh proof of administrator identity."
 *
 * The grant returned here authorizes exactly ONE action, against ONE target,
 * for a couple of minutes. The administrator may stay signed into the dashboard
 * indefinitely; that grants nothing on its own.
 *
 * The privileged action and target are named at re-authentication time and are
 * baked into the grant. That is what stops a re-auth performed for a benign
 * action from being spent on an MFA override — and it is why the reason is
 * demanded here rather than at spend time.
 */

import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { requireAdmin } from "@/lib/admin";
import { issueStepUp, type PrivilegedAction } from "@/lib/admin-stepup";
import { sendEmailOTP, verifyEmailOTP } from "@/lib/auth/email-mfa";
import { checkRateLimit } from "@/lib/rate-limit";
import { auditLogin, getClientIP, getClientUA } from "@/lib/audit";
import { prisma } from "@/lib/db";
import {
  forbidden,
  badRequest,
  validationError,
  tooManyRequests,
  safeHandler,
} from "@/lib/errors";

const PRIVILEGED_ACTIONS = [
  "REVOKE_SESSION",
  "REVOKE_AUTHORIZATION",
  "TERMINATE_W2_SESSION",
  "MFA_OVERRIDE",
  "EMERGENCY_CONFIRM_OUTAGE",
  "EMERGENCY_CONNECT",
  "APPROVE_DEVICE",
  "REVOKE_DEVICE",
  "APPROVE_RECOVERY",
  "REVOKE_EMPLOYEE_ACCESS",
  "RESTORE_EMPLOYEE_ACCESS",
  "OOB_REVOKE_W2_SESSION",
] as const;

const sendSchema = z.object({ action: z.literal("send") });
const verifySchema = z.object({
  code: z.string().regex(/^\d{6}$/),
  privilegedAction: z.enum(PRIVILEGED_ACTIONS),
  targetUserId: z.string().optional(),
  reason: z.string().min(5).max(500),
});

/**
 * The OTP store is keyed by session id. Administrator step-up is keyed by the
 * admin's identity instead, so a step-up challenge is never confused with the
 * login MFA challenge on the same session.
 */
function otpKey(adminUserId: string): string {
  return `admin-stepup:${adminUserId}`;
}

export async function POST(request: NextRequest): Promise<NextResponse> {
  return safeHandler(async () => {
    const ip = getClientIP(request);
    const ua = getClientUA(request);

    const admin = await requireAdmin(request);
    if (!admin.authorized || !admin.adminUserId) {
      return forbidden("Admin access required");
    }

    // §13: rate-limited like any other authentication surface. An admin
    // re-auth endpoint that can be hammered is an OTP oracle.
    const rate = await checkRateLimit(`admin-stepup:${admin.adminUserId}`, 10, 300);
    if (!rate.allowed) return tooManyRequests(rate.resetAt);

    const body = await request.json().catch(() => ({}));

    if (body.action) {
      const parsed = sendSchema.safeParse(body);
      if (!parsed.success) return validationError(parsed.error);

      const adminUser = await prisma.user.findUnique({ where: { id: admin.adminUserId } });
      if (!adminUser) return forbidden("Admin identity not found");

      const result = await sendEmailOTP(otpKey(admin.adminUserId), adminUser.email);

      void auditLogin({
        eventType: "ADMIN_STEP_UP_CHALLENGE_SENT",
        userId: admin.adminUserId,
        ipAddress: ip,
        userAgent: ua,
        outcome: result.success ? "SUCCESS" : "FAILURE",
        severity: "NOTICE",
        metadata: {},
      });

      return NextResponse.json({ success: result.success });
    }

    const parsed = verifySchema.safeParse(body);
    if (!parsed.success) return validationError(parsed.error);

    const { valid, reason } = await verifyEmailOTP(otpKey(admin.adminUserId), parsed.data.code);
    if (!valid) {
      void auditLogin({
        eventType: "ADMIN_STEP_UP_FAILED",
        userId: admin.adminUserId,
        ipAddress: ip,
        userAgent: ua,
        outcome: "FAILURE",
        severity: "WARNING",
        metadata: { privilegedAction: parsed.data.privilegedAction, reason },
      });
      return badRequest(reason ?? "Invalid code", "STEP_UP_FAILED");
    }

    const grant = await issueStepUp({
      adminUserId: admin.adminUserId,
      action: parsed.data.privilegedAction as PrivilegedAction,
      targetUserId: parsed.data.targetUserId ?? null,
      reason: parsed.data.reason,
    });

    void auditLogin({
      eventType: "ADMIN_STEP_UP_ISSUED",
      userId: admin.adminUserId,
      ipAddress: ip,
      userAgent: ua,
      outcome: "SUCCESS",
      severity: "HIGH",
      metadata: {
        stepUpId: grant.id,
        privilegedAction: grant.action,
        targetUserId: grant.targetUserId,
        // §15 requires the reason on record; it is captured at issue time so it
        // cannot be back-filled after the fact.
        justification: parsed.data.reason,
      },
    });

    return NextResponse.json({
      success: true,
      stepUpId: grant.id,
      action: grant.action,
      expiresAt: grant.expiresAt,
      message: "This authorization is valid for one action only.",
    });
  });
}
