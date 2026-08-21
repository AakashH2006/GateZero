/**
 * app/api/admin/mfa-override/route.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Administrative MFA override — website-1-defense.md §15
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * POST /api/admin/mfa-override
 * Body: { targetUserId, stepUpId, reason }
 *
 * This bypasses a normal security control, which is why §15 attaches seven
 * conditions to it. All seven are implemented here:
 *
 *   1. strong administrator authentication  → requirePrivilegedAction
 *   2. required role verified               → requireAdmin
 *   3. administrator identity recorded      → audit metadata
 *   4. affected employee recorded           → audit userId + step-up target
 *   5. reason recorded                      → captured at step-up issue time
 *   6. audit event                          → MFA_OVERRIDE_GRANTED
 *   7. security alert                       → raiseSecurityAlert, HIGH
 *
 * And the three limits §15 places on the *result*:
 *
 *   - It must not silently create a normal 7-day employee session.
 *   - The session is flagged MFA-overridden and short-lived.
 *   - Fresh MFA is required at the next Connect regardless of remaining
 *     lifetime — `connectStepUpRequired` is set at creation.
 *
 * The override therefore never yields Website 2 access on its own: the
 * employee still has to pass a real MFA challenge before Connect will issue an
 * authorization.
 *
 * KNOWN RESIDUAL RISK (W1 §23, W2 §31)
 * ────────────────────────────────────
 * A single administrator can perform this. The architecture has one
 * administrator, so true two-person approval cannot be enforced, and W2 §31
 * accepts that as residual risk. `SECOND_APPROVER_REQUIRED` below is the seam
 * where dual control attaches when a second administrator identity exists.
 */

import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { requirePrivilegedAction } from "@/lib/admin-action";
import { createMfaOverriddenSession } from "@/lib/auth/session";
import { auditLogin } from "@/lib/audit";
import { raiseSecurityAlert } from "@/lib/alerts";
import { notifyEmployee } from "@/lib/notify";
import { prisma } from "@/lib/db";
import { MFA_OVERRIDE_SESSION_TTL_MS } from "@/lib/config";
import { AuditStream } from "@prisma/client";
import { validationError, notFound, badRequest, safeHandler } from "@/lib/errors";

const schema = z.object({
  targetUserId: z.string().min(1),
  stepUpId: z.string().min(1),
  reason: z.string().min(5).max(500),
});

/**
 * Dual-control seam. Left as an explicit constant rather than dead code so the
 * requirement is visible at the site it would apply to. Flipping it on requires
 * a second administrator identity to exist first — see W2 §5A.
 */
const SECOND_APPROVER_REQUIRED = false;

export async function POST(request: NextRequest): Promise<NextResponse> {
  return safeHandler(async () => {
    const parsed = schema.safeParse(await request.json().catch(() => ({})));
    if (!parsed.success) return validationError(parsed.error);

    const target = await prisma.user.findUnique({ where: { id: parsed.data.targetUserId } });
    if (!target) return notFound();

    const guard = await requirePrivilegedAction({
      request,
      action: "MFA_OVERRIDE",
      stepUpId: parsed.data.stepUpId,
      targetUserId: target.id,
    });
    if (!guard.ok) return guard.response;

    if (SECOND_APPROVER_REQUIRED) {
      return badRequest(
        "A second administrator approval is required for MFA override",
        "SECOND_APPROVER_REQUIRED"
      );
    }

    // An override must never be usable to elevate into administrative
    // privilege — that would let one override manufacture the next.
    if (target.role === "ADMIN") {
      void auditLogin({
        eventType: "MFA_OVERRIDE_REFUSED_ADMIN_TARGET",
        userId: target.id,
        ipAddress: guard.context.ip,
        userAgent: guard.context.ua,
        outcome: "DENIED",
        severity: "CRITICAL",
        metadata: { adminUserId: guard.context.adminUserId, stepUpId: guard.context.stepUpId },
      });
      return badRequest(
        "MFA override cannot target an administrator account",
        "OVERRIDE_TARGET_FORBIDDEN"
      );
    }

    const session = await createMfaOverriddenSession({
      userId: target.id,
      adminUserId: guard.context.adminUserId,
      ipAddress: guard.context.ip,
      userAgent: guard.context.ua,
    });

    void auditLogin({
      eventType: "MFA_OVERRIDE_GRANTED",
      userId: target.id,
      sessionId: session.id,
      ipAddress: guard.context.ip,
      userAgent: guard.context.ua,
      outcome: "SUCCESS",
      severity: "CRITICAL",
      metadata: {
        adminUserId: guard.context.adminUserId,
        adminEmail: guard.context.adminEmail,
        targetUserEmail: target.email,
        justification: parsed.data.reason,
        stepUpId: guard.context.stepUpId,
        sessionTtlMinutes: MFA_OVERRIDE_SESSION_TTL_MS / 60000,
        mfaOverridden: true,
        connectRequiresFreshMfa: true,
      },
    });

    void raiseSecurityAlert({
      alertKey: `mfa_override:${target.id}`,
      severity: "CRITICAL",
      userId: target.id,
      sessionId: session.id,
      ipAddress: guard.context.ip,
      userAgent: guard.context.ua,
      stream: AuditStream.LOGIN,
      metadata: {
        adminUserId: guard.context.adminUserId,
        justification: parsed.data.reason,
      },
    });

    void notifyEmployee(target, "MFA_OVERRIDDEN");

    return NextResponse.json({
      success: true,
      sessionId: session.id,
      expiresAt: session.expiresAt,
      mfaOverridden: true,
      connectRequiresFreshMfa: true,
      message:
        "Override session created. It is short-lived and Connect will still require fresh MFA.",
    });
  });
}
