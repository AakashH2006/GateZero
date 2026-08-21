/**
 * app/api/admin/terminate/route.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Administrator-forced termination — website-2-defense.md §22
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * POST /api/admin/terminate
 * Body: { targetUserId, stepUpId, reason, revokeAccess? }
 *
 * §22 requires four things of administrator-forced termination, all here:
 *
 *   - revoke the employee's active Website 2 session
 *   - invalidate pending Website 2 authorizations
 *   - prevent new authorization while the access restriction remains active
 *   - create a security audit event
 *
 * The first two cross the trust boundary, so they travel as a critical security
 * event (§21) rather than as a direct call into Website 2. Website 1 does not
 * reach into Website 2's session store; that separation is the point of §35.
 *
 * The third is `user.accessRevoked`, checked by the Authorization Service
 * before any grant is minted. It is a standing restriction, not a one-off
 * termination — without it the employee could simply Connect again a second
 * later.
 *
 * `revokeAccess: false` performs a one-time termination without the standing
 * restriction, for the case where the intent is to end a session rather than
 * to suspend the employee.
 */

import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { requirePrivilegedAction } from "@/lib/admin-action";
import { revokeAllAuthorizationsForUser } from "@/lib/authz-service";
import { revokeAllSessionsForUser } from "@/lib/auth/session";
import { enqueueSecurityEvent } from "@/lib/security-events";
import { auditConnect } from "@/lib/audit";
import { raiseSecurityAlert } from "@/lib/alerts";
import { notifyEmployee } from "@/lib/notify";
import { prisma } from "@/lib/db";
import { validationError, notFound, safeHandler } from "@/lib/errors";

const schema = z.object({
  targetUserId: z.string().min(1),
  stepUpId: z.string().min(1),
  reason: z.string().min(5).max(500),
  /** Standing restriction on new authorizations, not just this termination. */
  revokeAccess: z.boolean().default(true),
  /** Also end the employee's Website 1 sessions. */
  terminateWebsite1: z.boolean().default(false),
});

export async function POST(request: NextRequest): Promise<NextResponse> {
  return safeHandler(async () => {
    const parsed = schema.safeParse(await request.json().catch(() => ({})));
    if (!parsed.success) return validationError(parsed.error);

    const target = await prisma.user.findUnique({ where: { id: parsed.data.targetUserId } });
    if (!target) return notFound();

    const guard = await requirePrivilegedAction({
      request,
      action: parsed.data.revokeAccess ? "REVOKE_EMPLOYEE_ACCESS" : "TERMINATE_W2_SESSION",
      stepUpId: parsed.data.stepUpId,
      targetUserId: target.id,
    });
    if (!guard.ok) return guard.response;

    // Standing restriction first, so that nothing can slip through in the gap
    // between revoking the current grants and blocking new ones.
    if (parsed.data.revokeAccess) {
      await prisma.user.update({
        where: { id: target.id },
        data: { accessRevoked: true, accessRevokedAt: new Date() },
      });
    }

    const revokedAuthorizations = await revokeAllAuthorizationsForUser(target.id);

    let revokedW1Sessions = 0;
    if (parsed.data.terminateWebsite1) {
      revokedW1Sessions = await revokeAllSessionsForUser(target.id);
    }

    // Crosses the boundary as a signed, deduplicated critical event (§21, §32).
    const eventId = await enqueueSecurityEvent({
      type: parsed.data.revokeAccess ? "ACCESS_REVOKED" : "ADMIN_TERMINATION",
      userId: target.id,
      reason: parsed.data.reason,
    });

    void auditConnect({
      eventType: "ADMIN_FORCED_TERMINATION",
      userId: target.id,
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
        accessRevoked: parsed.data.revokeAccess,
        revokedAuthorizations,
        revokedW1Sessions,
        eventId,
      },
    });

    void raiseSecurityAlert({
      alertKey: `admin_termination:${target.id}`,
      severity: "HIGH",
      userId: target.id,
      ipAddress: guard.context.ip,
      userAgent: guard.context.ua,
      metadata: { adminUserId: guard.context.adminUserId, justification: parsed.data.reason },
    });

    void notifyEmployee(target, parsed.data.revokeAccess ? "ACCESS_REVOKED" : "W2_SESSION_REPLACED");

    return NextResponse.json({
      success: true,
      accessRevoked: parsed.data.revokeAccess,
      revokedAuthorizations,
      revokedW1Sessions,
      eventId,
      message:
        "Termination event queued for Website 2. Delivery is at-least-once and acknowledged.",
    });
  });
}

const restoreSchema = z.object({
  targetUserId: z.string().min(1),
  stepUpId: z.string().min(1),
  reason: z.string().min(5).max(500),
});

/** Lift a standing access restriction. Privileged in its own right (§14). */
export async function DELETE(request: NextRequest): Promise<NextResponse> {
  return safeHandler(async () => {
    const parsed = restoreSchema.safeParse(await request.json().catch(() => ({})));
    if (!parsed.success) return validationError(parsed.error);

    const target = await prisma.user.findUnique({ where: { id: parsed.data.targetUserId } });
    if (!target) return notFound();

    const guard = await requirePrivilegedAction({
      request,
      action: "RESTORE_EMPLOYEE_ACCESS",
      stepUpId: parsed.data.stepUpId,
      targetUserId: target.id,
    });
    if (!guard.ok) return guard.response;

    await prisma.user.update({
      where: { id: target.id },
      data: { accessRevoked: false, accessRevokedAt: null },
    });

    void auditConnect({
      eventType: "ADMIN_ACCESS_RESTORED",
      userId: target.id,
      ipAddress: guard.context.ip,
      userAgent: guard.context.ua,
      outcome: "SUCCESS",
      severity: "HIGH",
      metadata: {
        adminUserId: guard.context.adminUserId,
        targetUserEmail: target.email,
        justification: parsed.data.reason,
        stepUpId: guard.context.stepUpId,
      },
    });

    return NextResponse.json({ success: true, accessRevoked: false });
  });
}
