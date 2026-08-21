/**
 * app/api/admin/oob-revoke/route.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Out-of-band Website 2 revocation — website-2-defense.md §26
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * POST /api/admin/oob-revoke
 * Body: { targetUserId, stepUpId, reason }
 *
 * The normal path for ending a Website 2 session is a critical security event
 * carried through the Gateway (§21). When the Gateway is unavailable, that path
 * does not exist — and §26 provides a separate, direct Admin → Website 2
 * channel so an administrator is not left unable to cut off a live session.
 *
 * THE CHANNEL IS REVOKE-ONLY
 * ──────────────────────────
 * §26 enumerates what it must not be able to do: create sessions, authorize
 * devices, bypass MFA, create emergency credentials, or modify Website 2
 * security controls. That is guaranteed on the receiving side — Website 2's
 * /api/oob/revoke handler performs exactly one operation and contains no code
 * for anything else. This endpoint is only the caller.
 *
 * It carries the same protection as the Gateway boundary (§26 "Out-of-Band
 * Channel Security"): service authentication on the call, administrator
 * authentication and a fresh action-specific step-up grant, and full auditing.
 *
 * The step-up grant is forwarded rather than spent here: Website 2 consumes it
 * itself, so Website 2 verifies the administrator's authorization directly
 * instead of trusting this endpoint's assurance that a check was done.
 */

import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { requireAdmin } from "@/lib/admin";
import { signServiceRequest } from "@/lib/service-auth";
import { auditConnect, getClientIP, getClientUA } from "@/lib/audit";
import { raiseSecurityAlert } from "@/lib/alerts";
import { prisma } from "@/lib/db";
import { resolveTargetApp } from "@/lib/config";
import { forbidden, badRequest, validationError, notFound, safeHandler } from "@/lib/errors";

const schema = z.object({
  targetUserId: z.string().min(1),
  stepUpId: z.string().min(1),
  reason: z.string().min(5).max(500),
});

export async function POST(request: NextRequest): Promise<NextResponse> {
  return safeHandler(async () => {
    const ip = getClientIP(request);
    const ua = getClientUA(request);

    const admin = await requireAdmin(request);
    if (!admin.authorized || !admin.adminUserId) {
      return forbidden("Admin access required");
    }

    const parsed = schema.safeParse(await request.json().catch(() => ({})));
    if (!parsed.success) return validationError(parsed.error);

    const target = await prisma.user.findUnique({ where: { id: parsed.data.targetUserId } });
    if (!target) return notFound();

    const deskUrl = resolveTargetApp("operations-desk");
    if (!deskUrl) return badRequest("Target application not configured", "UNKNOWN_TARGET_APP");

    const path = "/api/oob/revoke";
    const payload = JSON.stringify({
      targetUserId: target.id,
      adminUserId: admin.adminUserId,
      stepUpId: parsed.data.stepUpId,
      reason: parsed.data.reason,
    });

    let revokedSessions = 0;
    try {
      const res = await fetch(`${deskUrl}${path}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          // §26: the direct channel gets the same protection as the Gateway
          // boundary — authenticated service-to-service communication.
          ...signServiceRequest({ serviceId: "admin-oob", path, body: payload }),
        },
        body: payload,
      });

      const data = await res.json().catch(() => ({}));

      if (!res.ok) {
        void auditConnect({
          eventType: "OOB_REVOCATION_DENIED",
          userId: target.id,
          ipAddress: ip,
          userAgent: ua,
          outcome: "DENIED",
          severity: "HIGH",
          metadata: {
            adminUserId: admin.adminUserId,
            status: res.status,
            reason: data?.error ?? "UNKNOWN",
          },
        });
        return badRequest("Out-of-band revocation was refused", "OOB_REVOCATION_REFUSED");
      }

      revokedSessions = Number(data?.revokedSessions ?? 0);
    } catch (err) {
      void auditConnect({
        eventType: "OOB_REVOCATION_FAILED",
        userId: target.id,
        ipAddress: ip,
        userAgent: ua,
        outcome: "FAILURE",
        severity: "HIGH",
        metadata: {
          adminUserId: admin.adminUserId,
          error: err instanceof Error ? err.message : "unknown",
        },
      });
      return badRequest(
        "Website 2 could not be reached for out-of-band revocation",
        "OOB_TARGET_UNREACHABLE"
      );
    }

    // §26: "The revocation is logged as a high-priority security event."
    void auditConnect({
      eventType: "OOB_REVOCATION_COMPLETED",
      userId: target.id,
      ipAddress: ip,
      userAgent: ua,
      outcome: "SUCCESS",
      severity: "CRITICAL",
      metadata: {
        adminUserId: admin.adminUserId,
        adminEmail: admin.adminEmail,
        targetUserEmail: target.email,
        justification: parsed.data.reason,
        stepUpId: parsed.data.stepUpId,
        revokedSessions,
        channel: "OUT_OF_BAND",
      },
    });

    void raiseSecurityAlert({
      alertKey: `oob_revocation:${target.id}`,
      severity: "HIGH",
      userId: target.id,
      ipAddress: ip,
      userAgent: ua,
      metadata: { adminUserId: admin.adminUserId, justification: parsed.data.reason },
    });

    return NextResponse.json({ success: true, revokedSessions });
  });
}
