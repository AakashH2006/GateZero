/**
 * app/api/admin/devices/route.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Administrator device control — website-2-defense.md §6, §7, §9
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * GET    /api/admin/devices           — pending and active credentials
 * POST   /api/admin/devices           — approve a registration (§6, §7)
 * DELETE /api/admin/devices           — revoke a credential (§9)
 *
 * Both mutating operations require a fresh, action-specific administrator
 * step-up grant (§14) — see lib/admin-action.
 *
 * Approval is the moment "one employee → one authorized device" (§5) is
 * enforced: activating a new credential retires any previous one, and the
 * sessions bound to the retired credential are terminated through the critical
 * event channel (§7 step 7, §9).
 */

import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { requireAdmin } from "@/lib/admin";
import { requirePrivilegedAction } from "@/lib/admin-action";
import { approveDeviceCredential, revokeDeviceCredential } from "@/lib/device";
import { enqueueSecurityEvent } from "@/lib/security-events";
import { auditLogin } from "@/lib/audit";
import { notifyEmployeeById } from "@/lib/notify";
import { prisma } from "@/lib/db";
import { forbidden, badRequest, validationError, notFound, safeHandler } from "@/lib/errors";

const approveSchema = z.object({
  credentialId: z.string().min(1),
  stepUpId: z.string().min(1),
});

const revokeSchema = z.object({
  credentialId: z.string().min(1),
  stepUpId: z.string().min(1),
  reason: z.string().min(3).max(200),
});

export async function GET(request: NextRequest): Promise<NextResponse> {
  return safeHandler(async () => {
    const admin = await requireAdmin(request);
    if (!admin.authorized) return forbidden("Admin access required");

    const credentials = await prisma.deviceCredential.findMany({
      where: { status: { in: ["PENDING_APPROVAL", "ACTIVE"] } },
      orderBy: [{ status: "asc" }, { createdAt: "desc" }],
      include: { user: { select: { email: true, name: true } } },
    });

    return NextResponse.json({
      devices: credentials.map((c) => ({
        id: c.id,
        userId: c.userId,
        user: c.user,
        label: c.label,
        status: c.status,
        assurance: c.assurance,
        hardwareBacked: c.hardwareBacked,
        rotationDueAt: c.rotationDueAt,
        graceExpiresAt: c.graceExpiresAt,
        approvedAt: c.approvedAt,
        createdAt: c.createdAt,
      })),
    });
  });
}

export async function POST(request: NextRequest): Promise<NextResponse> {
  return safeHandler(async () => {
    const parsed = approveSchema.safeParse(await request.json().catch(() => ({})));
    if (!parsed.success) return validationError(parsed.error);

    const credential = await prisma.deviceCredential.findUnique({
      where: { id: parsed.data.credentialId },
    });
    if (!credential) return notFound();

    const guard = await requirePrivilegedAction({
      request,
      action: "APPROVE_DEVICE",
      stepUpId: parsed.data.stepUpId,
      targetUserId: credential.userId,
    });
    if (!guard.ok) return guard.response;

    const result = await approveDeviceCredential({
      credentialId: credential.id,
      adminUserId: guard.context.adminUserId,
    });

    if (!result.ok) {
      return badRequest(result.reason ?? "Approval failed", "DEVICE_APPROVAL_FAILED");
    }

    void auditLogin({
      eventType: "DEVICE_APPROVED_BY_ADMIN",
      userId: credential.userId,
      ipAddress: guard.context.ip,
      userAgent: guard.context.ua,
      outcome: "SUCCESS",
      severity: "HIGH",
      metadata: {
        credentialId: credential.id,
        adminUserId: guard.context.adminUserId,
        stepUpId: guard.context.stepUpId,
        supersededCredentialIds: result.supersededIds,
      },
    });

    // §7 step 7 / §9: sessions bound to the credential this one replaced must
    // not survive the replacement.
    if (result.supersededIds.length > 0) {
      await enqueueSecurityEvent({
        type: "DEVICE_REVOKED",
        userId: credential.userId,
        reason: "SUPERSEDED_BY_NEW_DEVICE",
        deviceCredentialIds: result.supersededIds,
      });
    }

    void notifyEmployeeById(credential.userId, "DEVICE_REGISTERED");

    return NextResponse.json({
      success: true,
      credentialId: credential.id,
      supersededCredentialIds: result.supersededIds,
    });
  });
}

export async function DELETE(request: NextRequest): Promise<NextResponse> {
  return safeHandler(async () => {
    const parsed = revokeSchema.safeParse(await request.json().catch(() => ({})));
    if (!parsed.success) return validationError(parsed.error);

    const credential = await prisma.deviceCredential.findUnique({
      where: { id: parsed.data.credentialId },
    });
    if (!credential) return notFound();

    const guard = await requirePrivilegedAction({
      request,
      action: "REVOKE_DEVICE",
      stepUpId: parsed.data.stepUpId,
      targetUserId: credential.userId,
    });
    if (!guard.ok) return guard.response;

    await revokeDeviceCredential({
      credentialId: credential.id,
      reason: parsed.data.reason,
    });

    void auditLogin({
      eventType: "DEVICE_REVOKED_BY_ADMIN",
      userId: credential.userId,
      ipAddress: guard.context.ip,
      userAgent: guard.context.ua,
      outcome: "SUCCESS",
      severity: "HIGH",
      metadata: {
        credentialId: credential.id,
        adminUserId: guard.context.adminUserId,
        stepUpId: guard.context.stepUpId,
        justification: parsed.data.reason,
      },
    });

    // §9: "When a credential is revoked, associated active Website 2 sessions
    // are terminated."
    await enqueueSecurityEvent({
      type: "DEVICE_REVOKED",
      userId: credential.userId,
      reason: parsed.data.reason,
      deviceCredentialIds: [credential.id],
    });

    void notifyEmployeeById(credential.userId, "DEVICE_REVOKED");

    return NextResponse.json({ success: true, credentialId: credential.id });
  });
}
