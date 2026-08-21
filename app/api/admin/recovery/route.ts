/**
 * app/api/admin/recovery/route.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Administrator device recovery — website-2-defense.md §8, website-1-defense.md §22.5
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * GET  /api/admin/recovery — pending recovery requests
 * POST /api/admin/recovery — record human verification and approve, or deny
 *
 * §8 spells out the sequence, and it is followed literally below:
 *   2. human verification is performed
 *   3. the administrator verifies the employee's identity
 *   4. the administrator reauthenticates
 *   5. the old device credential is revoked
 *   6. active Website 2 sessions on the old credential are terminated
 *   7. the administrator approves registration of the replacement device
 *
 * Step 7 approves *registration*, it does not register: the replacement key is
 * still generated on the employee's new device and enrolled through
 * /api/device. An administrator never handles a private key (§6).
 *
 * `verificationMethod` is required because §30-style accountability depends on
 * recording *how* identity was established, not merely that someone clicked
 * approve.
 */

import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { requireAdmin } from "@/lib/admin";
import { requirePrivilegedAction } from "@/lib/admin-action";
import { revokeDeviceCredential } from "@/lib/device";
import { enqueueSecurityEvent } from "@/lib/security-events";
import { auditLogin } from "@/lib/audit";
import { notifyEmployeeById } from "@/lib/notify";
import { prisma } from "@/lib/db";
import { forbidden, validationError, notFound, badRequest, safeHandler } from "@/lib/errors";

const decisionSchema = z.object({
  requestId: z.string().min(1),
  stepUpId: z.string().min(1),
  decision: z.enum(["APPROVE", "DENY"]),
  /** How the employee's identity was established out of band (§8 step 2-3). */
  verificationMethod: z.string().min(3).max(200),
});

export async function GET(request: NextRequest): Promise<NextResponse> {
  return safeHandler(async () => {
    const admin = await requireAdmin(request);
    if (!admin.authorized) return forbidden("Admin access required");

    const requests = await prisma.deviceRecoveryRequest.findMany({
      where: { status: "PENDING" },
      orderBy: { requestedAt: "asc" },
      include: { user: { select: { email: true, name: true } } },
    });

    return NextResponse.json({ requests });
  });
}

export async function POST(request: NextRequest): Promise<NextResponse> {
  return safeHandler(async () => {
    const parsed = decisionSchema.safeParse(await request.json().catch(() => ({})));
    if (!parsed.success) return validationError(parsed.error);

    const recovery = await prisma.deviceRecoveryRequest.findUnique({
      where: { id: parsed.data.requestId },
    });
    if (!recovery) return notFound();
    if (recovery.status !== "PENDING") {
      return badRequest("Recovery request is no longer pending", "RECOVERY_NOT_PENDING");
    }

    const guard = await requirePrivilegedAction({
      request,
      action: "APPROVE_RECOVERY",
      stepUpId: parsed.data.stepUpId,
      targetUserId: recovery.userId,
    });
    if (!guard.ok) return guard.response;

    const now = new Date();

    if (parsed.data.decision === "DENY") {
      await prisma.deviceRecoveryRequest.update({
        where: { id: recovery.id },
        data: {
          status: "DENIED",
          humanVerifiedByAdminId: guard.context.adminUserId,
          humanVerifiedAt: now,
          verificationMethod: parsed.data.verificationMethod,
        },
      });

      void auditLogin({
        eventType: "DEVICE_RECOVERY_DENIED",
        userId: recovery.userId,
        ipAddress: guard.context.ip,
        userAgent: guard.context.ua,
        outcome: "DENIED",
        severity: "HIGH",
        metadata: {
          requestId: recovery.id,
          adminUserId: guard.context.adminUserId,
          stepUpId: guard.context.stepUpId,
          verificationMethod: parsed.data.verificationMethod,
        },
      });

      return NextResponse.json({ success: true, status: "DENIED" });
    }

    // §8 step 5-6: the lost device's credential is revoked and its sessions end
    // BEFORE a replacement may be enrolled. Doing this in the other order would
    // leave a window where both the lost device and the new one are valid.
    const existing = await prisma.deviceCredential.findMany({
      where: { userId: recovery.userId, status: { in: ["ACTIVE", "PENDING_APPROVAL"] } },
      select: { id: true },
    });

    for (const credential of existing) {
      await revokeDeviceCredential({
        credentialId: credential.id,
        reason: "DEVICE_RECOVERY",
      });
    }

    if (existing.length > 0) {
      await enqueueSecurityEvent({
        type: "DEVICE_REVOKED",
        userId: recovery.userId,
        reason: "DEVICE_RECOVERY",
        deviceCredentialIds: existing.map((c) => c.id),
      });
    }

    await prisma.deviceRecoveryRequest.update({
      where: { id: recovery.id },
      data: {
        status: "APPROVED",
        humanVerifiedByAdminId: guard.context.adminUserId,
        humanVerifiedAt: now,
        verificationMethod: parsed.data.verificationMethod,
        approvedAt: now,
      },
    });

    void auditLogin({
      eventType: "DEVICE_RECOVERY_APPROVED",
      userId: recovery.userId,
      ipAddress: guard.context.ip,
      userAgent: guard.context.ua,
      outcome: "SUCCESS",
      severity: "HIGH",
      metadata: {
        requestId: recovery.id,
        adminUserId: guard.context.adminUserId,
        stepUpId: guard.context.stepUpId,
        verificationMethod: parsed.data.verificationMethod,
        revokedCredentialIds: existing.map((c) => c.id),
      },
    });

    void notifyEmployeeById(recovery.userId, "DEVICE_REVOKED");

    return NextResponse.json({
      success: true,
      status: "APPROVED",
      revokedCredentialIds: existing.map((c) => c.id),
      message:
        "Previous credentials revoked. The employee may now enrol a replacement device, which still requires administrator approval.",
    });
  });
}
