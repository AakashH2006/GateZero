/**
 * app/api/admin/emergency/route.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Emergency administrative access
 * website-1-defense.md §16, §17 / website-2-defense.md §27-§31
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * GET  /api/admin/emergency  — current trusted health state and eligibility
 * POST /api/admin/emergency  — { intent: "CONFIRM_OUTAGE" | "CONNECT", … }
 *
 * This is the break-glass path, and it is the most dangerous mechanism in the
 * system: it issues Gateway authorization while the normal checkpoint is
 * unavailable. Four independent gates stand in front of it.
 *
 *   1. TRUSTED OUTAGE (§16, §27). The health state is written only by the
 *      out-of-process monitor. Website 1 cannot declare itself unavailable, and
 *      neither can this endpoint — it only ever *reads* health.
 *
 *   2. HUMAN CONFIRMATION (§27, and W1 §23's open item on attacker-induced
 *      outages). Automated detection makes the path available; an administrator
 *      must explicitly confirm the outage, and that confirmation expires. An
 *      attacker who can sustain a denial-of-service still cannot self-serve.
 *
 *   3. FRESH RE-AUTHENTICATION PER STEP (§28: "The administrator must
 *      reauthenticate before every security-sensitive step"). Confirming the
 *      outage and issuing the grant are separate privileged actions, each
 *      spending its own step-up.
 *
 *   4. IDENTIFIED EMPLOYEE + DEVICE (§16, §29, §31). The resulting grant is
 *      employee-specific, device-bound, one-time and 5 minutes. There is no
 *      generic emergency credential and no reusable emergency token.
 *
 * The administrator cannot extend the window (§17). A further grant needs
 * another explicit action and another re-authentication. When Website 1 becomes
 * healthy the monitor clears the state and this path closes on its own.
 */

import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { requireAdmin } from "@/lib/admin";
import { requirePrivilegedAction } from "@/lib/admin-action";
import {
  checkEmergencyEligibility,
  recordHumanConfirmation,
  getAllHealth,
  type ComponentName,
} from "@/lib/health";
import { issueAuthorization } from "@/lib/authz-service";
import { getActiveCredential } from "@/lib/device";
import { auditConnect, auditLogin } from "@/lib/audit";
import { raiseSecurityAlert } from "@/lib/alerts";
import { notifyEmployee } from "@/lib/notify";
import { prisma } from "@/lib/db";
import { AUTHZ_TTL_SECONDS } from "@/lib/config";
import { AuditStream, SessionStatus } from "@prisma/client";
import { forbidden, badRequest, validationError, notFound, safeHandler } from "@/lib/errors";

const confirmSchema = z.object({
  intent: z.literal("CONFIRM_OUTAGE"),
  component: z.enum(["website-1", "gateway"]),
  stepUpId: z.string().min(1),
});

const connectSchema = z.object({
  intent: z.literal("CONNECT"),
  targetUserId: z.string().min(1),
  stepUpId: z.string().min(1),
  reason: z.string().min(5).max(500),
});

export async function GET(request: NextRequest): Promise<NextResponse> {
  return safeHandler(async () => {
    const admin = await requireAdmin(request);
    if (!admin.authorized) return forbidden("Admin access required");

    const [health, eligibility] = await Promise.all([
      getAllHealth(),
      checkEmergencyEligibility("website-1"),
    ]);

    return NextResponse.json({
      health,
      eligibility,
      // Stated explicitly so the admin UI never implies a bypass button exists
      // while things are healthy (§16).
      note:
        "Emergency access is available only while an independently detected outage is confirmed by an administrator.",
    });
  });
}

export async function POST(request: NextRequest): Promise<NextResponse> {
  return safeHandler(async () => {
    const body = await request.json().catch(() => ({}));

    // ── Step 1: explicit human confirmation of a detected outage (§27) ──────
    if (body?.intent === "CONFIRM_OUTAGE") {
      const parsed = confirmSchema.safeParse(body);
      if (!parsed.success) return validationError(parsed.error);

      const guard = await requirePrivilegedAction({
        request,
        action: "EMERGENCY_CONFIRM_OUTAGE",
        stepUpId: parsed.data.stepUpId,
      });
      if (!guard.ok) return guard.response;

      const result = await recordHumanConfirmation({
        component: parsed.data.component as ComponentName,
        adminUserId: guard.context.adminUserId,
      });

      // The administrator confirms an outage the monitor already detected.
      // They cannot declare one that was never observed.
      if (!result.ok) {
        void auditLogin({
          eventType: "EMERGENCY_CONFIRM_REFUSED",
          userId: guard.context.adminUserId,
          ipAddress: guard.context.ip,
          userAgent: guard.context.ua,
          outcome: "DENIED",
          severity: "HIGH",
          metadata: { component: parsed.data.component, reason: result.reason },
        });
        return badRequest(
          "No independently confirmed outage to confirm",
          "NO_CONFIRMED_OUTAGE"
        );
      }

      void auditLogin({
        eventType: "EMERGENCY_OUTAGE_CONFIRMED_BY_ADMIN",
        userId: guard.context.adminUserId,
        ipAddress: guard.context.ip,
        userAgent: guard.context.ua,
        outcome: "SUCCESS",
        severity: "CRITICAL",
        metadata: {
          component: parsed.data.component,
          adminUserId: guard.context.adminUserId,
          stepUpId: guard.context.stepUpId,
          confirmationExpiresAt: result.expiresAt,
        },
      });

      return NextResponse.json({
        success: true,
        component: parsed.data.component,
        confirmationExpiresAt: result.expiresAt,
        message: "Outage confirmed. Emergency Connect now requires a further re-authentication.",
      });
    }

    // ── Step 2: issue an emergency authorization (§16, §28-§31) ────────────
    const parsed = connectSchema.safeParse(body);
    if (!parsed.success) return validationError(parsed.error);

    const target = await prisma.user.findUnique({ where: { id: parsed.data.targetUserId } });
    if (!target) return notFound();

    const guard = await requirePrivilegedAction({
      request,
      action: "EMERGENCY_CONNECT",
      stepUpId: parsed.data.stepUpId,
      targetUserId: target.id,
    });
    if (!guard.ok) return guard.response;

    // Gates 1 and 2, re-checked at the moment of issue rather than trusted from
    // the earlier step: the outage may have cleared or the confirmation expired
    // between confirming and connecting.
    const eligibility = await checkEmergencyEligibility("website-1");
    if (!eligibility.eligible) {
      void auditConnect({
        eventType: "EMERGENCY_CONNECT_REFUSED",
        userId: target.id,
        ipAddress: guard.context.ip,
        userAgent: guard.context.ua,
        outcome: "DENIED",
        severity: "HIGH",
        metadata: {
          adminUserId: guard.context.adminUserId,
          reason: eligibility.reason,
          healthState: eligibility.state,
        },
      });
      return forbidden(
        "Emergency access is not available — no confirmed outage",
        "EMERGENCY_UNAVAILABLE"
      );
    }

    if (target.accessRevoked) {
      return forbidden("Employee access has been revoked", "ACCESS_REVOKED");
    }

    // §16, §29: device-bound like any other authorization. Emergency access is
    // not a way around device binding — §29 forbids exactly that.
    const credential = await getActiveCredential(target.id);
    if (!credential) {
      void auditConnect({
        eventType: "EMERGENCY_CONNECT_REFUSED",
        userId: target.id,
        ipAddress: guard.context.ip,
        userAgent: guard.context.ua,
        outcome: "DENIED",
        severity: "HIGH",
        metadata: { adminUserId: guard.context.adminUserId, reason: "NO_ACTIVE_DEVICE_CREDENTIAL" },
      });
      return badRequest(
        "The employee has no active device credential to bind an emergency authorization to",
        "NO_ACTIVE_DEVICE_CREDENTIAL"
      );
    }

    // The grant is anchored to the employee's most recent session record for
    // audit continuity. It does not require that session to be live — an
    // outage is precisely when it would not be.
    const anchorSession = await prisma.session.findFirst({
      where: { userId: target.id },
      orderBy: { createdAt: "desc" },
    });
    if (!anchorSession) {
      return badRequest("No session history for this employee", "NO_SESSION_ANCHOR");
    }

    const authorization = await issueAuthorization({
      sessionId: anchorSession.id,
      userId: target.id,
      ipAddress: guard.context.ip,
      userAgent: guard.context.ua,
      deviceCredentialId: credential.id,
      targetApp: "operations-desk",
      emergency: true,
      issuedByAdminId: guard.context.adminUserId,
    });

    // §30: high-priority audit event recording every listed field.
    void auditConnect({
      eventType: "EMERGENCY_CONNECT_GRANTED",
      userId: target.id,
      sessionId: anchorSession.id,
      authzId: authorization.tokenId,
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
        outageEvidence: {
          state: eligibility.state,
          humanConfirmed: eligibility.humanConfirmed,
        },
        deviceCredentialId: credential.id,
        expiresAt: authorization.expiresAt,
        ttlSeconds: AUTHZ_TTL_SECONDS,
        // §17: no extension is possible; another grant needs another re-auth.
        extendable: false,
      },
    });

    void raiseSecurityAlert({
      alertKey: `emergency_connect:${target.id}`,
      severity: "CRITICAL",
      userId: target.id,
      sessionId: anchorSession.id,
      ipAddress: guard.context.ip,
      userAgent: guard.context.ua,
      stream: AuditStream.CONNECT,
      metadata: {
        adminUserId: guard.context.adminUserId,
        justification: parsed.data.reason,
      },
    });

    // §30: the employee is notified when emergency access is established for
    // their account.
    void notifyEmployee(target, "W2_EMERGENCY_ACCESS");

    // Sanity: the anchor session's state is reported so the operator can see
    // whether they just issued a grant against a revoked session.
    const anchorState =
      anchorSession.status === SessionStatus.ACTIVE ? "ACTIVE" : anchorSession.status;

    return NextResponse.json({
      success: true,
      tokenId: authorization.tokenId,
      expiresAt: authorization.expiresAt,
      ttlSeconds: authorization.ttlSeconds,
      deviceCredentialId: credential.id,
      anchorSessionState: anchorState,
      message:
        "Emergency authorization issued: employee-specific, device-bound, one-time, 5 minutes, not extendable.",
    });
  });
}
