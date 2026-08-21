/**
 * app/api/device/recovery/route.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Device recovery request — website-2-defense.md §8, website-1-defense.md §22.5
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * POST /api/device/recovery  — open a recovery request
 * GET  /api/device/recovery  — the employee's own request status
 *
 * This endpoint opens a *request*. It registers nothing, revokes nothing, and
 * grants nothing. §8 is explicit that automated recovery must not bypass device
 * binding, and that recovery is human-controlled — because possession of the
 * original credential is exactly what can no longer be proved.
 *
 * The administrator-side flow (identity verification, re-authentication,
 * revoking the old credential, terminating its sessions, approving the
 * replacement) lives in /api/admin/recovery.
 *
 * §22.5 requires three controls on this path, all present here: audit logging
 * of the event, employee notification independent of any admin alert, and abuse
 * controls so the flow cannot be used to grind toward registering a rogue
 * device.
 */

import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { getPendingOrActiveSession } from "@/lib/auth/session";
import { checkRateLimit } from "@/lib/rate-limit";
import { auditLogin, getClientIP, getClientUA } from "@/lib/audit";
import { notifyEmployee } from "@/lib/notify";
import { raiseSecurityAlert } from "@/lib/alerts";
import { prisma } from "@/lib/db";
import { AuditStream } from "@prisma/client";
import {
  unauthorized,
  badRequest,
  validationError,
  tooManyRequests,
  safeHandler,
} from "@/lib/errors";

const schema = z.object({
  reason: z.string().min(5).max(500),
});

/** Repeated recovery requests inside this window get extra scrutiny (§8). */
const SCRUTINY_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;
const SCRUTINY_THRESHOLD = 2;

export async function GET(): Promise<NextResponse> {
  return safeHandler(async () => {
    const session = await getPendingOrActiveSession();
    if (!session) return unauthorized("Valid session required");

    const requests = await prisma.deviceRecoveryRequest.findMany({
      where: { userId: session.userId },
      orderBy: { requestedAt: "desc" },
      take: 10,
      select: {
        id: true,
        status: true,
        requestedAt: true,
        approvedAt: true,
        completedAt: true,
      },
    });

    return NextResponse.json({ requests });
  });
}

export async function POST(request: NextRequest): Promise<NextResponse> {
  return safeHandler(async () => {
    const ip = getClientIP(request);
    const ua = getClientUA(request);

    const session = await getPendingOrActiveSession();
    if (!session) return unauthorized("Valid session required");

    // §8 "Recovery Request Protection": rate-limited and monitored. This does
    // not replace the human verification below it — it just keeps the queue
    // from being flooded.
    const rate = await checkRateLimit(`device-recovery:${session.userId}`, 3, 86400);
    if (!rate.allowed) {
      void auditLogin({
        eventType: "DEVICE_RECOVERY_RATE_LIMITED",
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

    const pending = await prisma.deviceRecoveryRequest.findFirst({
      where: { userId: session.userId, status: "PENDING" },
    });
    if (pending) {
      return badRequest(
        "A recovery request is already awaiting administrator review",
        "RECOVERY_ALREADY_PENDING"
      );
    }

    const created = await prisma.deviceRecoveryRequest.create({
      data: {
        userId: session.userId,
        reason: parsed.data.reason,
        ipAddress: ip,
        userAgent: ua,
      },
    });

    void auditLogin({
      eventType: "DEVICE_RECOVERY_REQUESTED",
      userId: session.userId,
      sessionId: session.id,
      ipAddress: ip,
      userAgent: ua,
      outcome: "SUCCESS",
      severity: "NOTICE",
      metadata: { requestId: created.id },
    });

    // §22.5: the employee hears about it independently of any admin-facing
    // alert, so a recovery opened by someone else does not go unnoticed.
    void notifyEmployee(session.user, "DEVICE_RECOVERY_REQUESTED");

    // §8: repeated requests in a short period are themselves a higher-risk
    // signal warranting additional administrator scrutiny.
    const recentCount = await prisma.deviceRecoveryRequest.count({
      where: {
        userId: session.userId,
        requestedAt: { gte: new Date(Date.now() - SCRUTINY_WINDOW_MS) },
      },
    });
    if (recentCount > SCRUTINY_THRESHOLD) {
      void raiseSecurityAlert({
        alertKey: "device_recovery:repeated",
        severity: "HIGH",
        userId: session.userId,
        sessionId: session.id,
        ipAddress: ip,
        userAgent: ua,
        stream: AuditStream.LOGIN,
        metadata: { requestCount: recentCount, windowDays: 7 },
      });
    }

    return NextResponse.json({
      success: true,
      requestId: created.id,
      status: "PENDING",
      message:
        "Recovery request submitted. An administrator must verify your identity before a replacement device can be registered.",
    });
  });
}
