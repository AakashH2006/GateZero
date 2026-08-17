/**
 * app/api/admin/sessions/route.ts
 * Admin-only: View and manage active sessions.
 *
 * GET /api/admin/sessions — list all active sessions
 * DELETE /api/admin/sessions — revoke a session by ID
 */

import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { prisma } from "@/lib/db";
import { revokeSession } from "@/lib/auth/session";
import { requireAdmin } from "@/lib/admin";
import { auditLogin, getClientIP, getClientUA } from "@/lib/audit";
import { forbidden, validationError, notFound, safeHandler } from "@/lib/errors";
import { SessionStatus } from "@prisma/client";

export async function GET(request: NextRequest): Promise<NextResponse> {
  return safeHandler(async () => {
    const adminCheck = await requireAdmin(request);
    if (!adminCheck.authorized) return forbidden("Admin access required");

    const sessions = await prisma.session.findMany({
      where: {
        status: { in: [SessionStatus.ACTIVE, SessionStatus.PENDING_MFA] },
        expiresAt: { gt: new Date() },
      },
      include: {
        user: { select: { email: true, name: true, role: true } },
        authorizationTokens: {
          where: { status: "ACTIVE", expiresAt: { gt: new Date() } },
          select: { id: true, expiresAt: true, issuedAt: true },
        },
      },
      orderBy: { createdAt: "desc" },
    });

    return NextResponse.json({
      sessions: sessions.map((s) => ({
        id: s.id,
        status: s.status,
        user: s.user,
        ipAddress: s.ipAddress,
        createdAt: s.createdAt,
        expiresAt: s.expiresAt,
        activeAuthorizations: s.authorizationTokens.length,
      })),
    });
  });
}

const revokeSchema = z.object({ sessionId: z.string().min(1) });

export async function DELETE(request: NextRequest): Promise<NextResponse> {
  return safeHandler(async () => {
    const ip = getClientIP(request);
    const ua = getClientUA(request);

    const adminCheck = await requireAdmin(request);
    if (!adminCheck.authorized) return forbidden("Admin access required");

    const body = await request.json();
    const parsed = revokeSchema.safeParse(body);
    if (!parsed.success) return validationError(parsed.error);

    const { sessionId } = parsed.data;

    const session = await prisma.session.findUnique({ where: { id: sessionId } });
    if (!session) return notFound();

    await revokeSession(sessionId);

    // Also revoke all active authorizations for this session
    await prisma.authorizationToken.updateMany({
      where: { sessionId, status: "ACTIVE" },
      data: { status: "REVOKED", revokedAt: new Date() },
    });

    void auditLogin({
      eventType: "SESSION_REVOKED_BY_ADMIN",
      userId: session.userId,
      sessionId,
      ipAddress: ip,
      userAgent: ua,
      outcome: "SUCCESS",
      metadata: {},
    });

    return NextResponse.json({ success: true, message: `Session ${sessionId} revoked` });
  });
}
