/**
 * app/api/admin/audit-logs/route.ts
 * Admin-only: Query the two audit log streams.
 *
 * GET /api/admin/audit-logs?stream=LOGIN|CONNECT&limit=50&offset=0
 */

import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { requireAdmin } from "@/lib/admin";
import { forbidden, safeHandler } from "@/lib/errors";
import { AuditStream } from "@prisma/client";

export async function GET(request: NextRequest): Promise<NextResponse> {
  return safeHandler(async () => {
    const adminCheck = await requireAdmin(request);
    if (!adminCheck.authorized) return forbidden("Admin access required");

    const { searchParams } = new URL(request.url);
    const streamParam = searchParams.get("stream");
    const limit = Math.min(parseInt(searchParams.get("limit") ?? "50", 10), 200);
    const offset = parseInt(searchParams.get("offset") ?? "0", 10);
    const userId = searchParams.get("userId");

    const where = {
      ...(streamParam === "LOGIN" ? { stream: AuditStream.LOGIN } : {}),
      ...(streamParam === "CONNECT" ? { stream: AuditStream.CONNECT } : {}),
      ...(userId ? { userId } : {}),
    };

    const [logs, total] = await Promise.all([
      prisma.auditLog.findMany({
        where,
        include: { user: { select: { email: true, name: true } } },
        orderBy: { createdAt: "desc" },
        take: limit,
        skip: offset,
      }),
      prisma.auditLog.count({ where }),
    ]);

    return NextResponse.json({
      logs: logs.map((l) => ({
        id: l.id,
        stream: l.stream,
        eventType: l.eventType,
        user: l.user,
        sessionId: l.sessionId,
        authzId: l.authzId,
        ipAddress: l.ipAddress,
        outcome: l.outcome,
        metadata: JSON.parse(l.metadata),
        createdAt: l.createdAt,
      })),
      total,
      limit,
      offset,
    });
  });
}
