/**
 * app/api/admin/audit-logs/route.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Audit log query and integrity check — website-1-defense.md §11, §20
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * GET /api/admin/audit-logs?stream=LOGIN|CONNECT&severity=HIGH&limit=50&offset=0
 * GET /api/admin/audit-logs?verify=1  — recompute the tamper-evident chain
 *
 * §11 requires the log to be protected against unauthorized modification.
 * Detection is only useful if someone can actually run it, so the chain
 * verification is exposed here rather than left as an internal function.
 * `brokenAtSeq` names the first entry that fails to verify — that entry, or one
 * before it, is where the record was altered.
 *
 * §20: `severity` filtering exists so triage can look at what matters without
 * paging through routine entries.
 *
 * LOG DATA CLASSIFICATION (W1 §23 open item, W2 §37)
 * ──────────────────────────────────────────────────
 * These entries contain PII — IP addresses, employee identity tied to risk
 * decisions. Retention period, access controls, and classification of the log
 * store itself are deployment decisions and remain open in both documents. The
 * access control implemented here is the minimum: administrators only.
 */

import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { requireAdmin } from "@/lib/admin";
import { verifyAuditChain } from "@/lib/audit";
import { forbidden, safeHandler } from "@/lib/errors";
import { AuditStream } from "@prisma/client";

export async function GET(request: NextRequest): Promise<NextResponse> {
  return safeHandler(async () => {
    const adminCheck = await requireAdmin(request);
    if (!adminCheck.authorized) return forbidden("Admin access required");

    const { searchParams } = new URL(request.url);

    // §11: verify that no entry has been altered or removed.
    if (searchParams.get("verify")) {
      const result = await verifyAuditChain();
      return NextResponse.json({
        chain: result,
        note: result.valid
          ? "Hash chain intact — no entry has been altered or removed."
          : `Chain verification failed at seq ${result.brokenAtSeq}. Entries from that point on cannot be trusted.`,
      });
    }

    const streamParam = searchParams.get("stream");
    const severity = searchParams.get("severity");
    const limit = Math.min(parseInt(searchParams.get("limit") ?? "50", 10), 200);
    const offset = parseInt(searchParams.get("offset") ?? "0", 10);
    const userId = searchParams.get("userId");

    const where = {
      ...(streamParam === "LOGIN" ? { stream: AuditStream.LOGIN } : {}),
      ...(streamParam === "CONNECT" ? { stream: AuditStream.CONNECT } : {}),
      ...(userId ? { userId } : {}),
      ...(severity ? { severity } : {}),
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
        severity: l.severity,
        seq: l.seq,
        metadata: JSON.parse(l.metadata),
        createdAt: l.createdAt,
      })),
      total,
      limit,
      offset,
    });
  });
}
