/**
 * app/api/authz/revoke/route.ts
 * Admin-only: Revoke an authorization token immediately.
 *
 * POST /api/authz/revoke
 * Body: { tokenId: string }
 * Header: X-Admin-Secret (dev mode) or admin session role (production)
 *
 * After revocation, the mock gateway will return 404 on the next request.
 */

import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { revokeAuthorization } from "@/lib/authz-service";
import { requireAdmin } from "@/lib/admin";
import { auditConnect, getClientIP, getClientUA } from "@/lib/audit";
import {
  forbidden,
  badRequest,
  validationError,
  notFound,
  safeHandler,
} from "@/lib/errors";
import { prisma } from "@/lib/db";

const revokeSchema = z.object({
  tokenId: z.string().min(1),
});

export async function POST(request: NextRequest): Promise<NextResponse> {
  return safeHandler(async () => {
    const ip = getClientIP(request);
    const ua = getClientUA(request);

    const adminCheck = await requireAdmin(request);
    if (!adminCheck.authorized) {
      return forbidden("Admin access required");
    }

    const body = await request.json();
    const parsed = revokeSchema.safeParse(body);
    if (!parsed.success) return validationError(parsed.error);

    const { tokenId } = parsed.data;

    // Check the token exists
    const token = await prisma.authorizationToken.findUnique({
      where: { id: tokenId },
    });
    if (!token) return notFound();

    await revokeAuthorization(tokenId);

    void auditConnect({
      eventType: "AUTHZ_REVOKED_BY_ADMIN",
      userId: token.userId,
      sessionId: token.sessionId,
      authzId: tokenId,
      ipAddress: ip,
      userAgent: ua,
      outcome: "SUCCESS",
      metadata: { revokedBy: "admin" },
    });

    return NextResponse.json({
      success: true,
      message: `Authorization ${tokenId} revoked. Gateway will deny the next request.`,
    });
  });
}
