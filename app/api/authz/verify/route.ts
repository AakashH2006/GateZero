/**
 * app/api/authz/verify/route.ts
 * Live introspection endpoint called by Website 2 on EVERY request to verify token status.
 * Supports instant token revocation and client device fingerprint binding.
 *
 * POST /api/authz/verify
 * Body: { tokenId: string, userAgent?: string, ipAddress?: string }
 */

import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { introspectTokenLive } from "@/lib/authz-service";
import { getClientIP, getClientUA } from "@/lib/audit";
import { badRequest, validationError, safeHandler } from "@/lib/errors";

const verifySchema = z.object({
  tokenId: z.string().min(1),
  userAgent: z.string().optional(),
  ipAddress: z.string().optional(),
});

export async function POST(request: NextRequest): Promise<NextResponse> {
  return safeHandler(async () => {
    const body = await request.json().catch(() => null);
    if (!body) return badRequest("Request body required");

    const parsed = verifySchema.safeParse(body);
    if (!parsed.success) return validationError(parsed.error);

    const clientUA = request.headers.get("x-client-user-agent") || parsed.data.userAgent || getClientUA(request);
    const clientIP = request.headers.get("x-client-ip") || parsed.data.ipAddress || getClientIP(request);

    const result = await introspectTokenLive({
      tokenId: parsed.data.tokenId,
      userAgent: clientUA,
      ipAddress: clientIP,
    });

    if (!result.valid) {
      return NextResponse.json(
        { valid: false, reason: result.reason },
        { status: 401 }
      );
    }

    return NextResponse.json({
      valid: true,
      user: {
        id: result.userId,
        email: result.userEmail,
        name: result.userName,
        role: result.userRole,
      },
      sessionId: result.sessionId,
      expiresAt: result.expiresAt,
    });
  });
}
