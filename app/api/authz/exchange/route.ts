/**
 * app/api/authz/exchange/route.ts
 * Back-channel exchange endpoint where Website 2 exchanges single-use code for Authorization Token.
 *
 * POST /api/authz/exchange
 * Body: { code: string, userAgent?: string, ipAddress?: string }
 */

import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { exchangeCodeForToken } from "@/lib/authz-service";
import { getClientIP, getClientUA } from "@/lib/audit";
import { badRequest, validationError, safeHandler } from "@/lib/errors";

const exchangeSchema = z.object({
  code: z.string().min(10),
  userAgent: z.string().optional(),
  ipAddress: z.string().optional(),
});

export async function POST(request: NextRequest): Promise<NextResponse> {
  return safeHandler(async () => {
    const body = await request.json().catch(() => null);
    if (!body) return badRequest("Request body required");

    const parsed = exchangeSchema.safeParse(body);
    if (!parsed.success) return validationError(parsed.error);

    const clientUA = request.headers.get("x-client-user-agent") || parsed.data.userAgent || getClientUA(request);
    const clientIP = request.headers.get("x-client-ip") || parsed.data.ipAddress || getClientIP(request);

    try {
      const result = await exchangeCodeForToken({
        code: parsed.data.code,
        ipAddress: clientIP,
        userAgent: clientUA,
      });

      return NextResponse.json({
        success: true,
        tokenId: result.tokenId,
        tokenJwt: result.tokenJwt,
        expiresAt: result.expiresAt,
        ttlSeconds: result.ttlSeconds,
        user: result.user,
      });
    } catch (err: any) {
      return NextResponse.json(
        { success: false, error: err.message || "Failed to exchange code" },
        { status: 400 }
      );
    }
  });
}
