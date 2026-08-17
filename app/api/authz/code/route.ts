/**
 * app/api/authz/code/route.ts
 * Generates a single-use exchange code (60s TTL) for an active session to launch protected apps.
 *
 * POST /api/authz/code
 * Returns: { success: true, code: "...", targetUrl: "http://localhost:3002/api/auth/callback?code=..." }
 */

import { NextRequest, NextResponse } from "next/server";
import { getPendingOrActiveSession } from "@/lib/auth/session";
import { issueExchangeCode } from "@/lib/authz-service";
import { getClientIP, getClientUA } from "@/lib/audit";
import { unauthorized, safeHandler } from "@/lib/errors";
import { SessionStatus } from "@prisma/client";

export async function POST(request: NextRequest): Promise<NextResponse> {
  return safeHandler(async () => {
    const session = await getPendingOrActiveSession();
    if (!session || session.status !== SessionStatus.ACTIVE) {
      return unauthorized("Active authenticated session required to generate launch code");
    }

    const ip = getClientIP(request);
    const ua = getClientUA(request);

    const body = await request.json().catch(() => ({}));
    const targetApp = body.targetApp || "operations-desk";

    const code = await issueExchangeCode({
      sessionId: session.id,
      userId: session.userId,
      ipAddress: ip,
      userAgent: ua,
      targetApp,
    });

    const targetUrl = `http://localhost:3002/api/auth/callback?code=${code}`;

    return NextResponse.json({
      success: true,
      code,
      targetUrl,
    });
  });
}
