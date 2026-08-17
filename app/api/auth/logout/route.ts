/**
 * app/api/auth/logout/route.ts
 * Destroys the current session server-side and clears the session cookie.
 */

import { NextRequest, NextResponse } from "next/server";
import { getValidSession, getPendingOrActiveSession, destroySession } from "@/lib/auth/session";
import { auditLogin, getClientIP, getClientUA } from "@/lib/audit";
import { APP_URL } from "@/lib/config";
import { safeHandler } from "@/lib/errors";

export async function POST(request: NextRequest): Promise<NextResponse> {
  return safeHandler(async () => {
    const ip = getClientIP(request);
    const ua = getClientUA(request);

    // Get any session (pending or active) for audit log
    const session = await getPendingOrActiveSession();

    await destroySession();

    if (session) {
      void auditLogin({
        eventType: "LOGOUT",
        userId: session.userId,
        sessionId: session.id,
        ipAddress: ip,
        userAgent: ua,
        outcome: "SUCCESS",
        metadata: {},
      });
    }

    return NextResponse.json({ success: true, redirect: "/" });
  });
}

// Also support GET for simple logout links
export async function GET(request: NextRequest): Promise<NextResponse> {
  return safeHandler(async () => {
    const ip = getClientIP(request);
    const ua = getClientUA(request);
    const session = await getPendingOrActiveSession();

    await destroySession();

    if (session) {
      void auditLogin({
        eventType: "LOGOUT",
        userId: session.userId,
        sessionId: session.id,
        ipAddress: ip,
        userAgent: ua,
        outcome: "SUCCESS",
        metadata: {},
      });
    }

    return NextResponse.redirect(`${APP_URL}/`);
  });
}
