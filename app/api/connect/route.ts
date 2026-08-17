/**
 * app/api/connect/route.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Connect Endpoint — the core of the explicit access grant flow
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * POST /api/connect
 *
 * What it does:
 *   (a) Verifies the 7-day session is currently valid (ACTIVE, not expired/revoked)
 *   (b) Checks rate limiting (sliding window, per user+IP)
 *   (c) Calls the mock Authorization Service to issue a short-lived token
 *   (d) Logs the event to the CONNECT audit stream
 *   (e) Returns status and expiry to the frontend (NOT the token itself)
 *
 * The authorization token is NEVER sent to the browser.
 * The frontend receives only the tokenId (a DB record ID) and expiry time,
 * which it uses to check gateway access via /api/internal.
 */

import { NextRequest, NextResponse } from "next/server";
import { getValidSession } from "@/lib/auth/session";
import { issueAuthorization } from "@/lib/authz-service";
import { checkRateLimit, connectRateLimitKey } from "@/lib/rate-limit";
import { auditConnect, getClientIP, getClientUA } from "@/lib/audit";
import {
  unauthorized,
  tooManyRequests,
  serverError,
  safeHandler,
} from "@/lib/errors";

export async function POST(request: NextRequest): Promise<NextResponse> {
  return safeHandler(async () => {
    const ip = getClientIP(request);
    const ua = getClientUA(request);

    // (a) Verify session
    const session = await getValidSession();
    if (!session) {
      void auditConnect({
        eventType: "CONNECT_DENIED_NO_SESSION",
        ipAddress: ip,
        userAgent: ua,
        outcome: "DENIED",
        metadata: {},
      });
      return unauthorized("Valid session required to connect");
    }

    // (b) Rate limiting — per user + per IP (sliding window)
    const rateLimitKey = connectRateLimitKey(session.userId, ip);
    const rateCheck = await checkRateLimit(rateLimitKey);

    if (!rateCheck.allowed) {
      void auditConnect({
        eventType: "CONNECT_RATE_LIMITED",
        userId: session.userId,
        sessionId: session.id,
        ipAddress: ip,
        userAgent: ua,
        outcome: "DENIED",
        metadata: { resetAt: rateCheck.resetAt },
      });
      return tooManyRequests(rateCheck.resetAt);
    }

    // (c) Call Authorization Service
    let authResult: Awaited<ReturnType<typeof issueAuthorization>>;
    try {
      authResult = await issueAuthorization({
        sessionId: session.id,
        userId: session.userId,
        ipAddress: ip,
        userAgent: ua,
      });
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : String(err);

      void auditConnect({
        eventType: "CONNECT_AUTHZ_DENIED",
        userId: session.userId,
        sessionId: session.id,
        ipAddress: ip,
        userAgent: ua,
        outcome: "DENIED",
        metadata: { reason: errMsg },
      });

      if (errMsg === "SESSION_INVALID") {
        return unauthorized("Session is no longer valid");
      }
      return serverError("Authorization service error", err);
    }

    // (d) Audit log — success
    void auditConnect({
      eventType: "CONNECT_GRANTED",
      userId: session.userId,
      sessionId: session.id,
      authzId: authResult.tokenId,
      ipAddress: ip,
      userAgent: ua,
      outcome: "SUCCESS",
      metadata: {
        expiresAt: authResult.expiresAt,
        ttlSeconds: authResult.ttlSeconds,
      },
    });

    // (e) Return status to frontend — NOT the token itself
    return NextResponse.json({
      granted: true,
      tokenId: authResult.tokenId,         // opaque ID for gateway lookup
      expiresAt: authResult.expiresAt,
      ttlSeconds: authResult.ttlSeconds,
      rateLimitRemaining: rateCheck.remaining,
    });
  });
}
