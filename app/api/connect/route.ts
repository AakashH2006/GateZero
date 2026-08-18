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
import { getValidSession, flagStepUpRequired, revokeSession, getIronSessionStore } from "@/lib/auth/session";
import { issueAuthorization, getActiveAuthorization, revokeAuthorization } from "@/lib/authz-service";
import { checkRateLimit, connectRateLimitKey } from "@/lib/rate-limit";
import { CSRF_HEADER, verifyCsrfToken } from "@/lib/auth/csrf";
import { auditConnect, getClientIP, getClientUA } from "@/lib/audit";
import { assessConnectRisk } from "@/lib/mini-edr";
import {
  unauthorized,
  forbidden,
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

    // (a.5) CSRF check — Connect is a security-sensitive, state-changing action.
    // Reject before touching rate limiting or the Authorization Service so a
    // forged cross-site request never even consumes a rate-limit slot.
    const csrfToken = request.headers.get(CSRF_HEADER);
    if (!verifyCsrfToken(session.id, csrfToken)) {
      void auditConnect({
        eventType: "CONNECT_DENIED_CSRF",
        userId: session.userId,
        sessionId: session.id,
        ipAddress: ip,
        userAgent: ua,
        outcome: "DENIED",
        metadata: {},
      });
      return forbidden("Missing or invalid CSRF token");
    }

    // (a.6) Mini EDR step-up gate — a prior MEDIUM-risk assessment blocked
    // Connect until fresh MFA is completed via /api/auth/step-up. The
    // session itself stays ACTIVE (not revoked); this only gates Connect.
    // Checked before rate limiting so a gated user doesn't burn rate-limit
    // slots retrying Connect instead of completing step-up.
    if (session.connectStepUpRequired) {
      void auditConnect({
        eventType: "CONNECT_DENIED_STEP_UP_REQUIRED",
        userId: session.userId,
        sessionId: session.id,
        ipAddress: ip,
        userAgent: ua,
        outcome: "DENIED",
        metadata: {},
      });
      return forbidden(
        "Fresh MFA verification required before connecting",
        "STEP_UP_MFA_REQUIRED"
      );
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

    // (b.5) Mini EDR — risk assessment (§6-7)
    const assessment = await assessConnectRisk(session, ip, ua);

    if (assessment.level === "MEDIUM") {
      // Block Connect and require fresh MFA. The 7-day W1 session is left
      // untouched — only the Connect endpoint is gated.
      await flagStepUpRequired(session.id);
      void auditConnect({
        eventType: "CONNECT_BLOCKED_MEDIUM_RISK",
        userId: session.userId,
        sessionId: session.id,
        ipAddress: ip,
        userAgent: ua,
        outcome: "DENIED",
        metadata: { score: assessment.score, factors: assessment.factors },
      });
      return forbidden(
        "Fresh MFA verification required before connecting",
        "STEP_UP_MFA_REQUIRED"
      );
    }

    if (assessment.level === "HIGH" || assessment.level === "CRITICAL") {
      // HIGH/CRITICAL terminate the W1 session outright (approved to revoke,
      // unlike MEDIUM) and, for CRITICAL, also revoke any active
      // authorization token so Website 2 access is cut immediately.
      await revokeSession(session.id);

      if (assessment.level === "CRITICAL") {
        const activeToken = await getActiveAuthorization(session.id);
        if (activeToken) {
          await revokeAuthorization(activeToken.tokenId);
        }
      }

      const ironSession = await getIronSessionStore();
      ironSession.destroy();
      await ironSession.save();

      void auditConnect({
        eventType:
          assessment.level === "CRITICAL"
            ? "CONNECT_BLOCKED_CRITICAL_RISK"
            : "CONNECT_BLOCKED_HIGH_RISK",
        userId: session.userId,
        sessionId: session.id,
        ipAddress: ip,
        userAgent: ua,
        outcome: "DENIED",
        metadata: { score: assessment.score, factors: assessment.factors },
      });

      // Security alert — implemented as a distinguishable, severity-tagged
      // audit entry for now. Real external dispatch (email/Slack/pager) is
      // a named stub, not built in this pass.
      void auditConnect({
        eventType: "SECURITY_ALERT",
        userId: session.userId,
        sessionId: session.id,
        ipAddress: ip,
        userAgent: ua,
        outcome: "DENIED",
        metadata: { severity: assessment.level, score: assessment.score, factors: assessment.factors },
      });

      return unauthorized(
        "Session terminated due to elevated risk — please sign in again",
        "SESSION_TERMINATED_RISK"
      );
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
