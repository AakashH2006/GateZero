/**
 * app/api/authz/redeem/route.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * One-time authorization redemption
 * website-1-defense.md §8 / website-2-defense.md §3, §15, §24
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * POST /api/authz/redeem
 * Body: { tokenId, deviceCredentialId }
 *
 * Called by Website 2 at the exact moment it establishes a session, AFTER it
 * has independently verified the device's private-key proof (§8.1). This is
 * the step that makes the authorization one-time:
 *
 *     first successful use  → CONSUMED
 *     second use            → REJECTED   (§24)
 *
 * Consumption is a conditional update inside the Authorization Service, so two
 * devices redeeming the same grant concurrently produce exactly one winner.
 *
 * Redemption happens here rather than at exchange time so a handshake that
 * fails Website 2's own device check does not burn the employee's grant. The
 * authorization is spent only when it has actually produced a session.
 *
 * §24: a replay attempt is logged as a security event; the caller still gets
 * only the generic denial (§15).
 */

import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { redeemGatewayAuthorization, publicDenial } from "@/lib/gateway";
import { verifyServiceRequest } from "@/lib/service-auth";
import { auditConnect, getClientIP, getClientUA } from "@/lib/audit";
import { raiseSecurityAlert } from "@/lib/alerts";
import { forbidden, badRequest, validationError, safeHandler } from "@/lib/errors";

const schema = z.object({
  tokenId: z.string().min(1),
  deviceCredentialId: z.string().min(1),
  ipAddress: z.string().optional(),
  userAgent: z.string().optional(),
});

export async function POST(request: NextRequest): Promise<NextResponse> {
  return safeHandler(async () => {
    const raw = await request.text();
    const url = new URL(request.url);

    const auth = verifyServiceRequest({
      headers: request.headers,
      path: url.pathname + url.search,
      body: raw,
      allowedServices: ["operations-desk"],
    });
    if (!auth.authorized) {
      return forbidden("Service authentication required", "SERVICE_AUTH_FAILED");
    }

    let body: unknown;
    try {
      body = JSON.parse(raw);
    } catch {
      return badRequest("Request body required");
    }

    const parsed = schema.safeParse(body);
    if (!parsed.success) return validationError(parsed.error);

    const clientIP = parsed.data.ipAddress ?? getClientIP(request);
    const clientUA = parsed.data.userAgent ?? getClientUA(request);

    const result = await redeemGatewayAuthorization({
      tokenId: parsed.data.tokenId,
      deviceCredentialId: parsed.data.deviceCredentialId,
      ipAddress: clientIP,
      userAgent: clientUA,
    });

    if (!result.granted) {
      const isReplay = result.reason === "TOKEN_ALREADY_CONSUMED";

      void auditConnect({
        eventType: isReplay ? "AUTHZ_REPLAY_ATTEMPT" : "AUTHZ_REDEEM_DENIED",
        authzId: parsed.data.tokenId,
        ipAddress: clientIP,
        userAgent: clientUA,
        outcome: "DENIED",
        severity: isReplay ? "HIGH" : "WARNING",
        metadata: {
          reason: result.reason,
          deviceCredentialId: parsed.data.deviceCredentialId,
        },
      });

      // §15: "Repeated or high-confidence replay attempts are treated as
      // security events." Deduplicated by lib/alerts so a retry loop cannot
      // flood the alert stream.
      if (isReplay || result.reason === "DEVICE_MISMATCH") {
        void raiseSecurityAlert({
          alertKey: `authz_replay:${parsed.data.tokenId}`,
          severity: "HIGH",
          ipAddress: clientIP,
          userAgent: clientUA,
          metadata: { reason: result.reason },
        });
      }

      return NextResponse.json(publicDenial(), { status: 401 });
    }

    void auditConnect({
      eventType: "AUTHZ_CONSUMED",
      userId: result.userId,
      sessionId: result.sessionId,
      authzId: parsed.data.tokenId,
      ipAddress: clientIP,
      userAgent: clientUA,
      outcome: "SUCCESS",
      severity: "NOTICE",
      metadata: {
        deviceCredentialId: parsed.data.deviceCredentialId,
        emergency: result.emergency,
      },
    });

    return NextResponse.json({
      success: true,
      user: {
        id: result.userId,
        email: result.userEmail,
        name: result.userName,
        role: result.userRole,
      },
      sessionId: result.sessionId,
      deviceCredentialId: result.deviceCredentialId,
      emergency: result.emergency,
    });
  });
}
