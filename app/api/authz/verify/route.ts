/**
 * app/api/authz/verify/route.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Authorization introspection — website-2-defense.md §15, §25
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * POST /api/authz/verify
 * Body: { tokenId, deviceCredentialId? }
 *
 * Non-consuming validation of a Gateway authorization, used before a Website 2
 * session is established. Service-authenticated (§25) — a caller reaching the
 * port is not a caller the Gateway answers.
 *
 * NOT A PER-REQUEST SESSION CHECK
 * ───────────────────────────────
 * An earlier iteration had Website 2 call this on every single request. That
 * inverted the model: §35 and W1 §22.1 say a Website 2 session is maintained by
 * Website 2 and must not depend on continuous conversation with the Gateway,
 * and §26 requires existing sessions to survive a Gateway outage — which they
 * cannot if every page load needs the Gateway to answer. Per-request validation
 * now lives in the Session Guard, and this endpoint is used once, during
 * establishment.
 *
 * §15: internally the result distinguishes expired / consumed / device
 * mismatch / revoked. Externally, one generic denial.
 */

import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { introspectTokenLive } from "@/lib/authz-service";
import { publicDenial } from "@/lib/gateway";
import { verifyServiceRequest } from "@/lib/service-auth";
import { auditConnect, getClientIP, getClientUA } from "@/lib/audit";
import { forbidden, badRequest, validationError, safeHandler } from "@/lib/errors";

const verifySchema = z.object({
  tokenId: z.string().min(1),
  deviceCredentialId: z.string().optional(),
  userAgent: z.string().optional(),
  ipAddress: z.string().optional(),
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

    const parsed = verifySchema.safeParse(body);
    if (!parsed.success) return validationError(parsed.error);

    const clientUA =
      request.headers.get("x-client-user-agent") || parsed.data.userAgent || getClientUA(request);
    const clientIP =
      request.headers.get("x-client-ip") || parsed.data.ipAddress || getClientIP(request);

    const result = await introspectTokenLive({
      tokenId: parsed.data.tokenId,
      deviceCredentialId: parsed.data.deviceCredentialId,
      userAgent: clientUA,
      ipAddress: clientIP,
    });

    if (!result.valid) {
      // Replay of a consumed grant is a security event in its own right (§24),
      // distinguished here in the log while the response stays generic.
      void auditConnect({
        eventType:
          result.reason === "TOKEN_ALREADY_CONSUMED"
            ? "AUTHZ_REPLAY_ATTEMPT"
            : "AUTHZ_VERIFY_DENIED",
        authzId: parsed.data.tokenId,
        ipAddress: clientIP,
        userAgent: clientUA,
        outcome: "DENIED",
        severity: result.reason === "TOKEN_ALREADY_CONSUMED" ? "HIGH" : "WARNING",
        metadata: { reason: result.reason },
      });

      return NextResponse.json({ valid: false, ...publicDenial() }, { status: 401 });
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
      deviceCredentialId: result.deviceCredentialId,
      expiresAt: result.expiresAt,
      emergency: result.emergency,
    });
  });
}
