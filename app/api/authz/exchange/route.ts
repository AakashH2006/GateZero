/**
 * app/api/authz/exchange/route.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Back-channel code exchange — website-2-defense.md §3, §15, §25
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * POST /api/authz/exchange
 * Body: { code }
 *
 * Website 2 redeems the front-channel code for the authorization Connect
 * already minted. Back-channel and service-authenticated (§25): the Gateway
 * does not answer this to anything that merely reaches the port.
 *
 * The response tells Website 2 which device credential the grant is bound to
 * and hands over its public key, so Website 2 can run its OWN device
 * verification (§8.1) instead of taking the Gateway's word for it. The public
 * key is not a secret; the private key it corresponds to never leaves the
 * employee's device.
 *
 * WHAT THIS DOES NOT DO
 * ─────────────────────
 * It does not consume the authorization. Consumption happens only once
 * Website 2 has verified the device and actually established a session, so a
 * handshake that fails at the device check does not burn the employee's grant
 * and force them back through Connect.
 *
 * §15: failures return one generic error. Internally the reason is logged;
 * externally an attacker learns only that it did not work.
 */

import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { exchangeCodeForToken } from "@/lib/authz-service";
import { verifyServiceRequest } from "@/lib/service-auth";
import { auditConnect, getClientIP, getClientUA } from "@/lib/audit";
import { prisma } from "@/lib/db";
import { forbidden, badRequest, validationError, safeHandler } from "@/lib/errors";

const exchangeSchema = z.object({
  code: z.string().min(10),
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
      void auditConnect({
        eventType: "EXCHANGE_DENIED_SERVICE_AUTH",
        ipAddress: getClientIP(request),
        userAgent: getClientUA(request),
        outcome: "DENIED",
        severity: "HIGH",
        metadata: { reason: auth.reason },
      });
      return forbidden("Service authentication required", "SERVICE_AUTH_FAILED");
    }

    let body: unknown;
    try {
      body = JSON.parse(raw);
    } catch {
      return badRequest("Request body required");
    }

    const parsed = exchangeSchema.safeParse(body);
    if (!parsed.success) return validationError(parsed.error);

    const clientUA =
      request.headers.get("x-client-user-agent") || parsed.data.userAgent || getClientUA(request);
    const clientIP =
      request.headers.get("x-client-ip") || parsed.data.ipAddress || getClientIP(request);

    try {
      const result = await exchangeCodeForToken({
        code: parsed.data.code,
        ipAddress: clientIP,
        userAgent: clientUA,
      });

      // Website 2 needs the public key to verify its own challenge (§8.1).
      // Nothing secret crosses here.
      const credential = result.deviceCredentialId
        ? await prisma.deviceCredential.findUnique({
            where: { id: result.deviceCredentialId },
            select: { id: true, publicKeySpki: true, algorithm: true, status: true, assurance: true },
          })
        : null;

      if (!credential || credential.status !== "ACTIVE") {
        void auditConnect({
          eventType: "EXCHANGE_DENIED",
          userId: result.user.id,
          authzId: result.tokenId,
          ipAddress: clientIP,
          userAgent: clientUA,
          outcome: "DENIED",
          severity: "HIGH",
          metadata: { reason: "DEVICE_CREDENTIAL_UNAVAILABLE" },
        });
        return badRequest("Access denied", "ACCESS_DENIED");
      }

      void auditConnect({
        eventType: "EXCHANGE_COMPLETED",
        userId: result.user.id,
        authzId: result.tokenId,
        ipAddress: clientIP,
        userAgent: clientUA,
        outcome: "SUCCESS",
        metadata: { deviceCredentialId: credential.id, emergency: result.emergency },
      });

      return NextResponse.json({
        success: true,
        tokenId: result.tokenId,
        expiresAt: result.expiresAt,
        ttlSeconds: result.ttlSeconds,
        emergency: result.emergency,
        device: {
          credentialId: credential.id,
          publicKeySpki: credential.publicKeySpki,
          algorithm: credential.algorithm,
          assurance: credential.assurance,
        },
        user: result.user,
      });
    } catch (err: unknown) {
      const reason = err instanceof Error ? err.message : "UNKNOWN";

      void auditConnect({
        eventType: "EXCHANGE_DENIED",
        ipAddress: clientIP,
        userAgent: clientUA,
        outcome: "DENIED",
        severity: "WARNING",
        metadata: { reason },
      });

      // §15: one generic external response for every failure mode. The caller
      // must not learn whether the code was expired, already used, or unknown.
      return badRequest("Access denied", "ACCESS_DENIED");
    }
  });
}
