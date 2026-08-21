/**
 * app/api/device/challenge/route.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Device challenge issuance — website-2-defense.md §4, website-1-defense.md §8
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * POST /api/device/challenge
 * Body: { purpose: "REGISTRATION" | "CONNECT" | "ROTATION" }
 *
 * Returns a fresh, unpredictable, server-generated nonce for the device to
 * sign. Nonces are single-use and short-lived, so a captured signature is worth
 * nothing on the next request (§4 "Cryptographic Challenge Freshness").
 *
 * Only Website 1's own purposes are issuable here. Website 2 mints its own
 * W2_SESSION challenges (§8.1) — the whole point of its independent check is
 * that it does not accept a challenge Website 1 or the Gateway produced.
 *
 * Issuing a challenge is not an authorization decision and reveals nothing: the
 * nonce is only useful to whoever already holds the device private key.
 * Challenges are rate-limited anyway, to keep the table from being flooded.
 */

import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { getValidSession } from "@/lib/auth/session";
import { issueDeviceChallenge } from "@/lib/device";
import { checkRateLimit } from "@/lib/rate-limit";
import { getClientIP } from "@/lib/audit";
import {
  unauthorized,
  validationError,
  tooManyRequests,
  safeHandler,
} from "@/lib/errors";

const schema = z.object({
  purpose: z.enum(["REGISTRATION", "CONNECT", "ROTATION"]),
});

export async function POST(request: NextRequest): Promise<NextResponse> {
  return safeHandler(async () => {
    // Fully-authenticated sessions only. A challenge grants nothing on its own,
    // but the flows that redeem one (enrolment, Connect, rotation) are all
    // ACTIVE-only, so handing them out earlier serves no purpose.
    const session = await getValidSession();
    if (!session) return unauthorized("Valid session required");

    const parsed = schema.safeParse(await request.json().catch(() => ({})));
    if (!parsed.success) return validationError(parsed.error);

    const rate = await checkRateLimit(
      `device-challenge:${session.userId}:${getClientIP(request)}`,
      30,
      60
    );
    if (!rate.allowed) return tooManyRequests(rate.resetAt);

    const challenge = await issueDeviceChallenge({
      userId: session.userId,
      purpose: parsed.data.purpose,
      issuer: "website-1",
    });

    return NextResponse.json({
      nonce: challenge.nonce,
      expiresAt: challenge.expiresAt,
      purpose: challenge.purpose,
      issuer: challenge.issuer,
    });
  });
}
