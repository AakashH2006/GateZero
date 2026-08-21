/**
 * app/api/authz/code/route.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Front-channel handoff — website-1-defense.md §4, §9 / website-2-defense.md §3
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * POST /api/authz/code
 * Returns: { code, targetUrl }
 *
 * COMPONENT BOUNDARY
 * ──────────────────
 * This endpoint is the GATEWAY's, not Website 1's. W1 §4 and §9 are explicit
 * that Website 1 must never learn Website 2's network location — only the
 * Authorization Service and the Gateway resolve where Website 2 lives. The
 * destination is therefore resolved through lib/gateway from server-side
 * configuration, and Website 1's own code never names an address.
 *
 * (In this mock, the Gateway runs inside the same Next application. The trust
 * decisions are real; the process isolation is not. See lib/gateway.)
 *
 * The code carries no authority of its own. It is a 60-second handle that can
 * only be exchanged, over a back channel, for the authorization Connect already
 * minted — and only once. Losing it in a URL, a referrer header, or browser
 * history therefore does not hand over an access credential.
 */

import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { getValidSession } from "@/lib/auth/session";
import { issueExchangeCode, getActiveAuthorization } from "@/lib/authz-service";
import { resolveHandoffUrl } from "@/lib/gateway/client";
import { CSRF_HEADER, verifyCsrfToken } from "@/lib/auth/csrf";
import { auditConnect, getClientIP, getClientUA } from "@/lib/audit";
import {
  unauthorized,
  forbidden,
  badRequest,
  validationError,
  safeHandler,
} from "@/lib/errors";

const schema = z.object({
  targetApp: z.string().min(1).max(64).default("operations-desk"),
});

export async function POST(request: NextRequest): Promise<NextResponse> {
  return safeHandler(async () => {
    const ip = getClientIP(request);
    const ua = getClientUA(request);

    const session = await getValidSession();
    if (!session) {
      return unauthorized("Active authenticated session required to generate launch code");
    }

    // Launching is state-changing (it burns a code and starts a handoff), so it
    // gets the same CSRF treatment as Connect.
    if (!verifyCsrfToken(session.id, request.headers.get(CSRF_HEADER))) {
      return forbidden("Missing or invalid CSRF token");
    }

    const parsed = schema.safeParse(await request.json().catch(() => ({})));
    if (!parsed.success) return validationError(parsed.error);

    // A code is only meaningful alongside a live authorization. Issuing one
    // without a grant behind it would produce a handle that looks like access
    // and is not — better to refuse here than to fail opaquely at the exchange.
    const authorization = await getActiveAuthorization(session.id);
    if (!authorization) {
      void auditConnect({
        eventType: "LAUNCH_DENIED_NO_AUTHORIZATION",
        userId: session.userId,
        sessionId: session.id,
        ipAddress: ip,
        userAgent: ua,
        outcome: "DENIED",
        metadata: { targetApp: parsed.data.targetApp },
      });
      return forbidden(
        "Connect first — no active authorization for this session",
        "NO_ACTIVE_AUTHORIZATION"
      );
    }

    const code = await issueExchangeCode({
      sessionId: session.id,
      userId: session.userId,
      ipAddress: ip,
      userAgent: ua,
      targetApp: parsed.data.targetApp,
    });

    // Website 1 does not know where Website 2 lives (W1 §4, §9) — it asks the
    // Gateway, which is the only component that resolves the address (GW §8).
    // An unknown target is refused there rather than echoed back, so this
    // cannot be turned into an open redirector.
    const targetUrl = await resolveHandoffUrl({
      targetApp: parsed.data.targetApp,
      code,
    });
    if (!targetUrl) {
      return badRequest("Unknown target application", "UNKNOWN_TARGET_APP");
    }

    void auditConnect({
      eventType: "LAUNCH_CODE_ISSUED",
      userId: session.userId,
      sessionId: session.id,
      authzId: authorization.tokenId,
      ipAddress: ip,
      userAgent: ua,
      outcome: "SUCCESS",
      metadata: { targetApp: parsed.data.targetApp },
    });

    return NextResponse.json({ success: true, code, targetUrl });
  });
}
