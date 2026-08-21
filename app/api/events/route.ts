/**
 * app/api/events/route.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Critical security event delivery — website-2-defense.md §21, §32
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * GET  /api/events            — pull pending events (Website 2 → Gateway)
 * POST /api/events            — acknowledge processed events
 * GET  /api/events?reconcile= — fallback reconciliation for one employee
 *
 * Pull rather than push, deliberately. It means Website 2 exposes no
 * event-injection endpoint at all: nothing on the network can send Website 2 a
 * "terminate this employee" message, because Website 2 only ever asks.
 *
 * Both directions are service-authenticated (§25). The events themselves are
 * additionally HMAC-signed end to end, so this transport being compromised
 * still does not let an attacker forge an event Website 2 will act on.
 *
 * Acknowledgement is what marks an event DELIVERED — never the act of handing
 * it over. An unacknowledged event stays pending and is redelivered, which is
 * exactly the at-least-once behaviour §21 asks for, and is safe because
 * Website 2 deduplicates on `eventId`.
 */

import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import {
  pullPendingEvents,
  acknowledgeEvents,
  reconcileUserState,
} from "@/lib/security-events";
import { verifyServiceRequest } from "@/lib/service-auth";
import { forbidden, validationError, badRequest, safeHandler } from "@/lib/errors";

const ackSchema = z.object({
  eventIds: z.array(z.string().min(1)).min(1).max(200),
});

export const dynamic = "force-dynamic";

export async function GET(request: NextRequest): Promise<NextResponse> {
  return safeHandler(async () => {
    const url = new URL(request.url);
    // The signature covers the path including the query string, so a signature
    // captured on a plain pull cannot be replayed against a reconcile.
    const path = url.pathname + url.search;

    const auth = verifyServiceRequest({
      headers: request.headers,
      path,
      body: "",
      allowedServices: ["operations-desk"],
    });
    if (!auth.authorized) {
      return forbidden("Service authentication required", "SERVICE_AUTH_FAILED");
    }

    const reconcileUserId = url.searchParams.get("reconcile");
    if (reconcileUserId) {
      // §21: "A fallback reconciliation mechanism should verify critical
      // account-security state if event delivery cannot be confirmed."
      const state = await reconcileUserState(reconcileUserId);
      return NextResponse.json({ reconcile: true, userId: reconcileUserId, state });
    }

    const events = await pullPendingEvents();
    return NextResponse.json({ events });
  });
}

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

    const parsed = ackSchema.safeParse(body);
    if (!parsed.success) return validationError(parsed.error);

    const acknowledged = await acknowledgeEvents(parsed.data.eventIds);
    return NextResponse.json({ acknowledged });
  });
}
