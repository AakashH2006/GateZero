/**
 * app/api/health/route.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Liveness probe — website-1-defense.md §16, §19 / website-2-defense.md §27
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * GET /api/health
 *
 * The target of the independent health checks the Authorization Service runs
 * against Website 1. It answers whether this instance can actually serve
 * requests — it reaches the database, because an instance that accepts TCP but
 * cannot read its own state is not healthy in any useful sense.
 *
 * DELIBERATELY READ-ONLY
 * ──────────────────────
 * This endpoint reports; it never records. The stored health state is written
 * exclusively by the out-of-process monitor (scripts/health-monitor.ts). That
 * separation is the whole mechanism behind §16's "Website 1 must never be able
 * to declare itself unavailable": a fully compromised Website 1 can lie in this
 * response, but lying *healthy* opens nothing, and it cannot reach into the
 * health table to claim an outage.
 *
 * Unauthenticated by necessity — a prober that needs a working session cannot
 * detect the outage of the thing issuing sessions. The response therefore
 * carries no employee data, no counts, and no configuration.
 */

import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";

export const dynamic = "force-dynamic";

export async function GET(): Promise<NextResponse> {
  try {
    // Cheapest possible round trip that proves the datastore is reachable.
    await prisma.$queryRaw`SELECT 1`;
    return NextResponse.json(
      { status: "ok", component: "website-1", time: new Date().toISOString() },
      { headers: { "Cache-Control": "no-store" } }
    );
  } catch {
    return NextResponse.json(
      { status: "degraded", component: "website-1", time: new Date().toISOString() },
      { status: 503, headers: { "Cache-Control": "no-store" } }
    );
  }
}
