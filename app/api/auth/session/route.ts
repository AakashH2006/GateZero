/**
 * app/api/auth/session/route.ts
 * Returns the current session state for the frontend to consume.
 * Used by the dashboard to display user info and session expiry.
 *
 * NEVER returns sensitive tokens — only display-safe fields.
 */

import { NextRequest, NextResponse } from "next/server";
import { getValidSession } from "@/lib/auth/session";
import { getActiveAuthorization } from "@/lib/authz-service";
import { safeHandler } from "@/lib/errors";

export async function GET(_request: NextRequest): Promise<NextResponse> {
  return safeHandler(async () => {
    const session = await getValidSession();

    if (!session) {
      return NextResponse.json({ authenticated: false });
    }

    // Check for active authorization
    const authz = await getActiveAuthorization(session.id);

    return NextResponse.json({
      authenticated: true,
      user: {
        name: session.user.name,
        email: session.user.email,
        role: session.user.role,
      },
      session: {
        id: session.id,
        expiresAt: session.expiresAt,
        createdAt: session.createdAt,
      },
      authorization: authz
        ? {
            active: true,
            tokenId: authz.tokenId,
            expiresAt: authz.expiresAt,
            ttlSeconds: authz.ttlSeconds,
          }
        : { active: false },
    });
  });
}
