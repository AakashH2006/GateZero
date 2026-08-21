/**
 * app/api/auth/session/route.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Session state for the portal UI
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * GET /api/auth/session
 *
 * Display-safe fields only. Never returns an authorization grant, a device key,
 * an MFA secret, or anything else that would be a credential in its own right —
 * the client receives opaque identifiers and state flags.
 *
 * The CSRF token is deliberately readable by the page's own JavaScript: it is
 * not the httpOnly session cookie and proves nothing by itself. Its purpose is
 * that a cross-site caller cannot read this response, so it cannot obtain the
 * token to echo back on a mutating request.
 */

import { NextRequest, NextResponse } from "next/server";
import { getValidSession } from "@/lib/auth/session";
import { getActiveAuthorization } from "@/lib/authz-service";
import { getActiveCredential, credentialUsability } from "@/lib/device";
import { signCsrfToken } from "@/lib/auth/csrf";
import { connectCooldownRemainingMs } from "@/lib/auth/session";
import { prisma } from "@/lib/db";
import { safeHandler } from "@/lib/errors";

export async function GET(_request: NextRequest): Promise<NextResponse> {
  return safeHandler(async () => {
    const session = await getValidSession();

    if (!session) {
      return NextResponse.json({ authenticated: false });
    }

    const [authz, credential, pendingCredential] = await Promise.all([
      getActiveAuthorization(session.id),
      getActiveCredential(session.userId),
      prisma.deviceCredential.findFirst({
        where: { userId: session.userId, status: "PENDING_APPROVAL" },
        orderBy: { createdAt: "desc" },
        select: { id: true, label: true, createdAt: true },
      }),
    ]);

    const usability = credential ? credentialUsability(credential) : null;
    const cooldownMs = connectCooldownRemainingMs(session);

    return NextResponse.json({
      authenticated: true,
      user: {
        name: session.user.name,
        email: session.user.email,
        role: session.user.role,
        accessRevoked: session.user.accessRevoked,
      },
      session: {
        id: session.id,
        expiresAt: session.expiresAt,
        createdAt: session.createdAt,
        // §7 / §15: the UI needs to know Connect is gated so it can send the
        // employee to step-up rather than letting them retry into a wall.
        stepUpRequired: session.connectStepUpRequired,
        mfaOverridden: session.mfaOverridden,
        // §10: how long the punitive Connect freeze still has to run.
        connectCooldownSeconds: Math.ceil(cooldownMs / 1000),
      },
      // §8: Connect requires a registered, approved, usable device. Reported so
      // the portal can prompt for enrolment instead of failing at Connect.
      device: credential
        ? {
            registered: true,
            credentialId: credential.id,
            label: credential.label,
            assurance: credential.assurance,
            hardwareBacked: credential.hardwareBacked,
            usable: usability?.usable ?? false,
            rotationDue: usability?.rotationDue ?? false,
            rotationDueAt: credential.rotationDueAt,
            graceExpiresAt: credential.graceExpiresAt,
          }
        : {
            registered: false,
            pendingApproval: pendingCredential
              ? { id: pendingCredential.id, label: pendingCredential.label }
              : null,
          },
      csrfToken: signCsrfToken(session.id),
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
