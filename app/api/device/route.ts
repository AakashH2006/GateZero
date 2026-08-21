/**
 * app/api/device/route.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Device registration and status — website-2-defense.md §6, §9A
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * GET  /api/device   — the employee's credential state (no secrets)
 * POST /api/device   — register a new device public key
 *
 * Registration proves possession of the new private key and then stops. The
 * credential lands in PENDING_APPROVAL and an administrator must approve it
 * (§6). That approval step is what makes device enrolment a controlled event
 * rather than a self-service path an attacker with a stolen session could walk
 * through on their own.
 *
 * The private key is never sent, so nothing here can leak one — the request
 * carries only a public key and a signature over the server's own nonce.
 */

import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { getPendingOrActiveSession, getValidSession } from "@/lib/auth/session";
import {
  registerDeviceCredential,
  approveDeviceCredential,
  credentialUsability,
} from "@/lib/device";
import { CSRF_HEADER, verifyCsrfToken } from "@/lib/auth/csrf";
import { checkRateLimit } from "@/lib/rate-limit";
import { auditLogin, getClientIP, getClientUA } from "@/lib/audit";
import { notifyEmployee } from "@/lib/notify";
import { enqueueSecurityEvent } from "@/lib/security-events";
import { prisma } from "@/lib/db";
import { DEV_AUTO_APPROVE_DEVICES } from "@/lib/config";
import {
  unauthorized,
  forbidden,
  badRequest,
  validationError,
  tooManyRequests,
  safeHandler,
} from "@/lib/errors";

const registerSchema = z.object({
  label: z.string().min(1).max(120),
  publicKeySpki: z.string().min(50).max(2000),
  hardwareBacked: z.boolean().default(false),
  nonce: z.string().min(16),
  signature: z.string().min(16),
});

export async function GET(): Promise<NextResponse> {
  return safeHandler(async () => {
    const session = await getPendingOrActiveSession();
    if (!session) return unauthorized("Valid session required");

    const credentials = await prisma.deviceCredential.findMany({
      where: { userId: session.userId, status: { not: "REVOKED" } },
      orderBy: { createdAt: "desc" },
    });

    return NextResponse.json({
      // Public keys are not secret, but they are not needed by the browser
      // either — omitting them keeps the response minimal (§34 in spirit).
      devices: credentials.map((c) => {
        const usability = credentialUsability(c);
        return {
          id: c.id,
          label: c.label,
          status: c.status,
          assurance: c.assurance,
          hardwareBacked: c.hardwareBacked,
          usable: usability.usable,
          rotationDue: usability.rotationDue,
          rotationDueAt: c.rotationDueAt,
          graceExpiresAt: c.graceExpiresAt,
          approvedAt: c.approvedAt,
          createdAt: c.createdAt,
        };
      }),
    });
  });
}

export async function POST(request: NextRequest): Promise<NextResponse> {
  return safeHandler(async () => {
    const ip = getClientIP(request);
    const ua = getClientUA(request);

    // Enrolment requires a fully-authenticated session. An earlier version
    // accepted PENDING_MFA and therefore had to skip CSRF for it, since no CSRF
    // token is issued before MFA completes. SameSite=Lax already blocks the
    // cross-site POST, but the token is the defense-in-depth layer on top of
    // that (see lib/auth/csrf.ts), and the pre-MFA window is the worst place to
    // drop a layer. Nothing needs the permissiveness: the portal only ever
    // enrols a device from the dashboard, which is ACTIVE-only.
    const session = await getValidSession();
    if (!session) return unauthorized("Valid session required");

    if (!verifyCsrfToken(session.id, request.headers.get(CSRF_HEADER))) {
      return forbidden("Missing or invalid CSRF token");
    }

    // §8 "Recovery Request Protection" applies here too: registration attempts
    // are rate-limited so the flow cannot be used to spray public keys.
    const rate = await checkRateLimit(`device-register:${session.userId}`, 5, 3600);
    if (!rate.allowed) {
      void auditLogin({
        eventType: "DEVICE_REGISTER_RATE_LIMITED",
        userId: session.userId,
        sessionId: session.id,
        ipAddress: ip,
        userAgent: ua,
        outcome: "DENIED",
        severity: "WARNING",
        metadata: {},
      });
      return tooManyRequests(rate.resetAt);
    }

    const parsed = registerSchema.safeParse(await request.json().catch(() => ({})));
    if (!parsed.success) return validationError(parsed.error);

    const result = await registerDeviceCredential({
      userId: session.userId,
      label: parsed.data.label,
      publicKeySpki: parsed.data.publicKeySpki,
      // The client's claim about hardware backing is recorded, not trusted: it
      // only ever *lowers* trust, never raises it above what the server would
      // otherwise assign. See lib/device/client.ts.
      hardwareBacked: parsed.data.hardwareBacked,
      proof: { nonce: parsed.data.nonce, signature: parsed.data.signature },
    });

    if (!result.ok || !result.credential) {
      void auditLogin({
        eventType: "DEVICE_REGISTER_FAILED",
        userId: session.userId,
        sessionId: session.id,
        ipAddress: ip,
        userAgent: ua,
        outcome: "FAILURE",
        severity: "WARNING",
        metadata: { reason: result.reason },
      });
      return badRequest("Device registration failed", "DEVICE_REGISTRATION_FAILED");
    }

    void auditLogin({
      eventType: "DEVICE_REGISTERED_PENDING_APPROVAL",
      userId: session.userId,
      sessionId: session.id,
      ipAddress: ip,
      userAgent: ua,
      outcome: "SUCCESS",
      severity: "NOTICE",
      metadata: {
        credentialId: result.credential.id,
        assurance: result.credential.assurance,
        label: result.credential.label,
      },
    });

    // DEV-ONLY: stands in for the administrator approving the registration, so
    // a dev environment is usable without a second operator. Gated by DEV_MODE
    // (see lib/config) and therefore impossible in production.
    if (DEV_AUTO_APPROVE_DEVICES) {
      const approval = await approveDeviceCredential({
        credentialId: result.credential.id,
        adminUserId: "DEV_AUTO_APPROVAL",
      });

      void auditLogin({
        eventType: "DEVICE_AUTO_APPROVED_DEV_MODE",
        userId: session.userId,
        sessionId: session.id,
        ipAddress: ip,
        userAgent: ua,
        outcome: "SUCCESS",
        severity: "WARNING",
        metadata: { credentialId: result.credential.id },
      });

      // W1 §22.3 / W2 §7: a newly authorized device supersedes the old one, and
      // sessions bound to the superseded credential must not linger.
      if (approval.supersededIds.length > 0) {
        await enqueueSecurityEvent({
          type: "DEVICE_REVOKED",
          userId: session.userId,
          reason: "SUPERSEDED_BY_NEW_DEVICE",
          deviceCredentialIds: approval.supersededIds,
        });
      }

      void notifyEmployee(session.user, "DEVICE_REGISTERED");

      return NextResponse.json({
        success: true,
        credentialId: result.credential.id,
        status: "ACTIVE",
        autoApproved: true,
      });
    }

    void notifyEmployee(session.user, "DEVICE_REGISTERED");

    return NextResponse.json({
      success: true,
      credentialId: result.credential.id,
      status: "PENDING_APPROVAL",
      message: "Device registered. An administrator must approve it before it can be used.",
    });
  });
}
