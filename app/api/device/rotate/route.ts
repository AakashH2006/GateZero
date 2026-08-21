/**
 * app/api/device/rotate/route.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Device credential rotation — website-2-defense.md §9A
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * POST /api/device/rotate
 * Body: {
 *   currentNonce, currentSignature,   // proof for the credential being retired
 *   newPublicKeySpki, newNonce, newSignature, label, hardwareBacked
 * }
 *
 * Credentials must not remain valid indefinitely (§9A). Rotation requires the
 * device to prove possession of its *current* private key and of the incoming
 * one; the old credential is then revoked and the new one becomes active.
 *
 * Neither key ever leaves the device — the whole exchange is two signatures
 * over two server nonces.
 *
 * Unlike recovery (§8), rotation needs no administrator: possession of the
 * current key is itself the proof of continuity. Recovery is human-controlled
 * precisely because that proof is what has been lost.
 */

import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { getValidSession } from "@/lib/auth/session";
import { rotateDeviceCredential, getActiveCredential } from "@/lib/device";
import { CSRF_HEADER, verifyCsrfToken } from "@/lib/auth/csrf";
import { auditLogin, getClientIP, getClientUA } from "@/lib/audit";
import {
  unauthorized,
  forbidden,
  badRequest,
  validationError,
  safeHandler,
} from "@/lib/errors";

const schema = z.object({
  currentNonce: z.string().min(16),
  currentSignature: z.string().min(16),
  newPublicKeySpki: z.string().min(50).max(2000),
  newNonce: z.string().min(16),
  newSignature: z.string().min(16),
  label: z.string().min(1).max(120),
  hardwareBacked: z.boolean().default(false),
});

export async function POST(request: NextRequest): Promise<NextResponse> {
  return safeHandler(async () => {
    const ip = getClientIP(request);
    const ua = getClientUA(request);

    const session = await getValidSession();
    if (!session) return unauthorized("Valid session required");

    if (!verifyCsrfToken(session.id, request.headers.get(CSRF_HEADER))) {
      return forbidden("Missing or invalid CSRF token");
    }

    const parsed = schema.safeParse(await request.json().catch(() => ({})));
    if (!parsed.success) return validationError(parsed.error);

    const current = await getActiveCredential(session.userId);
    if (!current) {
      return badRequest("No active device credential to rotate", "NO_ACTIVE_CREDENTIAL");
    }

    const result = await rotateDeviceCredential({
      userId: session.userId,
      currentCredentialId: current.id,
      currentProof: {
        nonce: parsed.data.currentNonce,
        signature: parsed.data.currentSignature,
      },
      newPublicKeySpki: parsed.data.newPublicKeySpki,
      newProof: { nonce: parsed.data.newNonce, signature: parsed.data.newSignature },
      hardwareBacked: parsed.data.hardwareBacked,
      label: parsed.data.label,
    });

    if (!result.ok || !result.credential) {
      void auditLogin({
        eventType: "DEVICE_ROTATION_FAILED",
        userId: session.userId,
        sessionId: session.id,
        ipAddress: ip,
        userAgent: ua,
        outcome: "FAILURE",
        severity: "WARNING",
        metadata: { reason: result.reason, credentialId: current.id },
      });
      return badRequest("Device rotation failed", "DEVICE_ROTATION_FAILED");
    }

    void auditLogin({
      eventType: "DEVICE_ROTATED",
      userId: session.userId,
      sessionId: session.id,
      ipAddress: ip,
      userAgent: ua,
      outcome: "SUCCESS",
      severity: "NOTICE",
      metadata: {
        previousCredentialId: current.id,
        credentialId: result.credential.id,
        assurance: result.credential.assurance,
      },
    });

    // Existing Website 2 sessions are intentionally left alone. Rotation is the
    // *same* device re-keying, not a new device (W2 §9A); tearing down the
    // employee's work session for routine hygiene would be a self-inflicted
    // outage. Replacement and revocation are the paths that end sessions.
    return NextResponse.json({
      success: true,
      credentialId: result.credential.id,
      rotationDueAt: result.credential.rotationDueAt,
      graceExpiresAt: result.credential.graceExpiresAt,
    });
  });
}
