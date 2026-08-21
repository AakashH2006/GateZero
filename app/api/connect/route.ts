/**
 * app/api/connect/route.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * CONNECT — the explicit, security-sensitive access request
 * website-1-defense.md §4, §5, §7, §8, §10, §19
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * A valid 7-day Website 1 session does not authorize Website 2 (§4). The
 * employee must click Connect, and every click runs the full checkpoint:
 *
 *   1. Valid Website 1 session
 *   2. CSRF (§10) — before anything stateful is touched
 *   3. Cooldown from prior repeated failures (§10)
 *   4. Pending MFA step-up gate (§7 MEDIUM, §15 override)
 *   5. Rate limit (§10)
 *   6. Cryptographic device proof (§8) — authoritative device identity
 *   7. Mini EDR risk assessment (§5, §6, §7)
 *   8. Authorization Service issues a fresh 5-minute, one-time, device-bound
 *      grant (§8)
 *
 * Website 1 never contacts Website 2 or the Gateway here, and never learns
 * Website 2's location (§4). It requests an authorization; that is the whole of
 * its role.
 *
 * The response carries the opaque token id and expiry — never the grant itself.
 */

import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import {
  getValidSession,
  flagStepUpRequired,
  revokeSession,
  getIronSessionStore,
  applyConnectCooldown,
  connectCooldownRemainingMs,
  bindSessionDevice,
} from "@/lib/auth/session";
import { getActiveAuthorization, revokeAuthorization } from "@/lib/authz-service";
import { issueGrant } from "@/lib/gateway/client";
import { checkRateLimit, connectRateLimitKey } from "@/lib/rate-limit";
import { CSRF_HEADER, verifyCsrfToken } from "@/lib/auth/csrf";
import { auditConnect, getClientIP, getClientUA } from "@/lib/audit";
import { assessConnectRisk, type DeviceContext } from "@/lib/mini-edr";
import { verifyDeviceProof } from "@/lib/device";
import { raiseSecurityAlert } from "@/lib/alerts";
import { notifyEmployee } from "@/lib/notify";
import { prisma } from "@/lib/db";
import {
  CONNECT_FAILURE_THRESHOLD,
  CONNECT_FAILURE_WINDOW_SECONDS,
} from "@/lib/config";
import {
  unauthorized,
  forbidden,
  tooManyRequests,
  serverError,
  safeHandler,
} from "@/lib/errors";

/** §8: a Connect request without a device proof cannot produce a bound grant. */
const connectSchema = z.object({
  nonce: z.string().min(16),
  signature: z.string().min(16),
});

/**
 * §10: count recent Connect denials for this employee.
 *
 * Counts denials rather than attempts: an employee who connects successfully
 * ten times has done nothing wrong, while ten refusals is a pattern worth
 * freezing and telling them about.
 */
async function recentConnectFailures(userId: string): Promise<number> {
  const since = new Date(Date.now() - CONNECT_FAILURE_WINDOW_SECONDS * 1000);
  return prisma.auditLog.count({
    where: {
      userId,
      stream: "CONNECT",
      outcome: "DENIED",
      createdAt: { gte: since },
    },
  });
}

/**
 * Apply the cooldown and notify the employee once the failure threshold trips.
 *
 * §10 requires all three responses: the cooldown, the log entry, and a
 * notification to the employee that is independent of any admin-facing alert —
 * the person whose account it is should hear about it even when nothing rises
 * to an operator page.
 */
async function escalateFailures(params: {
  session: Awaited<ReturnType<typeof getValidSession>>;
  ip: string;
  ua: string;
}): Promise<void> {
  const session = params.session;
  if (!session) return;

  const failures = await recentConnectFailures(session.userId);
  if (failures < CONNECT_FAILURE_THRESHOLD) return;

  const until = await applyConnectCooldown(session.id);

  await auditConnect({
    eventType: "CONNECT_COOLDOWN_APPLIED",
    userId: session.userId,
    sessionId: session.id,
    ipAddress: params.ip,
    userAgent: params.ua,
    outcome: "DENIED",
    severity: "HIGH",
    metadata: { failures, cooldownUntil: until.toISOString() },
  });

  void notifyEmployee(session.user, "CONNECT_COOLDOWN");
}

export async function POST(request: NextRequest): Promise<NextResponse> {
  return safeHandler(async () => {
    const ip = getClientIP(request);
    const ua = getClientUA(request);

    // ── 1. Valid Website 1 session ──────────────────────────────────────────
    const session = await getValidSession();
    if (!session) {
      void auditConnect({
        eventType: "CONNECT_DENIED_NO_SESSION",
        ipAddress: ip,
        userAgent: ua,
        outcome: "DENIED",
        metadata: {},
      });
      return unauthorized("Valid session required to connect");
    }

    // ── 2. CSRF ─────────────────────────────────────────────────────────────
    // Rejected before rate limiting or the Authorization Service, so a forged
    // cross-site request never consumes a rate-limit slot on the employee's
    // behalf.
    if (!verifyCsrfToken(session.id, request.headers.get(CSRF_HEADER))) {
      void auditConnect({
        eventType: "CONNECT_DENIED_CSRF",
        userId: session.userId,
        sessionId: session.id,
        ipAddress: ip,
        userAgent: ua,
        outcome: "DENIED",
        metadata: {},
      });
      return forbidden("Missing or invalid CSRF token");
    }

    // ── 3. Cooldown from prior repeated failures (§10) ──────────────────────
    const cooldownMs = connectCooldownRemainingMs(session);
    if (cooldownMs > 0) {
      void auditConnect({
        eventType: "CONNECT_DENIED_COOLDOWN",
        userId: session.userId,
        sessionId: session.id,
        ipAddress: ip,
        userAgent: ua,
        outcome: "DENIED",
        metadata: { remainingSeconds: Math.ceil(cooldownMs / 1000) },
      });
      return tooManyRequests(new Date(Date.now() + cooldownMs));
    }

    // ── 4. Pending MFA step-up gate ─────────────────────────────────────────
    // Set by a prior MEDIUM-risk assessment (§7) or by an administrative MFA
    // override (§15). The Website 1 session stays ACTIVE — only Connect is
    // gated. Checked before rate limiting so a gated employee spends their
    // attempts on step-up rather than on doomed retries.
    if (session.connectStepUpRequired) {
      void auditConnect({
        eventType: "CONNECT_DENIED_STEP_UP_REQUIRED",
        userId: session.userId,
        sessionId: session.id,
        ipAddress: ip,
        userAgent: ua,
        outcome: "DENIED",
        metadata: { mfaOverridden: session.mfaOverridden },
      });
      return forbidden(
        "Fresh MFA verification required before connecting",
        "STEP_UP_MFA_REQUIRED"
      );
    }

    // W2 §22: an administratively revoked employee cannot obtain authorization.
    if (session.user.accessRevoked) {
      void auditConnect({
        eventType: "CONNECT_DENIED_ACCESS_REVOKED",
        userId: session.userId,
        sessionId: session.id,
        ipAddress: ip,
        userAgent: ua,
        outcome: "DENIED",
        severity: "HIGH",
        metadata: {},
      });
      return forbidden("Access has been revoked", "ACCESS_REVOKED");
    }

    // ── 5. Rate limiting (§10) ──────────────────────────────────────────────
    const rateCheck = await checkRateLimit(connectRateLimitKey(session.userId, ip));
    if (!rateCheck.allowed) {
      void auditConnect({
        eventType: "CONNECT_RATE_LIMITED",
        userId: session.userId,
        sessionId: session.id,
        ipAddress: ip,
        userAgent: ua,
        outcome: "DENIED",
        metadata: { resetAt: rateCheck.resetAt },
      });
      await escalateFailures({ session, ip, ua });
      return tooManyRequests(rateCheck.resetAt);
    }

    // ── 6. Cryptographic device proof (§8) ──────────────────────────────────
    const body = await request.json().catch(() => null);
    const parsed = connectSchema.safeParse(body);

    if (!parsed.success) {
      void auditConnect({
        eventType: "CONNECT_DENIED_NO_DEVICE_PROOF",
        userId: session.userId,
        sessionId: session.id,
        ipAddress: ip,
        userAgent: ua,
        outcome: "DENIED",
        metadata: {},
      });
      return forbidden(
        "A registered device is required to connect",
        "DEVICE_PROOF_REQUIRED"
      );
    }

    const proofResult = await verifyDeviceProof({
      userId: session.userId,
      proof: { nonce: parsed.data.nonce, signature: parsed.data.signature },
      purpose: "CONNECT",
      issuer: "website-1",
    });

    const deviceContext: DeviceContext = {
      proofValid: proofResult.valid,
      credentialId: proofResult.credential?.id,
      reason: proofResult.reason,
      previousCredentialId: session.deviceCredentialId,
    };

    // ── 7. Mini EDR risk assessment (§5-§7) ─────────────────────────────────
    // A failed device proof is scored rather than short-circuited: §7 defines
    // graded responses, and the assessment decides whether this is a
    // step-up situation or a terminate-and-alert one.
    const assessment = await assessConnectRisk(session, ip, ua, deviceContext);

    if (assessment.level === "MEDIUM") {
      // Block Connect and require fresh MFA. The 7-day session is untouched —
      // only the Connect endpoint is gated, so the employee keeps their portal
      // session and simply has to re-prove themselves before connecting.
      await flagStepUpRequired(session.id);
      void auditConnect({
        eventType: "CONNECT_BLOCKED_MEDIUM_RISK",
        userId: session.userId,
        sessionId: session.id,
        ipAddress: ip,
        userAgent: ua,
        outcome: "DENIED",
        severity: "WARNING",
        metadata: {
          score: assessment.score,
          factors: assessment.factors,
          reason: "Significant session/device change detected",
          action: "Step-up MFA required; Website 1 session retained",
          gatewayAuthorization: "Not issued",
        },
      });
      await escalateFailures({ session, ip, ua });
      return forbidden(
        "Fresh MFA verification required before connecting",
        "STEP_UP_MFA_REQUIRED"
      );
    }

    if (assessment.level === "HIGH" || assessment.level === "CRITICAL") {
      // §7: terminate the Website 1 session and require fresh SSO + MFA.
      // CRITICAL additionally revokes any outstanding authorization so Website 2
      // access is cut immediately rather than at the end of its 5 minutes.
      await revokeSession(session.id);

      if (assessment.level === "CRITICAL") {
        const activeToken = await getActiveAuthorization(session.id);
        if (activeToken) await revokeAuthorization(activeToken.tokenId);
      }

      const ironSession = await getIronSessionStore();
      ironSession.destroy();
      await ironSession.save();

      void auditConnect({
        eventType:
          assessment.level === "CRITICAL"
            ? "CONNECT_BLOCKED_CRITICAL_RISK"
            : "CONNECT_BLOCKED_HIGH_RISK",
        userId: session.userId,
        sessionId: session.id,
        ipAddress: ip,
        userAgent: ua,
        outcome: "DENIED",
        severity: assessment.level,
        metadata: {
          score: assessment.score,
          factors: assessment.factors,
          failedClosed: assessment.failedClosed ?? false,
          reason: "Significant session/device change detected",
          action: "Website 1 session terminated",
          gatewayAuthorization: "Not issued",
        },
      });

      // §20: deduplicated and severity-gated, so a repeating detection does not
      // page an operator every few seconds.
      void raiseSecurityAlert({
        alertKey: `connect_risk:${assessment.level}`,
        severity: assessment.level,
        userId: session.userId,
        sessionId: session.id,
        ipAddress: ip,
        userAgent: ua,
        metadata: { score: assessment.score, factors: assessment.factors },
      });

      void notifyEmployee(session.user, "SESSION_TERMINATED_RISK");

      return unauthorized(
        "Session terminated due to elevated risk — please sign in again",
        "SESSION_TERMINATED_RISK"
      );
    }

    // Below MEDIUM, a device proof is still mandatory. Reaching here without a
    // valid one would mean the scoring weights had drifted far enough to let an
    // unbound grant through, so this is a hard backstop rather than a branch we
    // expect to hit.
    if (!proofResult.valid || !proofResult.credential) {
      void auditConnect({
        eventType: "CONNECT_DENIED_DEVICE_PROOF_INVALID",
        userId: session.userId,
        sessionId: session.id,
        ipAddress: ip,
        userAgent: ua,
        outcome: "DENIED",
        severity: "HIGH",
        metadata: { reason: proofResult.reason, score: assessment.score },
      });
      await escalateFailures({ session, ip, ua });
      return forbidden(
        "A registered device is required to connect",
        "DEVICE_PROOF_REQUIRED"
      );
    }

    // ── 8. Fresh 5-minute, one-time, device-bound authorization (§8) ────────
    //
    // Website 1 asks; the Gateway decides and mints. There is deliberately no
    // code path here that produces a grant (gateway-defense.md §1) — a
    // compromised portal cannot mint one because the minting code lives in
    // another process.
    const issued = await issueGrant({
      sessionId: session.id,
      userId: session.userId,
      ipAddress: ip,
      userAgent: ua,
      deviceCredentialId: proofResult.credential.id,
      bindingNonce: parsed.data.nonce,
      targetApp: "operations-desk",
    });

    if (!issued.ok) {
      void auditConnect({
        eventType: "CONNECT_AUTHZ_DENIED",
        userId: session.userId,
        sessionId: session.id,
        ipAddress: ip,
        userAgent: ua,
        outcome: "DENIED",
        severity: "WARNING",
        metadata: { reason: issued.reason },
      });
      await escalateFailures({ session, ip, ua });

      if (issued.reason === "SESSION_INVALID") {
        return unauthorized("Session is no longer valid");
      }
      if (issued.reason === "ACCESS_REVOKED") {
        return forbidden("Access has been revoked", "ACCESS_REVOKED");
      }
      // §19 / GW §5: fail closed. A Gateway that is unreachable, slow, or
      // erroring denies Connect — it never implies authorization.
      return serverError("Authorization service error", issued.reason);
    }

    const authResult = issued.grant;

    await bindSessionDevice(session.id, proofResult.credential.id);

    void auditConnect({
      eventType: "CONNECT_GRANTED",
      userId: session.userId,
      sessionId: session.id,
      authzId: authResult.tokenId,
      ipAddress: ip,
      userAgent: ua,
      outcome: "SUCCESS",
      metadata: {
        expiresAt: authResult.expiresAt,
        ttlSeconds: authResult.ttlSeconds,
        deviceCredentialId: proofResult.credential.id,
        riskLevel: assessment.level,
        riskScore: assessment.score,
      },
    });

    // The grant itself never reaches the browser — only its opaque id.
    return NextResponse.json({
      granted: true,
      tokenId: authResult.tokenId,
      expiresAt: authResult.expiresAt,
      ttlSeconds: authResult.ttlSeconds,
      rateLimitRemaining: rateCheck.remaining,
    });
  });
}
