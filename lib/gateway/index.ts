/**
 * lib/gateway/index.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * ACCESS GATEWAY
 * website-2-defense.md §2, §15, §24, §25 / website-1-defense.md §4, §8, §21
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * The Gateway is the final enforcement point (W1 §21). It validates the
 * authorization, controls the transition into Website 2, enforces one-time use,
 * and carries critical security events across the boundary. It does nothing
 * else — §25 is explicit that it must stay small: no passwords, no business
 * data, no general-purpose API, no monitoring of Website 2, not an EDR.
 *
 * It is also the only component that knows where Website 2 lives. Website 1
 * requests an authorization and never learns a destination (W1 §4, §9), which
 * is why target resolution sits here rather than in the Connect route.
 *
 * EXTERNAL RESPONSE DISCIPLINE (W2 §15)
 * ─────────────────────────────────────
 * Internally the Gateway distinguishes expired / already-consumed / device
 * mismatch / revoked. Externally it returns one generic denial. Telling an
 * attacker *why* a grant failed tells them what to fix; `publicDenial()` below
 * is the single place that translation happens.
 *
 * MOCK BOUNDARY
 * ─────────────
 * In production this logic runs in a reverse proxy or auth sidecar in front of
 * Website 2, reached over mTLS, with Website 2 unroutable from anywhere else.
 * Here it is a module the Next app and the Operations Desk both call. The trust
 * decisions are real; the network isolation is not.
 */

import {
  introspectTokenLive,
  consumeAuthorization,
  type AuthorizationVerification,
} from "../authz-service";
import { resolveTargetApp } from "../config";

export interface GatewayCheckParams {
  tokenId: string;
  /** §8: the credential the presenting device just proved possession of. */
  deviceCredentialId?: string;
  /** Telemetry only. */
  userAgent?: string;
  ipAddress?: string;
}

export interface GatewayCheckResult {
  granted: boolean;
  userId?: string;
  userEmail?: string;
  userName?: string;
  userRole?: string;
  sessionId?: string;
  deviceCredentialId?: string;
  expiresAt?: Date;
  emergency?: boolean;
  /** INTERNAL reason for logging. Never returned to the client. */
  reason?: string;
}

/**
 * The single external denial message.
 *
 * One string for every failure mode, on purpose. A caller that wants to log the
 * real cause reads `reason` from the check result instead.
 */
export function publicDenial(): { error: string; code: string } {
  return { error: "Access denied", code: "ACCESS_DENIED" };
}

function fromVerification(v: AuthorizationVerification): GatewayCheckResult {
  if (!v.valid) return { granted: false, reason: v.reason };
  return {
    granted: true,
    userId: v.userId,
    userEmail: v.userEmail,
    userName: v.userName,
    userRole: v.userRole,
    sessionId: v.sessionId,
    deviceCredentialId: v.deviceCredentialId,
    expiresAt: v.expiresAt,
    emergency: v.emergency,
  };
}

/**
 * Validate an authorization without spending it.
 *
 * Used for the pre-flight check before Website 2 runs its own independent
 * device verification (§8.1). Deliberately non-consuming: a grant must not be
 * burned by a check that has not yet resulted in a session.
 */
export async function checkGatewayAccess(
  params: GatewayCheckParams
): Promise<GatewayCheckResult> {
  return fromVerification(
    await introspectTokenLive({
      tokenId: params.tokenId,
      userAgent: params.userAgent,
      ipAddress: params.ipAddress,
      deviceCredentialId: params.deviceCredentialId,
    })
  );
}

/**
 * Validate and consume, for the moment a Website 2 session is actually
 * established (W2 §3 step 9, §24).
 *
 * Consumption is atomic inside the Authorization Service, so two devices
 * redeeming the same grant produce exactly one winner. The loser's second
 * attempt is a replay and is reported as such internally while the client sees
 * only the generic denial.
 */
export async function redeemGatewayAuthorization(params: {
  tokenId: string;
  deviceCredentialId: string;
  userAgent?: string;
  ipAddress?: string;
}): Promise<GatewayCheckResult> {
  const check = await checkGatewayAccess(params);
  if (!check.granted) return check;

  const consumed = await consumeAuthorization({
    tokenId: params.tokenId,
    deviceCredentialId: params.deviceCredentialId,
  });
  if (!consumed.ok) return { granted: false, reason: consumed.reason };

  return check;
}

/**
 * Resolve where a target application lives.
 *
 * Returns null for an unknown target rather than echoing it back, so the
 * Gateway cannot be turned into an open redirector by a caller naming an
 * arbitrary destination.
 */
export function resolveTarget(targetApp: string): string | null {
  return resolveTargetApp(targetApp);
}

/** Build the front-channel handoff URL for a target application. */
export function buildHandoffUrl(targetApp: string, code: string): string | null {
  const base = resolveTarget(targetApp);
  if (!base) return null;
  return `${base}/api/auth/callback?code=${encodeURIComponent(code)}`;
}
