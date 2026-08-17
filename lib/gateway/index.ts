/**
 * lib/gateway/index.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * MOCK GATEWAY — Authorization verification for Website 2 stub
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * In a real deployment, this logic would live in a reverse proxy/gateway
 * (e.g. Envoy, nginx + Lua, or a custom auth sidecar) that sits in front
 * of Website 2. The gateway would call the Authorization Service on every
 * request to check if the session has a valid, non-expired, non-revoked
 * authorization token.
 *
 * MOCK BEHAVIOR:
 *   - Website 2 stub is at /api/internal
 *   - On every request, getIronSession() is used to get the session ID
 *   - verifyAuthorization() from authz-service is called (no caching)
 *   - No valid auth → generic 404 (NOT "Access Denied" — reveals nothing)
 *   - Valid auth → Website 2 stub content served
 *
 * PRODUCTION REPLACEMENT:
 *   - Move this check to a real gateway/proxy layer
 *   - The portal's /api/internal endpoint (or the real Website 2) would be
 *     completely unreachable without going through the gateway
 *   - Use mTLS between gateway and authorization service
 */

import { verifyAuthorization } from "../authz-service";

export interface GatewayCheckParams {
  tokenId: string;
  sessionId: string;
  userAgent: string;
}

export interface GatewayCheckResult {
  granted: boolean;
  userId?: string;
  expiresAt?: Date;
  reason?: string;
}

/**
 * Check if a request is authorized to access the internal site.
 * Called on every request to /api/internal — no decision is cached client-side.
 */
export async function checkGatewayAccess(
  params: GatewayCheckParams
): Promise<GatewayCheckResult> {
  const result = await verifyAuthorization({
    tokenId: params.tokenId,
    sessionId: params.sessionId,
    userAgent: params.userAgent,
  });

  if (!result.valid) {
    return {
      granted: false,
      reason: result.reason,
    };
  }

  return {
    granted: true,
    userId: result.userId,
    expiresAt: result.expiresAt,
  };
}
