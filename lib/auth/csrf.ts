/**
 * lib/auth/csrf.ts
 * CSRF protection for security-sensitive, state-changing endpoints (e.g. /api/connect).
 *
 * Pattern: signed double-submit token.
 *   - Token = HMAC-SHA256(sessionId) using SESSION_SECRET.
 *   - Server never stores it — it's cheaply recomputed and compared.
 *   - Handed to the frontend via the JSON session response (readable by JS,
 *     which is fine — it is NOT the httpOnly session cookie and proves nothing
 *     by itself without also holding a valid session).
 *   - Caller must echo it back on a custom header (x-csrf-token) for any
 *     mutating request. A cross-site form/fetch cannot read the response body
 *     of an authenticated same-origin request, so it cannot obtain a valid
 *     token to replay, even though the browser would auto-attach the session
 *     cookie.
 *
 * This is defense-in-depth on top of (not instead of) SameSite=Lax cookies.
 */

import crypto from "crypto";
import { SESSION_SECRET } from "../config";

export const CSRF_HEADER = "x-csrf-token";

export function signCsrfToken(sessionId: string): string {
  return crypto.createHmac("sha256", SESSION_SECRET).update(sessionId).digest("hex");
}

/** Constant-time comparison to avoid timing side-channels on token check. */
export function verifyCsrfToken(sessionId: string, presentedToken: string | null): boolean {
  if (!presentedToken) return false;

  const expected = signCsrfToken(sessionId);
  const expectedBuf = Buffer.from(expected, "hex");
  const presentedBuf = Buffer.from(presentedToken, "hex");

  if (expectedBuf.length !== presentedBuf.length) return false;
  return crypto.timingSafeEqual(expectedBuf, presentedBuf);
}
