/**
 * lib/auth/pkce.ts
 * PKCE (Proof Key for Code Exchange) helpers for OAuth2 Authorization Code flow.
 * Used by both the real OIDC path and the mock IdP path — so swapping IdPs
 * doesn't require changing the PKCE implementation.
 *
 * RFC 7636: https://www.rfc-editor.org/rfc/rfc7636
 */

import crypto from "crypto";

/**
 * Generate a cryptographically random code verifier (43–128 chars, URL-safe).
 */
export function generateCodeVerifier(): string {
  const bytes = crypto.randomBytes(32);
  return bytes
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

/**
 * Derive the code challenge from a code verifier using S256 method.
 * code_challenge = BASE64URL(SHA256(ASCII(code_verifier)))
 */
export function generateCodeChallenge(verifier: string): string {
  const hash = crypto.createHash("sha256").update(verifier).digest();
  return hash
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

/**
 * Verify that a code challenge matches the given verifier.
 * Used by the token endpoint (real or mock).
 */
export function verifyCodeChallenge(verifier: string, challenge: string): boolean {
  const expected = generateCodeChallenge(verifier);
  // Constant-time comparison to prevent timing attacks
  if (expected.length !== challenge.length) return false;
  return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(challenge));
}

/**
 * Generate a random state parameter for CSRF protection.
 */
export function generateState(): string {
  return crypto.randomBytes(16).toString("hex");
}

/**
 * Generate a random nonce for OIDC id_token validation.
 */
export function generateNonce(): string {
  return crypto.randomBytes(16).toString("hex");
}
