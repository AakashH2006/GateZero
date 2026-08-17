/**
 * lib/auth/sso-config.ts
 * SSO / OIDC provider configuration.
 *
 * MOCK vs REAL boundary:
 * ─────────────────────
 * When DEV_MODE=true, the "IdP" is a local stub at /api/mock-idp/*.
 * When DEV_MODE=false, set OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET in env.
 *
 * To swap to a real IdP (Okta/Azure AD/Google Workspace):
 *   1. Set DEV_MODE=false
 *   2. Set the four OIDC_* env vars
 *   3. That's it — the rest of the auth flow is IdP-agnostic.
 */

import {
  APP_URL,
  DEV_MODE,
  MOCK_IDP_CLIENT_ID,
  MOCK_IDP_CLIENT_SECRET,
  OIDC_CLIENT_ID,
  OIDC_CLIENT_SECRET,
  OIDC_ISSUER,
  OIDC_REDIRECT_URI,
} from "../config";

export interface SSOConfig {
  /** OAuth2 authorization endpoint */
  authorizationEndpoint: string;
  /** OAuth2 token endpoint */
  tokenEndpoint: string;
  /** OIDC userinfo endpoint (or null if claims come from id_token) */
  userinfoEndpoint: string | null;
  /** OAuth2 client ID */
  clientId: string;
  /** OAuth2 client secret */
  clientSecret: string;
  /** Where the IdP should redirect after authentication */
  redirectUri: string;
  /** OAuth2 scopes to request */
  scopes: string[];
}

function getMockSSOConfig(): SSOConfig {
  const base = `${APP_URL}/api/mock-idp`;
  return {
    authorizationEndpoint: `${base}/authorize`,
    tokenEndpoint: `${base}/token`,
    userinfoEndpoint: null, // mock returns all claims in the token response
    clientId: MOCK_IDP_CLIENT_ID,
    clientSecret: MOCK_IDP_CLIENT_SECRET,
    redirectUri: `${APP_URL}/api/auth/callback`,
    scopes: ["openid", "profile", "email"],
  };
}

function getRealSSOConfig(): SSOConfig {
  if (!OIDC_ISSUER || !OIDC_CLIENT_ID || !OIDC_CLIENT_SECRET) {
    throw new Error(
      "DEV_MODE is false but OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET are not set."
    );
  }
  return {
    authorizationEndpoint: `${OIDC_ISSUER}/oauth2/v1/authorize`,
    tokenEndpoint: `${OIDC_ISSUER}/oauth2/v1/token`,
    userinfoEndpoint: `${OIDC_ISSUER}/oauth2/v1/userinfo`,
    clientId: OIDC_CLIENT_ID,
    clientSecret: OIDC_CLIENT_SECRET,
    redirectUri: OIDC_REDIRECT_URI,
    scopes: ["openid", "profile", "email"],
  };
}

/** Returns the SSO config appropriate for the current environment. */
export function getSSOConfig(): SSOConfig {
  return DEV_MODE ? getMockSSOConfig() : getRealSSOConfig();
}

/** Standard claims expected from any OIDC-compatible IdP */
export interface IdentityClaims {
  sub: string;       // IdP subject — unique, stable identifier
  email: string;
  name: string;
  email_verified?: boolean;
}
