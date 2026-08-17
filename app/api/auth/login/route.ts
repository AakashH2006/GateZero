/**
 * app/api/auth/login/route.ts
 * Initiates the OAuth2 Authorization Code + PKCE flow.
 * Redirects the browser to the IdP (mock or real) authorization endpoint.
 */

import { NextRequest, NextResponse } from "next/server";
import { getSSOConfig } from "@/lib/auth/sso-config";
import { generateCodeVerifier, generateCodeChallenge, generateState, generateNonce } from "@/lib/auth/pkce";
import { getIronSession } from "iron-session";
import { cookies } from "next/headers";
import { IRON_SESSION_OPTIONS } from "@/lib/config";
import { auditLogin, getClientIP, getClientUA } from "@/lib/audit";
import { safeHandler } from "@/lib/errors";

interface LoginSessionData {
  sessionId?: string;
  pkceVerifier?: string;
  oauthState?: string;
  nonce?: string;
}

export async function GET(request: NextRequest): Promise<NextResponse> {
  return safeHandler(async () => {
    const config = getSSOConfig();

    // Generate PKCE values
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);
    const state = generateState();
    const nonce = generateNonce();

    // Store PKCE verifier and state in the session cookie for callback verification
    const cookieStore = await cookies();
    const ironSession = await getIronSession<LoginSessionData>(cookieStore, IRON_SESSION_OPTIONS);
    ironSession.pkceVerifier = codeVerifier;
    ironSession.oauthState = state;
    ironSession.nonce = nonce;
    await ironSession.save();

    // Build the IdP authorization URL
    const authUrl = new URL(config.authorizationEndpoint);
    authUrl.searchParams.set("client_id", config.clientId);
    authUrl.searchParams.set("response_type", "code");
    authUrl.searchParams.set("redirect_uri", config.redirectUri);
    authUrl.searchParams.set("scope", config.scopes.join(" "));
    authUrl.searchParams.set("state", state);
    authUrl.searchParams.set("code_challenge", codeChallenge);
    authUrl.searchParams.set("code_challenge_method", "S256");
    authUrl.searchParams.set("nonce", nonce);

    // Audit log: SSO flow initiated
    void auditLogin({
      eventType: "SSO_INITIATED",
      ipAddress: getClientIP(request),
      userAgent: getClientUA(request),
      outcome: "SUCCESS",
      metadata: { idpEndpoint: config.authorizationEndpoint },
    });

    return NextResponse.redirect(authUrl.toString());
  });
}
