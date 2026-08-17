/**
 * app/api/mock-idp/token/route.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * MOCK IDENTITY PROVIDER — Token Endpoint
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * Exchanges an authorization code for identity claims.
 * Only active when DEV_MODE=true.
 */

import { NextRequest, NextResponse } from "next/server";
import { DEV_MODE, MOCK_IDP_CLIENT_ID, MOCK_IDP_CLIENT_SECRET } from "@/lib/config";
import { verifyCodeChallenge } from "@/lib/auth/pkce";
import { mockIdpCodeStore } from "@/lib/auth/mock-idp-store";
import type { IdentityClaims } from "@/lib/auth/sso-config";

const MOCK_DEMO_USER: IdentityClaims = {
  sub: "mock-idp|demo-user-001",
  email: "demo@zerogate.internal",
  name: "Demo Employee",
  email_verified: true,
};

export async function POST(request: NextRequest): Promise<NextResponse> {
  if (!DEV_MODE) {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }

  let body: Record<string, string>;

  const contentType = request.headers.get("content-type") ?? "";
  if (contentType.includes("application/x-www-form-urlencoded")) {
    const text = await request.text();
    body = Object.fromEntries(new URLSearchParams(text));
  } else {
    body = await request.json();
  }

  const {
    grant_type,
    code,
    redirect_uri,
    code_verifier,
    client_id,
    client_secret,
  } = body;

  if (grant_type !== "authorization_code") {
    return NextResponse.json({ error: "unsupported_grant_type" }, { status: 400 });
  }
  if (client_id !== MOCK_IDP_CLIENT_ID || client_secret !== MOCK_IDP_CLIENT_SECRET) {
    return NextResponse.json({ error: "invalid_client" }, { status: 401 });
  }
  if (!code || !code_verifier) {
    return NextResponse.json({ error: "invalid_request" }, { status: 400 });
  }

  // Look up the code from the shared singleton store
  const codeData = mockIdpCodeStore.get(code);
  if (!codeData) {
    return NextResponse.json({ error: "invalid_grant: code not found or expired" }, { status: 400 });
  }
  if (codeData.expiresAt < Date.now()) {
    mockIdpCodeStore.delete(code);
    return NextResponse.json({ error: "invalid_grant: code expired" }, { status: 400 });
  }
  if (codeData.redirectUri !== redirect_uri) {
    return NextResponse.json({ error: "invalid_grant: redirect_uri mismatch" }, { status: 400 });
  }

  // Verify PKCE
  if (!verifyCodeChallenge(code_verifier, codeData.codeChallenge)) {
    mockIdpCodeStore.delete(code);
    return NextResponse.json({ error: "invalid_grant: PKCE verification failed" }, { status: 400 });
  }

  // Resolve user identity (custom created user or default demo user)
  const userClaims: IdentityClaims = codeData.user ?? MOCK_DEMO_USER;

  // Consume the code (one-time use)
  mockIdpCodeStore.delete(code);

  return NextResponse.json({
    token_type: "Bearer",
    expires_in: 3600,
    user: userClaims,
  });
}
