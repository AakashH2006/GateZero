/**
 * app/api/auth/callback/route.ts
 * Handles the OAuth2 callback after IdP authentication.
 *
 * Flow:
 *   1. Receives ?code=...&state=... from IdP redirect
 *   2. Validates state (CSRF protection)
 *   3. Exchanges code for identity claims at token endpoint (with PKCE verifier)
 *   4. Upserts user in DB (supporting custom credentials)
 *   5. Creates a PENDING_MFA session
 *   6. Redirects to /mfa page
 */

import { NextRequest, NextResponse } from "next/server";
import { getIronSession } from "iron-session";
import { cookies } from "next/headers";
import { IRON_SESSION_OPTIONS, APP_URL } from "@/lib/config";
import { getSSOConfig, IdentityClaims } from "@/lib/auth/sso-config";
import { prisma } from "@/lib/db";
import { createPendingSession } from "@/lib/auth/session";
import { beginMFAChallenge } from "@/lib/auth/mfa";
import { auditLogin, getClientIP, getClientUA } from "@/lib/audit";
import { badRequest, serverError, safeHandler } from "@/lib/errors";
import { UserRole } from "@prisma/client";

interface LoginSessionData {
  sessionId?: string;
  pkceVerifier?: string;
  oauthState?: string;
  nonce?: string;
}

export async function GET(request: NextRequest): Promise<NextResponse> {
  return safeHandler(async () => {
    const { searchParams } = new URL(request.url);
    const code = searchParams.get("code");
    const state = searchParams.get("state");
    const error = searchParams.get("error");
    const ip = getClientIP(request);
    const ua = getClientUA(request);

    // Handle IdP error responses
    if (error) {
      void auditLogin({
        eventType: "SSO_CALLBACK_ERROR",
        ipAddress: ip,
        userAgent: ua,
        outcome: "FAILURE",
        metadata: { error },
      });
      return NextResponse.redirect(`${APP_URL}/?error=sso_failed`);
    }

    if (!code || !state) {
      return NextResponse.redirect(`${APP_URL}/?error=sso_failed`);
    }

    // Retrieve PKCE verifier and validate state from session cookie
    const cookieStore = await cookies();
    const ironSession = await getIronSession<LoginSessionData>(cookieStore, IRON_SESSION_OPTIONS);

    if (!ironSession.oauthState || ironSession.oauthState !== state) {
      void auditLogin({
        eventType: "SSO_STATE_MISMATCH",
        ipAddress: ip,
        userAgent: ua,
        outcome: "FAILURE",
        metadata: {},
      });
      return NextResponse.redirect(`${APP_URL}/?error=invalid_state`);
    }

    const codeVerifier = ironSession.pkceVerifier;
    if (!codeVerifier) {
      return NextResponse.redirect(`${APP_URL}/?error=missing_verifier`);
    }

    // Exchange code for identity claims at the token endpoint
    const config = getSSOConfig();
    const tokenResponse = await fetch(config.tokenEndpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: config.redirectUri,
        code_verifier: codeVerifier,
        client_id: config.clientId,
        client_secret: config.clientSecret,
      }),
    });

    if (!tokenResponse.ok) {
      const errBody = await tokenResponse.text();
      console.error("[SSO Callback] Token exchange failed:", errBody);
      void auditLogin({
        eventType: "SSO_TOKEN_EXCHANGE_FAILED",
        ipAddress: ip,
        userAgent: ua,
        outcome: "FAILURE",
        metadata: { status: tokenResponse.status },
      });
      return NextResponse.redirect(`${APP_URL}/?error=token_exchange_failed`);
    }

    const tokenData = await tokenResponse.json() as { user: IdentityClaims };
    const claims: IdentityClaims = tokenData.user;

    if (!claims.sub || !claims.email) {
      return serverError("IdP returned invalid claims");
    }

    // Check if user exists by idpSubject OR by email
    const existingUser = await prisma.user.findFirst({
      where: {
        OR: [
          { idpSubject: claims.sub },
          { email: claims.email },
        ],
      },
    });

    let user;
    if (existingUser) {
      user = await prisma.user.update({
        where: { id: existingUser.id },
        data: {
          email: claims.email,
          name: claims.name,
          idpSubject: claims.sub,
        },
      });
    } else {
      user = await prisma.user.create({
        data: {
          idpSubject: claims.sub,
          email: claims.email,
          name: claims.name,
          role: UserRole.EMPLOYEE,
        },
      });
    }

    // Create a PENDING_MFA session
    const session = await createPendingSession({
      userId: user.id,
      ipAddress: ip,
      userAgent: ua,
    });

    // Start MFA challenge
    await beginMFAChallenge(session.id);

    // Write session ID and clear PKCE state from cookie
    ironSession.sessionId = session.id;
    ironSession.pkceVerifier = undefined;
    ironSession.oauthState = undefined;
    ironSession.nonce = undefined;
    await ironSession.save();

    void auditLogin({
      eventType: "SSO_CALLBACK_SUCCESS",
      userId: user.id,
      sessionId: session.id,
      ipAddress: ip,
      userAgent: ua,
      outcome: "SUCCESS",
      metadata: { email: claims.email, name: claims.name },
    });

    return NextResponse.redirect(`${APP_URL}/mfa`);
  });
}

// Allow both GET and POST requests on callback route
export const POST = GET;
