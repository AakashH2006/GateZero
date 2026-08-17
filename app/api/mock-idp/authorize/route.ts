/**
 * app/api/mock-idp/authorize/route.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * MOCK IDENTITY PROVIDER — Authorization Endpoint with Custom Credentials Form
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * Supports:
 *   - Fast 1-click Sign-In with Default Demo Employee
 *   - Custom Credentials Creation Form (Name, Email, Secret Code/Key)
 */

import { NextRequest, NextResponse } from "next/server";
import crypto from "crypto";
import { DEV_MODE, MOCK_IDP_CLIENT_ID, APP_URL } from "@/lib/config";
import { mockIdpCodeStore } from "@/lib/auth/mock-idp-store";

// Periodic cleanup of expired codes
setInterval(() => {
  const now = Date.now();
  for (const [code, data] of mockIdpCodeStore.entries()) {
    if (data.expiresAt < now) mockIdpCodeStore.delete(code);
  }
}, 30_000);

export async function GET(request: NextRequest): Promise<NextResponse> {
  if (!DEV_MODE) {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }

  const { searchParams } = new URL(request.url);

  const clientId = searchParams.get("client_id");
  const responseType = searchParams.get("response_type");
  const redirectUri = searchParams.get("redirect_uri");
  const state = searchParams.get("state");
  const codeChallenge = searchParams.get("code_challenge");
  const codeChallengeMethod = searchParams.get("code_challenge_method");
  const nonce = searchParams.get("nonce");

  // Basic validation
  if (clientId !== MOCK_IDP_CLIENT_ID) {
    return NextResponse.json({ error: "invalid_client" }, { status: 400 });
  }
  if (responseType !== "code") {
    return NextResponse.json({ error: "unsupported_response_type" }, { status: 400 });
  }
  if (!redirectUri || !redirectUri.startsWith(APP_URL)) {
    return NextResponse.json({ error: "invalid_redirect_uri" }, { status: 400 });
  }
  if (!codeChallenge || codeChallengeMethod !== "S256") {
    return NextResponse.json({ error: "invalid_request: missing PKCE" }, { status: 400 });
  }

  // Check if custom credentials were passed directly in search query
  const customEmail = searchParams.get("custom_email");
  const customName = searchParams.get("custom_name");

  if (customEmail && customName) {
    const code = crypto.randomBytes(24).toString("hex");
    const customSub = `mock-idp|${crypto.createHash("sha256").update(customEmail).digest("hex").slice(0, 12)}`;

    mockIdpCodeStore.set(code, {
      codeChallenge,
      redirectUri,
      nonce: nonce ?? undefined,
      expiresAt: Date.now() + 60_000,
      user: {
        sub: customSub,
        email: customEmail,
        name: customName,
        email_verified: true,
      },
    });

    const callbackUrl = new URL(redirectUri);
    callbackUrl.searchParams.set("code", code);
    if (state) callbackUrl.searchParams.set("state", state);
    return NextResponse.redirect(callbackUrl.toString());
  }

  // Standard Authorization Code generation for 1-click default demo user
  const code = crypto.randomBytes(24).toString("hex");
  mockIdpCodeStore.set(code, {
    codeChallenge,
    redirectUri,
    nonce: nonce ?? undefined,
    expiresAt: Date.now() + 60_000,
  });

  const defaultCallbackUrl = new URL(redirectUri);
  defaultCallbackUrl.searchParams.set("code", code);
  if (state) defaultCallbackUrl.searchParams.set("state", state);

  // Return HTML page with both 1-click Demo Sign-In & Custom Credentials Creator
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>GateZero — SSO Identity Provider & Credentials Hub</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #090d16;
      color: #e2e8f0;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .card {
      background: rgba(15, 23, 42, 0.85);
      border: 1px solid rgba(99, 179, 237, 0.25);
      border-radius: 16px;
      padding: 36px;
      max-width: 460px;
      width: 100%;
      box-shadow: 0 20px 50px rgba(0,0,0,0.5);
      backdrop-filter: blur(12px);
    }
    .badge {
      display: inline-block;
      background: rgba(245,158,11,0.15);
      color: #f59e0b;
      border: 1px solid rgba(245,158,11,0.3);
      border-radius: 20px;
      padding: 4px 14px;
      font-size: 11px;
      font-weight: 700;
      margin-bottom: 20px;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }
    h1 { font-size: 22px; color: #63b3ed; margin-bottom: 6px; font-weight: 700; }
    p.subtitle { color: #94a3b8; font-size: 13px; margin-bottom: 24px; line-height: 1.5; }
    
    .section-title {
      font-size: 11px;
      font-weight: 700;
      color: #64748b;
      text-transform: uppercase;
      letter-spacing: 0.1em;
      margin-bottom: 12px;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .section-title::after {
      content: "";
      flex: 1;
      height: 1px;
      background: rgba(255,255,255,0.08);
    }

    .user-box {
      background: rgba(99,179,237,0.06);
      border: 1px solid rgba(99,179,237,0.18);
      border-radius: 10px;
      padding: 14px 16px;
      margin-bottom: 16px;
      text-align: left;
    }
    .user-box .label { font-size: 10px; color: #64748b; text-transform: uppercase; letter-spacing: 0.08em; }
    .user-box .value { font-size: 13px; color: #e2e8f0; font-weight: 600; margin-top: 2px; }

    .btn-default {
      display: block;
      width: 100%;
      padding: 12px;
      background: rgba(99, 179, 237, 0.12);
      border: 1px solid rgba(99, 179, 237, 0.3);
      color: #63b3ed;
      text-decoration: none;
      border-radius: 8px;
      font-size: 13px;
      font-weight: 600;
      text-align: center;
      transition: all 0.2s;
      margin-bottom: 24px;
    }
    .btn-default:hover {
      background: rgba(99, 179, 237, 0.22);
      color: #ffffff;
    }

    form { text-align: left; }
    .field-group { margin-bottom: 14px; }
    label { display: block; font-size: 11px; color: #94a3b8; margin-bottom: 6px; font-weight: 600; }
    input {
      width: 100%;
      padding: 10px 14px;
      background: rgba(15, 23, 42, 0.9);
      border: 1px solid rgba(148, 163, 184, 0.2);
      border-radius: 8px;
      color: #ffffff;
      font-size: 13px;
      outline: none;
      transition: border-color 0.2s;
    }
    input:focus {
      border-color: #3b82f6;
      box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.2);
    }
    .btn-primary {
      display: block;
      width: 100%;
      padding: 14px;
      background: linear-gradient(135deg, #3b82f6, #6366f1);
      border: none;
      color: white;
      border-radius: 8px;
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
      margin-top: 18px;
      box-shadow: 0 4px 14px rgba(59, 130, 246, 0.4);
      transition: opacity 0.2s;
    }
    .btn-primary:hover { opacity: 0.9; }
  </style>
</head>
<body>
  <div class="card">
    <div class="badge">🛡️ GATEZERO SSO IDENTITY HUB</div>
    <h1>Identity Provider</h1>
    <p class="subtitle">Choose quick demo access or create custom credentials for your user identity.</p>

    <!-- SECTION 1: Default Demo User -->
    <div class="section-title">Quick Demo Sign-In</div>
    <div class="user-box">
      <div class="label">Default Account</div>
      <div class="value">demo@zerogate.internal</div>
    </div>
    <a href="${defaultCallbackUrl.toString()}" class="btn-default">✓ Sign In as Default Demo Employee</a>

    <!-- SECTION 2: Create Custom Credentials -->
    <div class="section-title">Create Custom Credentials</div>
    <form action="/api/mock-idp/authorize" method="POST">
      <!-- Preserve OAuth Params -->
      <input type="hidden" name="client_id" value="${clientId || ''}">
      <input type="hidden" name="response_type" value="${responseType || ''}">
      <input type="hidden" name="redirect_uri" value="${redirectUri || ''}">
      <input type="hidden" name="state" value="${state || ''}">
      <input type="hidden" name="code_challenge" value="${codeChallenge || ''}">
      <input type="hidden" name="code_challenge_method" value="${codeChallengeMethod || ''}">
      <input type="hidden" name="nonce" value="${nonce || ''}">

      <div class="field-group">
        <label for="custom_name">Full Name</label>
        <input type="text" id="custom_name" name="custom_name" placeholder="e.g. Sahas Kumar" required>
      </div>

      <div class="field-group">
        <label for="custom_email">Email Address (for MFA Codes)</label>
        <input type="email" id="custom_email" name="custom_email" placeholder="e.g. sahas@company.com" required>
      </div>

      <div class="field-group">
        <label for="secret_code">Secret Passcode / Security Key</label>
        <input type="password" id="secret_code" name="secret_code" placeholder="Enter your custom secret key" required>
      </div>

      <button type="submit" class="btn-primary">+ Create & Sign In with My Credentials →</button>
    </form>
  </div>
</body>
</html>`;

  return new NextResponse(html, {
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}

/**
 * Handle POST submission for Custom Credentials Creation
 */
export async function POST(request: NextRequest): Promise<NextResponse> {
  if (!DEV_MODE) {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }

  const formData = await request.formData();
  const clientId = formData.get("client_id") as string;
  const redirectUri = formData.get("redirect_uri") as string;
  const state = formData.get("state") as string;
  const codeChallenge = formData.get("code_challenge") as string;
  const nonce = formData.get("nonce") as string;

  const customName = formData.get("custom_name") as string;
  const customEmail = formData.get("custom_email") as string;
  const secretCode = formData.get("secret_code") as string;

  if (!customName || !customEmail || !secretCode) {
    return NextResponse.json({ error: "Missing custom credential fields" }, { status: 400 });
  }

  const code = crypto.randomBytes(24).toString("hex");
  const customSub = `mock-idp|${crypto.createHash("sha256").update(customEmail + secretCode).digest("hex").slice(0, 12)}`;

  mockIdpCodeStore.set(code, {
    codeChallenge,
    redirectUri,
    nonce: nonce || undefined,
    expiresAt: Date.now() + 60_000,
    user: {
      sub: customSub,
      email: customEmail,
      name: customName,
      email_verified: true,
    },
  });

  const callbackUrl = new URL(redirectUri);
  callbackUrl.searchParams.set("code", code);
  if (state) callbackUrl.searchParams.set("state", state);

  // Return HTTP 303 (See Other) to force the browser to convert POST to GET for the callback redirect
  return NextResponse.redirect(callbackUrl.toString(), 303);
}
