/**
 * app/api/internal/route.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * MOCK GATEWAY / WEBSITE 2 STUB
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * This endpoint simulates "Website 2, reached through the Gateway."
 *
 * SECURITY BEHAVIOR:
 *   - No valid authorization → returns generic 404 (NOT "Access Denied")
 *     The response reveals nothing about what exists behind this URL.
 *   - Valid authorization → serves stub content
 *   - Authorization is re-checked on EVERY request (no client-side caching)
 *   - Checks session binding: the authorization must belong to the requesting session
 *   - Checks device binding: hashed User-Agent must match the issuing request
 *
 * URL: /api/internal
 * The browser sends: ?tokenId=...&sessionId=... as query params
 * (In a real system, the gateway would extract these from a session cookie
 * or a short-lived header — the mechanism here is simplified for the mock)
 *
 * PRODUCTION REPLACEMENT:
 *   - This endpoint (and everything behind it) moves to a separate internal host
 *   - The gateway proxy checks the authorization via mTLS to the AuthZ service
 *   - The URL is never exposed in the portal's client-side code until access is confirmed
 */

import { NextRequest, NextResponse } from "next/server";
import { checkGatewayAccess } from "@/lib/gateway";
import { auditConnect, getClientIP, getClientUA } from "@/lib/audit";
import { getValidSession } from "@/lib/auth/session";

export async function GET(request: NextRequest): Promise<NextResponse> {
  const ip = getClientIP(request);
  const ua = getClientUA(request);

  // Get the session from the session cookie
  const session = await getValidSession();

  // Get tokenId from query params
  const { searchParams } = new URL(request.url);
  const tokenId = searchParams.get("tokenId");

  // No tokenId or no session → generic 404 (not "access denied")
  if (!tokenId || !session) {
    return new NextResponse(null, { status: 404 });
  }

  // Check authorization — re-verified on every request, no caching
  const result = await checkGatewayAccess({
    tokenId,
    sessionId: session.id,
    userAgent: ua,
  });

  if (!result.granted) {
    void auditConnect({
      eventType: "GATEWAY_ACCESS_DENIED",
      userId: session?.userId,
      sessionId: session?.id,
      ipAddress: ip,
      userAgent: ua,
      outcome: "DENIED",
      metadata: { reason: result.reason, tokenId },
    });

    // Generic 404 — reveals nothing about why or what exists here
    return new NextResponse(null, { status: 404 });
  }

  void auditConnect({
    eventType: "GATEWAY_ACCESS_GRANTED",
    userId: result.userId,
    sessionId: session.id,
    ipAddress: ip,
    userAgent: ua,
    outcome: "SUCCESS",
    metadata: {
      tokenId,
      expiresAt: result.expiresAt,
    },
  });

  // Serve stub "Website 2" content
  const remainingMs = result.expiresAt
    ? result.expiresAt.getTime() - Date.now()
    : 0;
  const remainingSecs = Math.max(0, Math.floor(remainingMs / 1000));

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>GateZero Internal</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: system-ui, -apple-system, sans-serif;
      background: #0a0f1e;
      color: #e2e8f0;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .container {
      max-width: 600px;
      width: 100%;
      padding: 40px 24px;
      text-align: center;
    }
    .status-dot {
      width: 12px; height: 12px;
      background: #22c55e;
      border-radius: 50%;
      display: inline-block;
      margin-right: 8px;
      animation: pulse 2s infinite;
    }
    @keyframes pulse {
      0%, 100% { opacity: 1; }
      50% { opacity: 0.4; }
    }
    .badge {
      display: inline-flex;
      align-items: center;
      background: rgba(34,197,94,0.1);
      border: 1px solid rgba(34,197,94,0.3);
      border-radius: 9999px;
      padding: 6px 16px;
      font-size: 13px;
      color: #22c55e;
      margin-bottom: 32px;
    }
    h1 { font-size: 28px; font-weight: 700; color: #f1f5f9; margin-bottom: 12px; }
    .subtitle { color: #64748b; font-size: 15px; margin-bottom: 32px; line-height: 1.6; }
    .card {
      background: rgba(255,255,255,0.04);
      border: 1px solid rgba(255,255,255,0.08);
      border-radius: 12px;
      padding: 24px;
      text-align: left;
    }
    .card h2 { font-size: 13px; font-weight: 600; color: #64748b; text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 16px; }
    .row { display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid rgba(255,255,255,0.05); font-size: 14px; }
    .row:last-child { border-bottom: none; }
    .row .label { color: #94a3b8; }
    .row .value { color: #e2e8f0; font-weight: 500; }
    .ttl { color: #f59e0b !important; }
    .mock-notice {
      margin-top: 24px;
      padding: 12px 16px;
      background: rgba(245,158,11,0.08);
      border: 1px solid rgba(245,158,11,0.2);
      border-radius: 8px;
      font-size: 12px;
      color: #92400e;
      color: #fbbf24;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="badge"><span class="status-dot"></span>Authorized Access</div>
    <h1>GateZero Internal Application</h1>
    <p class="subtitle">
      This is the mock Website 2 stub. In a real deployment, this page would
      be hosted on a private network, never reachable without a valid
      authorization from the GateZero Portal.
    </p>
    <div class="card">
      <h2>Session Details</h2>
      <div class="row">
        <span class="label">User</span>
        <span class="value">${result.userId}</span>
      </div>
      <div class="row">
        <span class="label">Authorization expires in</span>
        <span class="value ttl" id="countdown">${remainingSecs}s</span>
      </div>
      <div class="row">
        <span class="label">Token ID</span>
        <span class="value">${tokenId.slice(0, 12)}...</span>
      </div>
    </div>
    <div class="mock-notice">
      🔧 MOCK WEBSITE 2 — This endpoint checks authorization on every request.
      When your authorization expires, the next request will return 404.
    </div>
  </div>
  <script>
    let ttl = ${remainingSecs};
    const el = document.getElementById('countdown');
    const t = setInterval(() => {
      ttl--;
      if (ttl <= 0) { el.textContent = 'EXPIRED'; clearInterval(t); return; }
      el.textContent = ttl + 's';
    }, 1000);
  </script>
</body>
</html>`;

  return new NextResponse(html, {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store, no-cache, must-revalidate",
      "X-Robots-Tag": "noindex, nofollow",
    },
  });
}
