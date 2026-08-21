/**
 * proxy.ts
 * Runs on every request before route handlers.
 *
 * (Next.js 16 renamed Middleware to Proxy; the file must be named proxy.ts and
 * export `proxy`. The functionality is unchanged.)
 *
 * Responsibilities:
 *   1. Security headers (CSP, HSTS, X-Frame-Options, etc.) on ALL responses
 *      — website-1-defense.md §18
 *   2. Cheap route protection: redirect anonymous browsers away from /dashboard
 *      and /admin
 *   3. Block direct access to mock IdP endpoints when DEV_MODE=false
 *
 * WHAT THIS IS NOT
 * ────────────────
 * The cookie check below is an optimistic redirect, not an authorization
 * decision. It only asks whether a session cookie is present — it does not
 * validate it, and it cannot: a revoked or expired session still carries a
 * cookie. Every protected route re-checks the session server-side, and the
 * Next.js docs are explicit that Proxy "should not be used as a full session
 * management or authorization solution". Treating this as the access control
 * would mean anyone who sets a cookie of the right name walks in.
 */

import { NextRequest, NextResponse } from "next/server";
import { IRON_SESSION_OPTIONS, DEV_MODE } from "./lib/config";

// Routes that require a valid ACTIVE session
const PROTECTED_ROUTES = ["/dashboard", "/admin"];

export async function proxy(request: NextRequest): Promise<NextResponse> {
  const { pathname } = request.nextUrl;

  // ── Block mock IdP in production ───────────────────────────────────────────
  if (!DEV_MODE && pathname.startsWith("/api/mock-idp")) {
    return new NextResponse(null, { status: 404 });
  }

  // ── Security headers ───────────────────────────────────────────────────────
  const response = NextResponse.next();

  // In development, Next.js Turbopack / HMR & React devtools require 'unsafe-eval'
  const isDev = process.env.NODE_ENV !== "production";
  const scriptSrc = isDev
    ? "script-src 'self' 'unsafe-inline' 'unsafe-eval'"
    : "script-src 'self' 'unsafe-inline'";

  // Content Security Policy
  const csp = [
    "default-src 'self'",
    scriptSrc,
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "img-src 'self' data:",
    "font-src 'self' https://fonts.gstatic.com",
    "connect-src 'self'",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'",
  ].join("; ");

  response.headers.set("Content-Security-Policy", csp);
  response.headers.set("X-Frame-Options", "DENY");
  response.headers.set("X-Content-Type-Options", "nosniff");
  response.headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
  response.headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");

  // HSTS — only in production (not on localhost)
  if (!isDev) {
    response.headers.set(
      "Strict-Transport-Security",
      "max-age=63072000; includeSubDomains; preload"
    );
  }

  // Remove information-leaking headers
  response.headers.delete("X-Powered-By");

  // ── Route protection ───────────────────────────────────────────────────────
  const needsProtection = PROTECTED_ROUTES.some((r) => pathname.startsWith(r));

  if (needsProtection) {
    const cookieHeader = request.headers.get("cookie") ?? "";
    const sessionCookieName = IRON_SESSION_OPTIONS.cookieName;
    if (!cookieHeader.includes(sessionCookieName)) {
      const loginUrl = new URL("/", request.url);
      loginUrl.searchParams.set("redirect", pathname);
      return NextResponse.redirect(loginUrl);
    }
  }

  return response;
}

export const config = {
  matcher: [
    // Match all routes except Next.js internals and static files
    "/((?!_next/static|_next/image|favicon.ico|.*\\.png$|.*\\.jpg$|.*\\.svg$).*)",
  ],
};
