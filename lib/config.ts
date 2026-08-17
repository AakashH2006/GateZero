/**
 * lib/config.ts
 * Central configuration and environment variable parsing for GateZero Portal.
 * All env access goes through this module — never read process.env directly elsewhere.
 */

function requireEnv(key: string): string {
  const value = process.env[key];
  if (!value) {
    throw new Error(`Missing required environment variable: ${key}`);
  }
  return value;
}

function optionalEnv(key: string, fallback: string): string {
  return process.env[key] ?? fallback;
}

// ── Dev mode flag ──────────────────────────────────────────────────────────────
// When true: mock IdP active, MFA accepts any 6-digit code, admin uses secret header
// MUST be false in production
export const DEV_MODE = optionalEnv("DEV_MODE", "false") === "true";

// ── Application ───────────────────────────────────────────────────────────────
export const APP_URL = optionalEnv("NEXT_PUBLIC_APP_URL", "http://localhost:3000");

// ── Session ────────────────────────────────────────────────────────────────────
export const SESSION_SECRET = requireEnv("SESSION_SECRET");
export const SESSION_TTL_DAYS = 7;
export const SESSION_TTL_MS = SESSION_TTL_DAYS * 24 * 60 * 60 * 1000;

// ── Authorization tokens ───────────────────────────────────────────────────────
export const AUTHZ_SIGNING_SECRET = requireEnv("AUTHZ_SIGNING_SECRET");
export const AUTHZ_TTL_SECONDS = parseInt(optionalEnv("AUTHZ_TTL_SECONDS", "300"), 10);

// ── Rate limiting ──────────────────────────────────────────────────────────────
export const RATE_LIMIT_MAX = parseInt(optionalEnv("RATE_LIMIT_MAX", "5"), 10);
export const RATE_LIMIT_WINDOW_SECONDS = parseInt(
  optionalEnv("RATE_LIMIT_WINDOW_SECONDS", "60"),
  10
);

// ── Admin (dev-mode only) ──────────────────────────────────────────────────────
export const ADMIN_SECRET = optionalEnv("ADMIN_SECRET", "");

// ── Mock IdP (dev-mode only) ───────────────────────────────────────────────────
export const MOCK_IDP_CLIENT_ID = optionalEnv("MOCK_IDP_CLIENT_ID", "zerogate-dev-client");
export const MOCK_IDP_CLIENT_SECRET = optionalEnv("MOCK_IDP_CLIENT_SECRET", "mock-secret");

// ── Real OIDC provider (production) ───────────────────────────────────────────
// These are only used when DEV_MODE=false
export const OIDC_ISSUER = optionalEnv("OIDC_ISSUER", "");
export const OIDC_CLIENT_ID = optionalEnv("OIDC_CLIENT_ID", "");
export const OIDC_CLIENT_SECRET = optionalEnv("OIDC_CLIENT_SECRET", "");
export const OIDC_REDIRECT_URI = optionalEnv(
  "OIDC_REDIRECT_URI",
  `${APP_URL}/api/auth/callback`
);

// ── Iron-session config ────────────────────────────────────────────────────────
export const IRON_SESSION_OPTIONS = {
  cookieName: "zerogate_session",
  password: SESSION_SECRET,
  cookieOptions: {
    secure: process.env.NODE_ENV === "production",
    httpOnly: true,
    sameSite: "lax" as const,
    maxAge: SESSION_TTL_MS / 1000,
  },
};
