/**
 * lib/config.ts
 * Central configuration and environment variable parsing for GateZero Portal.
 * All env access goes through this module — never read process.env directly elsewhere.
 */

import crypto from "crypto";

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

// ── Connect abuse controls (website-1-defense.md §10) ─────────────────────────
// The sliding-window rate limit above throttles bursts. The cooldown below is
// the punitive freeze applied once an account accumulates repeated *failures*,
// and is deliberately much longer than one rate-limit window.
export const CONNECT_FAILURE_THRESHOLD = parseInt(
  optionalEnv("CONNECT_FAILURE_THRESHOLD", "5"),
  10
);
export const CONNECT_FAILURE_WINDOW_SECONDS = parseInt(
  optionalEnv("CONNECT_FAILURE_WINDOW_SECONDS", "900"),
  10
);
export const CONNECT_COOLDOWN_SECONDS = parseInt(
  optionalEnv("CONNECT_COOLDOWN_SECONDS", "900"),
  10
);

// ── Cryptographic device identity (W1 §8 / W2 §4, §9A) ────────────────────────
// Challenge nonces are single-use and short-lived; the window only has to cover
// one round trip plus the device's signing latency.
export const DEVICE_CHALLENGE_TTL_SECONDS = parseInt(
  optionalEnv("DEVICE_CHALLENGE_TTL_SECONDS", "120"),
  10
);
// W2 §9A: credentials must not remain valid indefinitely.
export const DEVICE_ROTATION_DAYS = parseInt(
  optionalEnv("DEVICE_ROTATION_DAYS", "30"),
  10
);
// W2 §9A "Offline Grace Period": a device that is offline at its scheduled
// rotation is not locked out immediately.
export const DEVICE_ROTATION_GRACE_DAYS = parseInt(
  optionalEnv("DEVICE_ROTATION_GRACE_DAYS", "7"),
  10
);
// DEV-ONLY escape hatch mirroring the mock IdP: lets a dev environment
// self-approve device registrations that would otherwise need an admin (W2 §6).
// Requires DEV_MODE as well, and is asserted false in production.
export const DEV_AUTO_APPROVE_DEVICES =
  DEV_MODE && optionalEnv("DEV_AUTO_APPROVE_DEVICES", "false") === "true";

// ── Website 2 Session Guard (W2 §17-§18) ──────────────────────────────────────
// Organization security mode selects the inactivity and absolute-lifetime pair.
export type OrgMode = "STARTUP" | "ESTABLISHED";
export const ORG_MODE: OrgMode =
  optionalEnv("ORG_MODE", "ESTABLISHED").toUpperCase() === "STARTUP"
    ? "STARTUP"
    : "ESTABLISHED";

export const DESK_SESSION_LIMITS: Record<
  OrgMode,
  { inactivityMs: number; absoluteMs: number }
> = {
  STARTUP: {
    inactivityMs: 3 * 60 * 60 * 1000, // 3 hours
    absoluteMs: 36 * 60 * 60 * 1000, // 36 hours
  },
  ESTABLISHED: {
    inactivityMs: 2 * 60 * 60 * 1000, // 2 hours
    absoluteMs: 24 * 60 * 60 * 1000, // 24 hours
  },
};

export function deskSessionLimits(): { inactivityMs: number; absoluteMs: number } {
  return DESK_SESSION_LIMITS[ORG_MODE];
}

// W2 §14 "Session Theft Protection": a stolen session identifier must not be
// sufficient on its own. The session periodically re-proves possession of the
// device private key, which an attacker holding only the cookie cannot do.
//
// This is the window an attacker gets before the theft stops working. It is
// deliberately short — re-verification is transparent to the employee (the
// page signs a nonce in the background), so the only cost is one extra round
// trip per interval of activity.
export const DESK_DEVICE_REVERIFY_MS =
  parseInt(optionalEnv("DESK_DEVICE_REVERIFY_MINUTES", "5"), 10) * 60 * 1000;

// ── Clock skew (W1 §23 open item / W2 §3) ─────────────────────────────────────
// The 5-minute authorization is minted by the Authorization Service and
// enforced again by the Gateway and by Website 2. Server time is authoritative
// everywhere; this is the only slack permitted between those clocks.
export const CLOCK_SKEW_TOLERANCE_MS = parseInt(
  optionalEnv("CLOCK_SKEW_TOLERANCE_SECONDS", "30"),
  10
) * 1000;

// ── Service-to-service authentication (W2 §25, §26, §32 / GW §2) ──────────────
//
// Root secret. Kept for the event-signing HMAC, which is a producer/consumer
// MAC rather than a peer-authentication credential.
export const SERVICE_SHARED_SECRET = optionalEnv(
  "SERVICE_SHARED_SECRET",
  AUTHZ_SIGNING_SECRET
);
export const SERVICE_AUTH_MAX_SKEW_MS = 60 * 1000;

/**
 * gateway-defense.md §2: per-peer credentials, not one shared secret.
 *
 * With a single secret, every holder can impersonate every other service — a
 * leaked Website 2 credential would let an attacker speak as Website 1. Each
 * peer therefore gets its own key, derived from the root secret so a dev
 * environment needs no extra configuration, and overridable per peer so
 * production can supply independently-managed material.
 *
 * Derivation is HKDF-style: a leaked per-peer key does not reveal the root and
 * cannot be used to derive any other peer's key.
 *
 * This is still a stand-in for mTLS with per-peer certificates. What it buys
 * over the previous design is key separation — the property that actually
 * limits blast radius. What it does not buy is CA-backed identity, short-lived
 * credentials, or automated rotation (§2), which are deployment concerns.
 */
export function servicePeerKey(peer: string): string {
  const override = process.env[`SERVICE_KEY_${peer.toUpperCase().replace(/-/g, "_")}`];
  if (override) return override;

  return crypto
    .createHmac("sha256", SERVICE_SHARED_SECRET)
    .update(`gatezero:service-peer:v1:${peer}`)
    .digest("hex");
}

// ── Administrative controls (W1 §14-§17) ──────────────────────────────────────
// A step-up grant authorizes ONE privileged action and then expires.
export const ADMIN_STEP_UP_TTL_SECONDS = parseInt(
  optionalEnv("ADMIN_STEP_UP_TTL_SECONDS", "120"),
  10
);
// §15: an MFA-overridden session is never a normal 7-day session.
export const MFA_OVERRIDE_SESSION_TTL_MS =
  parseInt(optionalEnv("MFA_OVERRIDE_SESSION_TTL_MINUTES", "60"), 10) * 60 * 1000;

// ── Trusted outage detection (W1 §16 / W2 §27) ────────────────────────────────
// A single failed probe must never open the emergency path.
export const HEALTH_FAILURE_THRESHOLD = parseInt(
  optionalEnv("HEALTH_FAILURE_THRESHOLD", "3"),
  10
);
// …and the failures must persist, so a brief blip cannot trip the threshold.
export const HEALTH_MIN_OUTAGE_MS =
  parseInt(optionalEnv("HEALTH_MIN_OUTAGE_SECONDS", "120"), 10) * 1000;
export const HEALTH_PROBE_INTERVAL_MS =
  parseInt(optionalEnv("HEALTH_PROBE_INTERVAL_SECONDS", "15"), 10) * 1000;
// How long an administrator's explicit outage confirmation stays good before
// they must confirm again.
export const HEALTH_HUMAN_CONFIRM_TTL_MS =
  parseInt(optionalEnv("HEALTH_HUMAN_CONFIRM_MINUTES", "15"), 10) * 60 * 1000;

// ── Gateway grant signing (gateway-defense.md §3, §4) ─────────────────────────
// Seed for the DEV-ONLY deterministic derivation of the Gateway's ES256
// grant-signing key. Production replaces the derivation entirely with an
// HSM/KMS handle; see lib/gateway/grant.ts loadKeys().
export const GATEWAY_GRANT_KEY_SEED = optionalEnv(
  "GATEWAY_GRANT_KEY_SEED",
  AUTHZ_SIGNING_SECRET
);

// Where Website 1 and Website 2 reach the Gateway process (§1).
export const GATEWAY_URL = optionalEnv("GATEWAY_URL", "http://localhost:3001");
export const GATEWAY_PORT = parseInt(optionalEnv("GATEWAY_PORT", "3001"), 10);

// ── Website 2 location (W1 §4, §9) ────────────────────────────────────────────
// Deliberately NOT exported to Website 1's request path: W1 must never learn
// Website 2's address. Only the Authorization Service / Gateway resolve it.
export const GATEWAY_TARGET_URLS: Record<string, string> = {
  "operations-desk": optionalEnv("OPERATIONS_DESK_URL", "http://localhost:3002"),
};

export function resolveTargetApp(targetApp: string): string | null {
  return GATEWAY_TARGET_URLS[targetApp] ?? null;
}

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
