# SECURITY NOTES — GateZero Portal

> This document describes which parts of the GateZero Portal implementation
> are **mocked** for local development and what a **real production deployment**
> would need to replace them. It is intended for security reviewers and
> engineers planning the production rollout.

---

## 1. Identity Provider (SSO) — MOCKED

**What exists now:**
- A stub "IdP" runs at `/api/mock-idp/authorize` and `/api/mock-idp/token`
- It auto-approves any login as a fixed demo user (`demo@zerogate.internal`)
- It is **only active when `DEV_MODE=true`** — requests to these endpoints
  return 404 when `DEV_MODE=false`
- The OAuth2 PKCE flow and state validation are **real** and not mocked

**What production needs:**
- Set `DEV_MODE=false` in environment
- Set `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` to values from
  your real IdP (Okta, Azure AD, Google Workspace, etc.)
- The callback at `/api/auth/callback` will work with any OIDC-compliant IdP
  without code changes — it's IdP-agnostic
- Verify the IdP's JWKS endpoint for id_token signature validation
  (currently the mock returns claims directly; production should verify the
  id_token JWT signature using the IdP's public keys)

---

## 2. MFA — MOCKED

**What exists now:**
- `DEV_MODE=true`: any 6-digit numeric code is accepted; a "Simulate Approve"
  button triggers the push flow by setting a DB flag
- The MFA state machine (PENDING_MFA → ACTIVE) and expiry are real

**What production needs:**
- Integrate a real MFA provider: Duo Security, Okta Verify, or TOTP via RFC 6238
- Replace `verifyOTPCode()` in `lib/auth/mfa.ts` with a call to the provider's
  verification API
- Replace `simulatePushApprove()` with a real push notification webhook from
  the provider
- Store per-user TOTP secrets in a secure vault (AWS Secrets Manager, HashiCorp
  Vault, Azure Key Vault) — never in the application database

---

## 3. Session Store — PARTIALLY MOCKED

**What exists now:**
- Sessions are stored in a SQLite DB (dev) and reference real signed httpOnly
  cookies via iron-session
- The signing key is a symmetric secret in `SESSION_SECRET` env var
- Sessions are server-side revocable — this is production-quality

**What production needs:**
- Use PostgreSQL instead of SQLite (`DATABASE_URL` change + schema provider change)
- Replace the symmetric `SESSION_SECRET` with a key derived from a real
  secrets manager or HSM — rotate it without breaking existing sessions by
  supporting multiple valid keys during rotation
- Add session revalidation on privilege-changing operations (re-prompt MFA
  before issuing authorization)

---

## 4. Authorization Service — MOCKED (clean boundary)

**What exists now:**
- `lib/authz-service/index.ts` runs in the same process as the portal
- Signs tokens with a symmetric HMAC (HS256) key from `AUTHZ_SIGNING_SECRET`
- Token binding is simulated via session ID + hashed User-Agent
- Has its own internal-only endpoint namespace (`/api/authz/*`)

**What production needs:**
- Move this module to its own internal microservice (gRPC or HTTPS)
- The portal's `/api/connect` route would call it via HTTP — no other changes
  needed to the portal code
- Use asymmetric signing keys (RS256 or ES256) from an HSM or Vault
  (so even if the portal is compromised, it cannot forge authorization tokens)
- Add mTLS between the portal and the authorization service
- Add real device binding: client certificates, hardware attestation, or
  FIDO2/WebAuthn device credentials instead of just hashed User-Agent

---

## 5. Gateway / Website 2 — MOCKED

**What exists now:**
- A stub at `/api/internal` simulates the Gateway-protected resource
- The URL is in the same Next.js app — in production, it would be on a
  completely separate host unreachable from the internet
- Authorization is re-checked on every request via the authorization service

**What production needs:**
- Website 2 lives on a private network with no public-facing DNS
- A real Gateway (Envoy, nginx + Lua, or custom auth sidecar) sits in front
  of it and calls the authorization service on every request via mTLS
- The portal **never reveals Website 2's hostname** until authorization
  succeeds — even then, it provides only an opaque redirect or iframe token,
  not the raw internal URL
- The gateway must honor token revocation within milliseconds — implement a
  push revocation webhook from the authorization service to all gateway
  instances (or use very short-lived tokens, e.g. 30 seconds, with refresh)

---

## 6. Signing Keys — MOCKED

**What exists now:**
- `SESSION_SECRET` and `AUTHZ_SIGNING_SECRET` are symmetric secrets in env vars
- They are committed to `.env.example` as dev-only placeholders

**What production needs:**
- Never store signing keys in environment variables directly — use a secrets
  manager (AWS Secrets Manager, GCP Secret Manager, Azure Key Vault) or HSM
- Implement key rotation without service disruption (support multiple valid
  keys with a key ID header in tokens)
- For the authorization service specifically: use HSM-backed asymmetric keys
  so the signing capability is physically isolated

---

## 7. Audit Logs — PRODUCTION READY (with caveats)

**What exists now:**
- Two queryable log streams: LOGIN and CONNECT, stored in the DB
- Structured JSON metadata per event
- No log tampering protection (logs are in the same DB as everything else)

**What production needs:**
- Write audit logs to an append-only, tamper-evident log store (AWS CloudTrail,
  Azure Monitor, or a WORM-protected object store)
- Separate the audit log DB from the application DB
- Set up alerting on anomalous patterns (high Connect rate, failed MFA spikes,
  revocation floods)

---

## 8. Transport Security

**What exists now:**
- Security headers (CSP, HSTS, X-Frame-Options, etc.) are set in `middleware.ts`
- HSTS is only active in `NODE_ENV=production`
- CSP uses `unsafe-inline` for scripts (needed by Next.js dev mode)

**What production needs:**
- Tighten CSP to remove `unsafe-inline` — use nonces (Next.js supports this)
- Set `HSTS` with `preload` and submit the domain to the HSTS preload list
- Deploy behind a TLS-terminating load balancer/CDN with TLS 1.2+ only
- Add Subresource Integrity (SRI) for any third-party assets

---

## Summary: Mock vs Real

| Component | Mock Status | Production Replacement |
|---|---|---|
| Identity Provider | ✅ Fully mocked | Real OIDC IdP (Okta/Azure/Google) |
| MFA | ✅ Fully mocked | Duo/Okta Verify/TOTP with vault-stored secrets |
| Session store | ⚠️ Real logic, SQLite | PostgreSQL + HSM-backed signing key |
| Authorization Service | ⚠️ In-process | Separate microservice + mTLS + HSM |
| Gateway | ✅ Fully mocked | Real reverse proxy with auth sidecar |
| Signing keys | ✅ Symmetric env vars | HSM + secrets manager |
| Audit logs | ⚠️ App DB | Append-only, tamper-evident log store |
| Transport | ⚠️ Dev headers | Full HSTS + TLS 1.3 + CSP nonces |
