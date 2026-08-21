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

## 5. Gateway / Website 2 — PARTIALLY MOCKED

**What exists now:**
- Website 2 is a real, separate application (`server-desk.ts`, port 3002) with
  its own Session Guard, its own session store, and its own device
  verification — not a stub inside the portal.
- The Gateway (`lib/gateway`) is the only component that resolves Website 2's
  address. Website 1's request path never names it (W1 §4, §9).
- Website 2 independently verifies the device's private-key proof before
  trusting a session (W1 §8.1): it issues its own nonce and checks the
  signature itself, and it cross-checks the public key the Gateway reported
  against the credential of record.
- The authorization is consumed at session establishment and cannot be
  replayed (W2 §24).
- Gateway↔Website 2 calls are authenticated with an HMAC over the caller
  identity, timestamp, path, and body digest (`lib/service-auth`).
- Website 2 does **not** call the Gateway per request. Its session is validated
  locally, so an existing session survives a Website 1 or Gateway outage
  (W2 §26, §35). Critical events cross the boundary asynchronously, pulled by
  Website 2 and acknowledged (W2 §21).

**Session theft protection (W2 §14).** The session cookie alone is never
sufficient. Each session records when it last proved possession of its device
private key; once that lapses (`DESK_DEVICE_REVERIFY_MINUTES`, default 5), the
next request is held until a fresh signature over a new Website 2 nonce is
presented. A legitimate browser re-signs transparently — a fetch interceptor in
the Desk page does it and replays the request, so the employee sees nothing.
Someone holding only a stolen cookie cannot produce the signature and stops
working within one window. The session is not revoked by this: it is asked to
re-prove itself, not terminated.

On each successful re-proof the session identifier is rotated (W2 §16) and the
old one immediately stops resolving, so a leaked identifier has a bounded life
even if the leak is never noticed. Rotation does not reset the inactivity or
absolute lifetimes — it is a theft control, not a way past §17/§18.

**Superseded design note:** an earlier iteration re-checked authorization with
the Gateway on every Website 2 request. That inverted the model — it made every
page load depend on the Gateway being reachable, which contradicts W2 §26's
requirement that active sessions continue during an outage. Per-request
validation now lives in the Session Guard.

**What production needs:**
- Website 2 on a private network with no public DNS, unreachable except
  through the Gateway.
- The Gateway as a real reverse proxy or auth sidecar (Envoy, nginx + Lua) in
  its own process, reached over mTLS rather than a shared HMAC secret.
- The `admin-oob` channel (W2 §26) on a genuinely separate network path from
  the Gateway, or it does not provide the independence it exists for.

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
- Two queryable streams (LOGIN, CONNECT) with structured metadata and a
  severity level.
- **Tamper evidence** (W1 §11): every entry carries a monotonic `seq` and a
  SHA-256 hash over the previous entry's hash plus its own canonical content.
  Altering or deleting any entry breaks verification of every later one.
  Verify with `GET /api/admin/audit-logs?verify=1`.
- **Secret redaction**: metadata passes through a redaction filter before
  serialization, so a careless call site cannot write a password or token into
  the log.

**Caveats — these are detection, not prevention:**
- The chain proves nobody edited history *without also rewriting the chain*. An
  attacker with write access to the database can recompute every hash. Real
  prevention needs an append-only sink outside this database.
- Writes are serialized by an in-process promise chain. A multi-instance
  deployment would fork the chain; it needs a single writer or a database
  sequence.

**What production needs:**
- Ship entries to an append-only, tamper-evident store (CloudTrail, Azure
  Monitor, or WORM object storage) and periodically anchor the chain head
  somewhere the application cannot reach.
- Separate the audit store from the application database.
- **Log data classification (W1 §23 / W2 §37 — still open):** entries contain
  PII (IP addresses, employee identity tied to risk decisions). Retention
  period, access controls, and classification of the store itself are not yet
  specified in either design document.

---

## 8. Transport Security

**What exists now:**
- Security headers (CSP, HSTS, X-Frame-Options, etc.) are set in `proxy.ts`
  (Next.js 16 renamed Middleware to Proxy)
- HSTS is only active in `NODE_ENV=production`
- CSP uses `unsafe-inline` for scripts (needed by Next.js dev mode)

**What production needs:**
- Tighten CSP to remove `unsafe-inline` — use nonces (Next.js supports this)
- Set `HSTS` with `preload` and submit the domain to the HSTS preload list
- Deploy behind a TLS-terminating load balancer/CDN with TLS 1.2+ only
- Add Subresource Integrity (SRI) for any third-party assets

---

## 9. Cryptographic Device Identity — PARTIALLY MOCKED

**What exists now:**
- ECDSA P-256 key pairs generated in the browser with `extractable: false` and
  stored in IndexedDB (`lib/device/client.ts`). The private key is never
  exported, never transmitted, and is unreadable by script — including by an
  XSS payload, which can *use* the key but cannot exfiltrate it.
- Proof of possession is a signature over a single-use, server-generated nonce.
  The issuer and purpose are inside the signed bytes, so a signature obtained
  for Website 1's Connect challenge cannot be replayed at Website 2's
  independent checkpoint.
- Challenges are consumed on first verification — including on *failed*
  verification, which denies an attacker repeated attempts against one nonce.
- Registration is administrator-approved (W2 §6); rotation with an offline
  grace period is implemented (W2 §9A); recovery is human-controlled (W2 §8).

**What is genuinely weaker than the spec:**
- W2 §4 asks for hardware-backed storage (TPM, Secure Enclave) where
  available. A WebCrypto key is software-protected: strong against script-based
  exfiltration, but not against an attacker who can read the browser profile at
  OS level. The spec anticipates this and admits such devices at **lower
  assurance** rather than rejecting them, which is what the `assurance` field
  records.
- The client's `hardwareBacked` claim is a hint, not evidence. A compromised
  client would simply claim `true`. Production should use WebAuthn with a
  platform authenticator, whose attestation is verifiable server-side.

**Dev-only escape hatch:** `DEV_AUTO_APPROVE_DEVICES=true` (requires
`DEV_MODE=true`) self-approves registrations that would otherwise need an
administrator. It is impossible to enable in production; see `lib/config.ts`.

---

## 10. Emergency Access & Trusted Outage Detection — REAL, WITH ONE MOCK BOUNDARY

**What exists now:**
- Health state is written **only** by `scripts/health-monitor.ts`, an
  out-of-process monitor (`npm run health-monitor`). No route handler imports
  `recordProbe`, and no API endpoint can set health state. This is the
  structural enforcement of W1 §16: *Website 1 cannot declare itself
  unavailable.* A fully compromised Website 1 request path can lie in its
  `/api/health` response, but lying *healthy* opens nothing, and it has no path
  to the health table.
- Confirming an outage requires **both** repeated consecutive failures **and** a
  sustained duration, so a single failed probe — or a brief blip — cannot trip
  it.
- A confirmed outage only makes emergency access *available*. An administrator
  must then explicitly confirm it (W2 §27, and W1 §23's open item on
  attacker-induced outages), and that confirmation expires.
- Every emergency grant additionally requires a fresh, action-specific
  administrator re-authentication, and is employee-specific, device-bound,
  one-time, and capped at 5 minutes with no extension (W1 §17, W2 §29-§31).
- Recovery is automatic: the first successful probe clears the outage and voids
  any human confirmation.

**Mock boundary:** the monitor writes to the same database as the application.
In production it belongs on separate infrastructure with write access that the
application does not have — otherwise a database-level compromise of
Website 1 could forge an outage.

**Accepted residual risk (W2 §31):** the architecture has one administrator, so
true two-person approval cannot be enforced for MFA override or emergency
access. The dual-control seam is marked in
`app/api/admin/mfa-override/route.ts`.

---

## 11. Critical Security Events — REAL

**What exists now:**
- A durable outbox on the Authorization Service side and an idempotency ledger
  on the Website 2 side (`lib/security-events`).
- **At-least-once with acknowledgement** (W2 §21): an event is marked delivered
  only on an explicit ack, never on hand-off. Unacknowledged events are
  redelivered, which is safe because Website 2 deduplicates on `eventId`.
- **Authenticity** (W2 §32): each event is HMAC-signed over the eventId, type,
  userId, and payload, so an intercepted event cannot be re-aimed at another
  employee or given a fresh id to slip past the dedup ledger.
- **Pull, not push:** Website 2 asks the Gateway for events. It exposes no
  event-injection endpoint at all, so nothing on the network can send it a
  forged "terminate this employee" message.
- **Fallback reconciliation:** if delivery cannot be confirmed, Website 2
  re-derives the employee's critical account state from the system of record
  rather than assuming that silence means nothing happened.

**What production needs:**
- A real queue (SQS, Pub/Sub, Kafka) rather than database polling.
- Per-peer keys or mTLS instead of one shared HMAC secret.

---

## 12. Password Reset — REAL, SCOPED

`lib/auth/password.ts` and `/api/auth/password-reset` implement W1 §12: reset
requires MFA first, tokens are single-use, short-lived, hashed at rest, and
never logged. Success invalidates all Website 1 sessions **and** propagates a
critical event to Website 2, so neither a stolen portal session nor a live
Website 2 session survives the reset.

This is deliberately **not** an unauthenticated "forgot password" flow. §12's
constraint is that reset must not become an alternative authentication path, and
an anonymous recovery flow is a separate design problem that section does not
open.

For SSO-only deployments where the IdP owns the password, the same downstream
consequences are reachable through `applyPasswordChangeConsequences()`, so an
IdP webhook and the local flow cannot drift apart.

---

## Summary: Mock vs Real

| Component | Mock Status | Production Replacement |
|---|---|---|
| Identity Provider | Fully mocked | Real OIDC IdP (Okta/Azure/Google) |
| MFA | Fully mocked | Duo/Okta Verify/TOTP with vault-stored secrets |
| Session store | Real logic, SQLite | PostgreSQL + HSM-backed signing key |
| Authorization Service | In-process | Separate service + mTLS + HSM |
| Gateway | In-process module | Real reverse proxy / auth sidecar over mTLS |
| Website 2 | Real separate app | Private network, no public DNS |
| Device identity | Real crypto, software-protected key | WebAuthn platform authenticator with attestation |
| Device approval | Real (dev auto-approve flag available) | Administrator approval only |
| One-time authorization | Real | Unchanged |
| W2 Session Guard | Real | Unchanged |
| W2 session theft protection | Real, 5-min re-proof window | Shorter window, or per-request proof-of-possession |
| Critical events | Real, DB-polled outbox | Durable queue + per-peer keys |
| Outage detection | Real, separate process | Separate infrastructure the app cannot write to |
| Admin step-up | Real | Unchanged; add dual control with a second admin |
| Signing keys | Symmetric env vars | HSM + secrets manager |
| Audit logs | Real hash chain in app DB | Append-only external store + anchored chain head |
| Transport | Dev headers | Full HSTS + TLS 1.3 + CSP nonces |

---

## Where each design section is implemented

**website-1-defense.md**

| § | Topic | Implementation |
|---|---|---|
| 2, 3 | SSO + MFA, 7-day session, rotation | `lib/auth/session.ts`, `app/api/auth/*` |
| 4, 5 | Connect + connect-time check | `app/api/connect/route.ts` |
| 6, 7 | Mini EDR, risk levels | `lib/mini-edr/index.ts` |
| 8 | Device binding, one-time 5-min grant | `lib/device/`, `lib/authz-service/` |
| 8.1 | W2 independent device verification | `server-desk.ts` `/api/auth/device-proof` |
| 9 | W1 → Authorization Service | `lib/service-auth.ts` |
| 10 | Connect abuse, cooldown, notification | `app/api/connect/route.ts`, `lib/notify/` |
| 11 | Audit trail, tamper evidence | `lib/audit.ts` |
| 12 | Password reset | `lib/auth/password.ts` |
| 13, 14 | Admin identity, per-action re-auth | `lib/admin.ts`, `lib/admin-stepup.ts`, `lib/admin-action.ts` |
| 15 | MFA override | `app/api/admin/mfa-override/route.ts` |
| 16, 17 | Emergency Connect, trusted outage | `lib/health/`, `scripts/health-monitor.ts`, `app/api/admin/emergency/` |
| 18 | Web application security | `proxy.ts` |
| 19 | Fail closed | `app/api/connect/route.ts`, `lib/mini-edr/index.ts` |
| 20 | Alert management | `lib/alerts.ts` |
| 22 | Device lifecycle across systems | `lib/device/`, `lib/security-events/` |

**website-2-defense.md**

| § | Topic | Implementation |
|---|---|---|
| 3 | Gateway authorization flow | `app/api/authz/{code,exchange,redeem}` |
| 4 | Device credentials, challenge freshness | `lib/device/`, `lib/device/client.ts` |
| 5, 11 | Single device, single active session | `lib/device/`, `lib/desk-session/` |
| 5A | Administrator root of trust | `lib/admin.ts` |
| 6-9A | Registration, replacement, recovery, rotation | `app/api/device/*`, `app/api/admin/{devices,recovery}` |
| 10, 13, 17, 18 | Session establishment, security, limits | `lib/desk-session/index.ts` |
| 14 | Session theft protection (periodic device re-proof) | `lib/desk-session/index.ts`, `server-desk.ts` `/api/auth/device-reverify` |
| 16 | Session identifier rotation | `lib/desk-session/index.ts`, rotated on each re-verification |
| 12, 34 | Notifications | `lib/notify/index.ts` |
| 15, 24 | Replay protection, generic responses | `lib/gateway/index.ts`, `app/api/authz/redeem` |
| 21, 32 | Critical event delivery | `lib/security-events/index.ts` |
| 22 | Administrator termination | `app/api/admin/terminate/route.ts` |
| 25 | Service-to-service trust | `lib/service-auth.ts` |
| 26 | Out-of-band revocation | `app/api/admin/oob-revoke`, `server-desk.ts` `/api/oob/revoke` |
| 27-31 | Emergency access | `lib/health/`, `app/api/admin/emergency/` |
| 33 | W2 security logging | `server-desk.ts` `deskLog()` |

---

## Configuration

Beyond the existing variables, the following control the mechanisms above. All
have safe defaults; none is required for local development.

| Variable | Default | Purpose |
|---|---|---|
| `ORG_MODE` | `ESTABLISHED` | Selects W2 §17/§18 limits: `ESTABLISHED` = 2h idle / 24h absolute; `STARTUP` = 3h / 36h |
| `DESK_DEVICE_REVERIFY_MINUTES` | `5` | How long a Website 2 session may go without re-proving its device key (W2 §14). This is the window a stolen session cookie stays usable — lower is safer, at one extra round trip per interval |
| `DEVICE_ROTATION_DAYS` | `30` | Credential rotation period (W2 §9A) |
| `DEVICE_ROTATION_GRACE_DAYS` | `7` | Offline grace period after rotation is due |
| `DEVICE_CHALLENGE_TTL_SECONDS` | `120` | Challenge nonce lifetime |
| `DEV_AUTO_APPROVE_DEVICES` | `false` | **Dev only.** Self-approve device registrations; requires `DEV_MODE=true` |
| `CONNECT_FAILURE_THRESHOLD` | `5` | Denials before a Connect cooldown applies (W1 §10) |
| `CONNECT_COOLDOWN_SECONDS` | `900` | Cooldown duration |
| `ADMIN_STEP_UP_TTL_SECONDS` | `120` | Lifetime of a one-action admin grant (W1 §14) |
| `MFA_OVERRIDE_SESSION_MINUTES` | `60` | Lifetime of an MFA-overridden session (W1 §15) |
| `HEALTH_FAILURE_THRESHOLD` | `3` | Consecutive failed probes before an outage is confirmed |
| `HEALTH_MIN_OUTAGE_SECONDS` | `120` | Minimum sustained failure duration before confirmation |
| `HEALTH_HUMAN_CONFIRM_MINUTES` | `15` | Lifetime of an administrator's outage confirmation |
| `CLOCK_SKEW_TOLERANCE_SECONDS` | `30` | Agreed skew between the components enforcing the 5-minute grant |
| `SERVICE_SHARED_SECRET` | `AUTHZ_SIGNING_SECRET` | HMAC key for service-to-service calls and event signing |
| `OPERATIONS_DESK_URL` | `http://localhost:3002` | Where the Gateway resolves Website 2 |
| `GATEWAY_URL` | `http://localhost:3001` | Where Website 1 and Website 2 reach the Gateway process |
| `GATEWAY_PORT` | `3001` | Port the Gateway process listens on |
| `GATEWAY_GRANT_KEY_SEED` | `AUTHZ_SIGNING_SECRET` | **Dev only.** Seeds the deterministic ES256 grant-signing key. Production replaces the derivation with an HSM/KMS handle (GW §4) |
| `SERVICE_KEY_<PEER>` | derived | Per-peer service credential override, e.g. `SERVICE_KEY_WEBSITE_1` (GW §2) |

### Running the full system

```
npm run dev             # Website 1, the public portal (:3000)
npm run gateway         # The Access Gateway (:3001)
npm run desk            # Website 2, The Operations Desk (:3002)
npm run health-monitor  # Independent outage detection (required for §16)
```

The health monitor is a separate process by design. Without it running, health
state is never written — which fails safe: `checkEmergencyEligibility()` treats
an absent record as HEALTHY, so emergency access stays closed.
