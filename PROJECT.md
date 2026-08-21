# GateZero — Project Reference

A zero-trust access gateway. An employee authenticates once on a public portal
(**Website 1**), and every time they need the protected work environment
(**Website 2**) they click **Connect** and pass a fresh checkpoint.

The whole system exists to hold one line:

> **Authentication at Website 1 establishes identity; it does not establish
> access to Website 2.**

A stolen Website 1 session does not get you into Website 2. A stolen Website 2
session cookie does not get you in from another machine. A compromised Gateway
does not get you a trusted Website 2 session. Each of those is enforced by a
different mechanism, and each is tested.

This document describes the system as built. The authoritative designs are
[`website-1-defense.md`](website-1-defense.md) and
[`website-2-defense.md`](website-2-defense.md); section references below (§) point
into them.

---

## 1. The three components

| | Responsibility | Never does |
|---|---|---|
| **Website 1** — the portal | SSO + MFA, the 7-day session, the Connect action, Mini EDR risk scoring, requesting authorization | Grant access. Learn Website 2's address. Declare itself unavailable. |
| **Gateway** (`server-gateway.ts`, :3001) | Decide authorization, mint the ES256-signed one-time grant, resolve where Website 2 lives, relay critical events | Store passwords or business data. Become a general API. Monitor Website 2. Expose any admin or debug surface. |
| **Website 2** — the Operations Desk | Establish and guard the work session, verify the device itself, enforce its own limits | Trust the Gateway's word about a device. Depend on Website 1 staying up. |

Website 1 is the only permanently public-facing part. Website 2 sits behind the
Gateway and, in production, on a private network with no public DNS.

---

## 2. The trust chain

```
SSO + MFA
    │
    ▼
7-day Website 1 session          ← proves identity, grants nothing
    │
    │  employee clicks Connect
    ▼
Device proof  (ECDSA signature over a single-use nonce)
    │
    ▼
Mini EDR risk assessment          ← LOW / MEDIUM / HIGH / CRITICAL
    │
    ▼
Authorization Service
    │
    ▼
5-minute authorization             ← one-time, device-bound, employee-specific
    │
    ▼
Gateway
    │
    ▼
Website 2 verifies the device ITSELF   ← independent second checkpoint (§8.1)
    │
    ▼
Website 2 session                  ← own limits, own revocation, own re-proofs
```

Every arrow is a place something can be refused. The grant is consumed at the
last step and can never be replayed.

---

## 3. Security properties, and what enforces each

### Cryptographic device identity — W1 §8, W2 §4

An ECDSA P-256 key pair is generated **in the browser** with
`extractable: false` and kept in IndexedDB. The private key is never exported,
never transmitted, and cannot be read by script — including by an XSS payload,
which can *use* the key but cannot steal it.

Proof of possession is a signature over a fresh, single-use, server-generated
nonce. The signed message is:

```
gatezero:v1:<issuer>:<purpose>:<nonce>
```

The issuer and purpose are **inside the signed bytes** deliberately. A signature
produced for Website 1's Connect challenge cannot be replayed as the answer to
Website 2's independent challenge, even while both nonces are live.

Challenges are consumed on first verification — **including on failed
verification**, which denies an attacker unlimited signature attempts against one
live nonce.

> **Weaker than the spec, on purpose.** W2 §4 asks for hardware-backed storage
> (TPM, Secure Enclave). A WebCrypto key is software-protected: strong against
> script exfiltration, not against an attacker who can read the browser profile
> at OS level. The spec anticipates exactly this and admits such devices at
> **lower assurance** rather than rejecting them. The client's `hardwareBacked`
> claim is a hint recorded by the server, never trusted — a compromised client
> would simply claim `true`. Production upgrades this to WebAuthn with a platform
> authenticator, whose attestation is verifiable server-side.

### One-time, device-bound authorization — W1 §8, W2 §24

Each Connect mints a grant that is employee-specific, bound to a device
credential, valid 5 minutes, and **consumed atomically** the moment a Website 2
session is established. Second use is rejected as a replay and logged as a
security event.

Consumption is a conditional `UPDATE ... WHERE consumedAt IS NULL`, so two
devices redeeming the same grant concurrently produce exactly one winner. A
read-then-write would let both in.

### Website 2 verifies the device itself — W1 §8.1

Website 2 does not accept the Gateway's assertion that a device is legitimate.
It issues its **own** nonce, checks the signature itself, and cross-checks the
public key the Gateway reported against the credential of record. A Gateway that
forged or mis-validated a binding still cannot produce a trusted session.

### Session theft protection — W2 §14

The session cookie alone is never sufficient. Each session records when it last
proved possession of its device key; once that lapses (default 5 minutes), the
next request is held until a fresh signature arrives.

A legitimate browser re-signs **transparently** — a `fetch` interceptor in the
Desk page does it and replays the request, so the employee sees nothing. Someone
holding only a stolen cookie cannot produce the signature and stops working
within one window. The session is asked to re-prove itself, not revoked.

On each successful re-proof the session identifier **rotates** (§16) and the old
one immediately stops resolving. Rotation does not reset the inactivity or
absolute lifetimes — it is a theft control, not a way past §17/§18.

### Website 2 session independence — W2 §26, §35

Once established, the session is validated from local state. Website 2 does not
call the Gateway per request, so an existing session **survives a Website 1 or
Gateway outage** — which §26 requires. Only a small set of critical events
crosses the boundary afterwards, pulled asynchronously.

> An earlier iteration re-checked authorization with the Gateway on every
> request. That inverted the model and broke §26; it was removed.

### Telemetry is not identity — W1 §5, §6

IP address and User-Agent feed the risk score and nothing else. §5 is explicit
that UA strings are trivially spoofed and must not be treated as identity, and
that ordinary network changes must not log an employee out. The weights are set
so that **both telemetry signals together stay below the gate** on a device that
passed its cryptographic proof — an employee travelling and opening a different
browser is the ordinary case the spec says must not be interrupted.

### Graded device-proof failures — W1 §5, §7

"The proof didn't succeed" covers very different situations, so the reason is
graded:

| Class | Examples | Response |
|---|---|---|
| **Forgery** | bad signature, credential belongs to someone else | CRITICAL — terminate session, alert |
| **Misdirection** | challenge redirected across user / purpose / issuer | CRITICAL |
| **Staleness** | consumed or expired nonce — a retry, a stale tab | refuse Connect, session survives |
| **Lifecycle** | no device, not yet approved, revoked, past grace | refuse Connect, session survives |

An unclassified reason **fails safe as hostile**, so adding a new failure mode
without classifying it cannot silently downgrade it.

### Trusted outage detection — W1 §16, W2 §27

> *"Website 1 must never be able to declare itself unavailable."*

Enforced **structurally**, not by convention. Health state is written only by
`scripts/health-monitor.ts`, an out-of-process monitor. No route handler imports
`recordProbe`; no API endpoint can set health state. A fully compromised
Website 1 request path can lie in its `/api/health` response — but lying
*healthy* opens nothing, and it has no path to the health table.

Emergency access needs **four** independent gates, in order:

1. Sustained failure — N consecutive failed probes **and** a minimum duration, so
   neither a single blip nor a fast burst can trip it
2. Explicit human confirmation by an administrator, which expires
3. A fresh, action-specific administrator re-authentication
4. A named employee with an active device credential

Recovery is automatic: the first successful probe clears the outage and voids any
human confirmation, so the window closes by itself.

### Administrative controls — W1 §13–§15

> *"Admin login does not equal permanent administrative authorization."*

Every privileged action spends a **step-up grant** bound to one action, one
target, single-use, short-lived, and carrying a recorded reason. A grant obtained
for "revoke a session" cannot be spent on "override MFA". Being signed into the
admin dashboard grants nothing.

An MFA override produces a session that is flagged, short-lived, and pre-gated so
the employee must complete real MFA before Connect will work — it can never
silently become an ordinary 7-day session, and it cannot target an administrator.

### Critical security events — W2 §21, §32

The only things that cross the W1/W2 boundary after establishment:
password change, access revocation, administrator termination, device
revocation.

- **At-least-once** — an event is marked delivered only on an explicit ack
- **Idempotent** — Website 2 keeps a ledger keyed by `eventId`; redelivery is a
  no-op, which is what makes at-least-once safe
- **Authenticated** — HMAC over `eventId`, type, `userId`, and payload, so an
  intercepted event cannot be re-aimed at another employee or given a fresh id
- **Pull, not push** — Website 2 asks. It exposes no event-injection endpoint at
  all, so nothing on the network can forge a termination
- **Reconciled** — if delivery can't be confirmed, Website 2 re-derives the
  employee's critical state from the system of record

### Tamper-evident audit — W1 §11

Every entry carries a monotonic `seq` and a SHA-256 hash over the previous
entry's hash plus its own canonical content. Editing or deleting any entry breaks
verification of every later one. Verify with
`GET /api/admin/audit-logs?verify=1`.

Metadata passes through a redaction filter, so a careless call site cannot write
a password or token into the log.

> This is **detection, not prevention**. An attacker with database write access
> can recompute the whole chain. Real prevention needs an append-only sink
> outside this database.

---

## 3A. The Gateway as its own process

`gateway-defense.md` is implemented as a real, separate service on :3001.

**Grants are asymmetrically signed (§3).** The Gateway signs each grant with an
ES256 private key; Website 2 verifies with the **public** key and holds nothing
capable of minting one. "The Gateway really did approve this" is now a
cryptographically checkable claim rather than a shared-secret formality. The
payload carries the employee, a hash of the device public key, `iat`, `exp`, a
single-use `jti`, and an audience — so a grant minted for Website 2 is refused
anywhere else even though its signature is perfectly valid.

The `jti` **is** the authorization record's id, so the signed assertion and the
row that tracks one-time consumption name the same thing.

**Per-peer credentials (§2).** Each service signs with its own derived key
instead of one secret everyone shares. A leaked Website 2 credential lets an
attacker speak as Website 2 — not as Website 1.

**Website 1 cannot mint a grant (§1).** The minting code is not in that process.
Website 1 asks over an authenticated backend call and the Gateway decides.
Website 1 also cannot construct the handoff URL — it asks, because it holds no
configuration naming Website 2's address (W1 §4, §9).

**Nothing else is exposed (§6).** Grant issuance, handoff-URL resolution,
exchange, redemption, the public key, the event relay, and liveness. Every other
path is a flat 404. No admin surface, no debug endpoint, no general API.

### Where this design was not followed, and why

**No circuit breaker toward Website 2**, despite §7 asking for one. The Gateway
makes *zero* outbound calls to Website 2 — the event relay is pull-only and the
handoff is a URL handed to the browser. There is nothing to break. The pull model
already provides what §7 wants, structurally. A breaker here would be dead code
that reads like a safeguard while guarding nothing, which is worse than an
acknowledged absence because it invites the assumption that the risk is handled.
`server-gateway.ts` carries a note to add one the moment an outbound path
appears.

---

## 4. Session model — three independent clocks

| Clock | Length | Reset by |
|---|---|---|
| Website 1 session | 7 days | fresh SSO + MFA |
| Gateway authorization | 5 minutes, one-time | each Connect |
| Website 2 session | 2h idle / 24h absolute (`ESTABLISHED`)<br>3h idle / 36h absolute (`STARTUP`) | meaningful activity only |
| Website 2 device re-proof | 5 minutes | signing a fresh nonce |

The inactivity timer resets on **meaningful application activity only**.
Background polling deliberately does not, so an abandoned browser tab cannot keep
a session alive indefinitely.

Logging out of Website 2 affects Website 2 only — Website 1 stays signed in, and
the employee can Connect again (§20).

---

## 5. Code map

### Libraries

| Module | Purpose |
|---|---|
| `lib/device/` | Device identity: challenges, proofs, registration, rotation, revocation. `client.ts` is the browser-side non-extractable key custody |
| `lib/authz-service/` | Mints, introspects, and consumes authorizations |
| `lib/gateway/` | Final enforcement point; resolves where Website 2 lives; single generic denial |
| `lib/desk-session/` | Website 2 Session Guard — establishment, validation, limits, rotation, revocation |
| `lib/mini-edr/` | Connect risk scoring. Login/MFA/Connect only; never sees Website 2 |
| `lib/security-events/` | Cross-boundary critical event outbox, ledger, reconciliation |
| `lib/health/` | Trusted outage state machine (read-only from the app) |
| `lib/admin-stepup.ts`, `lib/admin-action.ts` | One-action privileged grants and the guard every admin route uses |
| `lib/service-auth.ts` | HMAC service-to-service authentication |
| `lib/audit.ts`, `lib/alerts.ts` | Hash-chained audit trail; severity-gated, deduplicated alerts |
| `lib/notify/` | Employee notifications from a fixed, secret-free template catalogue |
| `lib/auth/` | Sessions, CSRF, MFA, PKCE, password reset |

### Notable routes

| Route | Purpose |
|---|---|
| `POST /api/connect` | The checkpoint — CSRF, cooldown, step-up gate, rate limit, device proof, risk, grant |
| `POST /api/device/challenge` · `/api/device` · `/rotate` · `/recovery` | Device lifecycle |
| `POST /api/authz/code` · `/exchange` · `/redeem` · `/verify` | Handoff and one-time redemption |
| `GET/POST /api/events` | Critical event pull and ack |
| `POST /api/admin/step-up` | Administrator re-authentication (one action) |
| `POST /api/admin/emergency` | Outage confirmation, then emergency Connect |
| `POST /api/admin/oob-revoke` | Out-of-band revocation when the Gateway is down |
| `GET /api/health` | Liveness probe — reports, never records |

`server-desk.ts` is Website 2: handshake, its own device verification, the
Session Guard middleware, the event poller, the revoke-only out-of-band endpoint,
and the Desk UI.

---

## 6. Running it

```bash
npm install
npx prisma migrate deploy      # or: npm run db:migrate
npm run db:seed                # provisions the demo employee AND the admin identity

npm run dev                    # Website 1, the public portal                 :3000
npm run gateway                # The Access Gateway                           :3001
npm run desk                   # Website 2, The Operations Desk               :3002
npm run health-monitor         # independent outage detection — separate by design
```

Four processes, and the separation is the point: Website 1 has no code that
mints a grant, and the Gateway has no browser-facing surface.

The health monitor is a **separate process on purpose** (see §16 above). Without
it, health state is never written — which fails safe: an absent record is treated
as HEALTHY, so emergency access stays closed.

For local development, `DEV_AUTO_APPROVE_DEVICES=true` self-approves device
registrations that would otherwise need an administrator. It requires
`DEV_MODE=true` and is impossible to enable in production.

### Verification

```bash
npm run type-check
npm test        # 163 tests, 11 files
npm run e2e     # 32 checks across all three servers, with a real EC key
```

`npm run e2e` is the meaningful one — it drives real HTTP through the entire
flow and asserts the security properties, including that a Website 1 signature is
refused at Website 2, that a stolen cookie stops working, and that a rotated
identifier no longer resolves.

> **On Windows:** `pkill -f "next dev"` silently does nothing. Kill dev servers
> by PID (`netstat -ano | findstr :3000`, then `taskkill /PID <pid> /F`) or you
> will test code you already replaced.

---

## 7. What is mocked

| Component | State | Production replacement |
|---|---|---|
| Identity Provider | fully mocked | Real OIDC IdP |
| MFA | fully mocked — `DEV_MODE` accepts any 6-digit code; **production path returns "not configured"** | Duo / Okta Verify / TOTP with vault-stored secrets |
| Device key storage | real crypto, software-protected | WebAuthn platform authenticator with attestation |
| Service-to-service auth | shared HMAC secret | mTLS with per-peer keys |
| Gateway | own process, same host and database | Separate host, network-isolated by firewall, own datastore |
| Gateway peer auth | HMAC, per-peer derived keys | mTLS with pinned, short-lived CA certificates |
| Grant signing key | derived from a seed in-process | HSM / KMS handle |
| Health monitor | separate process, **same database** | Separate infrastructure the app cannot write to |
| Signing keys | env vars | HSM / secrets manager |
| Audit sink | hash chain in the app DB | Append-only external store, anchored chain head |
| Database | SQLite | PostgreSQL |
| External alerting | `console.warn` stub | SIEM / pager integration |
| Secondary notification channel | logged, not sent | Real SMS / push provider |

Two structural limits worth naming: the Website 2 handshake store is in-memory
and the audit chain is serialized in-process, so **both assume a single
instance**. Multi-instance deployment needs shared state and a single chain
writer.

---

## 8. What is left

### Closed by this implementation

Five of the specs' eight open items are now resolved: the Website 2 Session
Guard (§6), the cross-system propagation channel (§22.3–22.4), clock-skew
tolerance for the 5-minute grant, human confirmation for attacker-induced
outages, and cryptographic device binding.

### Still open

| Item | Why it's still open |
|---|---|
| **Log data classification, retention, access control** (W1 §23, W2 §37) | Not implemented anywhere. Entries contain PII — IPs and employee identity tied to risk decisions. Needs a retention period, an access policy, and a classification for the store itself. Policy decision first, then code. |
| **MFA override dual-control** (W1 §23) | The seam exists (`SECOND_APPROVER_REQUIRED` in `app/api/admin/mfa-override/route.ts`) but is off, because the architecture has **one administrator**. W2 §31 accepts this as residual risk. Unblocked only by provisioning a second administrator identity. |
| **Device recovery flow detail** (W1 §22.5) | The flow, rate limits, and audit are built; the specific identity-reverification *steps* an administrator must perform are a policy question the spec leaves open. |

### Beyond the specs

- **Business authorization inside Website 2** — W2 §1 puts this explicitly out of
  scope. The Desk currently authenticates who you are but does not restrict what
  you may see or do. Any real deployment needs RBAC and data permissions.
- **Production auth integration** — the mocked rows in §7 above.
- **Multi-instance readiness** — shared handshake store, single audit writer.

---

## 9. Design decisions worth knowing

Choices that are deliberate and would look like bugs otherwise:

- **UA mismatch is worth very little.** Weighted so two telemetry signals
  together cannot gate Connect on a proven device. Raising it re-creates the
  problem device binding was introduced to solve.
- **A failed device proof burns the nonce.** Deliberate — otherwise one live
  challenge allows unlimited signature attempts.
- **The authorization is consumed at session establishment, not at exchange.** A
  handshake that fails Website 2's device check must not cost the employee their
  grant.
- **`revokeAllForUser` scopes the authorization sweep to match the session
  sweep.** Unscoped revocation on a credential-scoped call breaks device
  replacement — the new device's fresh grant gets killed by the old device's
  revocation event.
- **Rotation does not extend lifetimes.** It is a theft control.
- **Website 2's out-of-band revoke endpoint contains exactly one operation.** §26
  forbids it creating sessions or credentials; that is guaranteed by there being
  no code for it, not by a check.

---

## 10. Document map

| Document | What it is |
|---|---|
| `website-1-defense.md` | Authoritative design — portal, Connect, Mini EDR, admin, emergency |
| `website-2-defense.md` | Authoritative design — Session Guard, device lifecycle, events |
| `gateway-defense.md` | Authoritative design — Gateway hardening and blast radius |
| `SECURITY-NOTES.md` | Mock vs real, per component, with a §-by-§ implementation map |
| `threat-model.md` | Threat analysis |
| `security-controls.md` | Threat-to-control mapping |
| `README.md` | Original project overview and quick start |

> `README.md` predates this implementation. One line is now wrong: it describes
> device binding as "SHA-256 hashed User-Agent binding". That is no longer true
> and is explicitly forbidden by W1 §5 — binding is cryptographic, and UA is
> telemetry only.
