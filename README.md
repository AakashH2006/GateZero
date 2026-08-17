# GateZero

A zero-trust access architecture that removes an internal application from the public internet entirely, forwarding traffic to it only through a single hardened gateway — and only when a currently valid, explicitly-requested authorization exists.

## The problem

Most internal apps are protected by a login page (often with MFA). But the app itself still sits on the public internet the whole time — its address, open port, software version, and login page are all scannable and attackable 24/7, regardless of whether anyone ever logs in. **Protecting the login is not the same as protecting the application.**

Traditional VPNs improve on this, but a single login often grants broad network access, and the VPN gateway itself becomes a high-value, frequently-exploited target.

## The approach

GateZero splits access into two websites connected only by a chain of trust:

- **Website 1 (Portal)** — a normal, publicly reachable login page. Handles SSO + MFA and starts a 7-day session. It never exposes Website 2's URL, IP, credentials, or infrastructure.
- **Website 2 (Internal Application)** — the actual sensitive app. It is *never* directly exposed to the internet. The only way to reach it is through the Access Gateway.

Logging into Website 1 does **not** grant access to Website 2. It only reveals a **Connect** button. The employee must explicitly click Connect, whenever they actually need Website 2, before any authorization is issued.

Clicking Connect doesn't redirect anywhere — it causes Website 1 to ask the **Authorization Service** to verify the 7-day session and issue a short-lived authorization to the **Access Gateway**. The employee then separately opens Website 2's own address; that connection is physically forwarded through the Gateway, and only forwarded at all if the authorization is currently valid.

There is no shared session, no redirect, and no code path directly connecting Website 1 and Website 2. The only link between them is a short-lived authorization signal, requested on demand, and mediated entirely by the Authorization Service.

An attacker cannot attack, scan, or exploit something they cannot reach — so GateZero shrinks the internet-facing attack surface down to two purpose-built, heavily hardened components (Website 1 and the Gateway), instead of the full sensitive application.

## Architecture

```
PUBLIC INTERNET
      │
      │ (1) employee logs in (SSO + MFA)
      ▼
┌──────────────────┐
│    WEBSITE 1      │ ← always reachable publicly
│ (Portal: SSO+MFA) │
└──────────────────┘
      │
      │ (2) 7-day session starts, Connect button appears
      │ (3) employee clicks Connect — on demand, not automatic
      ▼
┌───────────────────────┐
│ AUTHORIZATION SERVICE  │ ← internal only, trust root
└───────────────────────┘
      │
      │ (4) mTLS: verify 7-day session, issue short-lived authorization
      ▼
┌──────────────────┐
│  ACCESS GATEWAY   │ ← ONLY entry point to Website 2
│ (mTLS to Website 2)│
└──────────────────┘
      ▲                    │
      │ (5) employee        │ (6) forwarded only if
      │ connects here       │ currently authorized
      │ separately          ▼
  [ browser ]        ┌──────────────────┐
                      │    WEBSITE 2      │ ← never internet-facing directly
                      │ (Internal App)     │
                      └──────────────────┘
```

**Core principle:** Website 1 proves identity → the Authorization Service manages authorization → the Access Gateway enforces access → Website 2 serves the application. No direct Website 1 ↔ Website 2 relationship exists.

There are two paths through the system, and they never merge:

- **Control path:** Website 1 → Authorization Service → Gateway, triggered only by an explicit Connect click, carrying an authorization decision.
- **Data path:** browser → Gateway → Website 2, carrying the employee's actual traffic. Website 1 has no part in this path at all.

### Components

| Component | Role | Reachable From |
|---|---|---|
| **Website 1 (Portal)** | Handles SSO + MFA login and starts the 7-day session. Shows a Connect button once logged in — access to Website 2 is never automatic. | Public internet, always |
| **Authorization Service** | Trust root of the system. On Connect, verifies the 7-day session over mTLS with Website 1, then issues a short-lived authorization to the Gateway. Issues nothing without an explicit Connect request. | Internal only |
| **Access Gateway** | The only entry point to Website 2. Verifies authorization before forwarding, connects to Website 2 via mTLS, and can terminate active connections immediately on revocation. | Internal only |
| **Website 2 (Internal Application)** | The sensitive app itself. Accepts traffic only from the Gateway, requires its own login + MFA every 24 hours, and has strict egress restrictions. | Never directly — only via the Gateway |

## Session model: two clocks, plus an explicit gate

GateZero runs two independent session clocks, and neither grants access by itself:

- **Clock 1 — Website 1 session (7 days):** "Is this still the right person, recently verified through full SSO + MFA?"
- **Clock 2 — Website 2 login (24 hours):** "Has this person proven themselves again today, right before touching the sensitive application?" — with its own MFA check.

A stolen or leaked Website 1 session is not, by itself, a week of access to Website 2 — it isn't even a minute of access until Connect is explicitly clicked. Every Connect click is logged independently of login logs, giving a clear audit trail of intent.

## Step-by-step flow

1. **Employee visits Website 1.** Website 2 will not respond at all yet, even if its address is already known.
2. **Company SSO login** via the existing identity provider (Okta, Azure AD, Google Workspace, etc.).
3. **MFA.** Login does not proceed without a second factor.
4. **7-day session starts, Connect button appears.** Nothing further happens automatically.
5. **Employee clicks Connect** whenever Website 2 is actually needed — this can happen immediately, later, or any day within the 7-day window.
6. **Authorization Service verifies the session** and issues a short-lived authorization to the Gateway.
7. **Employee opens Website 2 directly.** The connection arrives at the Gateway, which forwards it only because a valid authorization exists.
8. **Daily login at Website 2**, with its own independent MFA, every 24 hours.
9. **Access ends** automatically (short-lived grant expiry, 24-hour Website 2 session, or 7-day Website 1 session) or immediately on administrator revocation.

## Security controls on the trust chain

- Authorization is never automatic — a valid 7-day session only reveals the Connect button.
- Every internal hop is mutually authenticated (mTLS): Website 1 ↔ Authorization Service, Authorization Service ↔ Gateway, Gateway ↔ Website 2.
- Gateway private keys and Authorization Service signing keys are stored in a vault/HSM, with defined rotation and revocation procedures.
- Website 2 has strict egress restrictions — a compromised Website 2 cannot reach back to Website 1, the Authorization Service, or the Gateway's management interface.
- Revocation is push-based; if the Gateway is unreachable, the authorization's own expiry acts as the worst-case bound.
- Every Connect click is logged with outcome (issued/denied), separate from login logs.

## Additional hardening

- **High availability** — redundant Authorization Service and Gateway instances with health checks, failover, and DDoS/rate-limit protection.
- **Short-lived grants** — each Connect action issues a grant initially proposed at 5 minutes, tunable based on testing.
- **Connect rate limiting** — per user, device/session, and IP.
- **MFA-fatigue protection** — phishing-resistant MFA preferred; number-matching and rate limiting where push MFA is used.
- **Device/session binding** — each grant is bound to the authenticated device/session, closing the token-replay gap of bearer-style grants.
- **Emergency kill switch (planned)** — system-wide invalidation of all sessions/grants if the signing key is ever suspected compromised.
- **Gateway protection** — management interfaces isolated from Website 2 and the public internet.

## Why it matters

Because Website 1 and Website 2 are never directly linked, an attacker who finds Website 1 still cannot see, scan, or reach Website 2. Even an attacker who fully compromises Website 2 cannot pivot outward — egress restrictions block any path back to the Gateway, Authorization Service, or Website 1. Security effort concentrates on two purpose-built components instead of being spread across the entire sensitive application — while, from the employee's side, it's simply logging in, clicking Connect when needed, and opening Website 2 as usual.

---

## 💻 Implementation

This repository contains the working implementation of the GateZero architecture described above.

### 🏗️ Implementation Architecture

```
Browser
  │
  ▼
┌─────────────────────────────────────────────┐
│         Website 1 — GateZero Gateway        │
│         Next.js 16 + TypeScript + Prisma    │
│                                             │
│  /api/auth/*    — SSO + Email MFA           │
│  /api/authz/*   — Zero-Trust token service  │
│  /api/connect   — Authorization grant       │
│  /api/admin/*   — Admin management          │
│  /api/mock-idp  — Mock IdP (dev only)       │
│                                             │
│  Port: 3000                                 │
└─────────────────────┬───────────────────────┘
                      │  Exchange Code Handshake
                      │  (60s TTL, single-use)
                      ▼
┌─────────────────────────────────────────────┐
│     Website 2 — The Operations Desk         │
│     Standalone Express Server               │
│                                             │
│  Per-request live token introspection       │
│  Zero-Trust: validates every request        │
│  Neutral 401 Gateway Intercept Screen       │
│                                             │
│  Port: 3002 (bound to 127.0.0.1)           │
└─────────────────────────────────────────────┘
```

### ✨ Key Features

**Website 1 — GateZero Access Gateway**
- Employee SSO Login via Mock IdP (PKCE-based OAuth 2.0 flow)
- Real Email MFA delivery via [Resend](https://resend.com) — 6-digit OTP
- Anti-Copy-Paste OTP protection on the MFA screen
- Session Management — 7-day sliding sessions bound to device fingerprint
- Admin Console — Audit logs, session revocation, token management
- Sliding-Window Rate Limiting — Protects against brute-force and DoS

**Website 2 — The Operations Desk**
- Zero-Trust Gating — Every request live-introspects the token against Website 1
- OIDC-Style Handshake — Single-use exchange code (60s TTL), back-channel server-to-server token exchange
- Instant Revocation — Token revoked on Website 1 = access cut in real-time on Website 2
- Device Fingerprint Binding — SHA-256 hashed User-Agent binding prevents stolen token reuse
- Neutral Intercept Screen — Displays a clean "Gateway Access Required" screen on unauthorized access

**Security Controls Applied**
- `X-Frame-Options: DENY` — Clickjacking prevention
- `X-Content-Type-Options: nosniff` — MIME sniffing prevention
- `Referrer-Policy: strict-origin-when-cross-origin`
- HTML entity escaping on all dynamic template renders (Stored XSS defense)
- `encodeURIComponent` on all URL-interpolated record IDs

### 🚀 Quick Start

**Prerequisites:** Node.js 20+, npm 9+

```bash
# 1. Clone and install
git clone https://github.com/AakashH2006/GateZero.git
cd GateZero
npm install

# 2. Set up environment variables
cp .env.example .env.local
# Fill in SESSION_SECRET, AUTHZ_SIGNING_SECRET, and RESEND_API_KEY

# 3. Initialize the database
npx prisma migrate dev

# 4. Seed demo data
npm run db:seed
npm run db:seed-desk

# 5. Start Website 1 (GateZero Gateway)
npm run dev

# 6. Start Website 2 (The Operations Desk) — in a second terminal
npm run desk
```

| Service | URL |
|:---|:---|
| GateZero Gateway | http://localhost:3000 |
| The Operations Desk | http://localhost:3002 |

### 🔄 End-to-End Flow

1. Visit `http://localhost:3000` → Click **[EMPLOYEE SSO SIGN IN]**
2. Authenticate via the Mock IdP → Complete **Email MFA** (check your inbox)
3. On the Dashboard, click **`🚀 [LAUNCH THE OPERATIONS DESK :3002] →`**
4. GateZero issues a 60-second exchange code, Website 2 exchanges it server-to-server for a token, and grants you access
5. Direct access to `http://localhost:3002` without going through GateZero returns the **Neutral Gateway Intercept Screen**

### 🧪 Automated Regression Tests

```bash
npm test
```

**28 / 28 tests passing**

| File | Tests | Coverage |
|:---|:---:|:---|
| `__tests__/authz-service.test.ts` | 11 | Token issuance, revocation, session checks, rate limiting, device binding |
| `__tests__/operations-desk-gate.test.ts` | 7 | Exchange code handshake, live introspection, CRUD operations |
| `__tests__/security-audit.test.ts` | 10 | Replay attacks, token forgery, MFA bypass, XSS defense |

### ⚙️ Environment Variables

| Variable | Required | Description |
|:---|:---:|:---|
| `DATABASE_URL` | ✅ | `file:./prisma/dev.db` for local SQLite |
| `SESSION_SECRET` | ✅ | Min 32 chars — signs session cookies |
| `AUTHZ_SIGNING_SECRET` | ✅ | Min 32 chars — signs authorization tokens |
| `RESEND_API_KEY` | ✅ | Resend API key for real email MFA delivery |
| `NEXT_PUBLIC_APP_URL` | ✅ | Website 1 URL (`http://localhost:3000`) |
| `DEV_MODE` | — | `true` enables mock IdP and dev tools |
| `AUTHZ_TTL_SECONDS` | — | Token lifetime in seconds (default: `300`) |
| `RATE_LIMIT_MAX` | — | Max requests per window (default: `5`) |
| `ADMIN_SECRET` | — | Dev-only admin header secret |

### 📁 Project Structure

```
├── app/
│   ├── api/
│   │   ├── auth/          # SSO callback, MFA, logout, session
│   │   ├── authz/         # Exchange code, token exchange, live verify
│   │   ├── connect/       # Authorization grant endpoint
│   │   └── admin/         # Admin: sessions, audit logs, revocation
│   ├── dashboard/         # Authenticated dashboard with launch button
│   └── mfa/               # MFA screen with anti-copy-paste protection
├── lib/
│   ├── auth/              # SSO config, PKCE, session, email MFA
│   ├── authz-service/     # Token issuance, exchange codes, introspection
│   ├── audit.ts           # Structured audit logging
│   ├── rate-limit.ts      # Sliding-window rate limiter
│   └── config.ts          # Central environment config
├── prisma/
│   ├── schema.prisma      # Full database schema
│   ├── seed.ts            # Gateway seed data
│   └── seed-dispatch.ts   # Operations Desk seed data
├── __tests__/             # Vitest automated regression tests
├── server-desk.ts         # Website 2 — Standalone Express server
└── SECURITY-NOTES.md      # Mock vs production documentation
```

### 🔒 Security Notes

See [SECURITY-NOTES.md](./SECURITY-NOTES.md) for full details on what is mocked vs production-ready.

> **⚠️ Never deploy with `DEV_MODE=true` in production.** This flag:
> - Activates the Mock IdP (anyone can sign in as any user)
> - Accepts any 6-digit MFA code
> - Enables admin access via a static header secret

---

## 📄 License

MIT
