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
