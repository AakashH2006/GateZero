# Gateway — Defense Design

The Gateway sits between Website 1 (public) and Website 2 (private). It decides
authorization, mints the one-time grant, resolves where Website 2 lives, and
carries critical security events across the boundary. It is deliberately kept
from being able to do the two things that would make its compromise
catastrophic: hold secrets or business data, and grant trusted access to
Website 2 on its own word.

> **A compromised Gateway does not get you a trusted Website 2 session.**

That invariant already exists — Website 2 independently verifies every device
itself (W1 §8.1) and never trusts the Gateway's assertion. This document does
not change that guarantee. It is about making the Gateway a harder target and
a smaller blast radius, so the invariant is protected by *two* layers instead
of resting entirely on Website 2's skepticism.

---

## 1. Network placement

```
                 public                      private, no public DNS
   Browser  ───────────────▶  Website 1
                                   │
                                   │  TLS, authenticated backend call
                                   ▼
                              ┌─────────┐
                              │ Gateway │   separate host / own process
                              └─────────┘
                                   │
                                   │  mTLS, private network only
                                   ▼
                              Website 2
```

- Gateway runs as its own process on its own host — not the in-process module
  it is today. It is the only thing that resolves Website 2's private address.
- No network path exists from Website 1 or the browser directly to Website 2.
  This is enforced by a firewall / security-group rule, **not just application
  logic** — if an app-layer bug ever let W1 construct a request that looked
  like it came from the Gateway, the network still refuses to deliver it.
- The Gateway accepts inbound connections from exactly two authenticated
  peers: Website 1's backend and Website 2's event-poller. Nothing else can
  reach it, including the public internet.

---

## 2. Service-to-service authentication

Today: a shared HMAC secret (§7 of README.md flags this as a mock).
Production:

- **mTLS with per-peer certificates.** Website 1 and Website 2 each hold a
  distinct client certificate, issued by an internal CA and short-lived
  (hours, not months).
- **Certificate pinning on top of CA trust.** The Gateway checks the
  presented cert against the specific fingerprint it expects for that peer —
  not just "signed by our CA." A stolen or mis-issued cert from the same CA
  is still rejected. This matters because CA compromise is exactly the kind
  of failure mTLS alone doesn't protect against.
- **Automated rotation** (e.g. SPIFFE/SPIRE-style workload identity) so a
  leaked certificate has a small window before it stops working, with no
  manual redeploy required to rotate it.

---

## 3. Grant issuance — signed, not shared-secret

Today the grant is a row a service can be tricked into trusting if it knows
the shared secret. Redesign:

- The Gateway signs each grant **asymmetrically**. The private key never
  leaves the Gateway (see §4). Website 2 verifies the signature with the
  corresponding public key — it needs no shared secret at all.
- The signed payload carries: employee id, the device's public key (or a
  hash of it), issued-at, expiry (unchanged: 5 minutes), a single-use
  `jti`, and an audience/purpose string.
- That audience/purpose binding is the same pattern already used for the
  device-proof signature (`gatezero:v1:<issuer>:<purpose>:<nonce>`), applied
  one layer up: a grant minted for redemption at Website 2 cannot be replayed
  anywhere else, even if the signature itself is valid.
- This does **not** replace Website 2's independent device check — it adds a
  second, cryptographically verifiable claim ("the Gateway really did approve
  this") that stands on its own instead of depending on a secret both sides
  hold.

---

## 4. Key management

- The grant-signing key lives in an HSM or KMS. It is never an environment
  variable, never on disk in plaintext — this closes the gap README.md §7
  names explicitly ("Signing keys: env vars → HSM / secrets manager").
- Keys rotate automatically. Because grants live at most 5 minutes, a
  rotation only needs to keep the immediately-previous key valid for
  verification for a few minutes past rotation — there's no long tail of old
  keys to protect.
- The Gateway process has no read path to Website 1's password store or
  Website 2's session store. This is an IAM/network-policy fact, not just a
  line of application code that could be edited or bypassed.

---

## 5. Fail closed, always

| Situation | Behavior |
|---|---|
| Gateway can't resolve Website 2's address | Deny |
| Signature verification errors or times out | Deny |
| Unrecognized/unclassified error of any kind | Deny |
| Gateway process is down | Connect fails — never "connect anyway" |

No ambiguous state resolves to permissive. This mirrors the same rule already
applied to device-proof failures (README.md §3): an unclassified failure
fails safe as hostile, so a new failure mode introduced later can't silently
become a bypass just because nobody wrote a case for it yet.

---

## 6. Statelessness and minimal footprint

- The Gateway holds no long-lived session state, no passwords, no business
  data — that's already a stated invariant for this component, and the
  design keeps it structurally true rather than a matter of discipline.
- Grant records live in the shared database (already required for the
  atomic, conditional-`UPDATE` consumption). The Gateway process itself is
  disposable: no local state means any instance can be killed and replaced,
  and horizontal scaling doesn't require sticky sessions.
- Minimal image: no shell, read-only root filesystem, non-root user,
  distroless base. Fewer things on the host means fewer things an attacker
  who lands on it can do next.
- The Gateway exposes exactly its named routes — grant issuance, exchange,
  redemption, verification, address resolution for Website 2, and the
  event-relay endpoint — and nothing else. No admin surface, no debug
  endpoint, no general-purpose API. "Never becomes a general API" (an
  explicit non-goal in README.md §1) is enforced by there being no code
  for anything else, the same way Website 2's out-of-band revoke endpoint is
  kept to one operation by having no code for a second one.

---

## 7. Rate limiting and abuse resistance

- Per-employee and per-IP limits on grant issuance and redemption.
- Redemption is already atomic (conditional `UPDATE ... WHERE consumedAt IS
  NULL`), so a second redemption attempt fails cleanly rather than racing.
  Repeated failed-redemption attempts against the same grant are logged as a
  CRITICAL event — the same severity grading already used for device-proof
  forgery, since a burst of failed redemptions looks like probing or a
  stolen grant being raced against the legitimate one.
- A circuit breaker toward Website 2 means a Gateway under load, or under
  attack, can't be turned into an amplifier that hammers Website 2.

---

## 8. Resolving an address is not granting trust

The Gateway is the only thing that knows where Website 2 lives. That's an
operational fact, not an authorization decision:

- Returning Website 2's address to a caller doesn't make that caller able to
  reach it — network ACLs independently restrict who can open a connection
  to Website 2, regardless of what the Gateway says.
- Internal service-discovery calls are themselves authenticated over mTLS,
  so a compromised internal service can't ask the Gateway to leak or
  redirect Website 2's address for reconnaissance.

---

## 9. Critical event relay

The Gateway forwards events (password change, access revocation,
administrator termination, device revocation) — it does not originate them.

- It relays only events Website 1 already authenticated and signed. Even a
  fully compromised Gateway can't fabricate a new event, only withhold or
  delay a real one — and withholding is caught by Website 2's own
  reconciliation, which re-derives critical state from the system of record
  when delivery can't be confirmed (README.md §3).
- The pull model is unchanged: Website 2 asks, the Gateway never pushes into
  Website 2. No event-injection surface exists on the Gateway side either.

---

## 10. Observability

- Logs pass through the same redaction filter used on Website 1 — secrets
  and tokens are never written, by construction, not by reviewer discipline.
- Every grant mint, redemption, and denial is a hash-chained audit entry,
  using the same tamper-**evident** mechanism already in place. In
  production this writes to an append-only external sink rather than the
  application database, closing the "detection, not prevention" gap noted
  for the system as a whole (README.md §3, §7).
- Metrics and denials feed the same alerting path as the rest of the system,
  replacing the `console.warn` stub with real SIEM/pager integration for at
  least the Gateway's own events.

---

## What stays exactly the same

This design does not ask Website 2 to trust the Gateway any more than it
does today. Website 2 still runs its own device verification against its
own nonce and its own credential record, independent of anything the
Gateway asserts. Everything above is about reducing the odds the Gateway is
compromised in the first place, and shrinking what an attacker gets if it
is — not about relying on the Gateway being trustworthy.

---

## Residual risk / open items

| Item | Status |
|---|---|
| mTLS / workload-identity rollout (SPIFFE/SPIRE or equivalent) | Design only — not built |
| HSM/KMS integration for the grant-signing key | Design only — not built |
| Append-only external audit sink | Shared gap with rest of system (README.md §7); Gateway should not ship its own separate solution |
| SIEM/pager integration | Shared gap with rest of system (README.md §7) |
| Coordination with Website 2's in-memory handshake store | Both must move to shared state together before either scales past one instance |

None of these change the core guarantee. They determine how expensive it is
for an attacker to reach "compromised Gateway" in the first place, and how
much it costs to detect and recover once they have — not whether reaching it
would be enough to get into Website 2.
