# Website 1 — Defense Design

## 1. Purpose

Website 1 is the only permanently public-facing application in GateZero.

Its primary responsibilities are:

- Employee authentication through SSO + MFA
- Maintaining the employee's 7-day authenticated session
- Providing the Connect action for Website 2
- Performing a lightweight security check whenever Connect is clicked
- Sending authorization requests to the Authorization Service
- Recording security-relevant events

Website 1 must never directly grant access to Website 2.

---

## 2. Authentication Defense

Website 1 uses the organization's existing SSO system with MFA.

### Requirements

- SSO authentication is required before access to the portal.
- MFA is required during initial authentication.
- Authentication attempts are rate-limited.
- Repeated failed authentication attempts are monitored.
- Authentication sessions use secure server-side/session-cookie controls.
- Session identifiers are rotated after authentication.
- Passwords, MFA secrets, session tokens, and other sensitive credentials must never be written to logs.

### Authentication Lifetime

The default authentication freshness period is:

**7 days**

After the 7-day period expires, the employee must complete SSO + MFA again.

The 7-day session only proves that the employee has recently authenticated.

It does **not** automatically provide access to Website 2.

---

## 3. Website 1 Session Security

The Website 1 session must be protected against:

- Session fixation
- Session hijacking
- Session theft
- Unauthorized session reuse

Sessions should use:

- Secure cookies
- HttpOnly cookies
- Appropriate SameSite settings
- Server-side session validation
- Session rotation
- Explicit server-side invalidation
- Reasonable session/token entropy

A valid Website 1 session cannot directly be converted into unrestricted Website 2 access.

---

## 4. Connect Button

The Connect button is an explicit security-sensitive action.

The employee must click Connect whenever Website 2 access is required.

A valid 7-day Website 1 session alone does not authorize Website 2.

### Connect Flow

```text
Employee
   |
   | Click Connect
   v
Website 1
   |
   | Security check
   v
Mini EDR / Risk Assessment
   |
   v
Authorization Service
   |
   | Fresh authorization
   v
Access Gateway
   |
   | 5-minute authorization
   v
Website 2
```

Website 1 never directly communicates with Website 2 or the Access Gateway.

Connect generates a one-time, short-lived authorization for the Gateway to act on. Website 1 never creates, controls, or holds the resulting Website 2 session — that session exists only between the Gateway and Website 2.

**Website 1 must never learn or store Website 2's network location, address, or endpoint details.** Only the Authorization Service and Access Gateway resolve where Website 2 lives; Website 1's role ends at requesting an authorization, not at knowing or routing to a destination.

---

## 5. Connect-Time Security Check

Every Connect request triggers a lightweight background security check.

The purpose is to detect significant changes that may indicate:

- Session theft
- Account compromise
- Device compromise
- Abnormal authentication behavior
- Unauthorized session reuse

The check should not unnecessarily interrupt normal employees.

Normal changes, such as switching between ordinary networks, should not automatically result in logout.

The system should instead evaluate the overall risk.

The Connect request also establishes the device/session context that will be associated with the resulting Gateway authorization. Device identification for this purpose relies on cryptographic device identity (§8), not user-agent string fingerprinting — UA strings are trivially spoofed and must not be treated as a reliable identity signal. IP address and other network characteristics are used only as risk telemetry inputs (§6) and never as a substitute for device identity.

---

## 6. Mini EDR

Website 1 contains a small, purpose-built detection layer.

It is intentionally limited to three event categories:

### Login

Monitor:

- Successful logins
- Failed logins
- Repeated failures
- Abnormal login patterns

### MFA

Monitor:

- Successful MFA
- Failed MFA
- Repeated MFA attempts
- Possible MFA-fatigue behavior

### Connect

Monitor:

- Connect attempts
- Connect frequency
- Relevant session/device changes
- Whether the request was allowed or denied

The Mini EDR does not perform endpoint monitoring, process monitoring, file monitoring, or general network monitoring.

**Device identity vs. IP address.** Cryptographic device identity (§8) is the authoritative signal for "is this the employee's known device." IP address is treated strictly as telemetry that feeds the risk score (e.g., unexpected geolocation jump) — it is never used on its own to identify or authenticate a device, since IPs are shared, rotated, and spoofable.

### Scope Boundary

The Mini EDR monitors Website 1 login, MFA, and Connect activity only. It does not monitor Website 2 activity or Website 2 session telemetry. Website 2 has its own, separately designed **Session Guard** responsible for detecting anomalies within its own session once a connection is established. The two detection layers are independent and do not share responsibility for each other's domain.

---

## 7. Risk Levels

The Mini EDR assigns a risk level to relevant Connect requests.

### Low Risk

Examples:

- Normal login behavior
- Expected device/session characteristics
- Ordinary network changes

Action:

```text
Allow Connect
        |
        v
Issue 5-minute Gateway authorization
```

The resulting authorization is one-time (single-use) and bound to the authenticated Website 1 session and its associated device context.

### Medium Risk

Examples:

- Significant but not conclusive session/device change
- Unusual authentication pattern
- Other moderate anomalies

Action:

```text
Block current Connect request
        |
        v
Terminate Website 1 session
        |
        v
Require fresh SSO + MFA
```

If authentication succeeds, the employee can attempt Connect again.

### High Risk

Examples:

- Multiple significant anomalies
- Strong indication of session theft
- Highly abnormal Connect behavior

Action:

```text
Block Connect
        |
        v
Terminate Website 1 session
        |
        v
Require fresh SSO + MFA
        |
        v
Generate security alert
```

### Critical Risk

Examples:

- Strong evidence of account/session compromise
- Confirmed malicious behavior

Action:

```text
Block Connect
        |
        v
Terminate Website 1 session
        |
        v
Revoke active authorization if applicable
        |
        v
Generate high-priority security alert
```

The exact signals and thresholds for each level will be defined during implementation and testing.

---

## 8. Fresh Gateway Authorization

Every successful Connect request generates a **new authorization**.

The authorization is valid for:

**5 minutes**

The authorization is:

- **One-time.** It is consumed on first use and cannot be replayed for a second connection.
- **Cryptographically device-bound.** The authorization is bound to the device's public-key credential. The corresponding private key never leaves the device (e.g., hardware-backed key storage), so a copied or intercepted authorization cannot be redeemed from a different device.

The Gateway must verify both the one-time consumption state and the device-key binding before allowing access to Website 2. The Gateway validates the device-bound proof at authorization time but does not need to persist or permanently store the device's public-key credential — validation is scoped to the current authorization, with the Authorization Service remaining the system of record for registered device credentials.

The 7-day Website 1 session is therefore never directly used as a Website 2 access credential.

```text
7-day authentication
        |
        | Connect
        v
Security check
        |
        | Device/session binding
        v
Fresh 5-minute authorization
        |
        v
Gateway
```

The employee must click Connect again to obtain another authorization window.

The Gateway enforces the 5-minute expiration independently.

### 8.1 Independent Device Verification at Website 2

As a defense-in-depth measure, Website 2 does not rely solely on the Gateway's assertion that a device is legitimate. Website 2 independently verifies the device's private-key proof itself before treating the resulting session as fully trusted. This means a Gateway compromise that forged or mis-validated a device binding is not sufficient on its own to gain a trusted Website 2 session — Website 2 performs its own cryptographic check of the device credential as a second, independent checkpoint.

---

## 9. Website 1 → Authorization Service

Website 1 communicates with the Authorization Service through a mutually authenticated and protected service-to-service channel.

The Authorization Service is responsible for making the authorization decision and issuing the Gateway authorization.

Website 1 must not possess:

- Gateway private keys
- Authorization Service signing keys
- Gateway administrative credentials
- Website 2 credentials
- Website 2 network location, address, or endpoint information

Authorization Service signing keys must receive equivalent protection to other high-value system keys.

The Authorization Service must also maintain the trusted health state used for the emergency Website 1 outage mechanism.

Website 1 must not be able to declare itself unavailable or force the emergency path open.

---

## 10. Connect Abuse Protection

Connect is a security-sensitive operation and must be protected against abuse.

Controls include:

- Rate limiting
- Per-account limits
- Per-session limits
- Request validation
- CSRF protection
- Replay protection
- Monitoring of repeated Connect attempts

Every Connect attempt is logged, including denied attempts.

Excessive or repeated Connect failures trigger:

1. A temporary cooldown on further Connect attempts for that account/session.
2. A security log entry recording the failure pattern.
3. A notification to the employee (e.g., email/push) so they are aware of the activity, independent of any security alert routed to administrators.

---

## 11. Security Logging

Website 1 maintains an auditable security trail for:

- Successful logins
- Failed logins
- MFA success/failure
- Connect attempts
- Connect approvals
- Connect denials
- Risk-level decisions
- Forced session termination
- MFA overrides
- Emergency administrative Connect
- Password resets
- Authorization Service errors

When a Connect request is blocked or the employee is logged out, the security event should record the reason for the decision.

Example:

```text
Event: CONNECT_BLOCKED
Risk: HIGH
Reason: Significant session/device change detected
Action: Website 1 session terminated
Gateway authorization: Not issued
```

Sensitive credentials, MFA secrets, session tokens, and other secrets must never be logged.

Logs must also be protected against unauthorized modification.

---

## 12. Password Reset

Password reset must not become an alternative authentication path.

A password reset is permitted only after successful MFA verification.

### Reset Token Security

Password-reset tokens must:

- Be single-use
- Have a short expiration
- Be invalidated immediately after successful use
- Be securely generated
- Never be written to logs

### Session Invalidation

After a successful password reset:

```text
MFA verification
      |
      v
Password reset
      |
      v
Invalidate existing Website 1 sessions
      |
      v
Fresh authentication required
```

This ensures that an attacker with a previously stolen 7-day Website 1 session cannot continue using that session after the legitimate employee resets their password.

Password change is additionally treated as a critical security event that propagates beyond Website 1: the Authorization Service notifies the Gateway / Website 2's Session Guard so that any active Website 2 session belonging to the employee is also terminated (see §23.3). Without this propagation, an attacker holding a live Website 2 session could survive a password reset intended to lock them out.

---

## 13. Administrative Security

Administrators have significantly greater privileges than normal employees.

Administrative accounts therefore require stronger security controls.

### Administrative Controls

- Strong MFA
- Strict role-based access control
- Separate administrative privileges
- No shared administrator accounts
- Rate limiting
- Detailed audit logging
- Alerts for sensitive administrative actions

Administrative actions involving authentication or Website 2 access must always be auditable.

The administrator is a dedicated administrative identity and should not rely on a normal employee session being elevated into an administrative session.

---

## 14. Admin Re-authentication

Every privileged administrative action requires fresh authentication.

The administrator must re-authenticate before performing:

- MFA override
- Emergency Connect
- Session termination/revocation
- Employee access changes
- Security-policy changes
- Other security-sensitive administrative operations

Each successful re-authentication authorizes **one privileged action only**.

After the action is completed, the elevated authorization expires and the administrator must re-authenticate before performing another privileged action.

The administrator may remain logged into the administrative dashboard for convenience, but being logged into the dashboard does **not** provide permanent authorization to perform privileged operations.

### Security Principle

> **Admin login does not equal permanent administrative authorization. Every privileged action requires fresh proof of administrator identity.**

---

## 15. MFA Override

Administrators may override an employee's MFA requirement when necessary.

Because this bypasses a normal security control, the administrator account becomes a high-value target.

An MFA override should therefore:

1. Require strong administrator authentication.
2. Verify that the administrator has the required role.
3. Record the administrator identity.
4. Record the affected employee.
5. Record the reason.
6. Generate an audit event.
7. Generate an appropriate security alert.

An administrative MFA override must **not** silently create a normal 7-day employee session.

The resulting session must be flagged as **MFA-overridden** and subject to a shorter lifetime.

Additionally, the employee must complete fresh MFA at the next Connect attempt regardless of the remaining lifetime of the overridden session.

An administrative MFA override must not provide permanent Website 2 access.

---

## 16. Emergency Connect During Website 1 or Gateway Outage

Website 1 or the Access Gateway may become temporarily unavailable.

An emergency administrative Connect mechanism is provided for this situation.

### Important Restriction

The emergency Connect function must **only be enabled when Website 1 is independently confirmed to be unavailable**.

Website 1 must never be able to declare itself unavailable or directly trigger the emergency state.

The Authorization Service performs independent health checks against Website 1 (and the Gateway) and maintains the trusted health state used to determine whether the emergency mechanism may be enabled.

A single failed health check must not immediately open emergency access.

The system should use multiple failed checks or another trusted stability threshold to distinguish a genuine outage from a transient failure or attacker-induced disruption.

```text
Authorization Service
        |
        | Independent health checks
        v
   Website 1
        |
        v
Trusted health state
        |
        +----------------------+
        |                      |
     Healthy               Confirmed outage
        |                      |
        v                      v
Emergency Connect          Emergency Connect
DISABLED                   CONDITIONALLY ENABLED
```

An administrator must not have a permanent bypass button that can be used while Website 1 is operating normally.

Once conditionally enabled, an emergency Connect request still requires strong administrator re-authentication and explicit verification of the affected employee's identity before a 5-minute Gateway authorization is issued.

The resulting emergency authorization is:

- **Employee-specific.** Issued for one named employee only, never a generic or shared emergency credential.
- **Device-bound.** Bound to that employee's device public-key credential, the same as a normal Connect authorization.
- **One-time.** Consumed on first use, not reusable across connections.
- **Time-bounded.** Capped at 5 minutes with no extension (see §17).

There is no permanent bypass credential and no reusable emergency token.

---

## 17. Emergency Access Limit

Emergency administrative access uses the exact same Gateway authorization boundary as normal Connect.

Maximum authorization:

**5 minutes**

The administrator cannot extend this authorization.

A new authorization requires another explicit administrative action and fresh administrator re-authentication.

This prevents the emergency mechanism from becoming a permanent backdoor.

When Website 1 becomes healthy again, the emergency Connect mechanism is automatically disabled.

Every emergency authorization must be logged and auditable.

---

## 18. Web Application Security

Website 1 is permanently exposed to the public internet and therefore receives standard web application security controls.

These include protection against:

- XSS
- CSRF
- Injection
- SSRF
- Authentication bypass
- Access-control flaws
- Malicious input
- Automated attacks

Security headers, input validation, output encoding, dependency management, and secure configuration must be implemented as part of deployment.

---

## 19. Availability and Failure Handling

Website 1 should be designed for availability because it is the normal entry point for authorization.

Availability controls should include:

- Rate limiting
- DDoS protection
- Health monitoring
- Redundant deployment where appropriate
- Monitoring of the Authorization Service connection

If the Authorization Service is unavailable, Website 1 must **fail closed** for new Connect requests.

It must never issue or imply authorization simply because the authorization system cannot be reached.

The emergency administrative path exists separately for verified Website 1 outages.

---

## 20. Alert Management

Risk detection should not generate unbounded alerts.

The Mini EDR should use:

- Threshold tuning
- Alert deduplication/correlation
- Severity-based alerting
- Periodic false-positive review
- Defined ownership for alert triage

Medium- and high-risk detections should be reviewed and tuned over time so that repeated legitimate employee behavior does not create alert fatigue.

The exact thresholds and triage workflow will be defined during implementation and testing.

---

## 21. Core Security Principle

Website 1 should follow the principle:

> **Authentication at Website 1 establishes identity; it does not directly establish access to Website 2.**

The security chain is:

```text
SSO + MFA
    |
    v
7-day Website 1 authentication
    |
    | Employee clicks Connect
    v
Mini EDR / Risk Assessment
    |
    | Device/session binding
    v
Authorization Service
    |
    v
5-minute Gateway authorization
    |
    v
Access Gateway
    |
    v
Website 2
```

A compromise of Website 1 must therefore not automatically provide unrestricted access to Website 2.

The Gateway remains the final enforcement point.

---

## 22. Device Identity, Cross-System Session Lifecycle, and Recovery

Cryptographic device identity (§8) is the backbone of device trust across the whole chain — Website 1 risk scoring, Gateway authorization, and Website 2's independent verification (§8.1). This section defines how that identity interacts with session lifecycle across systems.

### 22.1 Website 2 Session Independence

Once established, a Website 2 session is managed and monitored by Website 2's own Session Guard (§6 scope boundary). Its ongoing validity does **not** depend on continuous real-time communication with the Gateway or Website 1. The Gateway's role ends at issuing/consuming the one-time authorization that establishes the session; it is not a continuous dependency for the session's survival.

### 22.2 Device Replacement

Registering a new device credential does not, by itself, immediately terminate Website 2 sessions already established from a previously-registered device. Those sessions continue to be governed by Website 2's normal Session Guard rules and expiry — until superseded per §22.3 or ended through normal expiry/logout.

### 22.3 New-Device Login Triggers Old-Session Termination

When an employee successfully authenticates, completes Connect, and establishes a Website 2 session from a newly-registered device, this event terminates prior active Website 2 sessions for that employee. The Authorization Service propagates this as a termination signal to the Gateway/Website 2 Session Guard, closing the window where an old device's session could otherwise persist indefinitely alongside a new one.

### 22.4 Password Change Propagation

As noted in §12, a password change is a critical security event that is propagated beyond Website 1's own session invalidation. The Authorization Service notifies the Gateway/Website 2 Session Guard to terminate any active Website 2 sessions tied to the employee, preventing a stolen Website 2 session from surviving a password reset.

### 22.5 Device Recovery / Replacement Controls

Recovering account access or registering a replacement device credential (e.g., after a lost or stolen device) is itself a security-sensitive operation and must include:

- **Audit logging** of the recovery/replacement event (who, when, method used, outcome).
- **Employee notification** (e.g., email/push) independent of any administrator-facing alert, so the employee is aware a new device was registered to their account.
- **Abuse controls**, such as rate limiting, identity re-verification steps, and cooldowns, to prevent an attacker from using the recovery flow to register a rogue device.

---

## 23. Open Items / Follow-Up

The following are not yet resolved in this design and should be addressed before or during implementation:

- **Attacker-induced outage confirmation.** The emergency Connect path (§16) currently enables on multiple automated failed health checks alone. An attacker able to sustain a denial-of-service against Website 1 (or the Gateway) could still trip this threshold. Consider requiring a human confirmation step (on-call/second admin) in addition to automated detection before conditionally enabling emergency access.
- **MFA override dual-control.** §15 allows a single administrator to bypass an employee's MFA. Given the sensitivity, consider requiring a second approver or an additional automated policy check before the override takes effect.
- **Clock skew / replay tolerance for the 5-minute grant.** Validation of the grant happens across two services (Authorization Service and Gateway). The design should state an explicit clock-sync requirement and skew tolerance so "5 minutes" is enforced consistently.
- **Log data classification.** Security logs (§11) may contain PII (IP addresses, device fingerprints, employee identity tied to risk events). The design should state retention period, access controls, and classification for the log store itself.
- **Website 2 Session Guard.** §6 references Website 2's own Session Guard as the detection layer for the W2 side, but it is out of scope for this document and not yet designed. Track separately.
- **Cross-system propagation channel (§22.3, §22.4).** The exact mechanism/protocol by which the Authorization Service notifies the Gateway/Website 2 Session Guard of termination events (new-device login, password change) is not yet specified and should be defined during implementation.
- **Device recovery flow detail (§22.5).** The specific identity-reverification steps and rate-limit thresholds for device recovery are not yet defined.

~~Device/session binding mechanism undefined~~ — **Resolved.** §8 now specifies cryptographic, public-key-based device binding with the private key never leaving the device.

These items are lower severity than the core trust model, which is otherwise complete, but should be tracked and closed out before production rollout.

### Status

Per design review, Website 1 is considered **frozen** as of this revision, pending closure of the open items above (which do not block moving forward with implementation).
