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

The Connect request also establishes the device/session context that will be associated with the resulting Gateway authorization.

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

The resulting authorization is bound to the authenticated Website 1 session and its associated device context.

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

The authorization is cryptographically or otherwise securely bound to the authenticated Website 1 session and its associated device/session context.

The Gateway must verify this binding before allowing access to Website 2.

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

---

## 9. Website 1 → Authorization Service

Website 1 communicates with the Authorization Service through a mutually authenticated and protected service-to-service channel.

The Authorization Service is responsible for making the authorization decision and issuing the Gateway authorization.

Website 1 must not possess:

- Gateway private keys
- Authorization Service signing keys
- Gateway administrative credentials
- Website 2 credentials

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

## 16. Emergency Connect During Website 1 Outage

Website 1 may become temporarily unavailable.

An emergency administrative Connect mechanism is provided for this situation.

### Important Restriction

The emergency Connect function must **only be enabled when Website 1 is independently confirmed to be unavailable**.

Website 1 must never be able to declare itself unavailable or directly trigger the emergency state.

The Authorization Service performs independent health checks against Website 1 and maintains the trusted health state used to determine whether the emergency mechanism may be enabled.

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

## 22. Open Items / Follow-Up

The following are not yet resolved in this design and should be addressed before or during implementation:

- **Attacker-induced outage confirmation.** The emergency Connect path (§16) currently enables on multiple automated failed health checks alone. An attacker able to sustain a denial-of-service against Website 1 could still trip this threshold. Consider requiring a human confirmation step (on-call/second admin) in addition to automated detection before conditionally enabling emergency access.
- **MFA override dual-control.** §15 allows a single administrator to bypass an employee's MFA. Given the sensitivity, consider requiring a second approver or an additional automated policy check before the override takes effect.
- **Device/session binding mechanism undefined.** The document repeatedly states that Gateway authorizations are bound to a device/session context (§5, §7, §8, §21) but does not specify the mechanism (e.g., TLS client certificate, device fingerprint, bound cookie). This needs to be decided during implementation.
- **Clock skew / replay tolerance for the 5-minute grant.** Validation of the grant happens across two services (Authorization Service and Gateway). The design should state an explicit clock-sync requirement and skew tolerance so "5 minutes" is enforced consistently.
- **Log data classification.** Security logs (§11) may contain PII (IP addresses, device fingerprints, employee identity tied to risk events). The design should state retention period, access controls, and classification for the log store itself.

These items are lower severity than the core trust model, which is otherwise complete, but should be tracked and closed out before production rollout.
