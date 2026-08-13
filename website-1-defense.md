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

The 7-day Website 1 session is therefore never directly used as a Website 2 access credential.

```text
7-day authentication
        |
        | Connect
        v
Security check
        |
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

The reset process must not allow an attacker who only controls the password-reset channel to bypass MFA.

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

---

## 14. MFA Override

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

An administrative MFA override must not provide permanent Website 2 access.

---

## 15. Emergency Connect During Website 1 Outage

Website 1 may become temporarily unavailable.

An emergency administrative Connect mechanism is provided for this situation.

### Important Restriction

The emergency Connect function must **only be enabled when Website 1 is confirmed to be unavailable**.

An administrator must not have a permanent bypass button that can be used while Website 1 is operating normally.

The system should independently verify Website 1 health before enabling emergency access.

```text
Website 1 healthy
       |
       v
Emergency Connect DISABLED


Website 1 unavailable
       |
       v
Emergency Connect ENABLED
       |
       v
Strong admin authentication
       |
       v
Employee verification
       |
       v
5-minute Gateway authorization
```

Website 1 being unavailable must never automatically grant access.

---

## 16. Emergency Access Limit

Emergency administrative access uses the exact same Gateway authorization boundary as normal Connect.

Maximum authorization:

**5 minutes**

The administrator cannot extend this authorization.

A new authorization requires another explicit administrative action.

This prevents the emergency mechanism from becoming a permanent backdoor.

When Website 1 becomes healthy again, the emergency Connect mechanism is automatically disabled.

Every emergency authorization must be logged and auditable.

---

## 17. Web Application Security

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

## 18. Availability and Failure Handling

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

## 19. Core Security Principle

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

## Admin Re-authentication

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
