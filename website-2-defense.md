# Website 2 Defense

## 1. Security Objective

Website 2 is the protected work environment of GateZero.

Website 2 is intentionally kept as independent as possible from Website 1.

The security architecture follows this principle:

> Website 1 authenticates the employee. The Gateway authorizes access. Website 2 independently manages the resulting work session.

Website 2 does not depend on the Mini EDR and does not continuously monitor Website 1.

### Out of Scope: Business Authorization

This document covers how an employee securely reaches an authenticated Website 2 session. It does not cover what an authenticated employee is permitted to do or see once inside Website 2 — role-based access control, data permissions, and other business-logic authorization are a separate concern, addressed by Website 2's own application-level design.

---

## 2. Website 1 / Gateway / Website 2 Separation

The components have clearly separated responsibilities.

### Website 1

Responsible for:

- Employee authentication
- MFA
- Connect action
- Website 1 security checks
- Mini EDR monitoring of login, MFA, and Connect
- Creating the authorization request

### Gateway

Responsible for:

- Validating Website 1 authorization
- Controlling the transition into Website 2
- Handling one-time authorization
- Preventing authorization replay
- Carrying critical security events between Website 1 and Website 2
- Supporting controlled emergency access

### Website 2

Responsible for:

- Establishing the Website 2 session
- Maintaining session security
- Enforcing inactivity and absolute session limits
- Device/session binding
- Session revocation
- Single-device enforcement
- Website 2 security controls

The Mini EDR does not monitor Website 2.

---

## 3. Gateway Authorization

Website 2 cannot be accessed directly through normal authentication.

The normal access flow is:

1. Employee authenticates on Website 1.
2. Employee completes MFA.
3. Employee clicks Connect.
4. Website 1 performs its security checks.
5. A one-time authorization is generated.
6. The authorization is passed through the Gateway.
7. The Gateway validates the authorization.
8. Website 2 establishes the employee's session.
9. The authorization is consumed and cannot be reused.

The Gateway authorization is:

- One-time
- Short-lived
- Employee-specific
- Device-bound
- Bound to the authorization context
- Invalid after successful Website 2 session establishment

The authorization is not a reusable Website 2 credential.

### Authorization Time Validation

Server-side time is authoritative for all authorization and session-expiration decisions.

Client-provided timestamps are not trusted.

A small server-side clock-skew tolerance may be permitted for distributed components.

Expired authorizations remain invalid even if a client reports a different local time.

---

## 4. Cryptographic Device Binding

Website 2 uses cryptographic device credentials instead of relying solely on IP addresses or browser fingerprints.

An authorized device generates a public/private key pair.

The private key remains on the device and is never transmitted to Website 1, the Gateway, or Website 2.

The corresponding public credential is registered with the employee's account.

### Hardware-Backed Key Storage

Where the device supports it, the private key must be generated and stored in a hardware-backed secure store (e.g., TPM, Secure Enclave, or equivalent).

If hardware-backed storage is unavailable, the platform's strongest available secure credential store is used instead, and that device is treated as lower-assurance.

In all cases, the private key still never leaves the device.

Conceptually:

```text
Authorized Device
       |
       +-- Private Key → remains on device
       |
       +-- Public Key → registered with GateZero
```

Website 2 can require cryptographic proof that the device possesses the private key associated with the registered credential.

This prevents a stolen session identifier from being sufficient by itself to access Website 2.

### Cryptographic Challenge Freshness

Every cryptographic device-authentication request must use a fresh, unpredictable, server-generated nonce.

The device signs the challenge using its private key.

Website 2 verifies the signature using the registered public credential.

A previously generated signature or proof cannot be reused for another authentication request.

---

## 5. Single Authorized Device

Each employee may have only one authorized Website 2 device/browser context.

The policy is:

> One employee → one authorized device credential → one active Website 2 session.

Browser/device changes are not treated as normal session changes.

The employee must not switch to another browser or device while retaining the same Website 2 authorization.

The following are not considered device changes:

- Page refresh
- Normal browser activity
- Laptop sleep/wake
- IP/network changes

The following are considered unauthorized changes:

- Different device
- Different browser authorization context
- Use of the existing session from an unauthorized device

---

## 5A. Administrator Root of Trust

Every admin-gated operation in this document — device registration, recovery, credential revocation, emergency access — assumes a trusted administrator identity already exists. That identity must itself be established through a controlled process, not normal employee self-registration.

The initial administrator account is provisioned through a controlled administrative enrollment process.

This process requires:

- Strong MFA and device binding for the administrator, equivalent to or stronger than employee device binding.
- Secure provisioning of initial administrator credentials/keys, outside of any self-service flow.
- A separate, verified process for administrator recovery or replacement — an administrator cannot recover their own access through the same self-service path available to employees.

This administrator identity becomes the root of trust for all admin-gated operations described elsewhere in this document.

---

## 6. Initial Device Registration

Initial Website 2 device registration is handled by the administrator.

The administrator must authenticate and approve the employee's device registration.

The private key is generated and retained by the device.

The administrator never receives or stores the private key.

The registered public credential becomes associated with the employee's Website 2 access.

---

## 7. Device Replacement

A legitimate device replacement requires:

1. Employee authentication.
2. Successful MFA.
3. Device replacement request.
4. Administrator reauthentication.
5. Administrator approval.
6. Revocation of the previous device credential.
7. Termination of the previous Website 2 session.
8. Registration of the new device credential.

The old credential cannot continue to access Website 2 after replacement.

---

## 8. Lost Device and Recovery

Automated recovery must not bypass device binding.

If an employee loses access to their authorized device:

1. The employee requests recovery.
2. Human verification is performed.
3. The administrator verifies the employee's identity.
4. The administrator reauthenticates.
5. The old device credential is revoked.
6. Any active Website 2 session associated with the old credential is terminated.
7. The administrator approves registration of the replacement device.

Recovery is intentionally human-controlled because possession of the original device credential can no longer be used to prove device ownership.

### Recovery Request Protection

Device replacement and recovery requests are security-sensitive actions.

Recovery requests are:

- Rate-limited
- Logged
- Monitored for repeated requests
- Associated with employee notifications

Repeated recovery requests within a defined period may trigger a higher-risk security event and additional administrator scrutiny.

Rate limiting and monitoring do not replace the required human verification and administrator approval.

---

## 9. Credential Revocation

Device credential revocation permanently invalidates a previously authorized device credential.

A revoked credential cannot be reused to access Website 2.

Credential revocation may occur because of:

- Device replacement
- Lost or stolen device
- Suspected credential compromise
- Employee access removal
- Administrator action
- Security response

When a credential is revoked, associated active Website 2 sessions are terminated.

---

## 9A. Device Credential Rotation

Device credentials must not remain valid indefinitely.

The system periodically requires device re-attestation and credential rotation.

During successful rotation:

1. The device proves possession of the current private key.
2. A new device credential is established.
3. The new credential becomes active.
4. The previous credential is revoked.

The exact credential rotation period will be defined during final implementation.

Credential rotation must not require the private key to leave the device.

### Offline Grace Period

A device that is offline at the time of scheduled rotation is not immediately locked out.

The credential is given a defined grace period after its scheduled rotation date, during which the existing credential remains valid.

Once the device reconnects within the grace period, it must re-attest and complete rotation.

If the grace period expires without re-attestation, the credential becomes invalid and the device requires re-registration or recovery.

The exact grace period length will be defined during final implementation.

---

## 10. Website 2 Session Establishment

A Website 2 session is created only after successful Gateway authorization.

The resulting session is associated with:

- Employee identity
- Device credential
- Session identifier
- Session creation time
- Last meaningful activity
- Session expiration
- Session status

Website 2 maintains the session independently after establishment.

Website 1 does not need to continuously monitor the session.

---

## 11. Single Active Website 2 Session

Only one Website 2 session may be active for an employee at a time.

A second device cannot immediately terminate the existing session merely by attempting authorization.

The existing session remains active while the new device is:

- Failing MFA
- Failing security checks
- Failing Gateway authorization
- Using an expired authorization
- Attempting to access Website 2 without completing login

The existing session is revoked only after the new device successfully completes the entire Website 2 login/session-establishment process.

The resulting flow is:

```text
Device A
   |
   +-- W2 Session A → ACTIVE

Device B
   |
   +-- Full authorization flow
           |
           +-- W2 login succeeds
                    |
                    +-- Session A → REVOKED
                    +-- Session B → ACTIVE
```

---

## 12. Session Replacement Notification

When a new device successfully establishes a Website 2 session:

1. The previous Website 2 session is immediately revoked.
2. The new session becomes active.
3. The event is logged.
4. The employee is notified through their registered personal/recovery email.

The notification must not contain:

- Passwords
- Private keys
- Authorization codes
- Session tokens
- Sensitive security information

The notification exists to alert the employee that their previous Website 2 session was replaced.

---

## 13. Session Security

Website 2 uses normal secure web-session practices in addition to GateZero-specific controls.

Session credentials must be protected using appropriate secure cookie and server-side session controls.

Session protections include:

- Secure cookies
- HttpOnly cookies
- Appropriate SameSite protection
- HTTPS/TLS
- Server-side session validation
- Session identifier rotation
- Session expiration
- Session revocation
- CSRF protection
- XSS protection
- Input validation
- Injection protection
- Server-side authorization checks
- Appropriate security headers

The final implementation will define the exact technical mechanisms.

---

## 14. Session Theft Protection

A stolen Website 2 session identifier must not be sufficient to access Website 2 from another device.

The session is associated with the authorized device credential.

A request must satisfy the required session and device validation checks.

Conceptually:

```text
W2 Request
    |
    +-- Valid session?
    |
    +-- Correct device context?
    |
    +-- Valid cryptographic device proof?
    |
    +-- Session not revoked?
    |
    +-- Session not expired?
    |
    +-------- YES --------> ALLOW
```

A stolen session identifier used without the corresponding device credential is rejected.

---

## 15. Session Replay Protection

Authorization and session credentials must not be reusable outside their intended context.

If an authorization has already been successfully consumed, another attempt to use it is rejected.

Repeated or high-confidence replay attempts are treated as security events.

The external response should remain generic so the Gateway does not reveal unnecessary information about the reason for rejection.

Internally, the system may distinguish between:

- Expired authorization
- Already-used authorization
- Device mismatch
- IP mismatch during initial authorization
- Invalid authentication
- Invalid cryptographic proof

---

## 16. Session Identifier Rotation

Website 2 should rotate session identifiers after important authentication transitions and according to the final session implementation.

An old session identifier must become invalid after rotation.

This reduces the usefulness of leaked or previously valid session identifiers.

---

## 17. Session Inactivity Rules

Website 2 uses different inactivity limits depending on the organization security mode.

### Startup

Maximum inactivity:

**3 hours**

### Established Organization

Maximum inactivity:

**2 hours**

The inactivity timer should reset based on meaningful application activity rather than arbitrary background browser requests.

Background polling must not be sufficient to keep an abandoned session alive indefinitely.

---

## 18. Absolute Session Lifetime

Established organizations have an additional absolute session limit.

### Startup

Maximum inactivity:

**3 hours**

Maximum total Website 2 session lifetime:

**36 hours**

### Established Organization

Maximum inactivity:

**2 hours**

Maximum total Website 2 session lifetime:

**24 hours**

This applies regardless of activity.

Therefore:

```text
Established Organization

2 hours inactivity
        OR
24 hours total lifetime
        ↓
Session expires


Startup Organization

3 hours inactivity
        OR
36 hours total lifetime
        ↓
Session expires
```

Both startup and established organizations now have an absolute session lifetime in addition to their inactivity limit.

---

## 19. Website 2 Session Expiration

When a Website 2 session expires:

- The Website 2 session is revoked.
- Associated session authorization is invalidated.
- Website 1 remains active.
- The employee is not required to restart Website 1 authentication merely because Website 2 expired.

The employee can return to Website 1 and use Connect again to establish a new Website 2 session.

The session expiration message should remain simple:

> Session expired. Connect again to continue.

---

## 20. Logout

Website 2 logout only affects Website 2.

When an employee logs out:

- Current W2 session is revoked.
- Associated Gateway authorization is invalidated.
- Website 1 remains logged in.
- The employee may use Connect again through Website 1.

Logout from Website 2 does not automatically log the employee out of Website 1.

---

## 21. Password Change Security Event

A password change or password reset on Website 1 is treated as a critical security event.

Website 1 does not directly control Website 2.

Instead:

```text
Website 1
    |
    +-- PASSWORD_CHANGED
             |
             v
          Gateway
             |
             v
        Website 2
             |
             v
     Terminate W2 sessions
```

Website 2 terminates all active sessions associated with the affected employee.

Associated pending authorizations are also invalidated.

This allows password-change security to affect Website 2 without creating a permanent direct dependency between Website 1 and Website 2.

### Critical Event Delivery

Critical security events must use at-least-once delivery.

The Gateway must acknowledge successful delivery, retry undelivered events, and prevent duplicate processing through event identifiers.

Website 2 must process each critical event idempotently.

A fallback reconciliation mechanism should verify critical account-security state if event delivery cannot be confirmed.

Critical events include:

- Password changes/resets
- Access revocation
- Administrator-forced termination
- Critical account security events

---

## 22. Administrator Session Termination

An administrator may revoke an employee's Website 2 access through the controlled administrative security mechanism.

Administrator-forced termination:

- Revokes the employee's active Website 2 session.
- Invalidates pending Website 2 authorizations.
- Prevents new Website 2 authorization from succeeding while the access restriction remains active.
- Creates a security audit event.

Administrator actions require strong administrator authentication.

The administrator must reauthenticate before each security-sensitive action.

---

## 23. Connect Attempt Rate Limiting

Connect attempts from Website 1 are rate-limited.

The exact threshold remains configurable.

The system tracks:

- Total Connect attempts
- Failed Connect attempts
- Successful Connect attempts
- Failure reasons
- Time of attempts
- Relevant security context

Excessive failed attempts trigger:

1. Temporary Connect cooldown.
2. Security event logging.
3. Employee account notification.

The rate limit is enforced server-side.

Frontend controls may prevent accidental rapid clicking, but they are not considered a security control.

---

## 24. Gateway Authorization Replay Protection

Gateway authorizations are one-time and cannot be reused.

Example:

```text
Authorization
      |
      +-- First successful use → CONSUMED
      |
      +-- Second use → REJECTED
```

A replay attempt is logged as a security event.

The authorization must not become a permanent credential for Website 2.

---

## 25. Gateway and Website 2 Trust Boundary

Website 2 must not blindly trust requests merely because they originate from the Gateway.

Gateway-to-Website-2 communication must use authenticated service-to-service communication.

The Gateway must also validate requests coming from Website 1.

The Gateway should remain intentionally small and limited in responsibility.

It should not:

- Store employee passwords
- Store Website 2 business data
- Become a general-purpose API
- Continuously monitor Website 2 activity
- Function as an EDR

---

## 26. Website 1 / Gateway Outage

If Website 1 or the Gateway becomes unavailable:

### Existing Website 2 sessions

Existing valid Website 2 sessions continue normally.

Website 2 does not terminate active sessions merely because Website 1 or the Gateway is unavailable.

### New Website 2 access

Normal authorization cannot be completed while the required authorization infrastructure is unavailable.

A controlled administrator emergency path is therefore available.

### Out-of-Band Emergency Session Revocation

If the Gateway is unavailable while an active Website 2 session must be terminated, an administrator may use a separate out-of-band revocation mechanism that communicates directly with Website 2.

The mechanism is restricted to session revocation only.

It cannot:

- Create Website 2 sessions
- Authorize new devices
- Bypass MFA
- Create emergency credentials
- Modify Website 2 security controls

The administrator must reauthenticate before performing the revocation.

### Out-of-Band Channel Security

The direct Admin → Website 2 channel receives the same level of protection as the Gateway boundary:

- Strong authenticated service-to-service communication.
- Administrator authentication and authorization on every call.
- A narrow endpoint that can only revoke sessions — no other capability is exposed.
- No session creation or authorization is possible through this channel.
- Every use is fully audited.

```text
Gateway unavailable
        ↓
Active W2 session requires termination
        ↓
Admin reauthenticates
        ↓
Out-of-band W2 revocation
        ↓
W2 terminates session
```

The revocation is logged as a high-priority security event.

---

## 27. Trusted Outage Detection

The administrator emergency path must not activate simply because Website 1 or the Gateway claims that it is unavailable.

A trusted, independent health mechanism must verify the outage.

Conceptually:

```text
W1 / Gateway health
       |
       +-- Available → Emergency access blocked
       |
       +-- Confirmed unavailable → Emergency access enabled
```

This prevents an attacker from intentionally triggering a false outage state to obtain emergency access.

### Human Confirmation for Emergency Access

An independent health mechanism detects and verifies Website 1/Gateway availability.

A confirmed outage makes the emergency access path available but does not automatically authorize access.

The administrator must explicitly confirm the outage and then reauthenticate before emergency access can proceed.

```text
W1/Gateway outage detected
        ↓
Independent health verification
        ↓
Emergency path made available
        ↓
Admin explicitly confirms
        ↓
Admin reauthenticates
        ↓
Emergency access
```

This same human-confirmation requirement applies to the Website 1 emergency path.

---

## 28. Emergency Administrator Access

Emergency access is a break-glass mechanism.

It is available only when the trusted health mechanism confirms that normal Website 1/Gateway authorization is unavailable.

The flow is:

```text
W1 / Gateway outage
        |
        v
Trusted outage confirmation
        |
        v
Admin emergency access
        |
        v
Admin reauthentication
        |
        v
Employee selection
        |
        v
Admin reauthentication
        |
        v
Emergency Connect
        |
        v
Website 2
```

The administrator must reauthenticate before every security-sensitive step.

---

## 29. Emergency Access Restrictions

Emergency access must remain extremely limited.

The administrator cannot use it to:

- Disable Website 2 security
- Create permanent bypass credentials
- Disable device binding
- Create unlimited sessions
- Permanently bypass MFA
- Circumvent normal Website 2 session protections

Emergency authorization is:

- Employee-specific
- Device-specific
- One-time
- Short-lived
- Limited to the emergency access window
- Fully logged

The emergency establishment window is limited to **5 minutes**.

---

## 30. Emergency Access Logging

Every emergency access attempt creates a high-priority audit event.

The event records information such as:

- Administrator identity
- Target employee
- Timestamp
- Reason
- Trusted outage evidence/event
- Action requested
- Result
- Resulting session identifier where applicable

The employee is also notified when emergency Website 2 access is successfully established for their account.

---

## 31. Emergency Authorization Reuse

Emergency authorization must never become a reusable credential.

An emergency authorization is:

```text
Employee-specific
+
Device-specific
+
One-time
+
Short-lived
```

After successful Website 2 session establishment, the emergency authorization is consumed.

An expired or previously used emergency authorization is rejected.

### Emergency MFA Override Control

The current architecture uses a single administrator.

Because there is only one administrator, true two-person approval cannot be enforced.

Emergency administrator actions therefore require:

- Strong administrator reauthentication
- Explicit confirmation
- A documented reason
- High-priority audit logging
- Employee notification
- Strict emergency-access restrictions

Single-administrator emergency approval is an accepted residual risk of the current architecture.

---

## 32. Security Event Boundary

Website 2 does not continuously communicate with Website 1.

Only critical security events that genuinely need to cross the W1/W2 boundary are carried through the Gateway.

Examples include:

- Password changed/reset
- Website 2 access revoked
- Administrator-forced termination
- Critical account security events

These events must be authenticated and protected against:

- Forgery
- Tampering
- Replay
- Unauthorized modification

The exact event-delivery mechanism will be finalized during implementation.

---

## 33. Logging Philosophy

Website 2 does not use the Mini EDR.

Continuous endpoint telemetry is intentionally avoided because it would create unnecessary log volume and couple Website 2 to the endpoint monitoring system.

Website 2 logs security-relevant events such as:

- Session creation
- Session expiration
- Session replacement
- Session revocation
- Device mismatch
- Credential revocation
- Authorization replay
- Excessive Connect attempts
- Password-change session termination
- Administrator termination
- Emergency access
- Security-event processing

The final logging implementation will define storage, retention, integrity protection, and alerting.

---

## 34. Employee Notifications

Security-relevant events may generate notifications through the employee's registered personal/recovery email.

Notifications may include:

- New device/session successfully established
- Previous session replaced
- Emergency Website 2 access
- Excessive Connect attempts
- Other high-confidence account security events

Notifications must not contain:

- Passwords
- Private keys
- Session tokens
- Authorization codes
- Sensitive internal security information

Email notification is an alerting mechanism and must not be required for Website 2 authorization to succeed.

For high-severity security events, Website 2 should use the employee's registered personal/recovery email and a secondary configured notification channel such as SMS or push notification.

The secondary channel provides redundancy if the primary notification channel is compromised or unavailable.

Notifications are alerting mechanisms and are never used as authorization credentials.

---

## 35. W2 Security Principle

Website 2 should remain independent after authorization.

The intended relationship is:

```text
                WEBSITE 1
          Authentication + MFA
                  |
                  v
              GATEWAY
             Authorization
                  |
                  v
               WEBSITE 2
           Session + Security
```

Website 1 does not continuously control Website 2.

Website 2 does not continuously query Website 1.

The Mini EDR does not monitor Website 2.

The Gateway only carries the authorization and critical security events necessary to maintain the security boundary.

---

## 36. Final Security Model

The Website 2 defense is based on several layers:

```text
                    WEBSITE 2
                        |
             +----------+----------+
             |                     |
        Gateway Auth          Session Guard
             |                     |
      Device Binding         Session Security
             |                     |
       One-Time Access       Session Limits
             |                     |
             +----------+----------+
                        |
                 Device Credential
                        |
                  Private Key
                  stays on device
```

The core principle is:

> Website 1 proves identity. The Gateway authorizes access. Website 2 independently protects the work session.

This minimizes the dependency between Website 1 and Website 2 while maintaining strong controls over authorization, device identity, session security, and emergency access.

---

## 37. Open Items

- **Log data classification, retention, and access control.** Deferred to final implementation/design — not specified in this document.
