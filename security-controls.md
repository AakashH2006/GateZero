# GateZero Security Controls

This document defines the security controls designed to mitigate the threats
identified in `threat.md`.

Each control is mapped to a specific attack scenario and describes how the
system should prevent, detect, or limit the impact of that attack.

---

## 1. Direct Access to Website 2

### Threat

An attacker attempts to access Website 2 directly without going through the
Access Gateway.

### Defensive Controls

- Website 2 must not be directly exposed to the public internet.
- Network-level firewall rules must allow inbound traffic only from the
  legitimate Access Gateway.
- Website 2 must reject connections that do not originate from an authenticated
  Gateway.
- Gateway-to-Website 2 communication must use mTLS.
- DNS and network configuration must not expose an alternative public route
  to Website 2.

### Security Objective

Even if an attacker discovers the address of Website 2, the application
must remain unreachable without going through the legitimate Gateway.

---

## 2. Gateway Bypass

### Threat

An attacker attempts to find an alternative route to Website 2 that bypasses
the Gateway.

### Defensive Controls

- Website 2 must exist within a private network.
- Firewall rules must restrict inbound traffic to the Gateway.
- No alternate public-facing backend, port, or service should expose Website 2.
- Administrative interfaces must be separated from the Website 2 traffic path.
- Network segmentation must prevent unauthorized services from reaching
  Website 2.

### Security Objective

There must be no network path that allows an attacker to bypass the Gateway.

---

## 3. Forged Authorization Grant

### Threat

An attacker attempts to create or modify an authorization grant so that the
Gateway incorrectly considers the attacker authorized.

### Defensive Controls

- Grants must be cryptographically protected.
- The Gateway must verify the authenticity and integrity of every grant.
- Grant contents must not be trusted before validation.
- Grants must contain an expiration time.
- Grants should contain a defined scope limiting them to the intended resource.
- Signing keys must be protected and inaccessible to normal application
  processes where possible.
- Authorization Service signing keys must be stored using secure key
  management.

### Security Objective

An attacker must not be able to create or modify a valid authorization grant.

---

## 4. Authorization Grant Replay

### Threat

An attacker captures a legitimate authorization grant and attempts to reuse it.

### Defensive Controls

- Grants must have a short lifetime.
- Grants must contain an expiration timestamp.
- Grants should be bound to the authenticated employee session and/or device.
- The Gateway must reject expired grants.
- Replay protection should be implemented where the selected grant mechanism
  supports it.
- Revoked grants must be rejected.

### Security Objective

Stealing a grant should provide only limited and temporary value to an attacker.

---

## 5. Stolen Website 1 Session

### Threat

An attacker obtains a valid Website 1 session and attempts to use it to gain
Website 2 access.

### Defensive Controls

- Website 1 sessions must use secure, HttpOnly, SameSite cookies where
  applicable.
- Sessions must be protected against session fixation and hijacking.
- Connect requests must be authenticated against the current session.
- Connect requests should be bound to the authenticated device/session.
- Suspicious session changes should trigger additional verification.
- Connect requests must be rate-limited.
- Website 2 still requires its own authentication layer.

### Security Objective

Compromise of a Website 1 session must not automatically provide unrestricted
access to Website 2.

---

## 6. Connect Abuse

### Threat

An attacker repeatedly triggers the Connect mechanism to abuse the
authorization system.

### Defensive Controls

- Rate-limit Connect requests per user.
- Rate-limit requests per session/device.
- Apply IP-based rate limiting where appropriate.
- Detect abnormal Connect patterns.
- Log authorization requests.
- Temporarily block abusive clients.
- Require additional verification when suspicious activity is detected.

### Security Objective

The Connect mechanism must not become an unrestricted authorization API.

---

## 7. MFA Fatigue Attack

### Threat

An attacker repeatedly triggers MFA requests hoping that an employee
eventually approves one accidentally.

### Defensive Controls

- Prefer phishing-resistant MFA where possible.
- Use number matching or contextual approval for push-based MFA.
- Rate-limit authentication attempts.
- Limit repeated MFA requests.
- Notify users about suspicious authentication activity.
- Detect unusual authentication patterns.

### Security Objective

An attacker must not be able to overwhelm an employee with authentication
requests.

---

## 8. Compromised Website 1

### Threat

An attacker compromises Website 1 and attempts to use it to reach internal
services or obtain unauthorized Website 2 access.

### Defensive Controls

- Website 1 must not communicate directly with Website 2.
- Service-to-service communication with the Authorization Service must be
  authenticated.
- Website 1 must have only the minimum permissions required.
- Authorization Service credentials must not provide Gateway administrative
  access.
- Network segmentation must isolate Website 1 from internal services.
- Website 1 must not have access to Gateway or Authorization Service
  management interfaces.
- Secrets must not be stored in Website 1 source code or exposed to the
  frontend.

### Security Objective

Compromise of Website 1 must not result in automatic compromise of Website 2,
the Gateway, or the internal network.

---

## 9. Compromised Website 2

### Threat

An attacker compromises Website 2 and attempts to move laterally through the
internal network.

### Defensive Controls

- Website 2 must have strict outbound/egress filtering.
- Website 2 must not be able to access Gateway management interfaces.
- Website 2 must not have unrestricted access to the Authorization Service.
- Internal services must use separate authentication.
- Network segmentation must limit lateral movement.
- Website 2 should run with least-privilege permissions.

### Security Objective

Compromise of Website 2 must not provide unrestricted access to GateZero's
control plane or internal infrastructure.

---

## 10. Gateway Impersonation

### Threat

An attacker attempts to create a fake Gateway that Website 2 trusts.

### Defensive Controls

- Website 2 must authenticate the Gateway using mTLS.
- Website 2 must validate the Gateway certificate.
- Gateway private keys must be securely stored.
- Private keys should be protected using a vault, HSM, or equivalent mechanism.
- Certificates must support rotation and revocation.
- Unauthorized certificates must be rejected.
- Website 2 must not trust arbitrary certificates.

### Security Objective

An attacker without the legitimate Gateway's cryptographic identity must
not be able to impersonate the Gateway.

---

## 11. Authorization Service Compromise

### Threat

An attacker compromises the Authorization Service and attempts to issue
unauthorized grants or access sensitive signing keys.

### Defensive Controls

- Authorization Service signing keys must be strongly protected.
- Administrative access must be separated from normal service access.
- Least-privilege permissions must be enforced.
- Authorization actions must be logged.
- Sensitive operations should generate security alerts.
- Keys must be rotated when compromise is suspected.
- The Authorization Service should not expose unnecessary interfaces.
- High availability should be implemented without weakening access controls.

### Security Objective

The Authorization Service must remain a protected trust root and unauthorized
users must not be able to generate valid grants.

---

## 12. Revocation Bypass

### Threat

An attacker attempts to maintain access after their authorization has been
revoked.

### Defensive Controls

- Authorization grants must have short expiration periods.
- The Authorization Service must send authenticated revocation events to
  the Gateway.
- The Gateway must invalidate revoked grants.
- Active connections associated with revoked authorization should be
  terminated.
- Grant expiration provides a fallback if the Gateway temporarily cannot
  receive a revocation event.
- Revocation events must be logged.

### Security Objective

Revoked access must terminate immediately when the Gateway is reachable and
must never continue beyond the grant's maximum lifetime.

---

## 13. Gateway Availability Attack

### Threat

An attacker attempts to make the Gateway unavailable, preventing legitimate
employees from accessing Website 2.

### Defensive Controls

- Deploy multiple Gateway instances.
- Use health checks.
- Implement automatic failover.
- Apply rate limiting.
- Use DDoS protection.
- Monitor Gateway health and traffic.
- Ensure Website 2 is never exposed as a fallback when the Gateway fails.

### Security Objective

Gateway failure must result in denied access rather than direct exposure of
Website 2.

---

## 14. Authorization Service Availability Attack

### Threat

An attacker attempts to disrupt the Authorization Service and prevent
legitimate authorization requests.

### Defensive Controls

- Deploy multiple Authorization Service instances.
- Use health checks and failover.
- Rate-limit authorization requests.
- Monitor service health.
- Protect management interfaces.
- Ensure the failure of the Authorization Service does not cause Website 2
  to become publicly accessible.
- Fail closed when authorization cannot be verified.

### Security Objective

Availability failures must never result in unauthorized access to Website 2.

---

# Security Principle

GateZero follows a **fail-closed** security model.

When authorization cannot be verified, the system should deny access rather
than assume that access is permitted.

Compromising one component should not automatically grant an attacker trust
or administrative access to the other components.
