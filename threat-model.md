## 1. Objective

The objective of GateZero is to protect a sensitive internal web application (Website 2) from direct exposure to the public internet.

The system uses a separate public authentication portal (Website 1), an Authorization Service, and a protected Access Gateway.

The threat model identifies potential attackers, attack paths, trust boundaries, and security failures that could allow an attacker to bypass authentication, authorization, the Gateway, or the isolation of Website 2.

The goal is to identify these threats before implementation and use them later to guide security controls and testing.

## 2. Assets

The following assets require protection within the GateZero architecture:

### 2.1 Employee Identity

Employee credentials, SSO sessions, and MFA authentication state used to establish the employee's identity.

### 2.2 Website 1 Session

The authenticated session created after the employee successfully completes SSO and MFA.

### 2.3 Authorization Grants

Short-lived grants issued after the employee selects **Connect**. These grants determine whether the Gateway should allow access to Website 2.

### 2.4 Website 2

The sensitive application that GateZero is designed to protect from direct public exposure.

### 2.5 Authorization Service

The service responsible for validating authenticated sessions, issuing authorization grants, and handling revocation.

### 2.6 Access Gateway

The security enforcement point responsible for controlling and forwarding authorized traffic to Website 2.

### 2.7 Cryptographic Keys and Certificates

Private keys, certificates, signing keys, and other cryptographic material used to establish trust between GateZero components.

### 2.8 Employee and Company Data

Sensitive information processed or stored by Website 2 and its supporting infrastructure.

### 2.9 Audit and Security Logs

Records of authentication, authorization, Connect requests, Gateway activity, revocations, and security events.

### 2.10 Internal Infrastructure

The internal network, databases, services, containers, and management interfaces supporting GateZero.

## 3. Trust Boundaries

A trust boundary is a point where data or requests move between components with different levels of trust.

GateZero contains the following primary trust boundaries:

### 3.1 Internet → Website 1

Website 1 is publicly reachable and therefore exposed to untrusted internet traffic.

Security concerns include:

- Automated attacks
- Credential attacks
- Session attacks
- Web application vulnerabilities
- MFA abuse
- Bot activity

Website 1 must not expose Website 2 or its internal infrastructure.

### 3.2 Website 1 → Authorization Service

Website 1 communicates with the Authorization Service to request authorization after the employee selects **Connect**.

This is a trusted service-to-service boundary and must use authenticated and encrypted communication.

An attacker must not be able to impersonate Website 1 or submit unauthorized authorization requests.

### 3.3 Authorization Service → Access Gateway

The Authorization Service communicates authorization decisions and revocation information to the Gateway.

This is a highly sensitive trust boundary because the Authorization Service determines whether access can be granted.

The communication must be authenticated and protected against:

- Forged authorization messages
- Message modification
- Replay attacks
- Unauthorized revocation or grant requests

### 3.4 Internet → Access Gateway

The Gateway is the only public-facing entry point to Website 2.

It must treat incoming traffic as untrusted until the authorization and security checks are completed.

The Gateway must prevent unauthorized traffic from reaching Website 2.

### 3.5 Access Gateway → Website 2

Website 2 is inside the protected environment and should trust traffic only from the legitimate Gateway.

This boundary must use strong service authentication, such as mTLS, along with network isolation.

Direct internet traffic must not be able to bypass the Gateway and reach Website 2.

### 3.6 Website 2 → Internal Infrastructure

Website 2 must not automatically be trusted with unrestricted access to other internal systems.

Strict outbound/egress controls should prevent a compromised Website 2 from being used to:

- Reach the Authorization Service
- Access Gateway management interfaces
- Reach Website 1
- Scan internal services
- Move laterally through the internal network

### 3.7 Administrative Interfaces → GateZero Components

Administrative interfaces for the Gateway, Authorization Service, databases, and infrastructure represent privileged trust boundaries.

They must not be publicly accessible and should require separate administrative authentication and authorization.

---

### Trust Boundary Summary

```text
UNTRUSTED
    │
    ▼
Internet
    │
    ▼
Website 1
    │
    │ Authenticated Service Channel
    ▼
Authorization Service
    │
    │ Authenticated Service Channel
    ▼
Access Gateway
    │
    │ mTLS + Network Isolation
    ▼
Website 2
    │
    │ Restricted Egress
    ▼
Internal Infrastructure

```

### One important point

Notice the last sentence:

> **"Compromising one component does not automatically provide trusted access to the next component."**

That's basically the **core philosophy of your threat model**.

If someone compromises Website 1, we don't want them to automatically reach Website 2.

If someone compromises Website 2, we don't want them to automatically reach the Authorization Service.

If someone compromises the Gateway, we don't want them to automatically obtain the Authorization Service's signing keys.

That's the kind of thinking we'll use for the next section: **Threat Actors**.

## 4. Threat Actors

GateZero considers the following threat actors and compromise scenarios.

### 4.1 Anonymous Internet Attacker

An external attacker with no legitimate access to GateZero.

Potential capabilities:

- Scan publicly exposed services
- Send malicious requests
- Attempt to exploit Website 1
- Attack the Access Gateway
- Attempt to discover or bypass Website 2
- Perform automated credential or authentication attacks

### 4.2 Attacker With Stolen Employee Credentials

An attacker who has obtained an employee's username and password.

Potential capabilities:

- Attempt to authenticate to Website 1
- Attempt to complete MFA through social engineering or MFA fatigue
- Attempt to obtain a valid Website 1 session
- Attempt to request access through Connect

### 4.3 Attacker With a Stolen Website 1 Session

An attacker who has obtained a valid authenticated Website 1 session.

Potential capabilities:

- Access Website 1 without repeating authentication
- Attempt to use the Connect function
- Attempt to obtain an authorization grant
- Attempt to abuse the session until it expires or is revoked

### 4.4 Attacker With a Stolen Authorization Grant

An attacker who has obtained a valid short-lived authorization grant.

Potential capabilities:

- Replay the grant
- Use the grant from an unauthorized device or session
- Attempt to extend or modify the grant
- Attempt to access Website 2 before the grant expires

### 4.5 Compromised Website 1

An attacker who has gained control of Website 1 through a vulnerability or server compromise.

Potential capabilities:

- Attempt to abuse the communication with the Authorization Service
- Attempt to generate unauthorized authorization requests
- Attempt to access internal services
- Attempt to obtain sensitive configuration or credentials

Website 1 compromise must not automatically provide access to Website 2 or the Gateway.

### 4.6 Compromised Website 2

An attacker who has gained control of Website 2.

Potential capabilities:

- Access data available to Website 2
- Attempt to move laterally through the internal network
- Attempt to reach the Authorization Service
- Attempt to reach Gateway management interfaces
- Attempt to obtain internal credentials or secrets

Network segmentation and egress restrictions should limit these capabilities.

### 4.7 Compromised Access Gateway

An attacker who has gained control of the Access Gateway.

Potential capabilities:

- Inspect or manipulate traffic passing through the Gateway
- Attempt to access Website 2
- Attempt to obtain Gateway credentials or certificates
- Attempt to move toward other internal services

Gateway compromise is considered a high-severity scenario because the Gateway is a critical security enforcement point.

### 4.8 Compromised Authorization Service

An attacker who has gained control of the Authorization Service.

Potential capabilities:

- Issue unauthorized grants
- Revoke legitimate grants
- Manipulate authorization decisions
- Attempt to access signing keys
- Attempt to communicate with the Gateway as a trusted service

The Authorization Service is therefore considered a high-value trust component.

### 4.9 Malicious or Compromised Employee Device

An employee's device may be infected, stolen, or otherwise controlled by an attacker.

Potential capabilities:

- Steal sessions
- Capture credentials
- Attempt to obtain authorization grants
- Access Website 2 using legitimate employee authentication
- Manipulate requests originating from the device

GateZero should assume that a valid employee identity does not automatically mean the device is trustworthy.

## 5. Attack Scenarios

The following scenarios represent the primary attacks that GateZero must defend against.

### 5.1 Direct Access to Website 2

**Attacker Goal:**  
Reach Website 2 without going through the Access Gateway.

**Attack:**  
The attacker discovers or guesses the address of Website 2 and attempts to connect directly.

**Expected Security Control:**  
Website 2 must reject all traffic that does not originate from the legitimate Access Gateway.

**Test:**  
Attempt to access Website 2 directly from an external network.

**Expected Result:**  
Connection is rejected.

---

### 5.2 Gateway Bypass

**Attacker Goal:**  
Reach Website 2 while avoiding Gateway authorization.

**Attack:**  
The attacker attempts to identify an alternate route, exposed port, backend address, or misconfigured service that bypasses the Gateway.

**Expected Security Control:**  
Network isolation and firewall rules must ensure that Website 2 is reachable only through the Gateway.

**Test:**  
Scan for alternative paths to Website 2 and attempt direct connections.

**Expected Result:**  
No direct path to Website 2 exists.

---

### 5.3 Forged Authorization Grant

**Attacker Goal:**  
Create a fake grant that the Gateway accepts as legitimate.

**Attack:**  
The attacker attempts to modify or forge authorization data.

**Expected Security Control:**  
Grants must be cryptographically protected and validated by the Gateway.

**Test:**  
Modify grant contents, signatures, timestamps, or authorization scope.

**Expected Result:**  
The Gateway rejects the modified or forged grant.

---

### 5.4 Authorization Grant Replay

**Attacker Goal:**  
Reuse a previously valid grant.

**Attack:**  
The attacker captures a valid authorization grant and attempts to reuse it.

**Expected Security Control:**

- Short grant lifetime
- Expiration validation
- Device/session binding
- Replay protection where applicable

**Test:**  
Capture a valid grant, use it again, and attempt to use it after expiration.

**Expected Result:**  
The Gateway rejects expired or invalidly reused grants.

---

### 5.5 Stolen Website 1 Session

**Attacker Goal:**  
Use a stolen Website 1 session to obtain Website 2 access.

**Attack:**  
The attacker obtains a valid Website 1 session and attempts to use the Connect function.

**Expected Security Control:**

- Session protection
- Device/session binding
- Connect rate limiting
- Appropriate reauthentication for suspicious activity

**Test:**  
Attempt to use a stolen session from an unauthorized environment.

**Expected Result:**  
The attacker should not be able to obtain Website 2 access without satisfying the required security controls.

---

### 5.6 Connect Abuse

**Attacker Goal:**  
Abuse the Connect mechanism to obtain excessive authorization grants.

**Attack:**  
Repeatedly send Connect requests.

**Expected Security Control:**

- Per-user rate limiting
- Per-session/device rate limiting
- IP-based abuse detection
- Logging and monitoring

**Test:**  
Send repeated Connect requests within a short period.

**Expected Result:**  
Requests are throttled or blocked when the defined limits are exceeded.

---

### 5.7 MFA Fatigue Attack

**Attacker Goal:**  
Trick an employee into approving an authentication request.

**Attack:**  
Repeatedly trigger MFA requests in an attempt to make the employee approve one accidentally.

**Expected Security Control:**

- Phishing-resistant MFA where possible
- Number matching/contextual approval
- MFA rate limiting
- Suspicious authentication monitoring

**Test:**  
Generate repeated authentication attempts.

**Expected Result:**  
The system limits the attempts and prevents uncontrolled MFA requests.

---

### 5.8 Compromised Website 1

**Attacker Goal:**  
Use control of Website 1 to obtain unauthorized access to Website 2 or internal services.

**Attack:**  
The attacker compromises Website 1 and attempts to impersonate trusted communication with the Authorization Service.

**Expected Security Control:**

- Authenticated service-to-service communication
- Separate service credentials
- Least-privilege permissions
- Authorization Service validation
- Network segmentation

**Test:**  
Attempt to use a compromised Website 1 environment to communicate with internal services.

**Expected Result:**  
Compromise of Website 1 must not automatically provide access to Website 2 or internal management systems.

---

### 5.9 Compromised Website 2

**Attacker Goal:**  
Use control of Website 2 to move deeper into the internal network.

**Attack:**  
An attacker compromises Website 2 and attempts to contact internal services.

**Expected Security Control:**

- Strict egress filtering
- Network segmentation
- No access to Gateway management
- No access to Authorization Service unless explicitly required

**Test:**  
Attempt connections from Website 2 to internal services.

**Expected Result:**  
Unauthorized outbound connections are blocked.

---

### 5.10 Gateway Impersonation

**Attacker Goal:**  
Create or operate a fake Gateway that Website 2 trusts.

**Attack:**  
The attacker attempts to impersonate the legitimate Gateway.

**Expected Security Control:**

- mTLS
- Certificate validation
- Protected private keys
- Certificate rotation and revocation
- Network restrictions

**Test:**  
Attempt to connect to Website 2 using an unauthorized certificate.

**Expected Result:**  
Website 2 rejects the connection.

---

### 5.11 Authorization Service Compromise

**Attacker Goal:**  
Obtain the ability to issue unauthorized grants.

**Attack:**  
The attacker compromises the Authorization Service or its credentials.

**Expected Security Control:**

- Protected signing keys
- Least privilege
- Network isolation
- Monitoring
- High-value administrative controls
- Key rotation

**Test:**  
Attempt to issue or modify authorization decisions using unauthorized credentials.

**Expected Result:**  
Unauthorized operations are rejected and generate security alerts.

---

### 5.12 Revocation Bypass

**Attacker Goal:**  
Maintain Website 2 access after authorization has been revoked.

**Attack:**  
The attacker attempts to continue using an active connection or previously issued grant after revocation.

**Expected Security Control:**

- Authenticated revocation events
- Gateway-side revocation handling
- Grant expiration
- Active connection termination

**Test:**  
Establish access, revoke the grant, and attempt to continue using the connection.

**Expected Result:**  
Access is terminated when the Gateway receives the revocation event. If the Gateway is temporarily unreachable, access must end no later than grant expiration.

---

### 5.13 Gateway Availability Attack

**Attacker Goal:**  
Prevent legitimate employees from accessing Website 2.

**Attack:**  
Overwhelm or disrupt the Gateway.

**Expected Security Control:**

- Multiple Gateway instances
- Health checks
- Failover
- Rate limiting
- DDoS protection
- Monitoring

**Test:**  
Simulate Gateway overload or instance failure.

**Expected Result:**  
The system continues operating through available Gateway instances or fails safely without exposing Website 2 directly.

---

### 5.14 Authorization Service Availability Attack

**Attacker Goal:**  
Prevent employees from obtaining authorization.

**Attack:**  
Disrupt the Authorization Service or overwhelm its APIs.

**Expected Security Control:**

- Multiple Authorization Service instances
- Rate limiting
- Health checks
- Monitoring
- Failover

**Test:**  
Simulate service failure or excessive authorization requests.

**Expected Result:**  
The system fails securely and does not issue unauthorized grants.
