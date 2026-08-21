/**
 * server-gateway.ts
 * ═══════════════════════════════════════════════════════════════════════════════
 * THE ACCESS GATEWAY
 * gateway-defense.md (whole document)
 * ═══════════════════════════════════════════════════════════════════════════════
 *
 * Its own process on its own port (:3001), between Website 1 (:3000, public) and
 * Website 2 (:3002, private). It decides authorization, mints the one-time
 * grant, resolves where Website 2 lives, and relays critical security events.
 *
 * THE INVARIANT THIS DOES NOT CHANGE
 * ──────────────────────────────────
 *   A compromised Gateway does not get you a trusted Website 2 session.
 *
 * That already holds because Website 2 verifies every device itself against its
 * own nonce (W1 §8.1) and never trusts the Gateway's assertion. Nothing here
 * asks Website 2 to trust the Gateway more. This process exists to make the
 * Gateway a harder target and a smaller blast radius, so the invariant rests on
 * two layers rather than on Website 2's skepticism alone.
 *
 * WHAT IT WILL NOT DO (§6)
 * ────────────────────────
 * No admin surface. No debug endpoint. No general-purpose API. No passwords, no
 * business data, no long-lived session state. That is enforced the same way
 * Website 2's out-of-band revoke endpoint is kept to one operation — by there
 * being no code for anything else, not by a check someone can edit around.
 *
 * INBOUND PEERS (§1)
 * ──────────────────
 * Exactly two, both authenticated per-peer (§2): Website 1's backend and
 * Website 2's event poller. The browser never reaches this process.
 *
 * MOCK BOUNDARIES — what is NOT true here that §1/§2/§4 require in production:
 *   - Peer auth is HMAC with per-peer derived keys, not mTLS with pinned,
 *     short-lived certificates from an internal CA.
 *   - The grant-signing key is derived from a seed in this process, not held in
 *     an HSM/KMS.
 *   - This process shares one SQLite database with Website 1 and Website 2. §4
 *     requires the Gateway to have no read path to Website 1's credential store
 *     or Website 2's session store; here that separation does not exist.
 *   - Nothing enforces network isolation — §1's firewall rules are the real
 *     control, and there is no firewall in a dev box.
 */

import express, { Request, Response, NextFunction } from "express";
import { prisma } from "./lib/db";
import { verifyServiceRequest, type ServiceId } from "./lib/service-auth";
import {
  issueAuthorization,
  exchangeCodeForToken,
  introspectTokenLive,
  consumeAuthorization,
} from "./lib/authz-service";
import {
  mintGrant,
  verifyGrant,
  grantPublicKeyPem,
  grantPublicJwk,
  grantMatchesDevice,
  type GrantAudience,
} from "./lib/gateway/grant";
import { buildHandoffUrl, resolveTarget, publicDenial } from "./lib/gateway";
import {
  pullPendingEvents,
  acknowledgeEvents,
  reconcileUserState,
} from "./lib/security-events";
import { auditConnect } from "./lib/audit";
import { raiseSecurityAlert } from "./lib/alerts";
import { checkRateLimit } from "./lib/rate-limit";
import { GATEWAY_PORT } from "./lib/config";

const app = express();
const HOST = process.env.GATEWAY_HOST || "127.0.0.1";

app.use(express.json({ limit: "64kb" }));

// ─────────────────────────────────────────────────────────────────────────────
// Logging (§10)
// ─────────────────────────────────────────────────────────────────────────────
//
// Secrets never reach here: grant tokens and device keys are referenced by id
// or hash, never logged whole.

type GatewayEvent =
  | "GRANT_ISSUED"
  | "GRANT_MINTED"
  | "GRANT_REDEEMED"
  | "GRANT_DENIED"
  | "GRANT_REPLAY"
  | "PEER_AUTH_FAILED"
  | "RATE_LIMITED"
  | "EVENTS_RELAYED"
  | "TARGET_RESOLVED";

function gwLog(event: GatewayEvent, detail: Record<string, unknown> = {}): void {
  console.log(
    JSON.stringify({
      ts: new Date().toISOString(),
      component: "gateway",
      event,
      ...detail,
    })
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Peer authentication (§1, §2)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Require one of the named peers.
 *
 * `allowed` is mandatory per route, so adding a caller is a deliberate edit
 * rather than a side effect of holding a credential. Under mTLS this becomes a
 * check on the verified peer certificate; the shape does not change.
 */
function requirePeer(allowed: ServiceId[]) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const body = req.body ? JSON.stringify(req.body) : "";
    const path = req.originalUrl;

    const auth = verifyServiceRequest({
      headers: req.headers as Record<string, string | undefined>,
      path,
      body,
      allowedServices: allowed,
    });

    if (!auth.authorized) {
      gwLog("PEER_AUTH_FAILED", { path, reason: auth.reason });
      // §5: an unauthenticated caller learns nothing beyond refusal.
      res.status(403).json(publicDenial());
      return;
    }

    (req as Request & { peer?: string }).peer = auth.serviceId;
    next();
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// On the circuit breaker toward Website 2 (§7)
// ─────────────────────────────────────────────────────────────────────────────
//
// §7 asks for a circuit breaker so a Gateway under load or under attack cannot
// be turned into an amplifier pointed at Website 2.
//
// There is deliberately no breaker here, because there is nothing for it to
// break: this process makes NO outbound calls to Website 2. The event relay is
// pull-only — Website 2 asks, the Gateway answers — and the handoff is a URL
// handed to the browser, not a request the Gateway issues. Grant issuance,
// exchange and redemption all terminate in the database.
//
// The pull model therefore already provides the property §7 wants, structurally
// rather than by control: a Gateway being hammered generates no traffic toward
// Website 2 at all, so it cannot amplify. Adding a breaker would be dead code
// that reads like a safeguard while guarding nothing — and a control that
// cannot fire is worse than an acknowledged absence, because it invites the
// assumption that the risk is handled.
//
// If the Gateway ever gains an outbound path to Website 2 (a push channel, a
// synchronous health check, a proxied request), a breaker becomes necessary and
// this note must be replaced with one.

// ─────────────────────────────────────────────────────────────────────────────
// 1. Grant issuance — Website 1 only (§3)
// ─────────────────────────────────────────────────────────────────────────────
//
// Website 1 has already run the risk assessment and verified a device proof. It
// asks; the Gateway decides and records. The Gateway does not re-run Website 1's
// checks — it enforces the invariants that must hold regardless of caller, which
// issueAuthorization owns (device credential valid and belonging to the
// employee, session live unless emergency, access not revoked).

app.post("/grant/issue", requirePeer(["website-1"]), async (req: Request, res: Response) => {
  const { sessionId, userId, deviceCredentialId, ipAddress, userAgent, targetApp, bindingNonce } =
    req.body ?? {};

  if (
    typeof sessionId !== "string" ||
    typeof userId !== "string" ||
    typeof deviceCredentialId !== "string"
  ) {
    res.status(400).json(publicDenial());
    return;
  }

  // §7: per-employee limit on issuance, independent of Website 1's own limits.
  const rate = await checkRateLimit(`gw-issue:${userId}`, 10, 60);
  if (!rate.allowed) {
    gwLog("RATE_LIMITED", { stage: "issue", userId });
    res.status(429).json(publicDenial());
    return;
  }

  try {
    const result = await issueAuthorization({
      sessionId,
      userId,
      deviceCredentialId,
      ipAddress: typeof ipAddress === "string" ? ipAddress : "unknown",
      userAgent: typeof userAgent === "string" ? userAgent : "unknown",
      targetApp: typeof targetApp === "string" ? targetApp : "operations-desk",
      bindingNonce: typeof bindingNonce === "string" ? bindingNonce : undefined,
    });

    gwLog("GRANT_ISSUED", {
      userId,
      tokenId: result.tokenId,
      ttlSeconds: result.ttlSeconds,
    });

    res.json({
      tokenId: result.tokenId,
      expiresAt: result.expiresAt,
      ttlSeconds: result.ttlSeconds,
    });
  } catch (err) {
    const reason = err instanceof Error ? err.message : "UNKNOWN";
    gwLog("GRANT_DENIED", { stage: "issue", userId, reason });

    // §5: every failure denies. The caller gets the reason only for the cases
    // Website 1 must react to differently; everything else is generic.
    if (reason === "SESSION_INVALID" || reason === "ACCESS_REVOKED") {
      res.status(403).json({ error: reason });
      return;
    }
    res.status(403).json(publicDenial());
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. Handoff URL resolution — Website 1 only (§8)
// ─────────────────────────────────────────────────────────────────────────────
//
// §8: resolving an address is not granting trust. Returning Website 2's address
// does not make the caller able to reach it — network ACLs decide that
// independently of anything said here. Website 1 never learns the address from
// its own configuration (W1 §4, §9); it asks, and it receives a URL it hands to
// the browser as a redirect.

app.post("/grant/handoff-url", requirePeer(["website-1"]), (req: Request, res: Response) => {
  const { targetApp, code } = req.body ?? {};

  if (typeof targetApp !== "string" || typeof code !== "string") {
    res.status(400).json(publicDenial());
    return;
  }

  // An unknown target is refused rather than echoed, so this cannot be used as
  // an open redirector by naming an arbitrary destination.
  const url = buildHandoffUrl(targetApp, code);
  if (!url) {
    gwLog("GRANT_DENIED", { stage: "handoff-url", reason: "UNKNOWN_TARGET_APP" });
    res.status(400).json(publicDenial());
    return;
  }

  gwLog("TARGET_RESOLVED", { targetApp });
  res.json({ targetUrl: url });
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. Exchange — Website 2 only (§3)
// ─────────────────────────────────────────────────────────────────────────────
//
// Website 2 redeems the front-channel code for the authorization Website 1
// already obtained, and receives a SIGNED grant it can verify with the public
// key alone. That signature is what makes "the Gateway really did approve this"
// checkable without a shared secret.
//
// The grant's `jti` is the authorization record's id, so the signed assertion
// and the row tracking one-time consumption name the same thing.

app.post("/grant/exchange", requirePeer(["operations-desk"]), async (req: Request, res: Response) => {
  const { code } = req.body ?? {};
  if (typeof code !== "string") {
    res.status(400).json(publicDenial());
    return;
  }

  try {
    const result = await exchangeCodeForToken({
      code,
      ipAddress: "gateway",
      userAgent: "gateway",
    });

    if (!result.deviceCredentialId) {
      gwLog("GRANT_DENIED", { stage: "exchange", reason: "GRANT_NOT_DEVICE_BOUND" });
      res.status(403).json(publicDenial());
      return;
    }

    const credential = await prisma.deviceCredential.findUnique({
      where: { id: result.deviceCredentialId },
      select: { id: true, publicKeySpki: true, algorithm: true, status: true, assurance: true },
    });

    if (!credential || credential.status !== "ACTIVE") {
      gwLog("GRANT_DENIED", { stage: "exchange", reason: "DEVICE_CREDENTIAL_UNAVAILABLE" });
      res.status(403).json(publicDenial());
      return;
    }

    const grant = await mintGrant({
      employeeId: result.user.id,
      deviceCredentialId: credential.id,
      devicePublicKeySpki: credential.publicKeySpki,
      audience: "operations-desk",
      emergency: result.emergency,
      jti: result.tokenId,
      ttlSeconds: Math.max(1, result.ttlSeconds),
    });

    gwLog("GRANT_MINTED", {
      userId: result.user.id,
      tokenId: result.tokenId,
      emergency: result.emergency,
    });

    res.json({
      success: true,
      grantToken: grant.token,
      expiresAt: grant.expiresAt,
      ttlSeconds: result.ttlSeconds,
      emergency: result.emergency,
      device: {
        credentialId: credential.id,
        publicKeySpki: credential.publicKeySpki,
        algorithm: credential.algorithm,
        assurance: credential.assurance,
      },
      user: result.user,
    });
  } catch (err) {
    const reason = err instanceof Error ? err.message : "UNKNOWN";
    gwLog("GRANT_DENIED", { stage: "exchange", reason });
    // W2 §15: one generic external answer for every failure mode.
    res.status(403).json(publicDenial());
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. Redemption — Website 2 only (§3, §7)
// ─────────────────────────────────────────────────────────────────────────────
//
// Called at the moment Website 2 establishes a session, AFTER its own device
// verification. This is where the grant becomes single-use: consumption is an
// atomic conditional update, so two devices racing the same grant produce
// exactly one winner.

app.post("/grant/redeem", requirePeer(["operations-desk"]), async (req: Request, res: Response) => {
  const { grantToken, devicePublicKeySpki } = req.body ?? {};

  if (typeof grantToken !== "string" || typeof devicePublicKeySpki !== "string") {
    res.status(400).json(publicDenial());
    return;
  }

  const verified = await verifyGrant(grantToken, "operations-desk" as GrantAudience);
  if (!verified.valid || !verified.claims) {
    gwLog("GRANT_DENIED", { stage: "redeem", reason: verified.reason });
    res.status(403).json(publicDenial());
    return;
  }

  const claims = verified.claims;

  // The grant names the device it was minted for. A grant presented alongside a
  // different device key is refused before anything is consumed.
  if (!grantMatchesDevice(claims, devicePublicKeySpki)) {
    gwLog("GRANT_DENIED", { stage: "redeem", reason: "DEVICE_MISMATCH", jti: claims.jti });
    void raiseSecurityAlert({
      alertKey: `gateway_grant_device_mismatch:${claims.jti}`,
      severity: "HIGH",
      userId: claims.employeeId,
      ipAddress: "gateway",
      userAgent: "gateway",
      metadata: { stage: "redeem" },
    });
    res.status(403).json(publicDenial());
    return;
  }

  const consumed = await consumeAuthorization({
    tokenId: claims.jti,
    deviceCredentialId: claims.deviceCredentialId,
  });

  if (!consumed.ok) {
    const isReplay = consumed.reason === "TOKEN_ALREADY_CONSUMED";
    gwLog(isReplay ? "GRANT_REPLAY" : "GRANT_DENIED", {
      stage: "redeem",
      jti: claims.jti,
      reason: consumed.reason,
    });

    // §7: repeated failed redemption against one grant looks like probing, or
    // like a stolen grant being raced against the legitimate holder. Graded
    // CRITICAL, matching how device-proof forgery is treated.
    if (isReplay) {
      const attempts = await checkRateLimit(`gw-redeem-fail:${claims.jti}`, 3, 300);
      void auditConnect({
        eventType: "AUTHZ_REPLAY_ATTEMPT",
        userId: claims.employeeId,
        authzId: claims.jti,
        ipAddress: "gateway",
        userAgent: "gateway",
        outcome: "DENIED",
        severity: attempts.allowed ? "HIGH" : "CRITICAL",
        metadata: { stage: "redeem", repeated: !attempts.allowed },
      });

      void raiseSecurityAlert({
        alertKey: `gateway_grant_replay:${claims.jti}`,
        severity: attempts.allowed ? "HIGH" : "CRITICAL",
        userId: claims.employeeId,
        ipAddress: "gateway",
        userAgent: "gateway",
        metadata: { stage: "redeem" },
      });
    }

    res.status(403).json(publicDenial());
    return;
  }

  gwLog("GRANT_REDEEMED", { userId: claims.employeeId, jti: claims.jti });

  const introspection = await introspectTokenLive({ tokenId: claims.jti });

  res.json({
    success: true,
    employeeId: claims.employeeId,
    deviceCredentialId: claims.deviceCredentialId,
    emergency: claims.emergency,
    // Consumed above, so introspection now reports it spent — the identity
    // fields are read from the record for the caller's convenience.
    sessionId: introspection.sessionId ?? null,
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 5. Verification key (§3)
// ─────────────────────────────────────────────────────────────────────────────
//
// Public by nature: it verifies grants and cannot mint them. Exposed so a
// verifier can fetch it rather than having it configured out of band.

app.get("/grant/public-key", (_req: Request, res: Response) => {
  res.json({
    alg: "ES256",
    issuer: "gatezero-gateway",
    pem: grantPublicKeyPem(),
    jwk: grantPublicJwk(),
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 6. Critical event relay — Website 2 only (§9)
// ─────────────────────────────────────────────────────────────────────────────
//
// The Gateway FORWARDS events; it does not originate them. Every event was
// already signed by the producer, so a fully compromised Gateway can withhold
// or delay a real event but cannot fabricate one — and withholding is caught by
// Website 2's reconciliation, which re-derives critical state from the system
// of record when delivery cannot be confirmed.
//
// Pull only. There is no path by which the Gateway pushes into Website 2, so
// no event-injection surface exists on either side.

app.get("/events", requirePeer(["operations-desk"]), async (req: Request, res: Response) => {
  const reconcileUserId = typeof req.query.reconcile === "string" ? req.query.reconcile : null;

  if (reconcileUserId) {
    const state = await reconcileUserState(reconcileUserId);
    res.json({ reconcile: true, userId: reconcileUserId, state });
    return;
  }

  const events = await pullPendingEvents();
  if (events.length > 0) gwLog("EVENTS_RELAYED", { count: events.length });

  res.json({ events });
});

app.post("/events/ack", requirePeer(["operations-desk"]), async (req: Request, res: Response) => {
  const { eventIds } = req.body ?? {};
  if (!Array.isArray(eventIds) || eventIds.some((id) => typeof id !== "string")) {
    res.status(400).json(publicDenial());
    return;
  }

  const acknowledged = await acknowledgeEvents(eventIds as string[]);
  res.json({ acknowledged });
});

// ─────────────────────────────────────────────────────────────────────────────
// 7. Liveness (§5)
// ─────────────────────────────────────────────────────────────────────────────
//
// Unauthenticated by necessity — the health monitor cannot hold a session for
// the thing it is probing. Reports only; records nothing, and carries no
// employee data or configuration.

app.get("/health", async (_req: Request, res: Response) => {
  try {
    await prisma.$queryRaw`SELECT 1`;
    res.set("Cache-Control", "no-store").json({
      status: "ok",
      component: "gateway",
      time: new Date().toISOString(),
    });
  } catch {
    res.status(503).set("Cache-Control", "no-store").json({
      status: "degraded",
      component: "gateway",
      time: new Date().toISOString(),
    });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 8. Everything else is refused (§6)
// ─────────────────────────────────────────────────────────────────────────────
//
// The Gateway exposes exactly the routes above. Anything else gets a flat 404
// with no hint of what does exist.

app.use((req: Request, res: Response) => {
  gwLog("GRANT_DENIED", { stage: "unknown-route", path: req.path });
  res.status(404).json({ error: "NOT_FOUND" });
});

// §5: an unhandled error denies rather than leaking a stack or, worse, falling
// through to a permissive default.
app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
  gwLog("GRANT_DENIED", {
    stage: "unhandled",
    reason: err instanceof Error ? err.message : "UNKNOWN",
  });
  res.status(500).json(publicDenial());
});

app.listen(GATEWAY_PORT, HOST, () => {
  console.log(`\n=======================================================`);
  console.log(` ACCESS GATEWAY ACTIVE`);
  console.log(` URL: http://${HOST}:${GATEWAY_PORT}`);
  console.log(` Peers: website-1 (backend), operations-desk (poller)`);
  console.log(` Grants: ES256-signed, one-time, device-bound, 5 minutes`);
  console.log(` Target: ${resolveTarget("operations-desk") ?? "UNRESOLVED"}`);
  console.log(`=======================================================\n`);
});

export default app;
