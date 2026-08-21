/**
 * server-desk.ts
 * ═══════════════════════════════════════════════════════════════════════════════
 * WEBSITE 2: THE OPERATIONS DESK
 * website-2-defense.md (whole document) / website-1-defense.md §8.1, §22
 * ═══════════════════════════════════════════════════════════════════════════════
 *
 * The protected work environment, on PORT 3002.
 *
 * ARCHITECTURE (§1, §35)
 * ──────────────────────
 *   Website 1 proves identity. The Gateway authorizes access.
 *   Website 2 independently protects the work session.
 *
 * Three properties follow from that, and they shape everything below:
 *
 *   1. INDEPENDENT DEVICE VERIFICATION (§8.1, §4). Website 2 does not accept
 *      the Gateway's assertion that a device is legitimate. It issues its OWN
 *      challenge nonce and verifies the signature itself. A Gateway that forged
 *      or mis-validated a device binding still cannot produce a trusted session
 *      here.
 *
 *   2. SESSION INDEPENDENCE (§26, §35, W1 §22.1). Once established, the session
 *      is validated from local state. Website 2 does not call the Gateway per
 *      request, and an existing session survives a Website 1 or Gateway outage.
 *
 *   3. NARROW EVENT INTAKE (§21, §32). The only thing that crosses the boundary
 *      afterwards is a small set of critical security events, which Website 2
 *      PULLS. There is no inbound endpoint that can push a session termination
 *      into Website 2, so nothing on the network can forge one.
 *
 * OUT OF SCOPE (§1): what an authenticated employee may see or do inside the
 * Desk — role-based access control and data permissions are the application's
 * own concern, addressed separately from how the employee got here.
 */

import crypto from "crypto";
import express, { Request, Response, NextFunction } from "express";
import cookieParser from "cookie-parser";
import { prisma } from "./lib/db";
import { signServiceRequest, verifyServiceRequest } from "./lib/service-auth";
import {
  issueDeviceChallenge,
  verifyDeviceProof,
  credentialUsability,
} from "./lib/device";
import {
  establishDeskSession,
  validateDeskSession,
  touchDeskSession,
  revokeDeskSession,
  revokeAllForUser,
  recordDeviceVerification,
  rotateDeskSessionId,
  isMeaningfulActivity,
} from "./lib/desk-session";
import {
  processSecurityEvent,
  type DeliverableEvent,
} from "./lib/security-events";
import { notifyEmployeeById } from "./lib/notify";
import { deskSessionLimits, ORG_MODE, DESK_DEVICE_REVERIFY_MS } from "./lib/config";
import { consumeStepUp } from "./lib/admin-stepup";

const app = express();
const PORT = 3002;
const HOST = process.env.HOST || "127.0.0.1";

/**
 * The Gateway's address. Website 2 talks to the Gateway; it never talks to
 * Website 1 directly (§2, §35).
 */
const GATEWAY_URL = process.env.GATEWAY_URL || process.env.NEXT_PUBLIC_APP_URL || "http://localhost:3000";

const SESSION_COOKIE = "desk_session";
const HANDSHAKE_COOKIE = "desk_handshake";

// ─────────────────────────────────────────────────────────────────────────────
// Security headers (§13)
// ─────────────────────────────────────────────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cache-Control", "no-store");
  next();
});

app.use(express.json({ limit: "256kb" }));
app.use(express.urlencoded({ extended: true, limit: "256kb" }));
app.use(cookieParser());

interface AuthRequest extends Request {
  user?: { id: string; email: string; name: string; role: string };
  deskSessionId?: string;
  deviceCredentialId?: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// Website 2 security logging (§33)
// ─────────────────────────────────────────────────────────────────────────────
//
// Website 2 does not use the Mini EDR (§33): continuous endpoint telemetry
// would create needless log volume and couple the Desk to Website 1's
// monitoring. It records its own session-scoped security events instead, and
// never records secrets.

type DeskEventType =
  | "SESSION_CREATED"
  | "SESSION_EXPIRED"
  | "SESSION_REPLACED"
  | "SESSION_REVOKED"
  | "DEVICE_MISMATCH"
  | "DEVICE_PROOF_FAILED"
  | "DEVICE_REVERIFICATION_REQUIRED"
  | "CREDENTIAL_REVOKED"
  | "AUTHZ_REPLAY"
  | "HANDSHAKE_FAILED"
  | "SECURITY_EVENT_PROCESSED"
  | "SECURITY_EVENT_REJECTED"
  | "EMERGENCY_ACCESS"
  | "OOB_REVOCATION"
  | "RECONCILIATION";

function deskLog(
  type: DeskEventType,
  detail: Record<string, unknown> = {}
): void {
  console.log(
    JSON.stringify({
      ts: new Date().toISOString(),
      component: "operations-desk",
      event: type,
      ...detail,
    })
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Gateway calls (§25) — service-authenticated, never bare HTTP
// ─────────────────────────────────────────────────────────────────────────────

async function callGateway<T>(
  path: string,
  body: unknown
): Promise<{ ok: boolean; status: number; data: T | null }> {
  const payload = JSON.stringify(body ?? {});
  const res = await fetch(`${GATEWAY_URL}${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...signServiceRequest({ serviceId: "operations-desk", path, body: payload }),
    },
    body: payload,
  });

  const data = (await res.json().catch(() => null)) as T | null;
  return { ok: res.ok, status: res.status, data };
}

async function getFromGateway<T>(path: string): Promise<T | null> {
  const res = await fetch(`${GATEWAY_URL}${path}`, {
    method: "GET",
    headers: signServiceRequest({ serviceId: "operations-desk", path, body: "" }),
  });
  if (!res.ok) return null;
  return (await res.json().catch(() => null)) as T | null;
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Handshake state (§3)
// ─────────────────────────────────────────────────────────────────────────────
//
// Between redeeming the exchange code and completing Website 2's own device
// check, the pending handshake lives here — in memory, short-lived, and never
// in a cookie. The browser holds only an opaque handle.
//
// It is deliberately NOT a session: it confers no access, and it expires in
// two minutes whether or not the device answers the challenge.

interface PendingHandshake {
  tokenId: string;
  userId: string;
  deviceCredentialId: string;
  /** Public key as delivered by the Gateway, cross-checked at verification. */
  publicKeySpki: string;
  emergency: boolean;
  expiresAt: number;
}

const handshakes = new Map<string, PendingHandshake>();

function putHandshake(id: string, handshake: PendingHandshake): void {
  handshakes.set(id, handshake);
}

function takeHandshake(id: string | undefined): PendingHandshake | null {
  if (!id) return null;
  const found = handshakes.get(id);
  if (!found) return null;
  if (found.expiresAt < Date.now()) {
    handshakes.delete(id);
    return null;
  }
  return found;
}

// Periodic sweep so an abandoned handshake cannot accumulate.
setInterval(() => {
  const now = Date.now();
  for (const [id, handshake] of handshakes) {
    if (handshake.expiresAt < now) handshakes.delete(id);
  }
}, 60_000).unref?.();

function randomId(): string {
  return crypto.randomBytes(24).toString("hex");
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Session Guard middleware (§10, §13, §14, §17, §18)
// ─────────────────────────────────────────────────────────────────────────────
//
// Purely local. No Gateway call, no Website 1 call — that independence is what
// lets an established session survive an upstream outage (§26).

async function requireDeskSession(
  req: AuthRequest,
  res: Response,
  next: NextFunction
): Promise<void> {
  const sessionId = req.cookies?.[SESSION_COOKIE];

  if (!sessionId) {
    deny(req, res, "NO_ACTIVE_SESSION");
    return;
  }

  const validation = await validateDeskSession({ sessionId });

  if (!validation.valid || !validation.session) {
    res.clearCookie(SESSION_COOKIE);
    deskLog(
      validation.reason === "SESSION_EXPIRED" ? "SESSION_EXPIRED" : "SESSION_REVOKED",
      { reason: validation.reason }
    );
    deny(req, res, validation.reason ?? "SESSION_INVALID");
    return;
  }

  const user = await prisma.user.findUnique({
    where: { id: validation.session.userId },
    select: { id: true, email: true, name: true, role: true, accessRevoked: true },
  });

  // Belt and braces alongside the ACCESS_REVOKED event: if the event has not
  // arrived yet, the flag is still authoritative here.
  if (!user || user.accessRevoked) {
    await revokeDeskSession(validation.session.id, "ACCESS_REVOKED");
    res.clearCookie(SESSION_COOKIE);
    deny(req, res, "ACCESS_REVOKED");
    return;
  }

  // §14: the session identifier alone is never sufficient. When the device
  // proof has gone stale the request is held until the caller re-proves
  // possession of the private key. The session is NOT revoked — a legitimate
  // browser re-signs transparently and continues, while someone holding only a
  // stolen cookie can never satisfy this and is stopped here.
  if (validation.deviceReverificationRequired) {
    deskLog("DEVICE_REVERIFICATION_REQUIRED", {
      userId: validation.session.userId,
      sessionId: validation.session.id,
    });

    if (req.path.startsWith("/api/")) {
      res.status(401).json({ error: "DEVICE_REVERIFICATION_REQUIRED" });
      return;
    }
    res.status(401).send(renderDeviceVerificationScreen(req.originalUrl));
    return;
  }

  req.user = { id: user.id, email: user.email, name: user.name, role: user.role };
  req.deskSessionId = validation.session.id;
  req.deviceCredentialId = validation.session.deviceCredentialId;

  // §17: only meaningful application activity extends the session. Background
  // polling deliberately does not, so an abandoned tab cannot keep a session
  // alive forever.
  if (isMeaningfulActivity(req.method, req.path)) {
    void touchDeskSession(validation.session.id);
  }

  next();
}

/**
 * A single denial shape for every failure.
 *
 * §15: the external response stays generic. An attacker learns that access was
 * refused, never whether the grant was expired, consumed, bound elsewhere, or
 * simply absent — the specific reason goes to the local log only.
 */
function deny(req: Request, res: Response, reason: string): void {
  if (req.path.startsWith("/api/")) {
    res.status(401).json({ error: "ACCESS_DENIED" });
    return;
  }
  res.status(401).send(renderNeutralInterceptScreen(reason));
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Handshake: exchange code → device challenge → session (§3, §4, §8.1, §11)
// ─────────────────────────────────────────────────────────────────────────────

app.get("/api/auth/callback", async (req: Request, res: Response) => {
  const code = typeof req.query.code === "string" ? req.query.code : "";

  if (!code) {
    res.status(400).send(renderNeutralInterceptScreen("MISSING_EXCHANGE_CODE"));
    return;
  }

  try {
    const exchange = await callGateway<{
      success: boolean;
      tokenId: string;
      emergency: boolean;
      device: { credentialId: string; publicKeySpki: string; algorithm: string };
      user: { id: string; name: string; email: string; role: string };
    }>("/api/authz/exchange", { code });

    if (!exchange.ok || !exchange.data?.success || !exchange.data.tokenId) {
      deskLog("HANDSHAKE_FAILED", { stage: "exchange", status: exchange.status });
      res.status(401).send(renderNeutralInterceptScreen("GATEWAY_AUTHORIZATION_REQUIRED"));
      return;
    }

    const { tokenId, device, user, emergency } = exchange.data;

    // The authorization is NOT consumed yet. Website 2 must first satisfy
    // itself about the device (§8.1); consuming here would burn the employee's
    // grant on a handshake that has not produced a session.
    const handshakeId = randomId();
    putHandshake(handshakeId, {
      tokenId,
      userId: user.id,
      deviceCredentialId: device.credentialId,
      publicKeySpki: device.publicKeySpki,
      emergency: Boolean(emergency),
      expiresAt: Date.now() + 2 * 60 * 1000,
    });

    res.cookie(HANDSHAKE_COOKIE, handshakeId, {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      maxAge: 2 * 60 * 1000,
      path: "/",
    });

    res.send(renderDeviceVerificationScreen());
  } catch (err) {
    deskLog("HANDSHAKE_FAILED", {
      stage: "exchange",
      error: err instanceof Error ? err.message : "unknown",
    });
    res.status(503).send(renderNeutralInterceptScreen("GATEWAY_UNAVAILABLE"));
  }
});

/**
 * Website 2's OWN challenge (§4, §8.1).
 *
 * Issued by Website 2, recorded with issuer "website-2", and signed by the
 * device over a message that names that issuer. A signature produced for
 * Website 1's Connect challenge therefore cannot be presented here.
 */
app.post("/api/auth/device-challenge", async (req: Request, res: Response) => {
  // Two callers need a challenge: a pending handshake establishing a session,
  // and an established session whose §14 re-verification has come due.
  const handshake = takeHandshake(req.cookies?.[HANDSHAKE_COOKIE]);

  let userId: string | undefined;
  let deviceCredentialId: string | undefined;

  if (handshake) {
    userId = handshake.userId;
    deviceCredentialId = handshake.deviceCredentialId;
  } else {
    const sessionId = req.cookies?.[SESSION_COOKIE];
    if (sessionId) {
      // Read the session directly rather than through validateDeskSession:
      // that would report the session as needing re-verification, which is
      // precisely the state we are issuing this challenge to resolve.
      const session = await prisma.deskSession.findUnique({ where: { id: sessionId } });
      if (session && session.status === "ACTIVE") {
        userId = session.userId;
        deviceCredentialId = session.deviceCredentialId;
      }
    }
  }

  if (!userId || !deviceCredentialId) {
    res.status(401).json({ error: "ACCESS_DENIED" });
    return;
  }

  const challenge = await issueDeviceChallenge({
    userId,
    purpose: "W2_SESSION",
    issuer: "website-2",
    deviceCredentialId,
  });

  res.json({ nonce: challenge.nonce, expiresAt: challenge.expiresAt });
});

/**
 * §14: re-prove possession of the session's device private key.
 *
 * Pinned to the credential the session was established with, so a valid proof
 * from some *other* registered device cannot refresh someone else's session.
 * On success the verification window restarts; the session's inactivity and
 * absolute lifetimes are untouched, because re-verification is a theft control,
 * not a way to extend a session past its §17/§18 limits.
 */
app.post("/api/auth/device-reverify", async (req: Request, res: Response) => {
  const sessionId = req.cookies?.[SESSION_COOKIE];
  if (!sessionId) {
    res.status(401).json({ error: "ACCESS_DENIED" });
    return;
  }

  const session = await prisma.deskSession.findUnique({ where: { id: sessionId } });
  if (!session || session.status !== "ACTIVE") {
    res.status(401).json({ error: "ACCESS_DENIED" });
    return;
  }

  const { nonce, signature } = req.body ?? {};
  if (typeof nonce !== "string" || typeof signature !== "string") {
    res.status(400).json({ error: "ACCESS_DENIED" });
    return;
  }

  const proof = await verifyDeviceProof({
    userId: session.userId,
    proof: { nonce, signature },
    purpose: "W2_SESSION",
    issuer: "website-2",
    expectedCredentialId: session.deviceCredentialId,
  });

  if (!proof.valid) {
    deskLog("DEVICE_PROOF_FAILED", {
      userId: session.userId,
      sessionId: session.id,
      stage: "reverification",
      reason: proof.reason,
    });
    res.status(401).json({ error: "ACCESS_DENIED" });
    return;
  }

  await recordDeviceVerification(session.id);

  // §16: "Website 2 should rotate session identifiers after important
  // authentication transitions. An old session identifier must become invalid
  // after rotation."
  //
  // Re-proving possession of the device key IS such a transition, and it is the
  // one that recurs during a session's life — so rotating here means a leaked
  // identifier stops resolving within one verification window even if the leak
  // is never detected. Lifetimes are untouched; only the name changes.
  const rotated = await rotateDeskSessionId(session.id);

  if (rotated) {
    const limits = deskSessionLimits();
    res.cookie(SESSION_COOKIE, rotated.id, {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      // Cap the cookie at the session's REMAINING absolute lifetime, not a
      // fresh full window — rotation must not extend a session past §18.
      maxAge: Math.max(
        0,
        Math.min(limits.absoluteMs, rotated.absoluteExpiresAt.getTime() - Date.now())
      ),
      path: "/",
    });
  }

  res.json({ success: true });
});

/**
 * Verify the device proof, redeem the authorization, establish the session.
 *
 * Order matters and is enforced strictly:
 *   1. verify the device signature locally  (§8.1 — independent of the Gateway)
 *   2. redeem the one-time authorization    (§24 — only now is it spent)
 *   3. establish the session, replacing any incumbent (§11)
 *
 * §11 is explicit that an existing session must survive a *failed* attempt by
 * another device. Because the incumbent is only revoked inside step 3, every
 * failure above returns before the existing session is touched.
 */
app.post("/api/auth/device-proof", async (req: Request, res: Response) => {
  const handshakeId = req.cookies?.[HANDSHAKE_COOKIE];
  const handshake = takeHandshake(handshakeId);

  if (!handshake) {
    res.status(401).json({ error: "ACCESS_DENIED" });
    return;
  }

  const { nonce, signature } = req.body ?? {};
  if (typeof nonce !== "string" || typeof signature !== "string") {
    res.status(400).json({ error: "ACCESS_DENIED" });
    return;
  }

  // ── Step 1: Website 2's own cryptographic verification (§8.1) ────────────
  const proof = await verifyDeviceProof({
    userId: handshake.userId,
    proof: { nonce, signature },
    purpose: "W2_SESSION",
    issuer: "website-2",
    expectedCredentialId: handshake.deviceCredentialId,
  });

  if (!proof.valid || !proof.credential) {
    deskLog("DEVICE_PROOF_FAILED", {
      userId: handshake.userId,
      reason: proof.reason,
    });
    res.status(401).json({ error: "ACCESS_DENIED" });
    return;
  }

  // Cross-check the key the Gateway claimed against the credential of record.
  // A Gateway that mis-reported which key it bound is caught here rather than
  // silently trusted — which is the substance of §8.1's "second, independent
  // checkpoint".
  if (proof.credential.publicKeySpki !== handshake.publicKeySpki) {
    deskLog("DEVICE_MISMATCH", {
      userId: handshake.userId,
      reason: "GATEWAY_KEY_DISAGREEMENT",
    });
    res.status(401).json({ error: "ACCESS_DENIED" });
    return;
  }

  const usability = credentialUsability(proof.credential);
  if (!usability.usable) {
    deskLog("CREDENTIAL_REVOKED", {
      userId: handshake.userId,
      reason: usability.reason,
    });
    res.status(401).json({ error: "ACCESS_DENIED" });
    return;
  }

  // ── Step 2: spend the one-time authorization (§3 step 9, §24) ───────────
  const redeem = await callGateway<{ success: boolean }>("/api/authz/redeem", {
    tokenId: handshake.tokenId,
    deviceCredentialId: handshake.deviceCredentialId,
  });

  if (!redeem.ok || !redeem.data?.success) {
    deskLog("AUTHZ_REPLAY", { userId: handshake.userId, status: redeem.status });
    res.status(401).json({ error: "ACCESS_DENIED" });
    return;
  }

  // The handshake is single-use: consumed now, whatever happens next.
  handshakes.delete(handshakeId);

  // ── Step 3: establish, replacing any incumbent session (§11, §12) ───────
  const { session, replacedSessionIds } = await establishDeskSession({
    userId: handshake.userId,
    deviceCredentialId: handshake.deviceCredentialId,
    authzTokenId: handshake.tokenId,
    ipAddress: req.ip || "unknown",
  });

  const limits = deskSessionLimits();

  res.clearCookie(HANDSHAKE_COOKIE);
  res.cookie(SESSION_COOKIE, session.id, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    // The cookie is capped by the absolute lifetime, but the server-side
    // record remains authoritative — a cookie that outlives its session
    // resolves to nothing (§3: server time decides).
    maxAge: limits.absoluteMs,
    path: "/",
  });

  deskLog("SESSION_CREATED", {
    userId: handshake.userId,
    sessionId: session.id,
    deviceCredentialId: handshake.deviceCredentialId,
    emergency: handshake.emergency,
    replaced: replacedSessionIds.length,
  });

  // §12: the employee is told when a new session replaced their previous one.
  // §34: the message carries no tokens, codes, or internal security detail.
  void notifyEmployeeById(
    handshake.userId,
    replacedSessionIds.length > 0 ? "W2_SESSION_REPLACED" : "W2_SESSION_ESTABLISHED"
  );

  if (handshake.emergency) {
    deskLog("EMERGENCY_ACCESS", { userId: handshake.userId, sessionId: session.id });
    void notifyEmployeeById(handshake.userId, "W2_EMERGENCY_ACCESS");
  }

  if (replacedSessionIds.length > 0) {
    deskLog("SESSION_REPLACED", {
      userId: handshake.userId,
      replacedSessionIds,
    });
  }

  res.json({ success: true });
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. Session status and logout (§19, §20)
// ─────────────────────────────────────────────────────────────────────────────

app.get("/api/desk/session", requireDeskSession, async (req: AuthRequest, res: Response) => {
  const session = await prisma.deskSession.findUnique({
    where: { id: req.deskSessionId! },
    select: { createdAt: true, lastActivityAt: true, absoluteExpiresAt: true },
  });

  const limits = deskSessionLimits();

  res.json({
    user: req.user,
    orgMode: ORG_MODE,
    session: session && {
      createdAt: session.createdAt,
      lastActivityAt: session.lastActivityAt,
      absoluteExpiresAt: session.absoluteExpiresAt,
      inactivityExpiresAt: new Date(
        session.lastActivityAt.getTime() + limits.inactivityMs
      ),
    },
  });
});

/**
 * §20: logging out of Website 2 affects Website 2 only.
 *
 * The Website 1 session stays signed in, and the employee can Connect again to
 * establish a new Website 2 session. The authorization behind this session is
 * invalidated with it.
 */
app.all("/api/auth/logout", async (req: Request, res: Response) => {
  const sessionId = req.cookies?.[SESSION_COOKIE];
  if (sessionId) {
    await revokeDeskSession(sessionId, "USER_LOGOUT");
    deskLog("SESSION_REVOKED", { sessionId, reason: "USER_LOGOUT" });
  }
  res.clearCookie(SESSION_COOKIE);
  res.redirect(`${GATEWAY_URL}/dashboard`);
});

// ─────────────────────────────────────────────────────────────────────────────
// 5. Out-of-band administrative revocation (§26)
// ─────────────────────────────────────────────────────────────────────────────
//
// Used when the Gateway is unavailable but a Website 2 session must be ended.
//
// §26 constrains this channel severely, and the constraint is structural rather
// than advisory: this handler contains exactly one operation. It cannot create
// sessions, authorize devices, bypass MFA, mint credentials, or alter security
// controls, because no code path here does any of those things.
//
// It still requires service authentication AND a fresh administrator step-up
// grant issued for this specific action, and every use is logged.

app.post("/api/oob/revoke", async (req: Request, res: Response) => {
  const raw = JSON.stringify(req.body ?? {});

  const auth = verifyServiceRequest({
    headers: req.headers as Record<string, string | undefined>,
    path: "/api/oob/revoke",
    body: raw,
    allowedServices: ["admin-oob"],
  });

  if (!auth.authorized) {
    deskLog("OOB_REVOCATION", { outcome: "DENIED", reason: auth.reason });
    res.status(403).json({ error: "ACCESS_DENIED" });
    return;
  }

  const { targetUserId, adminUserId, stepUpId, reason } = req.body ?? {};
  if (
    typeof targetUserId !== "string" ||
    typeof adminUserId !== "string" ||
    typeof stepUpId !== "string" ||
    typeof reason !== "string"
  ) {
    res.status(400).json({ error: "INVALID_REQUEST" });
    return;
  }

  // §14 and §26: "The administrator must reauthenticate before performing the
  // revocation." The grant is spent here, and it must have been issued for
  // this action against this employee.
  const stepUp = await consumeStepUp({
    stepUpId,
    adminUserId,
    action: "OOB_REVOKE_W2_SESSION",
    targetUserId,
  });

  if (!stepUp.ok) {
    deskLog("OOB_REVOCATION", {
      outcome: "DENIED",
      reason: stepUp.reason,
      adminUserId,
      targetUserId,
    });
    res.status(403).json({ error: "STEP_UP_REQUIRED" });
    return;
  }

  const revoked = await revokeAllForUser(targetUserId, `OOB_ADMIN_REVOCATION:${reason}`);

  // §26: logged as a high-priority security event.
  deskLog("OOB_REVOCATION", {
    outcome: "SUCCESS",
    severity: "HIGH",
    adminUserId,
    targetUserId,
    justification: reason,
    revokedSessionIds: revoked,
  });

  res.json({ success: true, revokedSessions: revoked.length });
});

// ─────────────────────────────────────────────────────────────────────────────
// 6. Critical security event intake (§21, §32)
// ─────────────────────────────────────────────────────────────────────────────
//
// Website 2 pulls; nothing pushes. Each event is HMAC-verified and applied
// through the idempotency ledger, so redelivery of an already-applied event is
// a no-op — which is what makes at-least-once delivery safe.
//
// Only after an event has actually been applied is it acknowledged. An event
// that fails to apply stays pending upstream and is redelivered.

async function applyCriticalEvent(event: DeliverableEvent): Promise<string> {
  const { type, userId, payload } = event;

  switch (type) {
    // §21: a password change terminates every Website 2 session for the
    // employee. Without this, a reset would lock the attacker out of Website 1
    // while leaving them working inside Website 2.
    case "PASSWORD_CHANGED":
    case "ACCESS_REVOKED":
    case "ADMIN_TERMINATION": {
      const revoked = await revokeAllForUser(userId, type);
      return `REVOKED_${revoked.length}`;
    }

    // §9 / W1 §22.3: sessions bound to a revoked or superseded credential end.
    // Scoped to the named credentials so a device replacement does not tear
    // down the session the new device just established.
    //
    // NEW_DEVICE_SESSION is handled but never enqueued here: Website 2 owns its
    // own session store, so establishDeskSession already revokes the prior
    // sessions at the moment the new device establishes (§11). The branch is
    // kept so a deployment where Website 2 cannot observe establishment
    // directly still terminates correctly rather than falling through to the
    // unknown-type no-op.
    case "DEVICE_REVOKED":
    case "NEW_DEVICE_SESSION": {
      const revoked = await revokeAllForUser(userId, type, {
        deviceCredentialIds: payload.deviceCredentialIds,
        except: payload.exceptDeskSessionId,
      });
      return `REVOKED_${revoked.length}`;
    }

    default:
      return "IGNORED_UNKNOWN_TYPE";
  }
}

async function pollSecurityEvents(): Promise<void> {
  try {
    const result = await getFromGateway<{ events: DeliverableEvent[] }>("/api/events");
    if (!result?.events?.length) return;

    const acknowledged: string[] = [];

    for (const event of result.events) {
      const outcome = await processSecurityEvent(event, applyCriticalEvent);

      if (outcome.processed) {
        acknowledged.push(event.eventId);
        deskLog("SECURITY_EVENT_PROCESSED", {
          eventId: event.eventId,
          type: event.type,
          userId: event.userId,
          duplicate: outcome.duplicate,
        });
      } else {
        // Not acknowledged — it stays pending upstream and will be retried.
        // A signature failure is never acknowledged: acknowledging it would
        // let a forged event silently retire a real one.
        deskLog("SECURITY_EVENT_REJECTED", {
          eventId: event.eventId,
          type: event.type,
          reason: outcome.reason,
        });
      }
    }

    if (acknowledged.length > 0) {
      await callGateway("/api/events", { eventIds: acknowledged });
    }
  } catch (err) {
    // The Gateway being unreachable is not a reason to touch existing sessions
    // (§26). The poller simply retries.
    deskLog("SECURITY_EVENT_REJECTED", {
      reason: "GATEWAY_UNREACHABLE",
      error: err instanceof Error ? err.message : "unknown",
    });
  }
}

/**
 * §21 fallback reconciliation.
 *
 * If delivery cannot be confirmed, Website 2 re-derives the employee's critical
 * account state from the system of record rather than assuming that no event
 * means nothing happened.
 */
async function reconcileActiveSessions(): Promise<void> {
  try {
    const active = await prisma.deskSession.findMany({
      where: { status: "ACTIVE" },
      select: { userId: true },
      distinct: ["userId"],
    });

    for (const { userId } of active) {
      const state = await getFromGateway<{
        state: { accessRevoked: boolean; activeCredentialIds: string[] };
      }>(`/api/events?reconcile=${encodeURIComponent(userId)}`);

      if (!state?.state) continue;

      if (state.state.accessRevoked) {
        const revoked = await revokeAllForUser(userId, "RECONCILED_ACCESS_REVOKED");
        deskLog("RECONCILIATION", { userId, action: "ACCESS_REVOKED", revoked: revoked.length });
        continue;
      }

      // A session whose credential is no longer active upstream should not be
      // alive here — this catches a DEVICE_REVOKED event that never arrived.
      const sessions = await prisma.deskSession.findMany({
        where: { userId, status: "ACTIVE" },
        select: { id: true, deviceCredentialId: true },
      });

      for (const session of sessions) {
        if (!state.state.activeCredentialIds.includes(session.deviceCredentialId)) {
          await revokeDeskSession(session.id, "RECONCILED_CREDENTIAL_INACTIVE");
          deskLog("RECONCILIATION", {
            userId,
            sessionId: session.id,
            action: "CREDENTIAL_INACTIVE",
          });
        }
      }
    }
  } catch {
    // Reconciliation is best-effort; failure leaves state unchanged.
  }
}

const EVENT_POLL_INTERVAL_MS = Number(process.env.DESK_EVENT_POLL_MS ?? 10_000);
const RECONCILE_INTERVAL_MS = Number(process.env.DESK_RECONCILE_MS ?? 300_000);

setInterval(() => void pollSecurityEvents(), EVENT_POLL_INTERVAL_MS).unref?.();
setInterval(() => void reconcileActiveSessions(), RECONCILE_INTERVAL_MS).unref?.();

// ─────────────────────────────────────────────────────────────────────────────
// 7. Device verification interstitial (§4, §8.1)
// ─────────────────────────────────────────────────────────────────────────────
//
// Served between the exchange and the session. The page asks the browser to
// sign Website 2's own nonce with the device private key. The key is
// non-extractable and lives in IndexedDB, so this page can use it and still
// cannot read it.

function renderDeviceVerificationScreen(returnTo = "/"): string {
  // Only same-origin paths — never reflect an attacker-supplied absolute URL
  // back into a redirect.
  const safeReturn =
    returnTo.startsWith("/") && !returnTo.startsWith("//") ? returnTo : "/";

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Verifying device — The Operations Desk</title>
  <style>
    body { font-family: system-ui, -apple-system, sans-serif; background:#0f141f; color:#e2e8f0;
           min-height:100vh; display:flex; align-items:center; justify-content:center; margin:0; }
    .card { max-width: 440px; padding: 32px; border:1px solid #1e293b; border-radius:12px; background:#111827; }
    h1 { font-size:18px; margin:0 0 12px; }
    p { color:#94a3b8; font-size:14px; line-height:1.6; }
    .err { color:#f87171; }
    a { color:#60a5fa; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Verifying your device</h1>
    <p id="status">Proving possession of your registered device credential…</p>
    <p id="fallback" style="display:none">
      <a href="${GATEWAY_URL}/dashboard">Return to the GateZero portal</a>
    </p>
  </div>
  <script type="module">
    const RETURN_TO = ${JSON.stringify(safeReturn)};
    const statusEl = document.getElementById('status');
    const fallbackEl = document.getElementById('fallback');

    function fail(message) {
      statusEl.textContent = message;
      statusEl.className = 'err';
      fallbackEl.style.display = 'block';
    }

    function b64u(buffer) {
      const bytes = new Uint8Array(buffer);
      let binary = '';
      for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
      return btoa(binary).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
    }

    function openDb() {
      return new Promise((resolve, reject) => {
        const request = indexedDB.open('gatezero-device', 1);
        request.onupgradeneeded = () => {
          const db = request.result;
          if (!db.objectStoreNames.contains('credentials')) db.createObjectStore('credentials');
        };
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
      });
    }

    async function loadKey() {
      const db = await openDb();
      return new Promise((resolve, reject) => {
        const tx = db.transaction('credentials', 'readonly');
        const req = tx.objectStore('credentials').get('device-key');
        req.onsuccess = () => resolve(req.result ?? null);
        req.onerror = () => reject(req.error);
      });
    }

    (async () => {
      try {
        const key = await loadKey();
        if (!key) {
          fail('No device credential found in this browser. Enrol this device from the GateZero portal first.');
          return;
        }

        const challengeRes = await fetch('/api/auth/device-challenge', {
          method: 'POST', credentials: 'include',
          headers: { 'Content-Type': 'application/json' }, body: '{}'
        });
        if (!challengeRes.ok) { fail('Device verification could not be started.'); return; }

        const { nonce } = await challengeRes.json();

        // The issuer is part of the signed bytes, so this signature is valid
        // only for Website 2's checkpoint.
        const message = new TextEncoder().encode('gatezero:v1:website-2:W2_SESSION:' + nonce);
        const signature = await crypto.subtle.sign(
          { name: 'ECDSA', hash: 'SHA-256' }, key.privateKey, message
        );

        // Establishment and re-verification sign the same challenge; only the
        // endpoint differs. Try establishment first — it is a no-op for a
        // session that already exists — then fall back to re-verification.
        let proofRes = await fetch('/api/auth/device-proof', {
          method: 'POST', credentials: 'include',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ nonce, signature: b64u(signature) })
        });

        if (!proofRes.ok) {
          const retry = await fetch('/api/auth/device-challenge', {
            method: 'POST', credentials: 'include',
            headers: { 'Content-Type': 'application/json' }, body: '{}'
          });
          if (retry.ok) {
            const again = await retry.json();
            const sig2 = await crypto.subtle.sign(
              { name: 'ECDSA', hash: 'SHA-256' }, key.privateKey,
              new TextEncoder().encode('gatezero:v1:website-2:W2_SESSION:' + again.nonce)
            );
            proofRes = await fetch('/api/auth/device-reverify', {
              method: 'POST', credentials: 'include',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ nonce: again.nonce, signature: b64u(sig2) })
            });
          }
        }

        if (!proofRes.ok) { fail('Device verification failed.'); return; }

        statusEl.textContent = 'Verified. Opening the Operations Desk…';
        window.location.replace(RETURN_TO);
      } catch {
        fail('Device verification failed.');
      }
    })();
  </script>
</body>
</html>`;
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. REST API Endpoints (Protected by the Website 2 Session Guard)
// ─────────────────────────────────────────────────────────────────────────────

// Overview Stats
app.get("/api/desk/stats", requireDeskSession, async (req: AuthRequest, res: Response) => {
  const [activeAssignments, totalStaff, onDutyStaff, todayShifts, wireCount] = await Promise.all([
    prisma.assignment.count({ where: { status: { in: ["TODO", "IN_PROGRESS"] } } }),
    prisma.staffMember.count(),
    prisma.staffMember.count({ where: { status: "ON_DUTY" } }),
    prisma.calendarShift.count(),
    prisma.wireBulletin.count(),
  ]);

  res.json({
    activeAssignments,
    totalStaff,
    onDutyStaff,
    todayShifts,
    wireCount,
    user: req.user,
  });
});

// Assignments (CRUD)
app.get("/api/desk/assignments", requireDeskSession, async (req: AuthRequest, res: Response) => {
  const assignments = await prisma.assignment.findMany({
    orderBy: { createdAt: "desc" },
  });
  res.json({ assignments });
});

app.post("/api/desk/assignments", requireDeskSession, async (req: AuthRequest, res: Response) => {
  const { title, description, department, status, priority, assigneeName, assigneeEmail, deadline } = req.body;
  if (!title) return res.status(400).json({ error: "Title is required" });

  const randomRotation = (Math.random() * 3 - 1.5); // between -1.5deg and +1.5deg

  const item = await prisma.assignment.create({
    data: {
      title,
      description: description || "",
      department: department || "OPERATIONS",
      status: status || "TODO",
      priority: priority || "STANDARD",
      assigneeName: assigneeName || req.user?.name || "Staff Member",
      assigneeEmail: assigneeEmail || req.user?.email || "staff@company.internal",
      deadline: deadline || "1700 HRS",
      rotation: parseFloat(randomRotation.toFixed(2)),
    },
  });

  res.json({ success: true, assignment: item });
});

app.patch("/api/desk/assignments/:id", requireDeskSession, async (req: AuthRequest, res: Response) => {
  const id = req.params.id as string;
  const { status, priority, title, description } = req.body;

  const updated = await prisma.assignment.update({
    where: { id },
    data: {
      ...(status && { status }),
      ...(priority && { priority }),
      ...(title && { title }),
      ...(description && { description }),
    },
  });

  res.json({ success: true, assignment: updated });
});

app.delete("/api/desk/assignments/:id", requireDeskSession, async (req: AuthRequest, res: Response) => {
  const id = req.params.id as string;
  await prisma.assignment.delete({ where: { id } });
  res.json({ success: true });
});

// Wire Bulletins
app.get("/api/desk/wire", requireDeskSession, async (req: AuthRequest, res: Response) => {
  const bulletins = await prisma.wireBulletin.findMany({
    orderBy: { createdAt: "desc" },
    take: 25,
  });
  res.json({ bulletins });
});

app.post("/api/desk/wire", requireDeskSession, async (req: AuthRequest, res: Response) => {
  const { headline, body, category, urgency } = req.body;
  if (!headline) return res.status(400).json({ error: "Headline is required" });

  const now = new Date();
  const timestamp = String(now.getHours()).padStart(2, "0") + String(now.getMinutes()).padStart(2, "0");

  const item = await prisma.wireBulletin.create({
    data: {
      timestamp,
      category: category || "OPERATIONS",
      headline,
      body: body || "",
      urgency: urgency || "NORMAL",
    },
  });

  res.json({ success: true, bulletin: item });
});

// Staff Roster
app.get("/api/desk/roster", requireDeskSession, async (req: AuthRequest, res: Response) => {
  const staff = await prisma.staffMember.findMany({
    orderBy: [{ status: "asc" }, { department: "asc" }],
  });
  res.json({ staff });
});

app.patch("/api/desk/roster/:id", requireDeskSession, async (req: AuthRequest, res: Response) => {
  const id = req.params.id as string;
  const { status } = req.body;

  const updated = await prisma.staffMember.update({
    where: { id },
    data: { ...(status && { status }) },
  });

  res.json({ success: true, staff: updated });
});

// Ledger
app.get("/api/desk/ledger", requireDeskSession, async (req: AuthRequest, res: Response) => {
  const records = await prisma.ledgerRecord.findMany({
    orderBy: { entryDate: "desc" },
  });

  const totalDebits = records.filter(r => r.type === "DEBIT").reduce((acc: number, r) => acc + r.amount, 0);
  const totalCredits = records.filter(r => r.type === "CREDIT").reduce((acc: number, r) => acc + r.amount, 0);

  res.json({
    records,
    summary: {
      totalDebits,
      totalCredits,
      netBalance: totalCredits - totalDebits,
    },
  });
});

app.post("/api/desk/ledger", requireDeskSession, async (req: AuthRequest, res: Response) => {
  const { description, category, amount, type } = req.body;
  if (!description || !amount) return res.status(400).json({ error: "Description and amount required" });

  const count = await prisma.ledgerRecord.count();
  const refNumber = `LED-${8840 + count + 1}`;
  const entryDate = new Date().toISOString().slice(0, 10);

  const item = await prisma.ledgerRecord.create({
    data: {
      refNumber,
      entryDate,
      description,
      category: category || "OPERATIONS",
      amount: parseFloat(amount),
      type: type || "DEBIT",
      authorizedBy: req.user?.name || "Staff Lead",
    },
  });

  res.json({ success: true, record: item });
});

// Archive
app.get("/api/desk/archive", requireDeskSession, async (req: AuthRequest, res: Response) => {
  const { department, search } = req.query as { department?: string; search?: string };

  const records = await prisma.archiveRecord.findMany({
    where: {
      ...(department && department !== "ALL" && { department }),
      ...(search && {
        OR: [
          { title: { contains: search } },
          { summary: { contains: search } },
          { tags: { contains: search } },
        ],
      }),
    },
    orderBy: { filingDate: "desc" },
  });

  res.json({ records });
});

app.post("/api/desk/archive", requireDeskSession, async (req: AuthRequest, res: Response) => {
  const { title, department, summary, tags } = req.body;
  if (!title) return res.status(400).json({ error: "Title required" });

  const count = await prisma.archiveRecord.count();
  const recordNumber = `REC-2026-${String(count + 1).padStart(3, "0")}`;
  const filingDate = new Date().toISOString().slice(0, 10);

  const item = await prisma.archiveRecord.create({
    data: {
      recordNumber,
      title,
      department: department || "OPERATIONS",
      filingDate,
      summary: summary || "",
      tags: tags || "General, Operations",
      filedBy: req.user?.name || "Operations Lead",
    },
  });

  res.json({ success: true, record: item });
});

// Messages
app.get("/api/desk/messages", requireDeskSession, async (req: AuthRequest, res: Response) => {
  const messages = await prisma.deskMessage.findMany({
    orderBy: { createdAt: "desc" },
  });
  res.json({ messages });
});

app.post("/api/desk/messages", requireDeskSession, async (req: AuthRequest, res: Response) => {
  const { subject, content, urgent, recipientEmail } = req.body;
  if (!subject || !content) return res.status(400).json({ error: "Subject and content required" });

  const item = await prisma.deskMessage.create({
    data: {
      senderName: req.user?.name || "Desk Operator",
      senderEmail: req.user?.email || "desk@company.internal",
      recipientEmail: recipientEmail || "desk@company.internal",
      subject,
      content,
      urgent: Boolean(urgent),
      read: false,
    },
  });

  res.json({ success: true, message: item });
});

// Calendar
app.get("/api/desk/calendar", requireDeskSession, async (req: AuthRequest, res: Response) => {
  const shifts = await prisma.calendarShift.findMany({
    orderBy: [{ date: "asc" }, { startTime: "asc" }],
  });
  res.json({ shifts });
});

// ─────────────────────────────────────────────────────────────────────────────
// 9. Main HTML Page (Tactile Paper-and-Ink Interface)
// ─────────────────────────────────────────────────────────────────────────────
app.get("/", requireDeskSession, (req: AuthRequest, res: Response) => {
  res.send(renderOperationsDeskApp(req.user));
});

// ─────────────────────────────────────────────────────────────────────────────
// 10. Neutral Gateway Intercept Screen Template
// ─────────────────────────────────────────────────────────────────────────────
function renderNeutralInterceptScreen(reason: string) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Gateway Access Required — The Operations Desk</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Public+Sans:wght@400;600;700&family=IBM+Plex+Mono:wght@500;600&display=swap" rel="stylesheet">
  <style>
    body { font-family: 'Public Sans', sans-serif; background-color: #0f141f; color: #e2e8f0; }
    .mono { font-family: 'IBM Plex Mono', monospace; }
  </style>
</head>
<body class="min-h-screen flex flex-col justify-between p-6">
  <header class="w-full max-w-4xl mx-auto flex justify-between items-center py-4 border-b border-slate-800">
    <div class="flex items-center gap-3">
      <div class="w-3 h-3 bg-amber-500 rounded-sm"></div>
      <span class="font-bold tracking-wider text-slate-200 uppercase text-sm">CORPORATE ACCESS GATEWAY</span>
    </div>
    <span class="mono text-xs text-slate-400">NODE: DESK-UPSTREAM-3002</span>
  </header>

  <main class="w-full max-w-lg mx-auto my-12 bg-slate-900 border border-slate-700/80 rounded-xl p-8 shadow-2xl">
    <div class="flex items-center gap-3 text-amber-400 mb-4">
      <svg class="w-6 h-6 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
      </svg>
      <h1 class="text-lg font-bold tracking-wide uppercase">Gateway Access Required</h1>
    </div>

    <p class="text-sm text-slate-300 leading-relaxed mb-6">
      This enterprise application (<strong class="text-slate-100">The Operations Desk</strong>) is protected by the corporate Zero-Trust Access Gateway. An authenticated single-use token or active gateway session is required for access.
    </p>

    <div class="bg-slate-950 border border-slate-800 rounded-lg p-4 mb-6 mono text-xs space-y-2">
      <div class="flex justify-between text-slate-400">
        <span>GATEWAY STATUS:</span>
        <span class="text-amber-400 font-bold">ACCESS_DENIED</span>
      </div>
      <div class="flex justify-between text-slate-400">
        <span>INTERCEPT REASON:</span>
        <span class="text-slate-200">${reason.replace(/_/g, " ")}</span>
      </div>
      <div class="flex justify-between text-slate-400">
        <span>AUTH PROVIDER:</span>
        <span class="text-slate-300">GateZero Gateway (Port 3000)</span>
      </div>
    </div>

    <div class="space-y-3">
      <a href="${GATEWAY_URL}/dashboard" class="block w-full py-3 px-4 bg-blue-600 hover:bg-blue-500 text-white font-bold text-center text-xs rounded-lg transition-colors tracking-wider uppercase shadow-md">
        Authorize via GateZero Portal (Port 3000) →
      </a>
      <a href="${GATEWAY_URL}" class="block w-full py-2 px-4 bg-slate-800 hover:bg-slate-700 text-slate-300 text-center text-xs rounded-lg transition-colors">
        Return to Gateway Login Screen
      </a>
    </div>
  </main>

  <footer class="w-full max-w-4xl mx-auto py-4 border-t border-slate-800 flex justify-between items-center text-xs text-slate-500 mono">
    <span>© 2026 ENTERPRISE SECURITY GATEWAY</span>
    <span>ZERO-TRUST ENFORCEMENT ACTIVE</span>
  </footer>
</body>
</html>`;
}

// ─────────────────────────────────────────────────────────────────────────────
// 11. Complete Tactile Operations Desk Frontend Interface Template
// ─────────────────────────────────────────────────────────────────────────────
function renderOperationsDeskApp(user?: { name: string; email: string; role: string }) {
  return `<!DOCTYPE html>
<html lang="en" id="html-root" class="light">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>The Operations Desk — Corporate Operations & Dispatch Hub</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Bitter:ital,wght@0,400..900;1,400..900&family=IBM+Plex+Mono:ital,wght@0,400..700;1,400..700&family=Public+Sans:ital,wght@0,300..900;1,300..900&display=swap" rel="stylesheet">
  <link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap" rel="stylesheet">
  <script>
    tailwind.config = {
      darkMode: "class",
      theme: {
        extend: {
          colors: {
            "paper-base": "#E8E2D0",
            "paper-card": "#DED5BC",
            "ink-primary": "#21283B",
            "ink-secondary": "#5B6178",
            "accent-brass": "#B08D3E",
            "signal-progress": "#3B6EA5",
            "signal-done": "#3E7C6B",
            "signal-urgent": "#B4463A",
            "night-base": "#141721",
            "night-card": "#1e2230",
            "night-ink": "#e5e9f0",
            "night-sub": "#8a94a6",
          },
          fontFamily: {
            "masthead": ["Bitter", "serif"],
            "body": ["Public Sans", "sans-serif"],
            "mono": ["IBM Plex Mono", "monospace"],
          }
        }
      }
    }
  </script>
  <style>
    /* Paper & Ink Aesthetics */
    .paper-desk { background-color: #E8E2D0; color: #21283B; }
    .dark .paper-desk { background-color: #141721; color: #e5e9f0; }
    
    .card-surface { background-color: #DED5BC; border: 1px solid #c2b89d; box-shadow: 2px 3px 0px rgba(33, 40, 59, 0.15); }
    .dark .card-surface { background-color: #1e2230; border: 1px solid #2f364a; box-shadow: 2px 3px 0px rgba(0, 0, 0, 0.4); }

    .ink-rule { border-bottom: 2px solid #21283B; }
    .dark .ink-rule { border-bottom: 2px solid #e5e9f0; }

    .brass-pin {
      width: 14px; height: 14px;
      background: radial-gradient(circle at 35% 35%, #e6cb85, #B08D3E 70%, #73591f);
      border-radius: 50%;
      box-shadow: 1px 2px 3px rgba(0,0,0,0.35);
    }
    .urgent-pin {
      width: 14px; height: 14px;
      background: radial-gradient(circle at 35% 35%, #ff8578, #B4463A 70%, #6e1c14);
      border-radius: 50%;
      box-shadow: 1px 2px 3px rgba(0,0,0,0.35);
    }

    .tab-active {
      border-bottom: 3px solid #B08D3E !important;
      font-weight: 700;
      color: #21283B;
    }
    .dark .tab-active {
      color: #e5e9f0;
    }

    .folder-tab {
      clip-path: polygon(0% 0%, 85% 0%, 100% 100%, 0% 100%);
    }
  </style>
</head>
<body class="paper-desk font-body min-h-screen flex flex-col antialiased selection:bg-accent-brass selection:text-white">

  <script>
  /*
   * website-2-defense.md §14 — transparent device re-verification.
   *
   * The Session Guard refuses a request whose device proof has gone stale,
   * answering 401 DEVICE_REVERIFICATION_REQUIRED. Rather than teaching every
   * call site about that, fetch is wrapped once here: on that specific answer
   * the page re-signs a fresh Website 2 challenge with the non-extractable
   * device key and replays the original request.
   *
   * The employee sees nothing. Someone holding only a stolen session cookie
   * cannot produce the signature and simply stops working — which is the point
   * of §14: the identifier alone is never sufficient.
   *
   * Concurrent 401s share one in-flight re-verification, so a burst of parallel
   * requests does not start a burst of parallel signings.
   */
  (function () {
    var originalFetch = window.fetch.bind(window);
    var inFlight = null;

    function b64u(buffer) {
      var bytes = new Uint8Array(buffer), binary = '';
      for (var i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
      return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    function loadKey() {
      return new Promise(function (resolve, reject) {
        var open = indexedDB.open('gatezero-device', 1);
        open.onupgradeneeded = function () {
          var db = open.result;
          if (!db.objectStoreNames.contains('credentials')) db.createObjectStore('credentials');
        };
        open.onsuccess = function () {
          var tx = open.result.transaction('credentials', 'readonly');
          var req = tx.objectStore('credentials').get('device-key');
          req.onsuccess = function () { resolve(req.result || null); };
          req.onerror = function () { reject(req.error); };
        };
        open.onerror = function () { reject(open.error); };
      });
    }

    function reverify() {
      if (inFlight) return inFlight;

      inFlight = (async function () {
        var key = await loadKey();
        if (!key) return false;

        var challengeRes = await originalFetch('/api/auth/device-challenge', {
          method: 'POST', credentials: 'include',
          headers: { 'Content-Type': 'application/json' }, body: '{}'
        });
        if (!challengeRes.ok) return false;

        var challenge = await challengeRes.json();
        var signature = await crypto.subtle.sign(
          { name: 'ECDSA', hash: 'SHA-256' }, key.privateKey,
          new TextEncoder().encode('gatezero:v1:website-2:W2_SESSION:' + challenge.nonce)
        );

        var proofRes = await originalFetch('/api/auth/device-reverify', {
          method: 'POST', credentials: 'include',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ nonce: challenge.nonce, signature: b64u(signature) })
        });
        return proofRes.ok;
      })().finally(function () { inFlight = null; });

      return inFlight;
    }

    window.fetch = async function (input, init) {
      var res = await originalFetch(input, init);
      if (res.status !== 401) return res;

      // Only act on this one signal; every other 401 is a real denial.
      var body = await res.clone().json().catch(function () { return null; });
      if (!body || body.error !== 'DEVICE_REVERIFICATION_REQUIRED') return res;

      var ok = await reverify().catch(function () { return false; });
      if (!ok) { window.location.reload(); return res; }

      return originalFetch(input, init);
    };
  })();
  </script>


  <!-- MASTHEAD & TOP NAVIGATION -->
  <header class="bg-paper-base dark:bg-night-base border-b-[3px] border-ink-primary dark:border-night-ink sticky top-0 z-40">
    <div class="max-w-[1440px] mx-auto px-6 pt-5 pb-0 flex flex-col">
      <div class="flex justify-between items-end mb-3">
        <div class="flex items-baseline gap-4">
          <h1 class="font-masthead text-2xl font-black tracking-widest text-ink-primary dark:text-night-ink uppercase">THE OPERATIONS DESK</h1>
          <span class="font-mono text-xs text-ink-secondary dark:text-night-sub hidden sm:inline">CENTRAL LOGISTICS &amp; FIELD HUB</span>
        </div>
        
        <div class="flex items-center gap-5 font-mono text-xs">
          <!-- Gateway Status Badge -->
          <div class="flex items-center gap-2 bg-emerald-950/20 dark:bg-emerald-950/40 border border-emerald-700/50 px-2.5 py-1 rounded text-emerald-800 dark:text-emerald-300 font-bold">
            <span class="w-2 h-2 rounded-full bg-emerald-600 animate-pulse"></span>
            <span>GATEZERO VERIFIED</span>
          </div>

          <!-- Operator Info -->
          <div class="hidden md:flex items-center gap-2 text-ink-secondary dark:text-night-sub">
            <span class="material-symbols-outlined text-base">badge</span>
            <span>${user?.name || "Operator"} (${user?.email || "staff@company.internal"})</span>
          </div>

          <!-- Desk Mode (Day / Night) Toggle -->
          <button onclick="toggleTheme()" class="px-2 py-1 border border-ink-secondary/40 rounded hover:bg-black/5 dark:hover:bg-white/5 transition flex items-center gap-1">
            <span id="theme-icon" class="material-symbols-outlined text-sm">dark_mode</span>
            <span id="theme-text" class="text-[11px] font-bold">NIGHT DESK</span>
          </button>

          <!-- GateZero Return / Logout -->
          <a href="/api/auth/logout" class="text-ink-secondary hover:text-signal-urgent dark:text-night-sub transition font-bold">
            [EXIT GATEWAY]
          </a>
        </div>
      </div>

      <!-- Section Navigation Tabs -->
      <nav class="flex gap-8 overflow-x-auto no-scrollbar pt-2">
        <button onclick="switchTab('overview')" id="tab-overview" class="pb-2.5 font-masthead text-sm tracking-wider uppercase transition tab-active">OVERVIEW</button>
        <button onclick="switchTab('assignments')" id="tab-assignments" class="pb-2.5 font-masthead text-sm tracking-wider uppercase text-ink-secondary dark:text-night-sub hover:text-ink-primary transition">ASSIGNMENTS</button>
        <button onclick="switchTab('wire')" id="tab-wire" class="pb-2.5 font-masthead text-sm tracking-wider uppercase text-ink-secondary dark:text-night-sub hover:text-ink-primary transition">THE WIRE</button>
        <button onclick="switchTab('roster')" id="tab-roster" class="pb-2.5 font-masthead text-sm tracking-wider uppercase text-ink-secondary dark:text-night-sub hover:text-ink-primary transition">ROSTER</button>
        <button onclick="switchTab('ledger')" id="tab-ledger" class="pb-2.5 font-masthead text-sm tracking-wider uppercase text-ink-secondary dark:text-night-sub hover:text-ink-primary transition">LEDGER</button>
        <button onclick="switchTab('archive')" id="tab-archive" class="pb-2.5 font-masthead text-sm tracking-wider uppercase text-ink-secondary dark:text-night-sub hover:text-ink-primary transition">ARCHIVE</button>
        <button onclick="switchTab('messages')" id="tab-messages" class="pb-2.5 font-masthead text-sm tracking-wider uppercase text-ink-secondary dark:text-night-sub hover:text-ink-primary transition">MEMOS</button>
        <button onclick="switchTab('calendar')" id="tab-calendar" class="pb-2.5 font-masthead text-sm tracking-wider uppercase text-ink-secondary dark:text-night-sub hover:text-ink-primary transition">SCHEDULE</button>
      </nav>
    </div>
  </header>

  <!-- MAIN APPLICATION CONTENT CONTAINER -->
  <main class="flex-grow max-w-[1440px] w-full mx-auto p-6">
    
    <!-- 1. OVERVIEW VIEW -->
    <section id="view-overview" class="space-y-6">
      <!-- Lead Summary Card -->
      <div class="card-surface p-6 relative rounded-sm">
        <div class="absolute -top-2 left-1/2 -translate-x-1/2 brass-pin"></div>
        <div class="flex justify-between items-start mb-3">
          <h2 class="font-masthead text-xl font-bold uppercase tracking-wider text-ink-primary dark:text-night-ink">CENTRAL DISPATCH &amp; OPERATIONS STATUS</h2>
          <span class="font-mono text-xs text-accent-brass font-bold bg-black/5 dark:bg-white/5 px-2 py-0.5 rounded">STATION 01 // NOMINAL</span>
        </div>
        <p class="text-sm text-ink-secondary dark:text-night-sub leading-relaxed max-w-4xl">
          Primary operations center coordinating enterprise logistics, network infrastructure, regional customer support escalation, and departmental facilities. All units report standard cadence. Check the live wire feed and assignments corkboard for active dispatches.
        </p>
        <div class="mt-4 pt-3 border-t border-dashed border-ink-secondary/30 flex flex-wrap justify-between items-center font-mono text-xs text-ink-secondary dark:text-night-sub gap-4">
          <span>OPERATIONAL UPTIME: <strong class="text-signal-done">99.98%</strong></span>
          <span>DISPATCH TELEMETRY: <strong class="text-ink-primary dark:text-night-ink">STABLE</strong></span>
          <span>GATEWAY TUNNEL: <strong class="text-accent-brass">ENCRYPTED (PORT 3000)</strong></span>
        </div>
      </div>

      <!-- KPI Summary Cards -->
      <div class="grid grid-cols-2 sm:grid-cols-4 gap-4" id="kpi-grid">
        <div class="card-surface p-4 text-center">
          <span class="font-mono text-xs text-ink-secondary dark:text-night-sub uppercase">Active Tasks</span>
          <div id="stat-tasks" class="font-mono text-2xl font-bold text-ink-primary dark:text-night-ink mt-1">--</div>
        </div>
        <div class="card-surface p-4 text-center">
          <span class="font-mono text-xs text-ink-secondary dark:text-night-sub uppercase">Staff On Duty</span>
          <div id="stat-staff" class="font-mono text-2xl font-bold text-signal-done mt-1">--</div>
        </div>
        <div class="card-surface p-4 text-center">
          <span class="font-mono text-xs text-ink-secondary dark:text-night-sub uppercase">Today Shifts</span>
          <div id="stat-shifts" class="font-mono text-2xl font-bold text-signal-progress mt-1">--</div>
        </div>
        <div class="card-surface p-4 text-center">
          <span class="font-mono text-xs text-ink-secondary dark:text-night-sub uppercase">Wire Bulletins</span>
          <div id="stat-wire" class="font-mono text-2xl font-bold text-accent-brass mt-1">--</div>
        </div>
      </div>

      <!-- Split Column: Latest Wire & Urgent Tasks -->
      <div class="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <!-- Live Wire Digest -->
        <div class="lg:col-span-6 card-surface p-5">
          <div class="flex justify-between items-center border-b border-ink-primary/20 pb-2 mb-3">
            <span class="font-masthead font-bold text-sm uppercase">LATEST WIRE BULLETINS</span>
            <button onclick="switchTab('wire')" class="font-mono text-xs text-accent-brass hover:underline font-bold">VIEW ALL WIRE →</button>
          </div>
          <div id="overview-wire-list" class="space-y-3 font-mono text-xs">
            <div class="animate-pulse text-ink-secondary">Loading wire feed...</div>
          </div>
        </div>

        <!-- Urgent Assignments Digest -->
        <div class="lg:col-span-6 card-surface p-5">
          <div class="flex justify-between items-center border-b border-ink-primary/20 pb-2 mb-3">
            <span class="font-masthead font-bold text-sm uppercase">PINNED TASKS &amp; DELIVERABLES</span>
            <button onclick="switchTab('assignments')" class="font-mono text-xs text-accent-brass hover:underline font-bold">OPEN CORKBOARD →</button>
          </div>
          <div id="overview-assignments-list" class="space-y-3">
            <div class="animate-pulse text-ink-secondary font-mono text-xs">Loading tasks...</div>
          </div>
        </div>
      </div>
    </section>

    <!-- 2. ASSIGNMENTS CORKBOARD VIEW -->
    <section id="view-assignments" class="hidden space-y-6">
      <div class="flex justify-between items-center">
        <div>
          <h2 class="font-masthead text-xl font-bold uppercase tracking-wider text-ink-primary dark:text-night-ink">OPERATIONAL ASSIGNMENTS BOARD</h2>
          <p class="text-xs font-mono text-ink-secondary dark:text-night-sub">Tactile task cards pinned with active priority indicators.</p>
        </div>
        <button onclick="openNewTaskModal()" class="px-4 py-2 bg-ink-primary text-paper-base dark:bg-night-card dark:text-night-ink border border-accent-brass hover:bg-accent-brass hover:text-white transition font-mono text-xs font-bold uppercase flex items-center gap-2">
          <span>+ PIN NEW ASSIGNMENT</span>
        </button>
      </div>

      <!-- Corkboard 3-Column Grid -->
      <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
        <!-- Column 1: TO DO -->
        <div class="bg-black/5 dark:bg-white/5 p-4 rounded border border-ink-secondary/20 min-h-[500px]">
          <div class="flex justify-between items-center border-b-2 border-ink-secondary/40 pb-2 mb-4">
            <span class="font-masthead font-bold text-sm uppercase tracking-wider text-ink-secondary dark:text-night-sub">TO DO / DISPATCHED</span>
            <span id="count-todo" class="font-mono text-xs bg-ink-secondary/20 px-2 py-0.5 rounded font-bold">0</span>
          </div>
          <div id="col-todo" class="space-y-4"></div>
        </div>

        <!-- Column 2: IN PROGRESS -->
        <div class="bg-black/5 dark:bg-white/5 p-4 rounded border border-signal-progress/30 min-h-[500px]">
          <div class="flex justify-between items-center border-b-2 border-signal-progress pb-2 mb-4">
            <span class="font-masthead font-bold text-sm uppercase tracking-wider text-signal-progress">IN PROGRESS / ACTIVE</span>
            <span id="count-progress" class="font-mono text-xs bg-signal-progress/20 text-signal-progress px-2 py-0.5 rounded font-bold">0</span>
          </div>
          <div id="col-progress" class="space-y-4"></div>
        </div>

        <!-- Column 3: COMPLETED -->
        <div class="bg-black/5 dark:bg-white/5 p-4 rounded border border-signal-done/30 min-h-[500px]">
          <div class="flex justify-between items-center border-b-2 border-signal-done pb-2 mb-4">
            <span class="font-masthead font-bold text-sm uppercase tracking-wider text-signal-done">COMPLETED / FILED</span>
            <span id="count-completed" class="font-mono text-xs bg-signal-done/20 text-signal-done px-2 py-0.5 rounded font-bold">0</span>
          </div>
          <div id="col-completed" class="space-y-4"></div>
        </div>
      </div>
    </section>

    <!-- 3. THE WIRE VIEW -->
    <section id="view-wire" class="hidden space-y-6">
      <div class="flex justify-between items-center">
        <div>
          <h2 class="font-masthead text-xl font-bold uppercase tracking-wider text-ink-primary dark:text-night-ink">THE WIRE — REAL-TIME DISPATCH FEED</h2>
          <p class="text-xs font-mono text-ink-secondary dark:text-night-sub">Chronological operational announcements &amp; system status logs.</p>
        </div>
        <button onclick="openNewWireModal()" class="px-4 py-2 bg-ink-primary text-paper-base dark:bg-night-card dark:text-night-ink border border-accent-brass hover:bg-accent-brass hover:text-white transition font-mono text-xs font-bold uppercase">
          + BROADCAST WIRE BULLETIN
        </button>
      </div>

      <div class="card-surface p-6 font-mono text-xs space-y-4" id="wire-full-feed">
        <div class="animate-pulse text-ink-secondary">Connecting to operations wire...</div>
      </div>
    </section>

    <!-- 4. ROSTER VIEW -->
    <section id="view-roster" class="hidden space-y-6">
      <div class="flex justify-between items-center">
        <div>
          <h2 class="font-masthead text-xl font-bold uppercase tracking-wider text-ink-primary dark:text-night-ink">COMPANY STAFF &amp; OPERATIONS ROSTER</h2>
          <p class="text-xs font-mono text-ink-secondary dark:text-night-sub">Active personnel, duty statuses, desk stations, and departmental units.</p>
        </div>
      </div>

      <div class="card-surface overflow-hidden">
        <div class="overflow-x-auto">
          <table class="w-full text-left font-mono text-xs">
            <thead class="bg-ink-primary text-paper-base dark:bg-night-card dark:text-night-ink">
              <tr>
                <th class="p-3">NAME &amp; CONTACT</th>
                <th class="p-3">ROLE</th>
                <th class="p-3">DEPARTMENT</th>
                <th class="p-3">STATION</th>
                <th class="p-3">DUTY STATUS</th>
                <th class="p-3 text-right">ACTION</th>
              </tr>
            </thead>
            <tbody id="roster-table-body" class="divide-y divide-ink-secondary/20">
              <tr><td colspan="6" class="p-4 text-center animate-pulse">Loading staff roster...</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </section>

    <!-- 5. LEDGER VIEW -->
    <section id="view-ledger" class="hidden space-y-6">
      <div class="flex justify-between items-center">
        <div>
          <h2 class="font-masthead text-xl font-bold uppercase tracking-wider text-ink-primary dark:text-night-ink">DISPATCH &amp; OPERATIONS LEDGER</h2>
          <p class="text-xs font-mono text-ink-secondary dark:text-night-sub">Operational expenditures, vendor procurement, and logistical cost tracking.</p>
        </div>
        <button onclick="openNewLedgerModal()" class="px-4 py-2 bg-ink-primary text-paper-base dark:bg-night-card dark:text-night-ink border border-accent-brass hover:bg-accent-brass hover:text-white transition font-mono text-xs font-bold uppercase">
          + RECORD LEDGER ENTRY
        </button>
      </div>

      <!-- Ledger Balance Summary Cards -->
      <div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div class="card-surface p-4 font-mono text-xs">
          <span class="text-ink-secondary dark:text-night-sub">TOTAL DEBITS</span>
          <div id="ledger-debits" class="text-xl font-bold text-signal-urgent mt-1">$0.00</div>
        </div>
        <div class="card-surface p-4 font-mono text-xs">
          <span class="text-ink-secondary dark:text-night-sub">TOTAL CREDITS</span>
          <div id="ledger-credits" class="text-xl font-bold text-signal-done mt-1">$0.00</div>
        </div>
        <div class="card-surface p-4 font-mono text-xs">
          <span class="text-ink-secondary dark:text-night-sub">NET OPERATIONAL BALANCE</span>
          <div id="ledger-net" class="text-xl font-bold text-ink-primary dark:text-night-ink mt-1">$0.00</div>
        </div>
      </div>

      <div class="card-surface overflow-hidden">
        <div class="overflow-x-auto">
          <table class="w-full text-left font-mono text-xs">
            <thead class="bg-ink-primary text-paper-base dark:bg-night-card dark:text-night-ink">
              <tr>
                <th class="p-3">REF #</th>
                <th class="p-3">DATE</th>
                <th class="p-3">DESCRIPTION</th>
                <th class="p-3">CATEGORY</th>
                <th class="p-3">AUTHORIZED BY</th>
                <th class="p-3 text-right">AMOUNT</th>
              </tr>
            </thead>
            <tbody id="ledger-table-body" class="divide-y divide-ink-secondary/20">
              <tr><td colspan="6" class="p-4 text-center animate-pulse">Loading ledger entries...</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </section>

    <!-- 6. ARCHIVE VIEW -->
    <section id="view-archive" class="hidden space-y-6">
      <div class="flex flex-col sm:flex-row justify-between sm:items-center gap-4">
        <div>
          <h2 class="font-masthead text-xl font-bold uppercase tracking-wider text-ink-primary dark:text-night-ink">COMPANY ARCHIVE &amp; RECORDS</h2>
          <p class="text-xs font-mono text-ink-secondary dark:text-night-sub">Indexed historical filings, compliance documentation, and project post-mortems.</p>
        </div>
        <button onclick="openNewArchiveModal()" class="px-4 py-2 bg-ink-primary text-paper-base dark:bg-night-card dark:text-night-ink border border-accent-brass hover:bg-accent-brass hover:text-white transition font-mono text-xs font-bold uppercase shrink-0">
          + FILE NEW RECORD
        </button>
      </div>

      <!-- Search & Filter Controls -->
      <div class="card-surface p-4 flex flex-col sm:flex-row gap-4 font-mono text-xs">
        <input type="text" id="archive-search" oninput="loadArchive()" placeholder="Search archive by keyword, tag, or title..." class="flex-1 p-2 bg-paper-base dark:bg-night-base border border-ink-secondary/40 outline-none text-inherit">
        <select id="archive-filter-dept" onchange="loadArchive()" class="p-2 bg-paper-base dark:bg-night-base border border-ink-secondary/40 outline-none text-inherit font-mono">
          <option value="ALL">ALL DEPARTMENTS</option>
          <option value="OPERATIONS">OPERATIONS</option>
          <option value="LOGISTICS">LOGISTICS</option>
          <option value="ENGINEERING">ENGINEERING</option>
          <option value="FACILITIES">FACILITIES</option>
          <option value="SUPPORT">SUPPORT</option>
          <option value="FINANCE">FINANCE</option>
        </select>
      </div>

      <div id="archive-grid" class="grid grid-cols-1 md:grid-cols-2 gap-6"></div>
    </section>

    <!-- 7. MEMOS (MESSAGES) VIEW -->
    <section id="view-messages" class="hidden space-y-6">
      <div class="flex justify-between items-center">
        <div>
          <h2 class="font-masthead text-xl font-bold uppercase tracking-wider text-ink-primary dark:text-night-ink">DEPARTMENTAL COMMS &amp; MEMOS</h2>
          <p class="text-xs font-mono text-ink-secondary dark:text-night-sub">Inter-departmental communications and urgent priority dispatches.</p>
        </div>
        <button onclick="openNewMessageModal()" class="px-4 py-2 bg-ink-primary text-paper-base dark:bg-night-card dark:text-night-ink border border-accent-brass hover:bg-accent-brass hover:text-white transition font-mono text-xs font-bold uppercase">
          + COMPOSE MEMO
        </button>
      </div>

      <div id="messages-list" class="space-y-4"></div>
    </section>

    <!-- 8. SCHEDULE (CALENDAR) VIEW -->
    <section id="view-calendar" class="hidden space-y-6">
      <div>
        <h2 class="font-masthead text-xl font-bold uppercase tracking-wider text-ink-primary dark:text-night-ink">OPERATIONAL SHIFT &amp; ON-CALL SCHEDULE</h2>
        <p class="text-xs font-mono text-ink-secondary dark:text-night-sub">Weekly shift rotations, desk coverage, and scheduled maintenance windows.</p>
      </div>

      <div id="calendar-shifts-grid" class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6"></div>
    </section>

  </main>

  <!-- MODALS CONTAINER -->
  <div id="modal-backdrop" class="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 hidden flex items-center justify-center p-4">
    <div id="modal-content" class="card-surface p-6 max-w-lg w-full rounded-sm relative border-2 border-accent-brass"></div>
  </div>

  <!-- FOOTER INSTRUMENT STRIP -->
  <footer class="bg-paper-card dark:bg-night-card border-t border-ink-secondary/30 py-3 px-6 text-xs font-mono flex flex-wrap justify-between items-center text-ink-secondary dark:text-night-sub mt-12">
    <div>THE OPERATIONS DESK — v1.0.0 (PORT 3002)</div>
    <div class="flex items-center gap-4">
      <span>SECURED BY: GATEZERO ZERO-TRUST GATEWAY</span>
      <span class="text-signal-done font-bold">● LIVE VERIFIED</span>
    </div>
  </footer>

  <!-- CLIENT-SIDE CONTROLLER SCRIPT -->
  <script>
    let currentTab = 'overview';

    // HTML Entity Sanitizer (XSS Defense)
    function escapeHtml(str) {
      if (str === null || str === undefined) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    }

    // Theme Toggle
    function toggleTheme() {
      const html = document.getElementById('html-root');
      const isDark = html.classList.toggle('dark');
      document.getElementById('theme-icon').textContent = isDark ? 'light_mode' : 'dark_mode';
      document.getElementById('theme-text').textContent = isDark ? 'DAY DESK' : 'NIGHT DESK';
    }

    // Navigation Switcher
    function switchTab(tabId) {
      currentTab = tabId;
      document.querySelectorAll('main > section').forEach(sec => sec.classList.add('hidden'));
      document.querySelectorAll('nav button').forEach(btn => {
        btn.classList.remove('tab-active');
        btn.classList.add('text-ink-secondary', 'dark:text-night-sub');
      });

      const targetSec = document.getElementById('view-' + tabId);
      const targetBtn = document.getElementById('tab-' + tabId);
      if (targetSec) targetSec.classList.remove('hidden');
      if (targetBtn) {
        targetBtn.classList.add('tab-active');
        targetBtn.classList.remove('text-ink-secondary', 'dark:text-night-sub');
      }

      // Load tab-specific data
      if (tabId === 'overview') loadOverview();
      if (tabId === 'assignments') loadAssignments();
      if (tabId === 'wire') loadWire();
      if (tabId === 'roster') loadRoster();
      if (tabId === 'ledger') loadLedger();
      if (tabId === 'archive') loadArchive();
      if (tabId === 'messages') loadMessages();
      if (tabId === 'calendar') loadCalendar();
    }

    // Modal Helpers
    function closeModal() {
      document.getElementById('modal-backdrop').classList.add('hidden');
    }

    // 1. Overview Loader
    async function loadOverview() {
      try {
        const [statsRes, wireRes, tasksRes] = await Promise.all([
          fetch('/api/desk/stats'),
          fetch('/api/desk/wire'),
          fetch('/api/desk/assignments')
        ]);
        const stats = await statsRes.json();
        const wire = await wireRes.json();
        const tasks = await tasksRes.json();

        document.getElementById('stat-tasks').textContent = stats.activeAssignments ?? 0;
        document.getElementById('stat-staff').textContent = (stats.onDutyStaff ?? 0) + ' / ' + (stats.totalStaff ?? 0);
        document.getElementById('stat-shifts').textContent = stats.todayShifts ?? 0;
        document.getElementById('stat-wire').textContent = stats.wireCount ?? 0;

        // Render mini wire
        const wireEl = document.getElementById('overview-wire-list');
        wireEl.innerHTML = (wire.bulletins || []).slice(0, 4).map(b => \`
          <div class="border-b border-dotted border-ink-secondary/20 pb-2">
            <div class="flex items-center gap-2">
              <span class="text-accent-brass font-bold">[\${escapeHtml(b.timestamp)}]</span>
              <span class="font-bold \${b.urgency === 'FLASH' ? 'text-signal-urgent' : 'text-ink-primary dark:text-night-ink'}">\${escapeHtml(b.headline)}</span>
            </div>
            <p class="text-ink-secondary dark:text-night-sub mt-0.5 text-[11px]">\${escapeHtml(b.body)}</p>
          </div>
        \`).join('') || '<div class="text-ink-secondary">No active wire bulletins</div>';

        // Render mini tasks
        const tasksEl = document.getElementById('overview-assignments-list');
        tasksEl.innerHTML = (tasks.assignments || []).slice(0, 4).map(t => \`
          <div class="p-3 bg-black/5 dark:bg-white/5 border border-ink-secondary/20 flex justify-between items-center">
            <div>
              <div class="font-bold text-xs \${t.priority === 'URGENT' ? 'text-signal-urgent' : 'text-ink-primary dark:text-night-ink'}">\${escapeHtml(t.title)}</div>
              <div class="font-mono text-[10px] text-ink-secondary dark:text-night-sub">\${escapeHtml(t.department)} // \${escapeHtml(t.assigneeName)} // DUE \${escapeHtml(t.deadline)}</div>
            </div>
            <span class="font-mono text-[10px] px-2 py-0.5 rounded font-bold \${t.status === 'COMPLETED' ? 'bg-signal-done/20 text-signal-done' : t.status === 'IN_PROGRESS' ? 'bg-signal-progress/20 text-signal-progress' : 'bg-ink-secondary/20 text-ink-secondary'}">\${escapeHtml(t.status.replace('_', ' '))}</span>
          </div>
        \`).join('') || '<div class="text-ink-secondary">No active tasks</div>';
      } catch (err) {
        console.error(err);
      }
    }

    // 2. Assignments Loader
    async function loadAssignments() {
      const res = await fetch('/api/desk/assignments');
      const data = await res.json();
      const items = data.assignments || [];

      const todo = items.filter(i => i.status === 'TODO');
      const progress = items.filter(i => i.status === 'IN_PROGRESS');
      const completed = items.filter(i => i.status === 'COMPLETED');

      document.getElementById('count-todo').textContent = todo.length;
      document.getElementById('count-progress').textContent = progress.length;
      document.getElementById('count-completed').textContent = completed.length;

      const renderCard = (t) => \`
        <div class="card-surface p-4 relative rounded-sm group transition-transform hover:scale-[1.02]" style="transform: rotate(\${Number(t.rotation) || 0}deg);">
          <div class="absolute -top-2 left-1/2 -translate-x-1/2 \${t.priority === 'URGENT' ? 'urgent-pin' : 'brass-pin'}"></div>
          
          <div class="flex justify-between items-start mb-2 pt-1">
            <span class="font-mono text-[10px] font-bold text-ink-secondary dark:text-night-sub">\${escapeHtml(t.department)}</span>
            <span class="font-mono text-[10px] font-bold \${t.priority === 'URGENT' ? 'text-signal-urgent' : 'text-accent-brass'}">\${escapeHtml(t.priority)}</span>
          </div>

          <h3 class="font-bold text-sm text-ink-primary dark:text-night-ink mb-1.5 leading-snug">\${escapeHtml(t.title)}</h3>
          <p class="text-xs text-ink-secondary dark:text-night-sub mb-3 leading-relaxed">\${escapeHtml(t.description || '')}</p>

          <div class="pt-2 border-t border-dotted border-ink-secondary/30 flex justify-between items-center font-mono text-[10px] text-ink-secondary dark:text-night-sub">
            <span>\${escapeHtml(t.assigneeName)}</span>
            <span class="font-bold">DUE \${escapeHtml(t.deadline)}</span>
          </div>

          <!-- Quick Move Dropdown -->
          <div class="mt-3 flex justify-between items-center pt-2 border-t border-ink-secondary/10">
            <select onchange="updateAssignmentStatus('\${escapeHtml(t.id)}', this.value)" class="bg-paper-base dark:bg-night-base text-[10px] font-mono p-1 border border-ink-secondary/30 rounded outline-none">
              <option value="TODO" \${t.status === 'TODO' ? 'selected' : ''}>→ TO DO</option>
              <option value="IN_PROGRESS" \${t.status === 'IN_PROGRESS' ? 'selected' : ''}>→ IN PROGRESS</option>
              <option value="COMPLETED" \${t.status === 'COMPLETED' ? 'selected' : ''}>→ COMPLETED</option>
            </select>
            <button onclick="deleteAssignment('\${escapeHtml(t.id)}')" class="text-signal-urgent hover:underline font-mono text-[10px]">✕ DELETE</button>
          </div>
        </div>
      \`;

      document.getElementById('col-todo').innerHTML = todo.map(renderCard).join('') || '<div class="text-center text-xs font-mono text-ink-secondary py-8">No tasks in queue</div>';
      document.getElementById('col-progress').innerHTML = progress.map(renderCard).join('') || '<div class="text-center text-xs font-mono text-ink-secondary py-8">No active tasks</div>';
      document.getElementById('col-completed').innerHTML = completed.map(renderCard).join('') || '<div class="text-center text-xs font-mono text-ink-secondary py-8">No completed tasks</div>';
    }

    async function updateAssignmentStatus(id, newStatus) {
      await fetch('/api/desk/assignments/' + encodeURIComponent(id), {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: newStatus })
      });
      loadAssignments();
    }

    async function deleteAssignment(id) {
      if (!confirm('Remove this pinned assignment from board?')) return;
      await fetch('/api/desk/assignments/' + encodeURIComponent(id), { method: 'DELETE' });
      loadAssignments();
    }

    function openNewTaskModal() {
      const modal = document.getElementById('modal-content');
      modal.innerHTML = \`
        <div class="flex justify-between items-center border-b border-ink-primary/20 pb-3 mb-4">
          <h3 class="font-masthead font-bold text-lg uppercase">PIN NEW ASSIGNMENT</h3>
          <button onclick="closeModal()" class="text-ink-secondary hover:text-ink-primary font-mono text-sm">✕</button>
        </div>
        <form onsubmit="submitNewTask(event)" class="space-y-3 font-mono text-xs">
          <div>
            <label class="block text-ink-secondary dark:text-night-sub mb-1">TASK TITLE *</label>
            <input type="text" name="title" required class="w-full p-2 bg-paper-base dark:bg-night-base border border-ink-secondary/40 outline-none">
          </div>
          <div>
            <label class="block text-ink-secondary dark:text-night-sub mb-1">DESCRIPTION</label>
            <textarea name="description" rows="3" class="w-full p-2 bg-paper-base dark:bg-night-base border border-ink-secondary/40 outline-none"></textarea>
          </div>
          <div class="grid grid-cols-2 gap-3">
            <div>
              <label class="block text-ink-secondary dark:text-night-sub mb-1">DEPARTMENT</label>
              <select name="department" class="w-full p-2 bg-paper-base dark:bg-night-base border border-ink-secondary/40 outline-none">
                <option value="OPERATIONS">OPERATIONS</option>
                <option value="LOGISTICS">LOGISTICS</option>
                <option value="ENGINEERING">ENGINEERING</option>
                <option value="SUPPORT">SUPPORT</option>
                <option value="FACILITIES">FACILITIES</option>
                <option value="FINANCE">FINANCE</option>
              </select>
            </div>
            <div>
              <label class="block text-ink-secondary dark:text-night-sub mb-1">PRIORITY</label>
              <select name="priority" class="w-full p-2 bg-paper-base dark:bg-night-base border border-ink-secondary/40 outline-none">
                <option value="STANDARD">STANDARD (BRASS PIN)</option>
                <option value="URGENT">URGENT (RED PIN)</option>
              </select>
            </div>
          </div>
          <div class="grid grid-cols-2 gap-3">
            <div>
              <label class="block text-ink-secondary dark:text-night-sub mb-1">ASSIGNEE NAME</label>
              <input type="text" name="assigneeName" value="Marcus Vance" class="w-full p-2 bg-paper-base dark:bg-night-base border border-ink-secondary/40 outline-none">
            </div>
            <div>
              <label class="block text-ink-secondary dark:text-night-sub mb-1">DEADLINE / TIME</label>
              <input type="text" name="deadline" value="1700 HRS" class="w-full p-2 bg-paper-base dark:bg-night-base border border-ink-secondary/40 outline-none">
            </div>
          </div>
          <div class="flex justify-end gap-3 pt-3">
            <button type="button" onclick="closeModal()" class="px-4 py-2 border border-ink-secondary/40">Cancel</button>
            <button type="submit" class="px-4 py-2 bg-ink-primary text-paper-base dark:bg-night-card dark:text-night-ink border border-accent-brass font-bold">Pin Task Card →</button>
          </div>
        </form>
      \`;
      document.getElementById('modal-backdrop').classList.remove('hidden');
    }

    async function submitNewTask(e) {
      e.preventDefault();
      const formData = new FormData(e.target);
      const data = Object.fromEntries(formData.entries());
      await fetch('/api/desk/assignments', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
      });
      closeModal();
      loadAssignments();
    }

    // 3. Wire Loader
    async function loadWire() {
      const res = await fetch('/api/desk/wire');
      const data = await res.json();
      const el = document.getElementById('wire-full-feed');
      el.innerHTML = (data.bulletins || []).map(b => \`
        <div class="p-4 border-l-4 \${b.urgency === 'FLASH' ? 'border-signal-urgent bg-signal-urgent/5' : 'border-accent-brass bg-black/5 dark:bg-white/5'}">
          <div class="flex justify-between items-center mb-1">
            <div class="flex items-center gap-2">
              <span class="text-accent-brass font-bold">[\${escapeHtml(b.timestamp)} HRS]</span>
              <span class="px-1.5 py-0.2 bg-ink-secondary/20 rounded font-bold text-[10px]">\${escapeHtml(b.category)}</span>
              \${b.urgency === 'FLASH' ? '<span class="text-signal-urgent font-bold animate-pulse">● FLASH PRIORITY</span>' : ''}
            </div>
            <span class="text-ink-secondary dark:text-night-sub text-[10px]">\${new Date(b.createdAt).toLocaleDateString()}</span>
          </div>
          <h4 class="font-bold text-sm text-ink-primary dark:text-night-ink mb-1">\${escapeHtml(b.headline)}</h4>
          <p class="text-ink-secondary dark:text-night-sub leading-relaxed">\${escapeHtml(b.body)}</p>
        </div>
      \`).join('') || '<div class="text-center py-6 text-ink-secondary">Wire buffer empty</div>';
    }

    function openNewWireModal() {
      const modal = document.getElementById('modal-content');
      modal.innerHTML = \`
        <div class="flex justify-between items-center border-b border-ink-primary/20 pb-3 mb-4">
          <h3 class="font-masthead font-bold text-lg uppercase">BROADCAST WIRE BULLETIN</h3>
          <button onclick="closeModal()" class="text-ink-secondary hover:text-ink-primary font-mono text-sm">✕</button>
        </div>
        <form onsubmit="submitNewWire(event)" class="space-y-3 font-mono text-xs">
          <div>
            <label class="block text-ink-secondary dark:text-night-sub mb-1">BULLETIN HEADLINE *</label>
            <input type="text" name="headline" required class="w-full p-2 bg-paper-base dark:bg-night-base border border-ink-secondary/40 outline-none">
          </div>
          <div>
            <label class="block text-ink-secondary dark:text-night-sub mb-1">CONTENT BODY *</label>
            <textarea name="body" rows="3" required class="w-full p-2 bg-paper-base dark:bg-night-base border border-ink-secondary/40 outline-none"></textarea>
          </div>
          <div class="grid grid-cols-2 gap-3">
            <div>
              <label class="block text-ink-secondary dark:text-night-sub mb-1">CATEGORY</label>
              <select name="category" class="w-full p-2 bg-paper-base dark:bg-night-base border border-ink-secondary/40 outline-none">
                <option value="OPERATIONS">OPERATIONS</option>
                <option value="SYSTEM_STATUS">SYSTEM STATUS</option>
                <option value="LOGISTICS">LOGISTICS</option>
                <option value="FACILITY">FACILITY</option>
                <option value="ANNOUNCEMENT">ANNOUNCEMENT</option>
              </select>
            </div>
            <div>
              <label class="block text-ink-secondary dark:text-night-sub mb-1">URGENCY LEVEL</label>
              <select name="urgency" class="w-full p-2 bg-paper-base dark:bg-night-base border border-ink-secondary/40 outline-none">
                <option value="NORMAL">NORMAL</option>
                <option value="FLASH">FLASH PRIORITY</option>
              </select>
            </div>
          </div>
          <div class="flex justify-end gap-3 pt-3">
            <button type="button" onclick="closeModal()" class="px-4 py-2 border border-ink-secondary/40">Cancel</button>
            <button type="submit" class="px-4 py-2 bg-ink-primary text-paper-base dark:bg-night-card dark:text-night-ink border border-accent-brass font-bold">Transmit to Wire →</button>
          </div>
        </form>
      \`;
      document.getElementById('modal-backdrop').classList.remove('hidden');
    }

    async function submitNewWire(e) {
      e.preventDefault();
      const formData = new FormData(e.target);
      const data = Object.fromEntries(formData.entries());
      await fetch('/api/desk/wire', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
      });
      closeModal();
      loadWire();
    }

    // 4. Roster Loader
    async function loadRoster() {
      const res = await fetch('/api/desk/roster');
      const data = await res.json();
      const tbody = document.getElementById('roster-table-body');
      tbody.innerHTML = (data.staff || []).map(s => \`
        <tr class="hover:bg-black/5 dark:hover:bg-white/5 transition">
          <td class="p-3">
            <div class="font-bold text-ink-primary dark:text-night-ink">\${escapeHtml(s.name)}</div>
            <div class="text-[11px] text-ink-secondary dark:text-night-sub">\${escapeHtml(s.email)} • \${escapeHtml(s.extension)}</div>
          </td>
          <td class="p-3 text-ink-secondary dark:text-night-sub">\${escapeHtml(s.role)}</td>
          <td class="p-3 font-bold">\${escapeHtml(s.department)}</td>
          <td class="p-3 text-ink-secondary dark:text-night-sub">\${escapeHtml(s.deskLocation)}</td>
          <td class="p-3">
            <span class="px-2 py-0.5 rounded font-bold text-[10px] \${s.status === 'ON_DUTY' ? 'bg-signal-done/20 text-signal-done' : s.status === 'REMOTE' ? 'bg-signal-progress/20 text-signal-progress' : s.status === 'ON_CALL' ? 'bg-accent-brass/20 text-accent-brass' : 'bg-ink-secondary/20 text-ink-secondary'}">\${escapeHtml(s.status.replace('_', ' '))}</span>
          </td>
          <td class="p-3 text-right">
            <select onchange="updateStaffStatus('\${escapeHtml(s.id)}', this.value)" class="bg-paper-base dark:bg-night-base text-[10px] p-1 border border-ink-secondary/30 rounded outline-none font-mono">
              <option value="ON_DUTY" \${s.status === 'ON_DUTY' ? 'selected' : ''}>ON DUTY</option>
              <option value="REMOTE" \${s.status === 'REMOTE' ? 'selected' : ''}>REMOTE</option>
              <option value="ON_CALL" \${s.status === 'ON_CALL' ? 'selected' : ''}>ON CALL</option>
              <option value="OFF_DUTY" \${s.status === 'OFF_DUTY' ? 'selected' : ''}>OFF DUTY</option>
            </select>
          </td>
        </tr>
      \`).join('');
    }

    async function updateStaffStatus(id, newStatus) {
      await fetch('/api/desk/roster/' + encodeURIComponent(id), {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: newStatus })
      });
      loadRoster();
    }

    // 5. Ledger Loader
    async function loadLedger() {
      const res = await fetch('/api/desk/ledger');
      const data = await res.json();
      
      document.getElementById('ledger-debits').textContent = '$' + (data.summary?.totalDebits || 0).toLocaleString('en-US', { minimumFractionDigits: 2 });
      document.getElementById('ledger-credits').textContent = '$' + (data.summary?.totalCredits || 0).toLocaleString('en-US', { minimumFractionDigits: 2 });
      document.getElementById('ledger-net').textContent = '$' + (data.summary?.netBalance || 0).toLocaleString('en-US', { minimumFractionDigits: 2 });

      const tbody = document.getElementById('ledger-table-body');
      tbody.innerHTML = (data.records || []).map(r => \`
        <tr class="hover:bg-black/5 dark:hover:bg-white/5 transition">
          <td class="p-3 font-bold text-accent-brass">\${escapeHtml(r.refNumber)}</td>
          <td class="p-3 text-ink-secondary dark:text-night-sub">\${escapeHtml(r.entryDate)}</td>
          <td class="p-3 font-bold text-ink-primary dark:text-night-ink">\${escapeHtml(r.description)}</td>
          <td class="p-3"><span class="px-2 py-0.5 bg-ink-secondary/15 rounded text-[10px]">\${escapeHtml(r.category)}</span></td>
          <td class="p-3 text-ink-secondary dark:text-night-sub">\${escapeHtml(r.authorizedBy)}</td>
          <td class="p-3 text-right font-bold \${r.type === 'DEBIT' ? 'text-signal-urgent' : 'text-signal-done'}">
            \${r.type === 'DEBIT' ? '-' : '+'}$ \${Number(r.amount).toLocaleString('en-US', { minimumFractionDigits: 2 })}
          </td>
        </tr>
      \`).join('');
    }

    function openNewLedgerModal() {
      const modal = document.getElementById('modal-content');
      modal.innerHTML = \`
        <div class="flex justify-between items-center border-b border-ink-primary/20 pb-3 mb-4">
          <h3 class="font-masthead font-bold text-lg uppercase">RECORD LEDGER ENTRY</h3>
          <button onclick="closeModal()" class="text-ink-secondary hover:text-ink-primary font-mono text-sm">✕</button>
        </div>
        <form onsubmit="submitNewLedger(event)" class="space-y-3 font-mono text-xs">
          <div>
            <label class="block text-ink-secondary dark:text-night-sub mb-1">TRANSACTION DESCRIPTION *</label>
            <input type="text" name="description" required class="w-full p-2 bg-paper-base dark:bg-night-base border border-ink-secondary/40 outline-none">
          </div>
          <div class="grid grid-cols-2 gap-3">
            <div>
              <label class="block text-ink-secondary dark:text-night-sub mb-1">AMOUNT ($) *</label>
              <input type="number" step="0.01" name="amount" required class="w-full p-2 bg-paper-base dark:bg-night-base border border-ink-secondary/40 outline-none">
            </div>
            <div>
              <label class="block text-ink-secondary dark:text-night-sub mb-1">ENTRY TYPE</label>
              <select name="type" class="w-full p-2 bg-paper-base dark:bg-night-base border border-ink-secondary/40 outline-none">
                <option value="DEBIT">DEBIT (EXPENSE / OUTFLOW)</option>
                <option value="CREDIT">CREDIT (INFLOW / REIMBURSE)</option>
              </select>
            </div>
          </div>
          <div>
            <label class="block text-ink-secondary dark:text-night-sub mb-1">CATEGORY</label>
            <select name="category" class="w-full p-2 bg-paper-base dark:bg-night-base border border-ink-secondary/40 outline-none">
              <option value="PROCUREMENT">PROCUREMENT</option>
              <option value="INFRASTRUCTURE">INFRASTRUCTURE</option>
              <option value="VENDOR_PAYMENT">VENDOR PAYMENT</option>
              <option value="SUPPLIES">SUPPLIES</option>
              <option value="TRAVEL">TRAVEL</option>
            </select>
          </div>
          <div class="flex justify-end gap-3 pt-3">
            <button type="button" onclick="closeModal()" class="px-4 py-2 border border-ink-secondary/40">Cancel</button>
            <button type="submit" class="px-4 py-2 bg-ink-primary text-paper-base dark:bg-night-card dark:text-night-ink border border-accent-brass font-bold">Post Entry →</button>
          </div>
        </form>
      \`;
      document.getElementById('modal-backdrop').classList.remove('hidden');
    }

    async function submitNewLedger(e) {
      e.preventDefault();
      const formData = new FormData(e.target);
      const data = Object.fromEntries(formData.entries());
      await fetch('/api/desk/ledger', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
      });
      closeModal();
      loadLedger();
    }

    // 6. Archive Loader
    async function loadArchive() {
      const search = document.getElementById('archive-search')?.value || '';
      const dept = document.getElementById('archive-filter-dept')?.value || 'ALL';
      const res = await fetch(\`/api/desk/archive?department=\${dept}&search=\${encodeURIComponent(search)}\`);
      const data = await res.json();
      
      const grid = document.getElementById('archive-grid');
      grid.innerHTML = (data.records || []).map(r => \`
        <div class="card-surface p-5 relative border-l-4 border-accent-brass">
          <div class="flex justify-between items-start mb-2">
            <span class="font-mono text-xs font-bold text-accent-brass">\${escapeHtml(r.recordNumber)}</span>
            <span class="font-mono text-[10px] text-ink-secondary dark:text-night-sub">FILED: \${escapeHtml(r.filingDate)}</span>
          </div>
          <h3 class="font-masthead font-bold text-base text-ink-primary dark:text-night-ink mb-2">\${escapeHtml(r.title)}</h3>
          <p class="text-xs text-ink-secondary dark:text-night-sub mb-4 leading-relaxed">\${escapeHtml(r.summary)}</p>
          <div class="pt-3 border-t border-dotted border-ink-secondary/30 flex justify-between items-center font-mono text-[10px]">
            <span class="bg-black/5 dark:bg-white/5 px-2 py-0.5 rounded font-bold">\${escapeHtml(r.department)}</span>
            <span class="text-ink-secondary dark:text-night-sub">\${escapeHtml(r.tags)}</span>
          </div>
        </div>
      \`).join('') || '<div class="col-span-2 text-center py-8 font-mono text-xs text-ink-secondary">No matching archive records found</div>';
    }

    function openNewArchiveModal() {
      const modal = document.getElementById('modal-content');
      modal.innerHTML = \`
        <div class="flex justify-between items-center border-b border-ink-primary/20 pb-3 mb-4">
          <h3 class="font-masthead font-bold text-lg uppercase">FILE NEW ARCHIVE RECORD</h3>
          <button onclick="closeModal()" class="text-ink-secondary hover:text-ink-primary font-mono text-sm">✕</button>
        </div>
        <form onsubmit="submitNewArchive(event)" class="space-y-3 font-mono text-xs">
          <div>
            <label class="block text-ink-secondary dark:text-night-sub mb-1">RECORD TITLE *</label>
            <input type="text" name="title" required class="w-full p-2 bg-paper-base dark:bg-night-base border border-ink-secondary/40 outline-none">
          </div>
          <div>
            <label class="block text-ink-secondary dark:text-night-sub mb-1">DEPARTMENT</label>
            <select name="department" class="w-full p-2 bg-paper-base dark:bg-night-base border border-ink-secondary/40 outline-none">
              <option value="OPERATIONS">OPERATIONS</option>
              <option value="LOGISTICS">LOGISTICS</option>
              <option value="ENGINEERING">ENGINEERING</option>
              <option value="FACILITIES">FACILITIES</option>
              <option value="SUPPORT">SUPPORT</option>
              <option value="FINANCE">FINANCE</option>
            </select>
          </div>
          <div>
            <label class="block text-ink-secondary dark:text-night-sub mb-1">SUMMARY / RECORD DETAILS *</label>
            <textarea name="summary" rows="3" required class="w-full p-2 bg-paper-base dark:bg-night-base border border-ink-secondary/40 outline-none"></textarea>
          </div>
          <div>
            <label class="block text-ink-secondary dark:text-night-sub mb-1">TAGS (COMMA SEPARATED)</label>
            <input type="text" name="tags" value="Audit, 2026, Operations" class="w-full p-2 bg-paper-base dark:bg-night-base border border-ink-secondary/40 outline-none">
          </div>
          <div class="flex justify-end gap-3 pt-3">
            <button type="button" onclick="closeModal()" class="px-4 py-2 border border-ink-secondary/40">Cancel</button>
            <button type="submit" class="px-4 py-2 bg-ink-primary text-paper-base dark:bg-night-card dark:text-night-ink border border-accent-brass font-bold">Archive Document →</button>
          </div>
        </form>
      \`;
      document.getElementById('modal-backdrop').classList.remove('hidden');
    }

    async function submitNewArchive(e) {
      e.preventDefault();
      const formData = new FormData(e.target);
      const data = Object.fromEntries(formData.entries());
      await fetch('/api/desk/archive', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
      });
      closeModal();
      loadArchive();
    }

    // 7. Messages Loader
    async function loadMessages() {
      const res = await fetch('/api/desk/messages');
      const data = await res.json();
      const el = document.getElementById('messages-list');
      el.innerHTML = (data.messages || []).map(m => \`
        <div class="card-surface p-5 font-mono text-xs border-l-4 \${m.urgent ? 'border-signal-urgent' : 'border-ink-secondary/40'}">
          <div class="flex justify-between items-start mb-2">
            <div>
              <span class="font-bold text-sm text-ink-primary dark:text-night-ink">\${escapeHtml(m.subject)}</span>
              <div class="text-[11px] text-ink-secondary dark:text-night-sub mt-0.5">FROM: \${escapeHtml(m.senderName)} (\${escapeHtml(m.senderEmail)}) • TO: \${escapeHtml(m.recipientEmail)}</div>
            </div>
            <span class="text-ink-secondary dark:text-night-sub text-[10px]">\${new Date(m.createdAt).toLocaleDateString()}</span>
          </div>
          <p class="mt-2 text-ink-secondary dark:text-night-sub leading-relaxed">\${escapeHtml(m.content)}</p>
        </div>
      \`).join('') || '<div class="text-center py-8 font-mono text-xs text-ink-secondary">No messages in inbox</div>';
    }

    function openNewMessageModal() {
      const modal = document.getElementById('modal-content');
      modal.innerHTML = \`
        <div class="flex justify-between items-center border-b border-ink-primary/20 pb-3 mb-4">
          <h3 class="font-masthead font-bold text-lg uppercase">COMPOSE DEPARTMENTAL MEMO</h3>
          <button onclick="closeModal()" class="text-ink-secondary hover:text-ink-primary font-mono text-sm">✕</button>
        </div>
        <form onsubmit="submitNewMessage(event)" class="space-y-3 font-mono text-xs">
          <div>
            <label class="block text-ink-secondary dark:text-night-sub mb-1">MEMO SUBJECT *</label>
            <input type="text" name="subject" required class="w-full p-2 bg-paper-base dark:bg-night-base border border-ink-secondary/40 outline-none">
          </div>
          <div>
            <label class="block text-ink-secondary dark:text-night-sub mb-1">MESSAGE CONTENT *</label>
            <textarea name="content" rows="4" required class="w-full p-2 bg-paper-base dark:bg-night-base border border-ink-secondary/40 outline-none"></textarea>
          </div>
          <div class="flex items-center gap-2">
            <input type="checkbox" name="urgent" id="memo-urgent" class="accent-signal-urgent">
            <label for="memo-urgent" class="font-bold text-signal-urgent">MARK AS FLASH / URGENT PRIORITY</label>
          </div>
          <div class="flex justify-end gap-3 pt-3">
            <button type="button" onclick="closeModal()" class="px-4 py-2 border border-ink-secondary/40">Cancel</button>
            <button type="submit" class="px-4 py-2 bg-ink-primary text-paper-base dark:bg-night-card dark:text-night-ink border border-accent-brass font-bold">Dispatch Memo →</button>
          </div>
        </form>
      \`;
      document.getElementById('modal-backdrop').classList.remove('hidden');
    }

    async function submitNewMessage(e) {
      e.preventDefault();
      const formData = new FormData(e.target);
      const data = {
        subject: formData.get('subject'),
        content: formData.get('content'),
        urgent: formData.get('urgent') === 'on'
      };
      await fetch('/api/desk/messages', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
      });
      closeModal();
      loadMessages();
    }

    // 8. Calendar Loader
    async function loadCalendar() {
      const res = await fetch('/api/desk/calendar');
      const data = await res.json();
      const el = document.getElementById('calendar-shifts-grid');
      el.innerHTML = (data.shifts || []).map(s => \`
        <div class="card-surface p-4 font-mono text-xs relative border-t-4 border-accent-brass">
          <div class="text-[10px] text-ink-secondary dark:text-night-sub mb-1">\${escapeHtml(s.date)}</div>
          <h4 class="font-bold text-sm text-ink-primary dark:text-night-ink mb-1">\${escapeHtml(s.title)}</h4>
          <div class="text-accent-brass font-bold mb-2">[\${escapeHtml(s.startTime)} - \${escapeHtml(s.endTime)} HRS]</div>
          <div class="pt-2 border-t border-dotted border-ink-secondary/30 text-[11px] text-ink-secondary dark:text-night-sub">
            <strong>STAFF:</strong> \${escapeHtml(s.assignedStaff)}
          </div>
        </div>
      \`).join('') || '<div class="col-span-4 text-center py-8 font-mono text-xs text-ink-secondary">No shifts scheduled</div>';
    }

    // Initial Load
    loadOverview();

    // Auto-refresh wire every 20 seconds
    setInterval(() => {
      if (currentTab === 'overview') loadOverview();
      if (currentTab === 'wire') loadWire();
    }, 20000);
  </script>
</body>
</html>`;
}

// ─────────────────────────────────────────────────────────────────────────────
// Start Standalone Website 2 Server on Port 3002 (Bound to Localhost / 127.0.0.1)
// ─────────────────────────────────────────────────────────────────────────────
app.listen(PORT, HOST, () => {
  console.log(`\n=======================================================`);
  console.log(` 📰 THE OPERATIONS DESK (WEBSITE 2) ACTIVE`);
  console.log(` URL: http://${HOST}:${PORT}`);
  console.log(` Gated by GateZero Gateway: ${GATEWAY_URL}`);
  console.log(` Session Guard: ACTIVE (independent of Website 1 / Gateway)`);
  console.log(` Security Headers: ENFORCED`);
  console.log(`=======================================================\n`);
});

export default app;
