/**
 * lib/mini-edr/index.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Mini EDR — risk scoring for Connect requests (website-1-defense.md §5-§7)
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * SCOPE (§6 "Scope Boundary")
 * ───────────────────────────
 * Login, MFA, and Connect events on Website 1. Nothing else. No endpoint,
 * process, file, or general network monitoring, and explicitly no visibility
 * into Website 2 — Website 2 has its own Session Guard, and the two layers do
 * not share responsibility for each other's domain.
 *
 * DEVICE IDENTITY vs. TELEMETRY (§5, §6)
 * ──────────────────────────────────────
 * Cryptographic device identity is the authoritative answer to "is this the
 * employee's known device", and it is verified by the Connect route before this
 * module is consulted. What arrives here is the *result* of that check.
 *
 * IP address and User-Agent are telemetry that feed the score and nothing more.
 * They are shared, rotated, and trivially spoofed, so they never identify a
 * device on their own. Concretely: a UA mismatch alone stays under the MEDIUM
 * threshold, because §5 says an employee moving between ordinary networks and
 * browsers must not be logged out for it.
 *
 * WHAT THIS MODULE DOES NOT DO
 * ────────────────────────────
 * It computes an assessment. It does not revoke sessions, block requests, or
 * write audit logs — the Connect route acts on the result. That keeps scoring a
 * pure, independently-testable function of stored state.
 *
 * FAIL-CLOSED (§19)
 * ─────────────────
 * If telemetry cannot be read, the assessment returns CRITICAL with an explicit
 * `assessment_failed` factor rather than throwing. A risk engine that cannot see
 * must not answer "looks fine", and it must not merely 500 either — the caller
 * needs a decision it can log and act on.
 *
 * Thresholds and point values are tunable by design (§7, §20): the spec leaves
 * exact numbers to implementation and testing.
 */

import { prisma } from "../db";
import { hashUA } from "../authz-service";
import type { Session, User } from "@prisma/client";

export type RiskLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface RiskFactorHit {
  name: string;
  points: number;
  detail: string;
}

export interface RiskAssessment {
  level: RiskLevel;
  score: number;
  factors: RiskFactorHit[];
  /** True when scoring could not complete and the result is a fail-closed denial. */
  failedClosed?: boolean;
}

/** Result of the cryptographic device check, performed by the caller. */
export interface DeviceContext {
  /** A valid proof was presented for a registered, usable credential. */
  proofValid: boolean;
  /** The credential the proof resolved to. */
  credentialId?: string;
  /** Internal reason when the proof failed. */
  reason?: string;
  /** The credential this session used on its previous Connect, if any. */
  previousCredentialId?: string | null;
}

const THRESHOLDS: { level: RiskLevel; min: number }[] = [
  { level: "CRITICAL", min: 70 },
  { level: "HIGH", min: 45 },
  { level: "MEDIUM", min: 20 },
  { level: "LOW", min: 0 },
];

function levelForScore(score: number): RiskLevel {
  for (const t of THRESHOLDS) {
    if (score >= t.min) return t.level;
  }
  return "LOW";
}

/** First three octets of an IPv4 address, used only as a coarse subnet-change signal. */
function subnetOf(ip: string): string | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null; // not IPv4 (e.g. IPv6, "unknown") — skip subnet comparison
  return parts.slice(0, 3).join(".");
}

/**
 * Grade a device-proof failure. See the commentary at Factor 1.
 *
 * The default is the forgery weight: an unrecognised reason is treated as
 * hostile rather than benign, so adding a new failure mode without classifying
 * it fails safe.
 */
function deviceFailureFactor(reason: string | undefined): RiskFactorHit {
  const detail = `Device could not prove possession of a registered credential (${reason ?? "unknown"})`;

  switch (reason) {
    // Lifecycle: the employee has no usable credential. Connect is refused, but
    // this is an enrolment problem, not evidence of compromise.
    case "NO_REGISTERED_DEVICE":
    case "CREDENTIAL_NOT_APPROVED":
    case "CREDENTIAL_ROTATION_GRACE_EXPIRED":
    case "CREDENTIAL_EXPIRED":
      return { name: "device_not_enrolled", points: 0, detail };

    // A revoked credential is a deliberate administrative act. Worth noting,
    // and worth stacking with other signals, but the refusal is the response.
    case "CREDENTIAL_REVOKED":
      return { name: "device_credential_revoked", points: 15, detail };

    // Staleness: a consumed or expired nonce is what a retried request or a
    // long-idle tab produces.
    case "CHALLENGE_ALREADY_USED":
    case "CHALLENGE_EXPIRED":
    case "CHALLENGE_NOT_FOUND":
      return { name: "device_challenge_stale", points: 15, detail };

    // Misdirection: a challenge issued for another user, another purpose, or
    // another component. Nothing legitimate does this.
    case "CHALLENGE_USER_MISMATCH":
    case "CHALLENGE_PURPOSE_MISMATCH":
    case "CHALLENGE_ISSUER_MISMATCH":
      return { name: "device_challenge_misdirected", points: 70, detail };

    // Forgery: a bad signature against a live challenge, or a credential that
    // belongs to someone else.
    case "INVALID_DEVICE_SIGNATURE":
    case "CREDENTIAL_USER_MISMATCH":
    default:
      return { name: "device_proof_failed", points: 70, detail };
  }
}

/**
 * Assess Connect risk for a currently-valid session.
 *
 * `device` carries the already-completed cryptographic device check. It is a
 * required argument rather than an optional one so a caller cannot accidentally
 * score a Connect request without having established device identity at all.
 */
export async function assessConnectRisk(
  session: Session & { user: User },
  requestIp: string,
  requestUserAgent: string,
  device: DeviceContext
): Promise<RiskAssessment> {
  const factors: RiskFactorHit[] = [];

  try {
    // ── Factor 1: device proof outcome (AUTHORITATIVE, §5/§8) ─────────────────
    // Failure to prove possession of the registered private key is the
    // strongest single signal available, and the one an attacker holding only a
    // stolen session cookie cannot produce.
    //
    // But "the proof did not succeed" covers several very different situations,
    // and §5 is explicit that the check "should not unnecessarily interrupt
    // normal employees". Scoring every failure at the terminate-the-session
    // level would log people out for a retried request or an unapproved device,
    // so the reason is graded:
    //
    //   forgery      a bad signature, or a credential belonging to someone else
    //   misdirection a challenge redirected across user, purpose, or issuer
    //   staleness    a consumed or expired nonce — a retry or a stale browser tab
    //   lifecycle    no device, not yet approved, revoked, past its grace period
    //
    // Only the first two indicate an attack. Staleness and lifecycle still
    // refuse Connect — the route requires a valid proof regardless of score —
    // but they must not tear down the employee's Website 1 session.
    if (!device.proofValid) {
      factors.push(deviceFailureFactor(device.reason));
    } else if (
      device.previousCredentialId &&
      device.credentialId &&
      device.previousCredentialId !== device.credentialId
    ) {
      // A valid proof from a *different* credential than this session used
      // before. Legitimate right after a device replacement, so it is a strong
      // signal rather than an automatic denial.
      factors.push({
        name: "device_credential_changed",
        points: 40,
        detail: "Connect presented a different device credential than this session used previously",
      });
    }

    // ── Factor 2: IP change vs. the IP the session was bound to at MFA time ──
    // Telemetry only — never a substitute for device identity (§5/§6).
    if (session.ipAddress !== requestIp) {
      const boundSubnet = subnetOf(session.ipAddress);
      const currentSubnet = subnetOf(requestIp);
      if (boundSubnet && currentSubnet && boundSubnet === currentSubnet) {
        factors.push({
          name: "ip_change_same_subnet",
          points: 5,
          detail: `IP changed within the same /24 (${session.ipAddress} -> ${requestIp})`,
        });
      } else {
        factors.push({
          name: "ip_change_different_subnet",
          points: 10,
          detail: `IP changed to a different subnet (${session.ipAddress} -> ${requestIp})`,
        });
      }
    }

    // ── Factor 3: User-Agent hash mismatch ───────────────────────────────────
    // Weighted deliberately low. Before device binding existed this was the
    // closest available proxy for device identity; now that a real one exists,
    // a spoofable string must not be able to gate Connect (§5).
    //
    // The weight is the smallest that still lets the signal contribute when it
    // stacks with genuine anomalies. It is set so that the two pure-telemetry
    // factors TOGETHER — a different network and a different browser — stay
    // below the MEDIUM threshold on a device that passed its cryptographic
    // proof. An employee travelling and opening a different browser is the
    // ordinary case §5 says must not be interrupted; if that combination gated
    // Connect, the telemetry would effectively be acting as identity again.
    if (session.userAgent !== hashUA(requestUserAgent)) {
      factors.push({
        name: "user_agent_mismatch",
        points: 5,
        detail: "User-Agent fingerprint does not match the one bound at MFA time (telemetry only)",
      });
    }

    // ── Factor 4: Failed MFA attempts in the trailing 24h ────────────────────
    const since24h = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const failedMfaCount = await prisma.auditLog.count({
      where: {
        userId: session.userId,
        stream: "LOGIN",
        eventType: { in: ["MFA_TOTP_FAILED", "STEP_UP_MFA_FAILED"] },
        createdAt: { gte: since24h },
      },
    });
    if (failedMfaCount >= 3) {
      factors.push({
        name: "failed_mfa_high",
        points: 30,
        detail: `${failedMfaCount} failed MFA attempts in the last 24h`,
      });
    } else if (failedMfaCount >= 1) {
      factors.push({
        name: "failed_mfa_low",
        points: 10,
        detail: `${failedMfaCount} failed MFA attempt(s) in the last 24h`,
      });
    }

    // ── Factor 5: MFA-fatigue pattern (§6 "Possible MFA-fatigue behavior") ───
    // A burst of MFA challenges in a short window is the signature of an
    // attacker pushing prompts at an employee until one is approved.
    const since15min = new Date(Date.now() - 15 * 60 * 1000);
    const mfaChallengeCount = await prisma.auditLog.count({
      where: {
        userId: session.userId,
        stream: "LOGIN",
        eventType: { in: ["MFA_CODE_SENT", "STEP_UP_MFA_SENT", "MFA_CHALLENGE_STARTED"] },
        createdAt: { gte: since15min },
      },
    });
    if (mfaChallengeCount >= 5) {
      factors.push({
        name: "mfa_fatigue_pattern",
        points: 35,
        detail: `${mfaChallengeCount} MFA challenges issued in the last 15 minutes`,
      });
    }

    // ── Factor 6: Denied Connect attempts in the trailing 1h ─────────────────
    const since1h = new Date(Date.now() - 60 * 60 * 1000);
    const deniedConnects = await prisma.auditLog.findMany({
      where: {
        userId: session.userId,
        stream: "CONNECT",
        outcome: "DENIED",
        createdAt: { gte: since1h },
      },
      select: { eventType: true },
    });
    const deniedConnectCount = deniedConnects.filter(
      (e) =>
        e.eventType.startsWith("CONNECT_DENIED_") ||
        e.eventType.startsWith("CONNECT_BLOCKED_") ||
        e.eventType === "CONNECT_RATE_LIMITED"
    ).length;
    if (deniedConnectCount >= 3) {
      factors.push({
        name: "denied_connects_high",
        points: 35,
        detail: `${deniedConnectCount} denied Connect attempts in the last hour`,
      });
    } else if (deniedConnectCount >= 1) {
      factors.push({
        name: "denied_connects_low",
        points: 15,
        detail: `${deniedConnectCount} denied Connect attempt(s) in the last hour`,
      });
    }

    // ── Factor 7: Connect velocity in the trailing 5 minutes ─────────────────
    const since5min = new Date(Date.now() - 5 * 60 * 1000);
    const grantedConnectCount = await prisma.auditLog.count({
      where: {
        userId: session.userId,
        stream: "CONNECT",
        eventType: "CONNECT_GRANTED",
        createdAt: { gte: since5min },
      },
    });
    if (grantedConnectCount >= 4) {
      factors.push({
        name: "connect_velocity_high",
        points: 20,
        detail: `${grantedConnectCount} granted Connects in the last 5 minutes`,
      });
    } else if (grantedConnectCount >= 2) {
      factors.push({
        name: "connect_velocity_elevated",
        points: 10,
        detail: `${grantedConnectCount} granted Connects in the last 5 minutes`,
      });
    }

    // ── Factor 8: New session + IP change combo ──────────────────────────────
    // A Connect from a different IP within minutes of session creation can
    // indicate concurrent use of a stolen session/cookie.
    const sessionAgeMs = Date.now() - session.createdAt.getTime();
    if (sessionAgeMs < 5 * 60 * 1000 && session.ipAddress !== requestIp) {
      factors.push({
        name: "new_session_ip_change",
        points: 15,
        detail: "IP changed within 5 minutes of session creation",
      });
    }

    // ── Factor 9: MFA-overridden session (§15) ───────────────────────────────
    // The employee never presented a second factor for this session; an
    // administrator waived it. Connect from such a session is inherently
    // higher risk and §15 requires fresh MFA before it succeeds anyway.
    if (session.mfaOverridden) {
      factors.push({
        name: "mfa_overridden_session",
        points: 25,
        detail: "Session was created through an administrative MFA override",
      });
    }
  } catch (err) {
    // §19: fail closed. No telemetry means no confidence, and no confidence
    // means no Connect.
    return {
      level: "CRITICAL",
      score: 100,
      failedClosed: true,
      factors: [
        {
          name: "assessment_failed",
          points: 100,
          detail: `Risk assessment could not be completed: ${
            err instanceof Error ? err.message : "unknown error"
          }`,
        },
      ],
    };
  }

  const score = factors.reduce((sum, f) => sum + f.points, 0);
  return { level: levelForScore(score), score, factors };
}
