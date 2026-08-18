/**
 * lib/mini-edr/index.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Mini EDR — risk scoring for Connect requests (website-1-defense.md §6-7)
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * Scope: Login, MFA, and Connect events only. No endpoint/process/file
 * monitoring — this is explicitly out of scope per §6.
 *
 * This module only COMPUTES a risk assessment. It does not revoke sessions,
 * block requests, or write audit logs itself — the caller (the Connect route)
 * is responsible for acting on the returned assessment. That keeps this
 * module a pure, independently-testable scoring function.
 *
 * Thresholds and point values are intentionally tunable (see §7, §20) — the
 * spec leaves exact numbers to implementation/testing rather than locking them.
 *
 * NOTE on error handling: this pass does not yet implement explicit
 * fail-closed behavior (deliberate denial + audit on telemetry-query
 * failure). If a query below throws, the exception propagates to the
 * Connect route's `safeHandler`, which returns a generic 500 — Connect is
 * NOT granted in that case, but there is no structured "assessment failed"
 * audit entry yet. That is the next approved change, not part of this pass.
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
 * Assess Connect risk for a currently-valid session.
 * Pure function over DB state — does not mutate session/audit records.
 */
export async function assessConnectRisk(
  session: Session & { user: User },
  requestIp: string,
  requestUserAgent: string
): Promise<RiskAssessment> {
  const factors: RiskFactorHit[] = [];

  // ── Factor 1: IP change vs. the IP the session was bound to at MFA time ──
  // Telemetry only — never a substitute for device identity (§5/§6).
  if (session.ipAddress !== requestIp) {
    const boundSubnet = subnetOf(session.ipAddress);
    const currentSubnet = subnetOf(requestIp);
    if (boundSubnet && currentSubnet && boundSubnet === currentSubnet) {
      factors.push({
        name: "ip_change_same_subnet",
        points: 10,
        detail: `IP changed within the same /24 (${session.ipAddress} -> ${requestIp})`,
      });
    } else {
      factors.push({
        name: "ip_change_different_subnet",
        points: 20,
        detail: `IP changed to a different subnet (${session.ipAddress} -> ${requestIp})`,
      });
    }
  }

  // ── Factor 2: User-Agent hash mismatch vs. the UA the session was bound to ──
  // Closest available proxy for device identity until §8 (cryptographic
  // device binding) lands. Once §8 exists, this factor should be
  // supplemented/replaced by the real device-key check, not relied on alone.
  const currentUaHash = hashUA(requestUserAgent);
  const uaChanged = session.userAgent !== currentUaHash;
  if (uaChanged) {
    factors.push({
      name: "user_agent_mismatch",
      points: 25,
      detail: "User-Agent fingerprint does not match the one bound at MFA time",
    });
  }

  // ── Factor 3: Failed MFA attempts in the trailing 24h ──
  const since24h = new Date(Date.now() - 24 * 60 * 60 * 1000);
  const failedMfaCount = await prisma.auditLog.count({
    where: {
      userId: session.userId,
      stream: "LOGIN",
      eventType: "MFA_TOTP_FAILED",
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

  // ── Factor 4: Denied Connect attempts in the trailing 1h ──
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

  // ── Factor 5: Connect velocity in the trailing 5 minutes ──
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

  // ── Factor 6: New session + IP change combo ──
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

  const score = factors.reduce((sum, f) => sum + f.points, 0);
  const level = levelForScore(score);

  return { level, score, factors };
}
