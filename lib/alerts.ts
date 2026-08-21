/**
 * lib/alerts.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * SECURITY ALERT MANAGEMENT
 * website-1-defense.md §20 "Risk detection should not generate unbounded alerts"
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * Raising an alert per detection produces alert fatigue, and alert fatigue is
 * how real detections get ignored. This module sits between the detection
 * layers and the alert stream and applies:
 *
 *   - Deduplication. Repeated identical detections inside a correlation window
 *     collapse into the first alert, which records how many times the pattern
 *     recurred rather than firing again.
 *   - Severity gating. Only detections at or above the configured floor become
 *     alerts; everything else still lands in the audit trail, which is where
 *     tuning review reads from.
 *
 * Alerts are written to the audit store as severity-tagged entries rather than
 * dispatched to an external pager. `dispatchExternalAlert()` is the named seam
 * where a real SIEM/pager integration attaches — deliberately a stub, because
 * choosing and configuring that sink is a deployment decision.
 */

import { prisma } from "./db";
import { writeAuditLog, type AuditSeverity } from "./audit";
import { AuditStream } from "@prisma/client";

/** Detections below this severity are recorded but never alerted on. */
const ALERT_SEVERITY_FLOOR: AuditSeverity = "HIGH";

const SEVERITY_ORDER: Record<AuditSeverity, number> = {
  INFO: 0,
  NOTICE: 1,
  WARNING: 2,
  HIGH: 3,
  CRITICAL: 4,
};

/** How long an identical detection is folded into the existing alert. */
const DEDUP_WINDOW_MS = 10 * 60 * 1000;

export interface AlertParams {
  /** Stable identity of the *pattern*, e.g. "connect_risk:HIGH". Drives dedup. */
  alertKey: string;
  severity: AuditSeverity;
  userId?: string;
  sessionId?: string;
  ipAddress: string;
  userAgent: string;
  stream?: AuditStream;
  metadata?: Record<string, unknown>;
}

export interface AlertResult {
  raised: boolean;
  /** True when the detection was folded into an alert already in flight. */
  deduplicated: boolean;
}

/**
 * External dispatch seam (pager / SIEM / chat).
 *
 * Intentionally not implemented: the alert is durable in the audit store either
 * way, and a half-built integration that silently drops pages is worse than an
 * explicit stub.
 */
async function dispatchExternalAlert(params: AlertParams): Promise<void> {
  console.warn(
    `[SECURITY_ALERT] severity=${params.severity} key=${params.alertKey} user=${params.userId ?? "-"}`
  );
}

/**
 * Raise a security alert, subject to severity gating and deduplication.
 *
 * Correlation is scoped per user: the same pattern hitting two different
 * employees is two distinct incidents and both deserve an alert.
 */
export async function raiseSecurityAlert(params: AlertParams): Promise<AlertResult> {
  if (SEVERITY_ORDER[params.severity] < SEVERITY_ORDER[ALERT_SEVERITY_FLOOR]) {
    return { raised: false, deduplicated: false };
  }

  const since = new Date(Date.now() - DEDUP_WINDOW_MS);

  const recent = await prisma.auditLog
    .findMany({
      where: {
        eventType: "SECURITY_ALERT",
        userId: params.userId ?? null,
        createdAt: { gte: since },
      },
      orderBy: { createdAt: "desc" },
      take: 25,
      select: { metadata: true },
    })
    .catch(() => []);

  const duplicate = recent.some((entry) => {
    try {
      return (JSON.parse(entry.metadata) as { alertKey?: string }).alertKey === params.alertKey;
    } catch {
      return false;
    }
  });

  if (duplicate) {
    // The correlated occurrence is still recorded — suppressed alerts must not
    // become invisible, or tuning review has nothing to tune against (§20).
    await writeAuditLog({
      stream: params.stream ?? AuditStream.CONNECT,
      eventType: "SECURITY_ALERT_SUPPRESSED",
      userId: params.userId,
      sessionId: params.sessionId,
      ipAddress: params.ipAddress,
      userAgent: params.userAgent,
      outcome: "DENIED",
      severity: params.severity,
      metadata: { alertKey: params.alertKey, reason: "DEDUPLICATED", ...params.metadata },
    });
    return { raised: false, deduplicated: true };
  }

  await writeAuditLog({
    stream: params.stream ?? AuditStream.CONNECT,
    eventType: "SECURITY_ALERT",
    userId: params.userId,
    sessionId: params.sessionId,
    ipAddress: params.ipAddress,
    userAgent: params.userAgent,
    outcome: "DENIED",
    severity: params.severity,
    metadata: { alertKey: params.alertKey, ...params.metadata },
  });

  await dispatchExternalAlert(params).catch(() => {});

  return { raised: true, deduplicated: false };
}
