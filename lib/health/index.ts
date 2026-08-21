/**
 * lib/health/index.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * TRUSTED OUTAGE DETECTION
 * website-1-defense.md §16, §17 / website-2-defense.md §27, §28
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * The emergency path is the most dangerous mechanism in the system: it issues
 * Gateway authorization while the normal checks are unavailable. Everything
 * here exists to make sure it cannot be opened by the component it bypasses.
 *
 * THE CENTRAL RULE (§16)
 * ──────────────────────
 * "Website 1 must never be able to declare itself unavailable."
 *
 * Enforced structurally, not by convention: `recordProbe()` — the only function
 * that writes health state — is called exclusively from the out-of-process
 * monitor (`scripts/health-monitor.ts`). No route handler imports it, and no
 * API endpoint can set health state. A fully compromised Website 1 request path
 * still cannot mark Website 1 down.
 *
 * THREE INDEPENDENT GATES
 * ───────────────────────
 * Emergency access requires all three, in order:
 *
 *   1. Sustained failure. `HEALTH_FAILURE_THRESHOLD` consecutive failed probes
 *      AND `HEALTH_MIN_OUTAGE_MS` elapsed since the first one. A single failed
 *      check must never open emergency access (§16); the duration floor closes
 *      the gap where a burst of fast probes trips the count in a second or two.
 *
 *   2. Explicit human confirmation (§27, and W1 §23's open item on
 *      attacker-induced outages). Automated detection only makes the path
 *      *available*. An administrator must confirm the outage, that confirmation
 *      expires, and it is recorded against their identity. An attacker who can
 *      sustain a denial-of-service still has to get a human to agree.
 *
 *   3. Fresh administrator re-authentication per action (§14), enforced by the
 *      caller through lib/admin-stepup.
 *
 * Recovery is automatic and one-sided: the first successful probe clears the
 * outage and voids any human confirmation, so the window closes the moment
 * Website 1 is healthy again (§17).
 */

import { prisma } from "../db";
import {
  HEALTH_FAILURE_THRESHOLD,
  HEALTH_MIN_OUTAGE_MS,
  HEALTH_HUMAN_CONFIRM_TTL_MS,
} from "../config";

export type ComponentName = "website-1" | "gateway";
export type HealthState = "HEALTHY" | "DEGRADED" | "CONFIRMED_OUTAGE";

export interface EmergencyEligibility {
  eligible: boolean;
  state: HealthState;
  humanConfirmed: boolean;
  reason?: string;
}

// ── Writes: monitor process only ──────────────────────────────────────────────

/**
 * Record one probe result and advance the state machine.
 *
 * MUST NOT be called from any request handler — see the header. The monitor
 * process owns this function.
 */
export async function recordProbe(params: {
  component: ComponentName;
  healthy: boolean;
  now?: Date;
}): Promise<HealthState> {
  const now = params.now ?? new Date();

  const existing = await prisma.componentHealth.findUnique({
    where: { component: params.component },
  });

  if (params.healthy) {
    // Recovery clears the human confirmation as well. A confirmation given
    // during an outage must not stay spendable once service is restored (§17).
    const updated = await prisma.componentHealth.upsert({
      where: { component: params.component },
      create: {
        component: params.component,
        state: "HEALTHY",
        consecutiveSuccesses: 1,
        lastCheckAt: now,
        lastSuccessAt: now,
      },
      update: {
        state: "HEALTHY",
        consecutiveFailures: 0,
        consecutiveSuccesses: { increment: 1 },
        lastCheckAt: now,
        lastSuccessAt: now,
        firstFailureAt: null,
        confirmedOutageAt: null,
        humanConfirmedByAdminId: null,
        humanConfirmedAt: null,
        humanConfirmExpiresAt: null,
      },
    });
    return updated.state as HealthState;
  }

  const failures = (existing?.consecutiveFailures ?? 0) + 1;
  const firstFailureAt = existing?.firstFailureAt ?? now;
  const sustainedFor = now.getTime() - firstFailureAt.getTime();

  // Both gates: enough consecutive failures AND enough elapsed time.
  const confirmed =
    failures >= HEALTH_FAILURE_THRESHOLD && sustainedFor >= HEALTH_MIN_OUTAGE_MS;

  const state: HealthState = confirmed ? "CONFIRMED_OUTAGE" : "DEGRADED";

  const updated = await prisma.componentHealth.upsert({
    where: { component: params.component },
    create: {
      component: params.component,
      state,
      consecutiveFailures: failures,
      consecutiveSuccesses: 0,
      lastCheckAt: now,
      firstFailureAt,
      confirmedOutageAt: confirmed ? now : null,
    },
    update: {
      state,
      consecutiveFailures: failures,
      consecutiveSuccesses: 0,
      lastCheckAt: now,
      firstFailureAt,
      confirmedOutageAt: confirmed ? (existing?.confirmedOutageAt ?? now) : null,
    },
  });

  return updated.state as HealthState;
}

// ── Reads: safe from anywhere ─────────────────────────────────────────────────

export async function getHealth(component: ComponentName) {
  return prisma.componentHealth.findUnique({ where: { component } });
}

export async function getAllHealth() {
  return prisma.componentHealth.findMany();
}

/**
 * Whether the emergency path may be *offered* — automated gate only.
 *
 * A component with no health record at all is treated as HEALTHY: absence of
 * evidence is not evidence of an outage, and defaulting the other way would
 * mean emergency access is available on a fresh install.
 */
export async function isOutageConfirmed(component: ComponentName): Promise<boolean> {
  const health = await getHealth(component);
  return health?.state === "CONFIRMED_OUTAGE";
}

/** Record an administrator's explicit confirmation of a detected outage (§27). */
export async function recordHumanConfirmation(params: {
  component: ComponentName;
  adminUserId: string;
  now?: Date;
}): Promise<{ ok: boolean; reason?: string; expiresAt?: Date }> {
  const now = params.now ?? new Date();
  const health = await getHealth(params.component);

  // The administrator confirms a *detected* outage; they cannot declare one.
  if (!health || health.state !== "CONFIRMED_OUTAGE") {
    return { ok: false, reason: "NO_CONFIRMED_OUTAGE" };
  }

  const expiresAt = new Date(now.getTime() + HEALTH_HUMAN_CONFIRM_TTL_MS);

  await prisma.componentHealth.update({
    where: { component: params.component },
    data: {
      humanConfirmedByAdminId: params.adminUserId,
      humanConfirmedAt: now,
      humanConfirmExpiresAt: expiresAt,
    },
  });

  return { ok: true, expiresAt };
}

/**
 * Full eligibility check for emergency access: automated detection AND an
 * unexpired human confirmation. Callers must additionally require a fresh admin
 * step-up grant (§14) before acting.
 */
export async function checkEmergencyEligibility(
  component: ComponentName = "website-1",
  now: Date = new Date()
): Promise<EmergencyEligibility> {
  const health = await getHealth(component);

  if (!health || health.state !== "CONFIRMED_OUTAGE") {
    return {
      eligible: false,
      state: (health?.state as HealthState) ?? "HEALTHY",
      humanConfirmed: false,
      reason: "NO_CONFIRMED_OUTAGE",
    };
  }

  if (!health.humanConfirmedAt || !health.humanConfirmExpiresAt) {
    return {
      eligible: false,
      state: "CONFIRMED_OUTAGE",
      humanConfirmed: false,
      reason: "HUMAN_CONFIRMATION_REQUIRED",
    };
  }

  if (health.humanConfirmExpiresAt < now) {
    return {
      eligible: false,
      state: "CONFIRMED_OUTAGE",
      humanConfirmed: false,
      reason: "HUMAN_CONFIRMATION_EXPIRED",
    };
  }

  return { eligible: true, state: "CONFIRMED_OUTAGE", humanConfirmed: true };
}
