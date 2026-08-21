/**
 * __tests__/admin-controls.test.ts
 * Administrative controls and emergency access
 * website-1-defense.md §13-§17 / website-2-defense.md §27-§31
 *
 * The two mechanisms most worth pinning down: a step-up grant that authorizes
 * exactly one action, and an emergency path that cannot be opened by the
 * component it bypasses.
 */

import { describe, it, expect, beforeEach } from "vitest";
import { prisma } from "../lib/db";
import { issueStepUp, consumeStepUp, expireStaleStepUps } from "../lib/admin-stepup";
import {
  recordProbe,
  checkEmergencyEligibility,
  recordHumanConfirmation,
  getHealth,
} from "../lib/health";
import { HEALTH_FAILURE_THRESHOLD, HEALTH_MIN_OUTAGE_MS } from "../lib/config";

const ADMIN = "admin-user-1";
const OTHER_ADMIN = "admin-user-2";

async function resetHealth(component: "website-1" | "gateway" = "website-1") {
  await prisma.componentHealth.deleteMany({ where: { component } });
}

describe("Admin step-up grants (§14)", () => {
  it("authorizes exactly one action", async () => {
    const grant = await issueStepUp({
      adminUserId: ADMIN,
      action: "REVOKE_SESSION",
      reason: "investigating a report",
    });

    const first = await consumeStepUp({
      stepUpId: grant.id,
      adminUserId: ADMIN,
      action: "REVOKE_SESSION",
    });
    const second = await consumeStepUp({
      stepUpId: grant.id,
      adminUserId: ADMIN,
      action: "REVOKE_SESSION",
    });

    expect(first.ok).toBe(true);
    expect(second.ok).toBe(false);
    expect(second.reason).toBe("STEP_UP_ALREADY_USED");
  });

  it("cannot be spent on a different action than it was issued for", async () => {
    // Without this binding, a re-auth obtained for something benign would be a
    // blank cheque for whatever the attacker actually wanted.
    const grant = await issueStepUp({
      adminUserId: ADMIN,
      action: "REVOKE_SESSION",
      reason: "routine",
    });

    const result = await consumeStepUp({
      stepUpId: grant.id,
      adminUserId: ADMIN,
      action: "MFA_OVERRIDE",
    });

    expect(result.ok).toBe(false);
    expect(result.reason).toBe("STEP_UP_ACTION_MISMATCH");
  });

  it("cannot be redirected at a different employee", async () => {
    const grant = await issueStepUp({
      adminUserId: ADMIN,
      action: "MFA_OVERRIDE",
      targetUserId: "employee-a",
      reason: "lost phone",
    });

    const result = await consumeStepUp({
      stepUpId: grant.id,
      adminUserId: ADMIN,
      action: "MFA_OVERRIDE",
      targetUserId: "employee-b",
    });

    expect(result.ok).toBe(false);
    expect(result.reason).toBe("STEP_UP_TARGET_MISMATCH");
  });

  it("cannot be spent by a different administrator", async () => {
    const grant = await issueStepUp({
      adminUserId: ADMIN,
      action: "REVOKE_DEVICE",
      reason: "reported stolen",
    });

    const result = await consumeStepUp({
      stepUpId: grant.id,
      adminUserId: OTHER_ADMIN,
      action: "REVOKE_DEVICE",
    });

    expect(result.ok).toBe(false);
    expect(result.reason).toBe("STEP_UP_ADMIN_MISMATCH");
  });

  it("expires, so an unspent grant is not a standing privilege", async () => {
    const grant = await issueStepUp({
      adminUserId: ADMIN,
      action: "EMERGENCY_CONNECT",
      reason: "outage",
    });

    await prisma.adminStepUp.update({
      where: { id: grant.id },
      data: { expiresAt: new Date(Date.now() - 1000) },
    });

    const result = await consumeStepUp({
      stepUpId: grant.id,
      adminUserId: ADMIN,
      action: "EMERGENCY_CONNECT",
    });

    expect(result.ok).toBe(false);
    expect(result.reason).toBe("STEP_UP_EXPIRED");
  });

  it("only one of two concurrent spends wins", async () => {
    const grant = await issueStepUp({
      adminUserId: ADMIN,
      action: "TERMINATE_W2_SESSION",
      reason: "concurrent",
    });

    const results = await Promise.all([
      consumeStepUp({ stepUpId: grant.id, adminUserId: ADMIN, action: "TERMINATE_W2_SESSION" }),
      consumeStepUp({ stepUpId: grant.id, adminUserId: ADMIN, action: "TERMINATE_W2_SESSION" }),
    ]);

    expect(results.filter((r) => r.ok)).toHaveLength(1);
  });

  it("sweeping marks expired unspent grants", async () => {
    const grant = await issueStepUp({
      adminUserId: ADMIN,
      action: "APPROVE_DEVICE",
      reason: "sweep",
    });

    await prisma.adminStepUp.update({
      where: { id: grant.id },
      data: { expiresAt: new Date(Date.now() - 1000) },
    });

    await expireStaleStepUps();

    const record = await prisma.adminStepUp.findUnique({ where: { id: grant.id } });
    expect(record?.status).toBe("EXPIRED");
  });
});

describe("Trusted outage detection (§16, §27)", () => {
  beforeEach(async () => {
    await resetHealth();
  });

  it("a single failed probe does not confirm an outage", async () => {
    const state = await recordProbe({ component: "website-1", healthy: false });

    expect(state).toBe("DEGRADED");

    const eligibility = await checkEmergencyEligibility("website-1");
    expect(eligibility.eligible).toBe(false);
    expect(eligibility.reason).toBe("NO_CONFIRMED_OUTAGE");
  });

  it("repeated failures alone do not confirm without sustained duration", async () => {
    // The duration floor is what stops a burst of fast probes tripping the
    // count within a second or two.
    const start = new Date();
    for (let i = 0; i < HEALTH_FAILURE_THRESHOLD + 2; i++) {
      await recordProbe({ component: "website-1", healthy: false, now: start });
    }

    const health = await getHealth("website-1");
    expect(health?.state).toBe("DEGRADED");
  });

  it("confirms once failures are both repeated and sustained", async () => {
    const start = new Date();

    for (let i = 0; i < HEALTH_FAILURE_THRESHOLD - 1; i++) {
      await recordProbe({ component: "website-1", healthy: false, now: start });
    }

    const later = new Date(start.getTime() + HEALTH_MIN_OUTAGE_MS + 1000);
    const state = await recordProbe({ component: "website-1", healthy: false, now: later });

    expect(state).toBe("CONFIRMED_OUTAGE");
  });

  it("a confirmed outage still requires explicit human confirmation (§27)", async () => {
    const start = new Date();
    for (let i = 0; i < HEALTH_FAILURE_THRESHOLD - 1; i++) {
      await recordProbe({ component: "website-1", healthy: false, now: start });
    }
    await recordProbe({
      component: "website-1",
      healthy: false,
      now: new Date(start.getTime() + HEALTH_MIN_OUTAGE_MS + 1000),
    });

    const beforeConfirmation = await checkEmergencyEligibility("website-1");
    expect(beforeConfirmation.eligible).toBe(false);
    expect(beforeConfirmation.reason).toBe("HUMAN_CONFIRMATION_REQUIRED");

    await recordHumanConfirmation({ component: "website-1", adminUserId: ADMIN });

    const afterConfirmation = await checkEmergencyEligibility("website-1");
    expect(afterConfirmation.eligible).toBe(true);
    expect(afterConfirmation.humanConfirmed).toBe(true);
  });

  it("an administrator cannot confirm an outage that was never detected", async () => {
    const result = await recordHumanConfirmation({
      component: "website-1",
      adminUserId: ADMIN,
    });

    expect(result.ok).toBe(false);
    expect(result.reason).toBe("NO_CONFIRMED_OUTAGE");
  });

  it("an expired human confirmation stops being sufficient", async () => {
    const start = new Date();
    for (let i = 0; i < HEALTH_FAILURE_THRESHOLD - 1; i++) {
      await recordProbe({ component: "website-1", healthy: false, now: start });
    }
    await recordProbe({
      component: "website-1",
      healthy: false,
      now: new Date(start.getTime() + HEALTH_MIN_OUTAGE_MS + 1000),
    });
    await recordHumanConfirmation({ component: "website-1", adminUserId: ADMIN });

    await prisma.componentHealth.update({
      where: { component: "website-1" },
      data: { humanConfirmExpiresAt: new Date(Date.now() - 1000) },
    });

    const eligibility = await checkEmergencyEligibility("website-1");
    expect(eligibility.eligible).toBe(false);
    expect(eligibility.reason).toBe("HUMAN_CONFIRMATION_EXPIRED");
  });

  it("recovery closes the emergency path and voids the confirmation (§17)", async () => {
    const start = new Date();
    for (let i = 0; i < HEALTH_FAILURE_THRESHOLD - 1; i++) {
      await recordProbe({ component: "website-1", healthy: false, now: start });
    }
    await recordProbe({
      component: "website-1",
      healthy: false,
      now: new Date(start.getTime() + HEALTH_MIN_OUTAGE_MS + 1000),
    });
    await recordHumanConfirmation({ component: "website-1", adminUserId: ADMIN });

    expect((await checkEmergencyEligibility("website-1")).eligible).toBe(true);

    await recordProbe({ component: "website-1", healthy: true });

    const eligibility = await checkEmergencyEligibility("website-1");
    expect(eligibility.eligible).toBe(false);
    expect(eligibility.state).toBe("HEALTHY");

    const health = await getHealth("website-1");
    expect(health?.humanConfirmedAt).toBeNull();
    expect(health?.confirmedOutageAt).toBeNull();
  });

  it("a component with no health record is treated as healthy, not as an outage", async () => {
    // Defaulting the other way would leave emergency access open on a fresh
    // install, before the monitor has ever run.
    //
    // The precondition is "no record", so clear it explicitly rather than
    // assuming the seeded database has none — a real monitor run leaves rows
    // behind, and a test that depends on ambient state is not a test.
    await resetHealth("gateway");

    const eligibility = await checkEmergencyEligibility("gateway");
    expect(eligibility.eligible).toBe(false);
    expect(eligibility.state).toBe("HEALTHY");
  });
});
