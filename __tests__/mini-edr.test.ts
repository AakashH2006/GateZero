/**
 * __tests__/mini-edr.test.ts
 * Tests for Mini EDR Connect risk scoring (website-1-defense.md §6-7).
 *
 * Covers:
 *   1. Clean session (same IP/UA, no history) scores LOW
 *   2. UA mismatch alone scores MEDIUM
 *   3. Repeated failed MFA + UA mismatch escalates to HIGH
 *   4. Stacked signals (failed MFA + denied connects + UA mismatch + IP change) reach CRITICAL
 *   5. IP change within the same /24 scores lower than a cross-subnet change
 *   6. connectStepUpRequired defaults to false on new sessions
 */

import { describe, it, expect } from "vitest";
import { prisma } from "../lib/db";
import { assessConnectRisk } from "../lib/mini-edr";
import { hashUA } from "../lib/authz-service";
import { SessionStatus, UserRole } from "@prisma/client";

const BOUND_IP = "10.0.0.5";
const BOUND_UA = "Mozilla/5.0 (bound-device)";

async function createTestUser(suffix: string) {
  return prisma.user.create({
    data: {
      idpSubject: `test-idp|mini-edr-${suffix}-${Date.now()}`,
      email: `mini-edr-${suffix}-${Date.now()}@zerogate.test`,
      name: `Mini EDR Test ${suffix}`,
      role: UserRole.EMPLOYEE,
    },
  });
}

async function createTestSession(userId: string) {
  return prisma.session.create({
    data: {
      userId,
      status: SessionStatus.ACTIVE,
      ipAddress: BOUND_IP,
      userAgent: hashUA(BOUND_UA),
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    },
    include: { user: true },
  });
}

async function writeAuditEvents(
  userId: string,
  events: { stream: "LOGIN" | "CONNECT"; eventType: string; outcome: "SUCCESS" | "FAILURE" | "DENIED" }[]
) {
  for (const e of events) {
    await prisma.auditLog.create({
      data: {
        stream: e.stream,
        eventType: e.eventType,
        userId,
        ipAddress: BOUND_IP,
        userAgent: hashUA(BOUND_UA),
        outcome: e.outcome,
        metadata: "{}",
      },
    });
  }
}

describe("Mini EDR — assessConnectRisk", () => {
  it("scores LOW for a clean session with matching IP/UA and no history", async () => {
    const user = await createTestUser("clean");
    const session = await createTestSession(user.id);

    const result = await assessConnectRisk(session, BOUND_IP, BOUND_UA);

    expect(result.level).toBe("LOW");
    expect(result.score).toBe(0);
    expect(result.factors).toHaveLength(0);
  });

  it("scores MEDIUM for a User-Agent mismatch alone", async () => {
    const user = await createTestUser("ua-mismatch");
    const session = await createTestSession(user.id);

    const result = await assessConnectRisk(session, BOUND_IP, "Mozilla/5.0 (different-device)");

    expect(result.level).toBe("MEDIUM");
    expect(result.factors.some((f) => f.name === "user_agent_mismatch")).toBe(true);
  });

  it("scores HIGH when repeated failed MFA stacks with a UA mismatch", async () => {
    const user = await createTestUser("high-risk");
    const session = await createTestSession(user.id);

    await writeAuditEvents(user.id, [
      { stream: "LOGIN", eventType: "MFA_TOTP_FAILED", outcome: "FAILURE" },
      { stream: "LOGIN", eventType: "MFA_TOTP_FAILED", outcome: "FAILURE" },
      { stream: "LOGIN", eventType: "MFA_TOTP_FAILED", outcome: "FAILURE" },
    ]);

    const result = await assessConnectRisk(session, BOUND_IP, "Mozilla/5.0 (different-device)");

    expect(result.level).toBe("HIGH");
    expect(result.score).toBeGreaterThanOrEqual(45);
    expect(result.score).toBeLessThan(70);
  });

  it("scores CRITICAL when signals stack heavily", async () => {
    const user = await createTestUser("critical-risk");
    const session = await createTestSession(user.id);

    await writeAuditEvents(user.id, [
      { stream: "LOGIN", eventType: "MFA_TOTP_FAILED", outcome: "FAILURE" },
      { stream: "LOGIN", eventType: "MFA_TOTP_FAILED", outcome: "FAILURE" },
      { stream: "LOGIN", eventType: "MFA_TOTP_FAILED", outcome: "FAILURE" },
      { stream: "CONNECT", eventType: "CONNECT_DENIED_CSRF", outcome: "DENIED" },
      { stream: "CONNECT", eventType: "CONNECT_DENIED_CSRF", outcome: "DENIED" },
      { stream: "CONNECT", eventType: "CONNECT_DENIED_CSRF", outcome: "DENIED" },
    ]);

    // Different subnet entirely (not just a different host on the bound /24)
    const result = await assessConnectRisk(session, "203.0.113.9", "Mozilla/5.0 (different-device)");

    expect(result.level).toBe("CRITICAL");
    expect(result.score).toBeGreaterThanOrEqual(70);
  });

  it("weighs a same-subnet IP change lower than a cross-subnet change", async () => {
    // Backdate createdAt past the 5-minute "new session" window so the
    // new_session_ip_change combo factor doesn't contaminate this
    // comparison — isolates factor 1 (IP subnet change) on its own.
    const old = new Date(Date.now() - 10 * 60 * 1000);

    const userA = await createTestUser("subnet-a");
    const sessionARaw = await createTestSession(userA.id);
    const sessionA = await prisma.session.update({
      where: { id: sessionARaw.id },
      data: { createdAt: old },
      include: { user: true },
    });
    const sameSubnetResult = await assessConnectRisk(sessionA, "10.0.0.99", BOUND_UA);

    const userB = await createTestUser("subnet-b");
    const sessionBRaw = await createTestSession(userB.id);
    const sessionB = await prisma.session.update({
      where: { id: sessionBRaw.id },
      data: { createdAt: old },
      include: { user: true },
    });
    const diffSubnetResult = await assessConnectRisk(sessionB, "203.0.113.9", BOUND_UA);

    expect(sameSubnetResult.score).toBeLessThan(diffSubnetResult.score);
    expect(sameSubnetResult.level).toBe("LOW");
    expect(diffSubnetResult.level).toBe("MEDIUM");
  });

  it("new sessions default to connectStepUpRequired = false", async () => {
    const user = await createTestUser("step-up-default");
    const session = await createTestSession(user.id);

    expect(session.connectStepUpRequired).toBe(false);
  });
});
