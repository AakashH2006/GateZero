/**
 * __tests__/mini-edr.test.ts
 * Mini EDR Connect risk scoring — website-1-defense.md §5, §6, §7, §19
 *
 * NOTE ON THE WEIGHTING CHANGE
 * ────────────────────────────
 * An earlier version of these tests asserted that a User-Agent mismatch alone
 * scored MEDIUM. That is now deliberately wrong. §5 says device identification
 * "relies on cryptographic device identity, not user-agent string
 * fingerprinting — UA strings are trivially spoofed and must not be treated as
 * a reliable identity signal", and §5 also says ordinary network and browser
 * changes must not log an employee out. With real device binding in place, a
 * spoofable string must no longer be able to reach the threshold that
 * terminates a Connect. The tests below assert the corrected behaviour.
 */

import { describe, it, expect } from "vitest";
import { prisma } from "../lib/db";
import { assessConnectRisk, type DeviceContext } from "../lib/mini-edr";
import { hashUA } from "../lib/authz-service";
import { writeAuditLog } from "../lib/audit";
import { SessionStatus, UserRole, AuditStream } from "@prisma/client";

const BOUND_IP = "10.0.0.5";
const BOUND_UA = "Mozilla/5.0 (bound-device)";
const OTHER_UA = "Mozilla/5.0 (different-device)";

/** A device that successfully proved possession of its registered credential. */
const GOOD_DEVICE: DeviceContext = {
  proofValid: true,
  credentialId: "cred-known",
  previousCredentialId: "cred-known",
};

/** A device that could not prove possession — the strongest single signal (§8). */
const FAILED_DEVICE: DeviceContext = {
  proofValid: false,
  reason: "INVALID_DEVICE_SIGNATURE",
};

async function createTestUser(suffix: string) {
  return prisma.user.create({
    data: {
      idpSubject: `test-idp|mini-edr-${suffix}-${Date.now()}-${Math.random()}`,
      email: `mini-edr-${suffix}-${Date.now()}-${Math.random()}@zerogate.test`,
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
      deviceCredentialId: "cred-known",
    },
    include: { user: true },
  });
}

async function writeAuditEvents(
  userId: string,
  events: {
    stream: AuditStream;
    eventType: string;
    outcome: "SUCCESS" | "FAILURE" | "DENIED";
  }[]
) {
  for (const e of events) {
    await writeAuditLog({
      stream: e.stream,
      eventType: e.eventType,
      userId,
      ipAddress: BOUND_IP,
      userAgent: hashUA(BOUND_UA),
      outcome: e.outcome,
      metadata: {},
    });
  }
}

describe("Mini EDR — baseline", () => {
  it("scores LOW for a clean session on its known device", async () => {
    const user = await createTestUser("clean");
    const session = await createTestSession(user.id);

    const result = await assessConnectRisk(session, BOUND_IP, BOUND_UA, GOOD_DEVICE);

    expect(result.level).toBe("LOW");
    expect(result.score).toBe(0);
    expect(result.factors).toHaveLength(0);
  });
});

describe("Telemetry is not identity (§5, §6)", () => {
  it("a User-Agent change alone does not gate Connect", async () => {
    // The employee switched browsers. Device identity still holds, so this is
    // recorded but must not reach the threshold that blocks and demands MFA.
    const user = await createTestUser("ua-only");
    const session = await createTestSession(user.id);

    const result = await assessConnectRisk(session, BOUND_IP, OTHER_UA, GOOD_DEVICE);

    expect(result.factors.some((f) => f.name === "user_agent_mismatch")).toBe(true);
    expect(result.level).toBe("LOW");
  });

  it("an ordinary network change alone does not gate Connect", async () => {
    const user = await createTestUser("ip-only");
    const sessionRaw = await createTestSession(user.id);
    const session = await prisma.session.update({
      where: { id: sessionRaw.id },
      // Past the "new session" window so that combo factor stays out of it.
      data: { createdAt: new Date(Date.now() - 10 * 60 * 1000) },
      include: { user: true },
    });

    const result = await assessConnectRisk(session, "203.0.113.9", BOUND_UA, GOOD_DEVICE);

    expect(result.level).toBe("LOW");
  });

  it("even both together stay below the gate on a proven device", async () => {
    const user = await createTestUser("ip-and-ua");
    const sessionRaw = await createTestSession(user.id);
    const session = await prisma.session.update({
      where: { id: sessionRaw.id },
      data: { createdAt: new Date(Date.now() - 10 * 60 * 1000) },
      include: { user: true },
    });

    const result = await assessConnectRisk(session, "203.0.113.9", OTHER_UA, GOOD_DEVICE);

    expect(result.level).toBe("LOW");
  });

  it("weighs a same-subnet change below a cross-subnet change", async () => {
    const old = new Date(Date.now() - 10 * 60 * 1000);

    const userA = await createTestUser("subnet-a");
    const rawA = await createTestSession(userA.id);
    const sessionA = await prisma.session.update({
      where: { id: rawA.id },
      data: { createdAt: old },
      include: { user: true },
    });

    const userB = await createTestUser("subnet-b");
    const rawB = await createTestSession(userB.id);
    const sessionB = await prisma.session.update({
      where: { id: rawB.id },
      data: { createdAt: old },
      include: { user: true },
    });

    const sameSubnet = await assessConnectRisk(sessionA, "10.0.0.99", BOUND_UA, GOOD_DEVICE);
    const crossSubnet = await assessConnectRisk(sessionB, "203.0.113.9", BOUND_UA, GOOD_DEVICE);

    expect(sameSubnet.score).toBeLessThan(crossSubnet.score);
  });
});

describe("Device identity is authoritative (§5, §8)", () => {
  it("a failed device proof escalates to CRITICAL on its own", async () => {
    // This is the signal an attacker holding only a stolen session cookie
    // cannot produce, so it carries decisive weight.
    const user = await createTestUser("no-device");
    const session = await createTestSession(user.id);

    const result = await assessConnectRisk(session, BOUND_IP, BOUND_UA, FAILED_DEVICE);

    expect(result.level).toBe("CRITICAL");
    expect(result.factors.some((f) => f.name === "device_proof_failed")).toBe(true);
  });

  it("a stale challenge does not terminate the session", async () => {
    // A retried request or a long-idle tab presents a consumed nonce. Connect
    // is still refused — the route requires a valid proof — but §5 says an
    // ordinary hiccup must not log the employee out.
    const user = await createTestUser("stale-challenge");
    const session = await createTestSession(user.id);

    const result = await assessConnectRisk(session, BOUND_IP, BOUND_UA, {
      proofValid: false,
      reason: "CHALLENGE_ALREADY_USED",
    });

    expect(result.level).not.toBe("CRITICAL");
    expect(result.level).not.toBe("HIGH");
    expect(result.factors.some((f) => f.name === "device_challenge_stale")).toBe(true);
  });

  it("an unenrolled device is an enrolment problem, not an attack", async () => {
    const user = await createTestUser("unenrolled");
    const session = await createTestSession(user.id);

    const result = await assessConnectRisk(session, BOUND_IP, BOUND_UA, {
      proofValid: false,
      reason: "NO_REGISTERED_DEVICE",
    });

    expect(result.level).toBe("LOW");
    expect(result.factors.some((f) => f.name === "device_not_enrolled")).toBe(true);
  });

  it("a misdirected challenge is treated as hostile", async () => {
    const user = await createTestUser("misdirected");
    const session = await createTestSession(user.id);

    const result = await assessConnectRisk(session, BOUND_IP, BOUND_UA, {
      proofValid: false,
      reason: "CHALLENGE_USER_MISMATCH",
    });

    expect(result.level).toBe("CRITICAL");
  });

  it("an unclassified failure reason fails safe as hostile", async () => {
    // Adding a new failure mode without classifying it must not silently
    // downgrade it to benign.
    const user = await createTestUser("unclassified");
    const session = await createTestSession(user.id);

    const result = await assessConnectRisk(session, BOUND_IP, BOUND_UA, {
      proofValid: false,
      reason: "SOME_NEW_REASON_NOBODY_CLASSIFIED",
    });

    expect(result.level).toBe("CRITICAL");
  });

  it("a valid proof from a different credential is a strong but non-fatal signal", async () => {
    // Legitimate immediately after a device replacement, so it gates Connect
    // rather than terminating the session outright.
    const user = await createTestUser("device-changed");
    const sessionRaw = await createTestSession(user.id);
    const session = await prisma.session.update({
      where: { id: sessionRaw.id },
      data: { createdAt: new Date(Date.now() - 10 * 60 * 1000) },
      include: { user: true },
    });

    const result = await assessConnectRisk(session, BOUND_IP, BOUND_UA, {
      proofValid: true,
      credentialId: "cred-new",
      previousCredentialId: "cred-known",
    });

    expect(result.factors.some((f) => f.name === "device_credential_changed")).toBe(true);
    expect(result.level).toBe("MEDIUM");
  });
});

describe("Authentication-history signals (§6, §7)", () => {
  it("repeated failed MFA gates Connect", async () => {
    const user = await createTestUser("failed-mfa");
    const session = await createTestSession(user.id);

    await writeAuditEvents(user.id, [
      { stream: AuditStream.LOGIN, eventType: "MFA_TOTP_FAILED", outcome: "FAILURE" },
      { stream: AuditStream.LOGIN, eventType: "MFA_TOTP_FAILED", outcome: "FAILURE" },
      { stream: AuditStream.LOGIN, eventType: "MFA_TOTP_FAILED", outcome: "FAILURE" },
    ]);

    const result = await assessConnectRisk(session, BOUND_IP, BOUND_UA, GOOD_DEVICE);

    expect(result.factors.some((f) => f.name === "failed_mfa_high")).toBe(true);
    expect(result.level).toBe("MEDIUM");
  });

  it("detects the MFA-fatigue pattern (§6)", async () => {
    const user = await createTestUser("mfa-fatigue");
    const session = await createTestSession(user.id);

    await writeAuditEvents(
      user.id,
      Array.from({ length: 6 }, () => ({
        stream: AuditStream.LOGIN,
        eventType: "MFA_CODE_SENT" as const,
        outcome: "SUCCESS" as const,
      }))
    );

    const result = await assessConnectRisk(session, BOUND_IP, BOUND_UA, GOOD_DEVICE);

    expect(result.factors.some((f) => f.name === "mfa_fatigue_pattern")).toBe(true);
    expect(result.level).toBe("MEDIUM");
  });

  it("escalates to HIGH when authentication failures stack with denied Connects", async () => {
    const user = await createTestUser("stacked");
    const session = await createTestSession(user.id);

    await writeAuditEvents(user.id, [
      { stream: AuditStream.LOGIN, eventType: "MFA_TOTP_FAILED", outcome: "FAILURE" },
      { stream: AuditStream.LOGIN, eventType: "MFA_TOTP_FAILED", outcome: "FAILURE" },
      { stream: AuditStream.LOGIN, eventType: "MFA_TOTP_FAILED", outcome: "FAILURE" },
      { stream: AuditStream.CONNECT, eventType: "CONNECT_DENIED_CSRF", outcome: "DENIED" },
      { stream: AuditStream.CONNECT, eventType: "CONNECT_DENIED_CSRF", outcome: "DENIED" },
      { stream: AuditStream.CONNECT, eventType: "CONNECT_DENIED_CSRF", outcome: "DENIED" },
    ]);

    const result = await assessConnectRisk(session, BOUND_IP, BOUND_UA, GOOD_DEVICE);

    expect(result.level).toBe("HIGH");
    expect(result.score).toBeGreaterThanOrEqual(45);
  });

  it("treats an MFA-overridden session as elevated risk (§15)", async () => {
    const user = await createTestUser("overridden");
    const sessionRaw = await createTestSession(user.id);
    const session = await prisma.session.update({
      where: { id: sessionRaw.id },
      data: { mfaOverridden: true, mfaOverrideAdminId: "admin-1" },
      include: { user: true },
    });

    const result = await assessConnectRisk(session, BOUND_IP, BOUND_UA, GOOD_DEVICE);

    expect(result.factors.some((f) => f.name === "mfa_overridden_session")).toBe(true);
    expect(result.level).toBe("MEDIUM");
  });
});

describe("Fail-closed behaviour (§19)", () => {
  it("returns CRITICAL rather than LOW when telemetry cannot be read", async () => {
    // A risk engine that cannot see must not answer "looks fine".
    const user = await createTestUser("fail-closed");
    const session = await createTestSession(user.id);

    // A session object whose createdAt is unusable makes the scoring path throw.
    const broken = {
      ...session,
      createdAt: null as unknown as Date,
    };

    const result = await assessConnectRisk(broken, BOUND_IP, BOUND_UA, GOOD_DEVICE);

    expect(result.level).toBe("CRITICAL");
    expect(result.failedClosed).toBe(true);
    expect(result.factors.some((f) => f.name === "assessment_failed")).toBe(true);
  });
});

describe("Session defaults", () => {
  it("new sessions are not pre-gated", async () => {
    const user = await createTestUser("step-up-default");
    const session = await createTestSession(user.id);

    expect(session.connectStepUpRequired).toBe(false);
    expect(session.mfaOverridden).toBe(false);
  });
});
