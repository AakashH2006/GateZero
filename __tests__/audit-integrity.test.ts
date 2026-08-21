/**
 * __tests__/audit-integrity.test.ts
 * Audit trail — website-1-defense.md §11, §20
 *
 * §11 requires two things of the log: that secrets never enter it, and that
 * unauthorized modification is detectable. Both are tested here, including the
 * negative case — tampering must actually break verification, or the chain is
 * decoration.
 */

import { describe, it, expect } from "vitest";
import { prisma } from "../lib/db";
import { writeAuditLog, verifyAuditChain, redactMetadata } from "../lib/audit";
import { raiseSecurityAlert } from "../lib/alerts";
import { AuditStream, UserRole } from "@prisma/client";

async function createUser(suffix: string) {
  return prisma.user.create({
    data: {
      idpSubject: `test-idp|audit-${suffix}-${Date.now()}-${Math.random()}`,
      email: `audit-${suffix}-${Date.now()}-${Math.random()}@zerogate.test`,
      name: `Audit Test ${suffix}`,
      role: UserRole.EMPLOYEE,
    },
  });
}

describe("Secret redaction (§11)", () => {
  it("redacts values under sensitive key names", () => {
    const redacted = redactMetadata({
      password: "hunter2",
      sessionToken: "abc123",
      mfaSecret: "JBSWY3DPEHPK3PXP",
      signature: "deadbeef",
      privateKey: "-----BEGIN EC PRIVATE KEY-----",
      nonce: "abcdef",
    }) as Record<string, unknown>;

    for (const value of Object.values(redacted)) {
      expect(value).toBe("[REDACTED]");
    }
  });

  it("keeps opaque identifiers that only look sensitive", () => {
    // These are lookup handles, not credentials — redacting them would make the
    // trail useless for correlating an incident.
    const redacted = redactMetadata({
      tokenId: "tok_123",
      credentialId: "cred_456",
      stepUpId: "step_789",
      eventId: "evt_012",
    }) as Record<string, unknown>;

    expect(redacted.tokenId).toBe("tok_123");
    expect(redacted.credentialId).toBe("cred_456");
    expect(redacted.stepUpId).toBe("step_789");
    expect(redacted.eventId).toBe("evt_012");
  });

  it("redacts nested secrets", () => {
    const redacted = redactMetadata({
      outer: { inner: { apiKey: "sk-live-123" } },
    }) as { outer: { inner: { apiKey: string } } };

    expect(redacted.outer.inner.apiKey).toBe("[REDACTED]");
  });

  it("a secret passed by a careless call site never reaches the store", async () => {
    const user = await createUser("redact");

    await writeAuditLog({
      stream: AuditStream.LOGIN,
      eventType: "TEST_REDACTION",
      userId: user.id,
      ipAddress: "10.0.0.1",
      userAgent: "test",
      outcome: "SUCCESS",
      metadata: { password: "should-never-appear" },
    });

    const entry = await prisma.auditLog.findFirst({
      where: { userId: user.id, eventType: "TEST_REDACTION" },
    });

    expect(entry!.metadata).not.toContain("should-never-appear");
    expect(entry!.metadata).toContain("[REDACTED]");
  });
});

describe("Tamper-evident chain (§11)", () => {
  it("assigns a sequence and a hash to every entry", async () => {
    const user = await createUser("chain");

    await writeAuditLog({
      stream: AuditStream.CONNECT,
      eventType: "TEST_CHAIN",
      userId: user.id,
      ipAddress: "10.0.0.1",
      userAgent: "test",
      outcome: "SUCCESS",
      metadata: {},
    });

    const entry = await prisma.auditLog.findFirst({
      where: { userId: user.id, eventType: "TEST_CHAIN" },
    });

    expect(entry!.hash).toBeTruthy();
    expect(entry!.prevHash).toBeTruthy();
    expect(entry!.seq).toBeGreaterThan(0);
  });

  it("links each entry to its predecessor", async () => {
    const user = await createUser("link");

    for (let i = 0; i < 3; i++) {
      await writeAuditLog({
        stream: AuditStream.LOGIN,
        eventType: `TEST_LINK_${i}`,
        userId: user.id,
        ipAddress: "10.0.0.1",
        userAgent: "test",
        outcome: "SUCCESS",
        metadata: { i },
      });
    }

    const entries = await prisma.auditLog.findMany({
      where: { userId: user.id },
      orderBy: { seq: "asc" },
    });

    for (let i = 1; i < entries.length; i++) {
      expect(entries[i].prevHash).toBe(entries[i - 1].hash);
    }
  });

  it("verifies an untampered chain", async () => {
    const result = await verifyAuditChain();
    expect(result.valid).toBe(true);
    expect(result.checked).toBeGreaterThan(0);
  });

  it("detects an altered entry", async () => {
    const user = await createUser("tamper");

    await writeAuditLog({
      stream: AuditStream.CONNECT,
      eventType: "CONNECT_BLOCKED_HIGH_RISK",
      userId: user.id,
      ipAddress: "10.0.0.1",
      userAgent: "test",
      outcome: "DENIED",
      severity: "HIGH",
      metadata: { reason: "original" },
    });

    const entry = await prisma.auditLog.findFirst({
      where: { userId: user.id },
      orderBy: { seq: "desc" },
    });

    // Rewrite history the way someone covering their tracks would: change the
    // record and leave the stored hash alone.
    await prisma.auditLog.update({
      where: { id: entry!.id },
      data: { outcome: "SUCCESS", eventType: "CONNECT_GRANTED" },
    });

    const result = await verifyAuditChain();
    expect(result.valid).toBe(false);
    expect(result.brokenAtSeq).toBe(entry!.seq);

    // Restore so later tests in this file still see a coherent chain.
    await prisma.auditLog.update({
      where: { id: entry!.id },
      data: { outcome: "DENIED", eventType: "CONNECT_BLOCKED_HIGH_RISK" },
    });

    expect((await verifyAuditChain()).valid).toBe(true);
  });

  it("applies a sensible default severity", async () => {
    const user = await createUser("severity");

    await writeAuditLog({
      stream: AuditStream.CONNECT,
      eventType: "TEST_SEVERITY_DENIED",
      userId: user.id,
      ipAddress: "10.0.0.1",
      userAgent: "test",
      outcome: "DENIED",
      metadata: {},
    });

    const entry = await prisma.auditLog.findFirst({
      where: { userId: user.id, eventType: "TEST_SEVERITY_DENIED" },
    });

    expect(entry?.severity).toBe("WARNING");
  });
});

describe("Alert management (§20)", () => {
  it("suppresses a repeat of the same detection inside the correlation window", async () => {
    const user = await createUser("dedup");

    const first = await raiseSecurityAlert({
      alertKey: "connect_risk:HIGH",
      severity: "HIGH",
      userId: user.id,
      ipAddress: "10.0.0.1",
      userAgent: "test",
    });

    const second = await raiseSecurityAlert({
      alertKey: "connect_risk:HIGH",
      severity: "HIGH",
      userId: user.id,
      ipAddress: "10.0.0.1",
      userAgent: "test",
    });

    expect(first.raised).toBe(true);
    expect(second.raised).toBe(false);
    expect(second.deduplicated).toBe(true);
  });

  it("still records a suppressed occurrence, so tuning has something to read", async () => {
    const user = await createUser("suppressed");

    await raiseSecurityAlert({
      alertKey: "connect_risk:CRITICAL",
      severity: "CRITICAL",
      userId: user.id,
      ipAddress: "10.0.0.1",
      userAgent: "test",
    });
    await raiseSecurityAlert({
      alertKey: "connect_risk:CRITICAL",
      severity: "CRITICAL",
      userId: user.id,
      ipAddress: "10.0.0.1",
      userAgent: "test",
    });

    const suppressed = await prisma.auditLog.findFirst({
      where: { userId: user.id, eventType: "SECURITY_ALERT_SUPPRESSED" },
    });
    expect(suppressed).not.toBeNull();
  });

  it("does not alert below the severity floor", async () => {
    const user = await createUser("floor");

    const result = await raiseSecurityAlert({
      alertKey: "connect_risk:MEDIUM",
      severity: "WARNING",
      userId: user.id,
      ipAddress: "10.0.0.1",
      userAgent: "test",
    });

    expect(result.raised).toBe(false);
    expect(result.deduplicated).toBe(false);
  });

  it("correlates per employee — the same pattern on two people is two incidents", async () => {
    const a = await createUser("corr-a");
    const b = await createUser("corr-b");

    const first = await raiseSecurityAlert({
      alertKey: "shared_pattern",
      severity: "HIGH",
      userId: a.id,
      ipAddress: "10.0.0.1",
      userAgent: "test",
    });
    const second = await raiseSecurityAlert({
      alertKey: "shared_pattern",
      severity: "HIGH",
      userId: b.id,
      ipAddress: "10.0.0.1",
      userAgent: "test",
    });

    expect(first.raised).toBe(true);
    expect(second.raised).toBe(true);
  });
});
