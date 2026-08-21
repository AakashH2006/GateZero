/**
 * __tests__/security-events.test.ts
 * Critical cross-boundary events — website-2-defense.md §21, §32 / website-1-defense.md §12, §22
 *
 * §21 asks for four specific guarantees. Each has a test here: at-least-once
 * delivery, acknowledgement, idempotent processing, and fallback
 * reconciliation. §32 adds authenticity, which is the signature tests.
 */

import { describe, it, expect, vi } from "vitest";
import { prisma } from "../lib/db";
import {
  enqueueSecurityEvent,
  pullPendingEvents,
  acknowledgeEvents,
  processSecurityEvent,
  verifyEventSignature,
  signEvent,
  reconcileUserState,
  getUndeliveredEvents,
  type DeliverableEvent,
} from "../lib/security-events";
import { UserRole } from "@prisma/client";
import { createActiveCredential } from "./helpers/device";

async function createUser(suffix: string) {
  return prisma.user.create({
    data: {
      idpSubject: `test-idp|event-${suffix}-${Date.now()}-${Math.random()}`,
      email: `event-${suffix}-${Date.now()}-${Math.random()}@zerogate.test`,
      name: `Event Test ${suffix}`,
      role: UserRole.EMPLOYEE,
    },
  });
}

async function pullFor(userId: string): Promise<DeliverableEvent[]> {
  const events = await pullPendingEvents(200);
  return events.filter((e) => e.userId === userId);
}

describe("Authenticity (§32)", () => {
  it("a correctly signed event verifies", async () => {
    const user = await createUser("sig");
    await enqueueSecurityEvent({
      type: "PASSWORD_CHANGED",
      userId: user.id,
      reason: "test",
    });

    const [event] = await pullFor(user.id);
    expect(
      verifyEventSignature({
        eventId: event.eventId,
        type: event.type,
        userId: event.userId,
        payload: JSON.stringify(event.payload),
        signature: event.signature,
      })
    ).toBe(true);
  });

  it("a tampered payload fails verification", async () => {
    const user = await createUser("tamper");
    await enqueueSecurityEvent({ type: "ACCESS_REVOKED", userId: user.id, reason: "test" });

    const [event] = await pullFor(user.id);
    const tampered = { ...event.payload, reason: "attacker-supplied" };

    expect(
      verifyEventSignature({
        eventId: event.eventId,
        type: event.type,
        userId: event.userId,
        payload: JSON.stringify(tampered),
        signature: event.signature,
      })
    ).toBe(false);
  });

  it("an event cannot be re-aimed at a different employee", async () => {
    // The signature covers the userId, so redirecting a legitimate termination
    // at someone else invalidates it.
    const victim = await createUser("reaim-victim");
    const target = await createUser("reaim-target");

    await enqueueSecurityEvent({ type: "ACCESS_REVOKED", userId: victim.id, reason: "test" });
    const [event] = await pullFor(victim.id);

    expect(
      verifyEventSignature({
        eventId: event.eventId,
        type: event.type,
        userId: target.id,
        payload: JSON.stringify(event.payload),
        signature: event.signature,
      })
    ).toBe(false);
  });

  it("a forged signature is rejected by the processor", async () => {
    const user = await createUser("forged");

    const forged: DeliverableEvent = {
      eventId: `forged-${Date.now()}`,
      type: "ACCESS_REVOKED",
      userId: user.id,
      payload: { userId: user.id, reason: "forged", occurredAt: new Date().toISOString() },
      signature: "00".repeat(32),
      createdAt: new Date().toISOString(),
    };

    const apply = vi.fn(async () => "SHOULD_NOT_RUN");
    const result = await processSecurityEvent(forged, apply);

    expect(result.processed).toBe(false);
    expect(result.reason).toBe("INVALID_SIGNATURE");
    expect(apply).not.toHaveBeenCalled();
  });
});

describe("Idempotent processing (§21)", () => {
  it("applies once and treats redelivery as a no-op", async () => {
    const user = await createUser("idempotent");
    await enqueueSecurityEvent({
      type: "PASSWORD_CHANGED",
      userId: user.id,
      reason: "test",
    });

    const [event] = await pullFor(user.id);
    const apply = vi.fn(async () => "APPLIED");

    const first = await processSecurityEvent(event, apply);
    const second = await processSecurityEvent(event, apply);

    expect(first.processed).toBe(true);
    expect(first.duplicate).toBe(false);
    expect(second.processed).toBe(true);
    expect(second.duplicate).toBe(true);
    // The side effect ran exactly once, which is what makes at-least-once
    // delivery safe.
    expect(apply).toHaveBeenCalledTimes(1);
  });

  it("releases the ledger entry when applying fails, so a retry can retry", async () => {
    const user = await createUser("retry");
    await enqueueSecurityEvent({ type: "ADMIN_TERMINATION", userId: user.id, reason: "test" });

    const [event] = await pullFor(user.id);

    const failing = vi.fn(async () => {
      throw new Error("TRANSIENT");
    });
    const failed = await processSecurityEvent(event, failing);

    expect(failed.processed).toBe(false);

    const ledger = await prisma.processedSecurityEvent.findUnique({
      where: { eventId: event.eventId },
    });
    expect(ledger).toBeNull();

    // A subsequent delivery must still be able to apply it.
    const succeeding = vi.fn(async () => "APPLIED");
    const retried = await processSecurityEvent(event, succeeding);
    expect(retried.processed).toBe(true);
    expect(succeeding).toHaveBeenCalledTimes(1);
  });
});

describe("At-least-once delivery (§21)", () => {
  it("an event stays pending until acknowledged", async () => {
    const user = await createUser("pending");
    await enqueueSecurityEvent({ type: "PASSWORD_CHANGED", userId: user.id, reason: "test" });

    // Handing the event over is not delivery.
    await pullFor(user.id);

    const stillPending = await prisma.securityEvent.findFirst({
      where: { userId: user.id, status: "PENDING" },
    });
    expect(stillPending).not.toBeNull();
    expect(stillPending!.attempts).toBeGreaterThanOrEqual(1);
  });

  it("acknowledgement marks it delivered", async () => {
    const user = await createUser("ack");
    const eventId = await enqueueSecurityEvent({
      type: "PASSWORD_CHANGED",
      userId: user.id,
      reason: "test",
    });

    await pullFor(user.id);
    const count = await acknowledgeEvents([eventId]);

    expect(count).toBe(1);

    const record = await prisma.securityEvent.findUnique({ where: { eventId } });
    expect(record?.status).toBe("DELIVERED");
    expect(record?.ackedAt).not.toBeNull();
  });

  it("redelivery increments the attempt count so a silent consumer is visible", async () => {
    const user = await createUser("attempts");
    const eventId = await enqueueSecurityEvent({
      type: "ACCESS_REVOKED",
      userId: user.id,
      reason: "test",
    });

    await pullFor(user.id);
    await pullFor(user.id);
    await pullFor(user.id);

    const record = await prisma.securityEvent.findUnique({ where: { eventId } });
    expect(record!.attempts).toBeGreaterThanOrEqual(3);
    expect(record!.status).toBe("PENDING");
  });

  it("stale undelivered events are surfaced", async () => {
    const user = await createUser("stale");
    const eventId = await enqueueSecurityEvent({
      type: "ACCESS_REVOKED",
      userId: user.id,
      reason: "test",
    });

    await prisma.securityEvent.update({
      where: { eventId },
      data: { createdAt: new Date(Date.now() - 10 * 60 * 1000) },
    });

    const stale = await getUndeliveredEvents(60_000);
    expect(stale.some((e) => e.eventId === eventId)).toBe(true);
  });
});

describe("Fallback reconciliation (§21)", () => {
  it("reports the employee's critical account state from the system of record", async () => {
    const user = await createUser("reconcile");
    const { credential } = await createActiveCredential({ userId: user.id });

    await prisma.user.update({
      where: { id: user.id },
      data: { accessRevoked: true, passwordChangedAt: new Date() },
    });

    const state = await reconcileUserState(user.id);

    expect(state.accessRevoked).toBe(true);
    expect(state.passwordChangedAt).not.toBeNull();
    expect(state.activeCredentialIds).toContain(credential.id);
  });

  it("a revoked credential drops out of the reconciled state", async () => {
    const user = await createUser("reconcile-revoked");
    const { credential } = await createActiveCredential({ userId: user.id });

    await prisma.deviceCredential.update({
      where: { id: credential.id },
      data: { status: "REVOKED", revokedAt: new Date() },
    });

    const state = await reconcileUserState(user.id);
    expect(state.activeCredentialIds).not.toContain(credential.id);
  });
});

describe("Signature helper", () => {
  it("is deterministic for identical inputs", () => {
    const a = signEvent("id-1", "PASSWORD_CHANGED", "user-1", '{"x":1}');
    const b = signEvent("id-1", "PASSWORD_CHANGED", "user-1", '{"x":1}');
    expect(a).toBe(b);
  });

  it("changes when any bound field changes", () => {
    const base = signEvent("id-1", "PASSWORD_CHANGED", "user-1", '{"x":1}');
    expect(signEvent("id-2", "PASSWORD_CHANGED", "user-1", '{"x":1}')).not.toBe(base);
    expect(signEvent("id-1", "ACCESS_REVOKED", "user-1", '{"x":1}')).not.toBe(base);
    expect(signEvent("id-1", "PASSWORD_CHANGED", "user-2", '{"x":1}')).not.toBe(base);
    expect(signEvent("id-1", "PASSWORD_CHANGED", "user-1", '{"x":2}')).not.toBe(base);
  });
});
