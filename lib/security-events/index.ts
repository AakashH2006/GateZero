/**
 * lib/security-events/index.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * CRITICAL CROSS-BOUNDARY SECURITY EVENTS
 * website-2-defense.md §21, §32 / website-1-defense.md §12, §22.3-§22.4
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * Website 1 does not control Website 2, and Website 2 does not poll Website 1
 * about session validity (W2 §35). But a handful of events genuinely must cross
 * the boundary — a password reset that leaves a stolen W2 session alive defeats
 * the whole point of the reset (W1 §12).
 *
 * This is the transport for exactly those events, and nothing else.
 *
 * DELIVERY GUARANTEE (§21 "Critical Event Delivery")
 * ──────────────────────────────────────────────────
 *   at-least-once  — a PENDING event is retried until Website 2 acknowledges.
 *   acknowledged   — DELIVERED is set only on an explicit ack, never on a send.
 *   deduplicated   — every event carries an `eventId`; Website 2 keeps a ledger
 *                    of processed ids and treats a repeat as a no-op.
 *   reconciled     — `reconcileUser()` lets Website 2 re-derive critical account
 *                    state directly when delivery cannot be confirmed.
 *
 * AUTHENTICITY (§32)
 * ──────────────────
 * Each event is HMAC-signed over a canonical serialization. Website 2 verifies
 * the signature before acting, so a request that merely *reaches* Website 2
 * from the network cannot forge a "terminate this employee's session" event.
 * Signature covers the eventId too, so an intercepted event cannot be re-aimed
 * at a different user or given a new id to bypass the dedup ledger.
 *
 * The pull/ack shape (Website 2 asks; the Gateway answers) is deliberate: it
 * needs no inbound path from the Gateway into Website 2, so Website 2 exposes
 * no event-injection endpoint at all.
 */

import crypto from "crypto";
import { prisma } from "../db";
import { SERVICE_SHARED_SECRET } from "../config";

export type SecurityEventType =
  | "PASSWORD_CHANGED"
  | "ACCESS_REVOKED"
  | "ADMIN_TERMINATION"
  | "DEVICE_REVOKED"
  | "NEW_DEVICE_SESSION";

export interface SecurityEventPayload {
  /** Terminate sessions for this employee. */
  userId: string;
  /** Optional narrowing: only sessions bound to these device credentials. */
  deviceCredentialIds?: string[];
  /** Optional narrowing: keep this session alive (the one that just replaced others). */
  exceptDeskSessionId?: string;
  reason: string;
  occurredAt: string;
}

export interface DeliverableEvent {
  eventId: string;
  type: SecurityEventType;
  userId: string;
  payload: SecurityEventPayload;
  signature: string;
  createdAt: string;
}

/** Fixed-order serialization so both sides digest identical bytes. */
function canonical(eventId: string, type: string, userId: string, payload: string): string {
  return `${eventId}\n${type}\n${userId}\n${payload}`;
}

export function signEvent(
  eventId: string,
  type: string,
  userId: string,
  payload: string
): string {
  return crypto
    .createHmac("sha256", SERVICE_SHARED_SECRET)
    .update(canonical(eventId, type, userId, payload))
    .digest("hex");
}

export function verifyEventSignature(event: {
  eventId: string;
  type: string;
  userId: string;
  payload: string;
  signature: string;
}): boolean {
  const expected = signEvent(event.eventId, event.type, event.userId, event.payload);
  const a = Buffer.from(expected, "hex");
  const b = Buffer.from(event.signature, "hex");
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

// ── Producer side (Authorization Service) ─────────────────────────────────────

/**
 * Enqueue a critical event for delivery to Website 2.
 *
 * Writing to a durable outbox rather than calling Website 2 inline is what
 * makes at-least-once possible: the caller's transaction (revoke the session,
 * change the password) completes regardless of whether Website 2 is reachable,
 * and the event survives to be retried.
 */
export async function enqueueSecurityEvent(params: {
  type: SecurityEventType;
  userId: string;
  reason: string;
  deviceCredentialIds?: string[];
  exceptDeskSessionId?: string;
}): Promise<string> {
  const eventId = crypto.randomUUID();

  const payload: SecurityEventPayload = {
    userId: params.userId,
    deviceCredentialIds: params.deviceCredentialIds,
    exceptDeskSessionId: params.exceptDeskSessionId,
    reason: params.reason,
    occurredAt: new Date().toISOString(),
  };

  const payloadJson = JSON.stringify(payload);

  await prisma.securityEvent.create({
    data: {
      eventId,
      type: params.type,
      userId: params.userId,
      payload: payloadJson,
      signature: signEvent(eventId, params.type, params.userId, payloadJson),
    },
  });

  return eventId;
}

/**
 * Hand undelivered events to Website 2.
 *
 * `attempts` is incremented at hand-off, not at ack, so a consumer that keeps
 * pulling but never acknowledges is visible as a rising attempt count rather
 * than as silence.
 */
export async function pullPendingEvents(limit = 50): Promise<DeliverableEvent[]> {
  const rows = await prisma.securityEvent.findMany({
    where: { status: "PENDING" },
    orderBy: { createdAt: "asc" },
    take: limit,
  });

  if (rows.length > 0) {
    await prisma.securityEvent.updateMany({
      where: { id: { in: rows.map((r) => r.id) } },
      data: { attempts: { increment: 1 }, lastAttemptAt: new Date() },
    });
  }

  return rows.map((row) => ({
    eventId: row.eventId,
    type: row.type as SecurityEventType,
    userId: row.userId,
    payload: JSON.parse(row.payload) as SecurityEventPayload,
    signature: row.signature,
    createdAt: row.createdAt.toISOString(),
  }));
}

/** Record Website 2's acknowledgement. Only this closes out an event. */
export async function acknowledgeEvents(eventIds: string[]): Promise<number> {
  if (eventIds.length === 0) return 0;
  const now = new Date();
  const result = await prisma.securityEvent.updateMany({
    where: { eventId: { in: eventIds }, status: "PENDING" },
    data: { status: "DELIVERED", deliveredAt: now, ackedAt: now },
  });
  return result.count;
}

/** Events stuck undelivered past `staleAfterMs` — surfaced to the admin view. */
export async function getUndeliveredEvents(staleAfterMs = 60_000) {
  return prisma.securityEvent.findMany({
    where: {
      status: "PENDING",
      createdAt: { lt: new Date(Date.now() - staleAfterMs) },
    },
    orderBy: { createdAt: "asc" },
  });
}

// ── Consumer side (Website 2) ─────────────────────────────────────────────────

export interface ProcessResult {
  eventId: string;
  processed: boolean;
  duplicate: boolean;
  reason?: string;
}

/**
 * Idempotently process one critical event.
 *
 * The ledger insert is attempted FIRST and its unique-constraint violation is
 * what detects a duplicate. Checking-then-inserting would leave a window where
 * two concurrent deliveries of the same event both pass the check.
 */
export async function processSecurityEvent(
  event: DeliverableEvent,
  apply: (event: DeliverableEvent) => Promise<string>
): Promise<ProcessResult> {
  const payloadJson = JSON.stringify(event.payload);

  if (
    !verifyEventSignature({
      eventId: event.eventId,
      type: event.type,
      userId: event.userId,
      payload: payloadJson,
      signature: event.signature,
    })
  ) {
    return {
      eventId: event.eventId,
      processed: false,
      duplicate: false,
      reason: "INVALID_SIGNATURE",
    };
  }

  try {
    await prisma.processedSecurityEvent.create({
      data: {
        eventId: event.eventId,
        type: event.type,
        userId: event.userId,
        result: "PROCESSING",
      },
    });
  } catch {
    return { eventId: event.eventId, processed: true, duplicate: true, reason: "ALREADY_PROCESSED" };
  }

  let result: string;
  try {
    result = await apply(event);
  } catch (err) {
    // Release the ledger entry so the retry can actually retry. Leaving it
    // behind would turn a transient failure into a permanently dropped
    // termination event.
    await prisma.processedSecurityEvent
      .delete({ where: { eventId: event.eventId } })
      .catch(() => {});
    return {
      eventId: event.eventId,
      processed: false,
      duplicate: false,
      reason: err instanceof Error ? err.message : "APPLY_FAILED",
    };
  }

  await prisma.processedSecurityEvent
    .update({ where: { eventId: event.eventId }, data: { result } })
    .catch(() => {});

  return { eventId: event.eventId, processed: true, duplicate: false };
}

/**
 * Fallback reconciliation (§21).
 *
 * When delivery cannot be confirmed, Website 2 re-derives the employee's
 * critical account state from the system of record instead of assuming the
 * absence of an event means "nothing happened".
 */
export async function reconcileUserState(userId: string): Promise<{
  accessRevoked: boolean;
  passwordChangedAt: string | null;
  activeCredentialIds: string[];
}> {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { accessRevoked: true, passwordChangedAt: true },
  });

  const credentials = await prisma.deviceCredential.findMany({
    where: { userId, status: "ACTIVE" },
    select: { id: true },
  });

  return {
    accessRevoked: user?.accessRevoked ?? false,
    passwordChangedAt: user?.passwordChangedAt?.toISOString() ?? null,
    activeCredentialIds: credentials.map((c) => c.id),
  };
}
