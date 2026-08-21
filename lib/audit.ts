/**
 * lib/audit.ts
 * Structured audit logging for GateZero Portal.
 *
 * Two distinct streams:
 *   - LOGIN  — SSO initiation, callbacks, MFA events, logout
 *   - CONNECT — Connect clicks, authorization grants/denials, revocations
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * TAMPER EVIDENCE (website-1-defense.md §11: "Logs must also be protected
 * against unauthorized modification")
 * ─────────────────────────────────────────────────────────────────────────────
 * Each entry carries a monotonic `seq` and a `hash` computed over the previous
 * entry's hash plus this entry's canonical content. Editing or deleting any
 * historical row breaks verification for every row after it, so the store is
 * append-only in effect even though the database would happily allow an UPDATE.
 *
 * This is detection, not prevention. It makes silent tampering impossible to
 * hide; it does not stop an attacker with write access from rewriting the whole
 * chain. Preventing that needs an append-only sink outside this database
 * (WORM storage / external SIEM), which is a deployment concern.
 *
 * Writes are serialized through an in-process promise chain so concurrent
 * requests cannot interleave and produce two entries claiming the same
 * predecessor. That serialization is per-process: a multi-instance deployment
 * needs the chain anchored in a single writer or a DB sequence instead.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * SECRET REDACTION (§11: "Sensitive credentials, MFA secrets, session tokens,
 * and other secrets must never be logged")
 * ─────────────────────────────────────────────────────────────────────────────
 * Metadata passes through `redactMetadata()` before it is serialized. Callers
 * are expected not to log secrets in the first place; this is the backstop for
 * when someone forgets.
 *
 * All writes are fire-and-forget from route handlers (non-blocking) but
 * use a try/catch so audit failures never break the main request flow.
 */

import crypto from "crypto";
import { prisma } from "./db";
import { AuditStream } from "@prisma/client";

export type AuditOutcome = "SUCCESS" | "FAILURE" | "DENIED";
export type AuditSeverity = "INFO" | "NOTICE" | "WARNING" | "HIGH" | "CRITICAL";

export interface AuditParams {
  stream: AuditStream;
  eventType: string;
  userId?: string;
  sessionId?: string;
  authzId?: string;
  ipAddress: string;
  userAgent: string;
  outcome: AuditOutcome;
  severity?: AuditSeverity;
  metadata?: Record<string, unknown>;
}

// ── Secret redaction ──────────────────────────────────────────────────────────

/** Key names whose values must never reach the log store. */
const SENSITIVE_KEY_PATTERN =
  /(password|passwd|secret|token|jwt|otp|code|signature|privatekey|private_key|apikey|api_key|authorization|cookie|mfa|credential|nonce)/i;

/** Keys that only *look* sensitive — these are opaque identifiers, not secrets. */
const ALLOWED_KEYS = new Set([
  "tokenId",
  "authzId",
  "eventId",
  "credentialId",
  "deviceCredentialId",
  "stepUpId",
  "mfaOverridden",
  "codeSent",
]);

export function redactMetadata(value: unknown, depth = 0): unknown {
  if (depth > 6) return "[TRUNCATED]";
  if (value === null || value === undefined) return value;
  if (Array.isArray(value)) return value.map((v) => redactMetadata(v, depth + 1));

  if (typeof value === "object") {
    if (value instanceof Date) return value.toISOString();
    const out: Record<string, unknown> = {};
    for (const [key, inner] of Object.entries(value as Record<string, unknown>)) {
      if (!ALLOWED_KEYS.has(key) && SENSITIVE_KEY_PATTERN.test(key)) {
        out[key] = "[REDACTED]";
        continue;
      }
      out[key] = redactMetadata(inner, depth + 1);
    }
    return out;
  }

  return value;
}

// ── Hash chain ────────────────────────────────────────────────────────────────

const GENESIS_HASH = "0".repeat(64);

interface ChainableEntry {
  seq: number;
  stream: AuditStream;
  eventType: string;
  userId: string | null;
  sessionId: string | null;
  authzId: string | null;
  ipAddress: string;
  userAgent: string;
  outcome: string;
  severity: string;
  metadata: string;
  createdAt: Date;
}

/**
 * Canonical serialization for hashing. Field order is fixed here rather than
 * derived from object iteration order so the digest is reproducible by an
 * external verifier that never ran this code.
 */
export function auditEntryDigest(entry: ChainableEntry, prevHash: string): string {
  const canonical = [
    prevHash,
    entry.seq,
    entry.stream,
    entry.eventType,
    entry.userId ?? "",
    entry.sessionId ?? "",
    entry.authzId ?? "",
    entry.ipAddress,
    entry.userAgent,
    entry.outcome,
    entry.severity,
    entry.metadata,
    entry.createdAt.toISOString(),
  ].join("␟"); // unit separator — cannot appear in the fields above

  return crypto.createHash("sha256").update(canonical, "utf8").digest("hex");
}

// Serializes audit writes within this process so two concurrent requests cannot
// both read the same tail entry and fork the chain.
let writeChain: Promise<unknown> = Promise.resolve();

function enqueueWrite<T>(fn: () => Promise<T>): Promise<T> {
  const next = writeChain.then(fn, fn);
  // Keep the chain alive even if one write rejects.
  writeChain = next.catch(() => undefined);
  return next;
}

/**
 * Write a structured audit log entry.
 * Returns silently on failure — audit logs must never block the request.
 */
export async function writeAuditLog(params: AuditParams): Promise<void> {
  try {
    await enqueueWrite(async () => {
      const tail = await prisma.auditLog.findFirst({
        orderBy: { seq: "desc" },
        select: { seq: true, hash: true },
      });

      const seq = (tail?.seq ?? 0) + 1;
      const prevHash = tail?.hash ?? GENESIS_HASH;
      const createdAt = new Date();

      const entry: ChainableEntry = {
        seq,
        stream: params.stream,
        eventType: params.eventType,
        userId: params.userId ?? null,
        sessionId: params.sessionId ?? null,
        authzId: params.authzId ?? null,
        ipAddress: params.ipAddress,
        userAgent: params.userAgent,
        outcome: params.outcome,
        severity: params.severity ?? defaultSeverity(params),
        metadata: JSON.stringify(redactMetadata(params.metadata ?? {})),
        createdAt,
      };

      await prisma.auditLog.create({
        data: { ...entry, prevHash, hash: auditEntryDigest(entry, prevHash) },
      });
    });
  } catch (err) {
    // Audit failure is logged to stderr but never thrown
    console.error("[AUDIT] Failed to write audit log:", err);
  }
}

/** Sensible default so every call site does not have to think about severity. */
function defaultSeverity(params: AuditParams): AuditSeverity {
  if (params.outcome === "DENIED") return "WARNING";
  if (params.outcome === "FAILURE") return "NOTICE";
  return "INFO";
}

/**
 * Recompute the chain and report the first entry that fails verification.
 * Used by the admin audit view and by tests.
 */
export async function verifyAuditChain(limit = 5000): Promise<{
  valid: boolean;
  checked: number;
  brokenAtSeq?: number;
}> {
  const entries = await prisma.auditLog.findMany({
    orderBy: { seq: "asc" },
    take: limit,
  });

  let expectedPrev = GENESIS_HASH;
  let checked = 0;

  for (const entry of entries) {
    // Entries written before the chain existed have no hash; they anchor
    // nothing and are skipped rather than reported as tampering.
    if (!entry.hash) continue;

    const recomputed = auditEntryDigest(
      {
        seq: entry.seq,
        stream: entry.stream,
        eventType: entry.eventType,
        userId: entry.userId,
        sessionId: entry.sessionId,
        authzId: entry.authzId,
        ipAddress: entry.ipAddress,
        userAgent: entry.userAgent,
        outcome: entry.outcome,
        severity: entry.severity,
        metadata: entry.metadata,
        createdAt: entry.createdAt,
      },
      entry.prevHash ?? expectedPrev
    );

    if (recomputed !== entry.hash || (entry.prevHash ?? GENESIS_HASH) !== expectedPrev) {
      return { valid: false, checked, brokenAtSeq: entry.seq };
    }

    expectedPrev = entry.hash;
    checked++;
  }

  return { valid: true, checked };
}

// ── Convenience wrappers ──────────────────────────────────────────────────────

export function auditLogin(
  params: Omit<AuditParams, "stream">
): Promise<void> {
  return writeAuditLog({ ...params, stream: AuditStream.LOGIN });
}

export function auditConnect(
  params: Omit<AuditParams, "stream">
): Promise<void> {
  return writeAuditLog({ ...params, stream: AuditStream.CONNECT });
}

// ── Request helpers ───────────────────────────────────────────────────────────

/** Extract IP address from a Next.js Request object */
export function getClientIP(request: Request): string {
  return (
    request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ??
    request.headers.get("x-real-ip") ??
    "unknown"
  );
}

/** Extract User-Agent from a Next.js Request object */
export function getClientUA(request: Request): string {
  return request.headers.get("user-agent") ?? "unknown";
}
