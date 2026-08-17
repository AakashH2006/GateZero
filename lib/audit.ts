/**
 * lib/audit.ts
 * Structured audit logging for GateZero Portal.
 *
 * Two distinct streams:
 *   - LOGIN  — SSO initiation, callbacks, MFA events, logout
 *   - CONNECT — Connect clicks, authorization grants/denials, revocations
 *
 * All writes are fire-and-forget from route handlers (non-blocking) but
 * use a try/catch so audit failures never break the main request flow.
 */

import { prisma } from "./db";
import { AuditStream } from "@prisma/client";

export type AuditOutcome = "SUCCESS" | "FAILURE" | "DENIED";

export interface AuditParams {
  stream: AuditStream;
  eventType: string;
  userId?: string;
  sessionId?: string;
  authzId?: string;
  ipAddress: string;
  userAgent: string;
  outcome: AuditOutcome;
  metadata?: Record<string, unknown>;
}

/**
 * Write a structured audit log entry.
 * Returns silently on failure — audit logs must never block the request.
 */
export async function writeAuditLog(params: AuditParams): Promise<void> {
  try {
    await prisma.auditLog.create({
      data: {
        stream: params.stream,
        eventType: params.eventType,
        userId: params.userId,
        sessionId: params.sessionId,
        authzId: params.authzId,
        ipAddress: params.ipAddress,
        userAgent: params.userAgent,
        outcome: params.outcome,
        metadata: JSON.stringify(params.metadata ?? {}),
      },
    });
  } catch (err) {
    // Audit failure is logged to stderr but never thrown
    console.error("[AUDIT] Failed to write audit log:", err);
  }
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
