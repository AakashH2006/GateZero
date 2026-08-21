/**
 * lib/admin-action.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Privileged-action guard — website-1-defense.md §13, §14, §15
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * Every administrative endpoint that changes security state runs through this
 * one guard, so the §14 rule is enforced in a single place rather than
 * re-implemented per route — where one route would eventually forget.
 *
 * The guard requires, in order:
 *   1. Administrator authentication (identity, not just a shared secret).
 *   2. A step-up grant issued for THIS action and THIS target, spent here.
 *   3. An audit entry naming the administrator, the target, and the reason
 *      (§15 steps 3-6), written whether the action is allowed or refused.
 *
 * A refusal is logged at HIGH severity: an attempt to spend a grant on the
 * wrong action or the wrong employee is exactly the event an operator wants to
 * see, and it would otherwise be invisible.
 */

import { NextRequest, NextResponse } from "next/server";
import { requireAdmin } from "./admin";
import { consumeStepUp, type PrivilegedAction } from "./admin-stepup";
import { auditLogin, getClientIP, getClientUA } from "./audit";
import { forbidden, badRequest } from "./errors";

export interface PrivilegedContext {
  adminUserId: string;
  adminEmail?: string;
  stepUpId: string;
  targetUserId?: string | null;
  ip: string;
  ua: string;
}

export type PrivilegedOutcome =
  | { ok: true; context: PrivilegedContext }
  | { ok: false; response: NextResponse };

/**
 * Authenticate the administrator and spend a step-up grant on `action`.
 *
 * Callers pass the `stepUpId` from the request body. It is deliberately not
 * read from a cookie or header: the grant is a one-shot capability the client
 * must present explicitly, so it cannot ride along on an unrelated request.
 */
export async function requirePrivilegedAction(params: {
  request: NextRequest;
  action: PrivilegedAction;
  stepUpId: string | undefined;
  targetUserId?: string | null;
}): Promise<PrivilegedOutcome> {
  const ip = getClientIP(params.request);
  const ua = getClientUA(params.request);

  const admin = await requireAdmin(params.request);
  if (!admin.authorized || !admin.adminUserId) {
    return { ok: false, response: forbidden("Admin access required") };
  }

  if (!params.stepUpId) {
    void auditLogin({
      eventType: "ADMIN_ACTION_DENIED_NO_STEP_UP",
      userId: admin.adminUserId,
      ipAddress: ip,
      userAgent: ua,
      outcome: "DENIED",
      severity: "HIGH",
      metadata: { attemptedAction: params.action, targetUserId: params.targetUserId },
    });
    return {
      ok: false,
      response: forbidden(
        "Fresh administrator re-authentication is required for this action",
        "STEP_UP_REQUIRED"
      ),
    };
  }

  const consumed = await consumeStepUp({
    stepUpId: params.stepUpId,
    adminUserId: admin.adminUserId,
    action: params.action,
    targetUserId: params.targetUserId ?? null,
  });

  if (!consumed.ok) {
    void auditLogin({
      eventType: "ADMIN_ACTION_DENIED_STEP_UP_INVALID",
      userId: admin.adminUserId,
      ipAddress: ip,
      userAgent: ua,
      outcome: "DENIED",
      severity: "HIGH",
      metadata: {
        attemptedAction: params.action,
        targetUserId: params.targetUserId,
        reason: consumed.reason,
      },
    });
    return {
      ok: false,
      response: badRequest(
        consumed.reason ?? "Step-up authorization invalid",
        "STEP_UP_INVALID"
      ),
    };
  }

  return {
    ok: true,
    context: {
      adminUserId: admin.adminUserId,
      adminEmail: admin.adminEmail,
      stepUpId: params.stepUpId,
      targetUserId: params.targetUserId ?? null,
      ip,
      ua,
    },
  };
}
