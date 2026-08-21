/**
 * lib/admin-stepup.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * ADMINISTRATIVE RE-AUTHENTICATION
 * website-1-defense.md §13, §14 / website-2-defense.md §5A, §22
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * §14, stated as a principle:
 *
 *   "Admin login does not equal permanent administrative authorization. Every
 *    privileged action requires fresh proof of administrator identity."
 *
 * A step-up grant is therefore:
 *
 *   - Single-action. `action` is fixed at issue time and checked at spend time,
 *     so a grant obtained for "revoke a session" cannot be spent on "override
 *     MFA". Without that binding, a coerced or phished re-auth would be a blank
 *     cheque for whichever action the attacker actually wanted.
 *   - Single-target where a target applies. A grant naming employee A cannot be
 *     spent against employee B.
 *   - Single-use. Consumption is a conditional update, so two concurrent
 *     requests cannot both spend one grant.
 *   - Short-lived, so an unspent grant is not a standing privilege.
 *   - Reason-bearing, because §15 requires the reason to be recorded, and
 *     demanding it at issue time is what makes that possible.
 *
 * The administrator may stay signed into the dashboard; that grants nothing.
 */

import { prisma } from "./db";
import { ADMIN_STEP_UP_TTL_SECONDS } from "./config";

export type PrivilegedAction =
  | "REVOKE_SESSION"
  | "REVOKE_AUTHORIZATION"
  | "TERMINATE_W2_SESSION"
  | "MFA_OVERRIDE"
  | "EMERGENCY_CONFIRM_OUTAGE"
  | "EMERGENCY_CONNECT"
  | "APPROVE_DEVICE"
  | "REVOKE_DEVICE"
  | "APPROVE_RECOVERY"
  | "REVOKE_EMPLOYEE_ACCESS"
  | "RESTORE_EMPLOYEE_ACCESS"
  | "OOB_REVOKE_W2_SESSION";

export interface StepUpGrant {
  id: string;
  action: PrivilegedAction;
  targetUserId: string | null;
  expiresAt: Date;
}

export interface ConsumeResult {
  ok: boolean;
  grant?: StepUpGrant;
  /** Internal reason — surfaced to admins, who are entitled to the detail. */
  reason?: string;
}

/**
 * Issue a grant after the administrator has re-proved their identity.
 *
 * The caller is responsible for having actually performed that re-verification
 * (fresh MFA) before calling — this function mints the grant, it does not
 * authenticate.
 */
export async function issueStepUp(params: {
  adminUserId: string;
  action: PrivilegedAction;
  targetUserId?: string | null;
  reason: string;
}): Promise<StepUpGrant> {
  const expiresAt = new Date(Date.now() + ADMIN_STEP_UP_TTL_SECONDS * 1000);

  const record = await prisma.adminStepUp.create({
    data: {
      adminUserId: params.adminUserId,
      action: params.action,
      targetUserId: params.targetUserId ?? null,
      reason: params.reason.slice(0, 500),
      expiresAt,
    },
  });

  return {
    id: record.id,
    action: record.action as PrivilegedAction,
    targetUserId: record.targetUserId,
    expiresAt: record.expiresAt,
  };
}

/**
 * Spend a grant on exactly one action.
 *
 * Every mismatch is reported as its own reason so the audit trail distinguishes
 * "the admin's grant expired" from "someone tried to redirect a grant at a
 * different employee" — those are very different events.
 */
export async function consumeStepUp(params: {
  stepUpId: string;
  adminUserId: string;
  action: PrivilegedAction;
  targetUserId?: string | null;
}): Promise<ConsumeResult> {
  const record = await prisma.adminStepUp.findUnique({ where: { id: params.stepUpId } });

  if (!record) return { ok: false, reason: "STEP_UP_NOT_FOUND" };
  if (record.adminUserId !== params.adminUserId) {
    return { ok: false, reason: "STEP_UP_ADMIN_MISMATCH" };
  }
  if (record.status === "CONSUMED") return { ok: false, reason: "STEP_UP_ALREADY_USED" };
  if (record.expiresAt < new Date()) {
    await prisma.adminStepUp
      .updateMany({ where: { id: record.id, status: "ISSUED" }, data: { status: "EXPIRED" } })
      .catch(() => {});
    return { ok: false, reason: "STEP_UP_EXPIRED" };
  }
  if (record.action !== params.action) {
    return { ok: false, reason: "STEP_UP_ACTION_MISMATCH" };
  }
  if (record.targetUserId && record.targetUserId !== (params.targetUserId ?? null)) {
    return { ok: false, reason: "STEP_UP_TARGET_MISMATCH" };
  }

  // Conditional update: whichever concurrent request updates the row first is
  // the only one that gets to spend the grant.
  const claimed = await prisma.adminStepUp.updateMany({
    where: { id: record.id, status: "ISSUED" },
    data: { status: "CONSUMED", consumedAt: new Date() },
  });
  if (claimed.count !== 1) return { ok: false, reason: "STEP_UP_ALREADY_USED" };

  return {
    ok: true,
    grant: {
      id: record.id,
      action: record.action as PrivilegedAction,
      targetUserId: record.targetUserId,
      expiresAt: record.expiresAt,
    },
  };
}

/** Sweep expired, unspent grants. Called by the monitor process. */
export async function expireStaleStepUps(now: Date = new Date()): Promise<number> {
  const result = await prisma.adminStepUp.updateMany({
    where: { status: "ISSUED", expiresAt: { lt: now } },
    data: { status: "EXPIRED" },
  });
  return result.count;
}
