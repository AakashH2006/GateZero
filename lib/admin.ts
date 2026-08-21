/**
 * lib/admin.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * ADMINISTRATOR AUTHENTICATION
 * website-1-defense.md §13, §14 / website-2-defense.md §5A
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * This module answers only "is the caller the administrator". It deliberately
 * does NOT answer "may the caller perform this privileged action" — that is
 * lib/admin-stepup, and §14 requires the two to be separate: being signed in as
 * an administrator authorizes nothing on its own.
 *
 * Every result carries `adminUserId`. §13 forbids shared administrator accounts
 * and §15 requires the acting administrator's identity in the audit record, so
 * an authentication result that cannot name the human behind it is not usable
 * for privileged work.
 *
 * DEV_MODE: the X-Admin-Secret header stands in for administrator SSO, and the
 *           identity resolves to the seeded ADMIN user.
 * PRODUCTION: a real session carrying the ADMIN role, established through the
 *           controlled administrative enrolment process (W2 §5A) — never by
 *           elevating an ordinary employee session (W1 §13).
 */

import { NextRequest } from "next/server";
import crypto from "crypto";
import { ADMIN_SECRET, DEV_MODE } from "./config";
import { getValidSession } from "./auth/session";
import { prisma } from "./db";
import { UserRole } from "@prisma/client";

export interface AdminAuthResult {
  authorized: boolean;
  /** The acting administrator's identity. Present whenever authorized. */
  adminUserId?: string;
  adminEmail?: string;
  reason?: string;
}

/** Constant-time secret comparison so the header cannot be probed by timing. */
function secretMatches(provided: string | null): boolean {
  if (!provided || !ADMIN_SECRET) return false;
  const a = Buffer.from(provided, "utf8");
  const b = Buffer.from(ADMIN_SECRET, "utf8");
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

/**
 * Check if the request is authenticated as an administrator.
 *
 * DEV_MODE: X-Admin-Secret header, with the identity taken from the caller's
 * own session when they are an ADMIN, and otherwise from the seeded
 * administrator. Production: ADMIN role on a valid session.
 */
export async function requireAdmin(req: NextRequest): Promise<AdminAuthResult> {
  if (DEV_MODE) {
    if (!secretMatches(req.headers.get("x-admin-secret"))) {
      return {
        authorized: false,
        reason: "DEV_MODE: Missing or invalid X-Admin-Secret header",
      };
    }

    // Prefer the caller's own identity so dev audit entries name a real admin.
    const session = await getValidSession().catch(() => null);
    if (session?.user.role === UserRole.ADMIN) {
      return { authorized: true, adminUserId: session.userId, adminEmail: session.user.email };
    }

    const seeded = await prisma.user.findFirst({
      where: { role: UserRole.ADMIN },
      orderBy: { createdAt: "asc" },
      select: { id: true, email: true },
    });
    if (!seeded) {
      return { authorized: false, reason: "DEV_MODE: No administrator identity provisioned" };
    }
    return { authorized: true, adminUserId: seeded.id, adminEmail: seeded.email };
  }

  const session = await getValidSession();
  if (!session) {
    return { authorized: false, reason: "No valid session" };
  }

  if (session.user.role !== UserRole.ADMIN) {
    return { authorized: false, reason: "Insufficient role" };
  }

  // §15: an MFA-overridden session must never be able to act as an
  // administrator — that would let one override bootstrap another.
  if (session.mfaOverridden) {
    return { authorized: false, reason: "MFA-overridden session cannot hold admin privileges" };
  }

  return { authorized: true, adminUserId: session.userId, adminEmail: session.user.email };
}
