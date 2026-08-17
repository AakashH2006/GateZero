/**
 * lib/admin.ts
 * Admin authentication middleware for GateZero Portal.
 *
 * DEV_MODE: Admin access is granted by the ADMIN_SECRET header.
 * PRODUCTION: Admin access should be derived from an IdP role claim
 *             (e.g. "admin" group in Okta/Azure AD) in the session record.
 *
 * This file is the single place to change admin auth logic.
 */

import { NextRequest } from "next/server";
import { ADMIN_SECRET, DEV_MODE } from "./config";
import { getValidSession } from "./auth/session";
import { UserRole } from "@prisma/client";

export interface AdminAuthResult {
  authorized: boolean;
  reason?: string;
}

/**
 * Check if the request has admin authorization.
 * DEV_MODE: checks X-Admin-Secret header
 * Production: checks user role from active session
 */
export async function requireAdmin(req: NextRequest): Promise<AdminAuthResult> {
  if (DEV_MODE) {
    const secret = req.headers.get("x-admin-secret");
    if (!secret || secret !== ADMIN_SECRET) {
      return {
        authorized: false,
        reason: "DEV_MODE: Missing or invalid X-Admin-Secret header",
      };
    }
    return { authorized: true };
  }

  // Production: check session for admin role
  const session = await getValidSession();
  if (!session) {
    return { authorized: false, reason: "No valid session" };
  }

  if (session.user.role !== UserRole.ADMIN) {
    return { authorized: false, reason: "Insufficient role" };
  }

  return { authorized: true };
}
