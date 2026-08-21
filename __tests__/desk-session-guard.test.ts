/**
 * __tests__/desk-session-guard.test.ts
 * Website 2 Session Guard — website-2-defense.md §10-§20
 *
 * The rules under test are the ones that make a Website 2 session independent
 * and bounded: single active session, replacement only on full success,
 * inactivity and absolute ceilings, and revocation that also kills the
 * authorization behind the session.
 */

import { describe, it, expect } from "vitest";
import { prisma } from "../lib/db";
import {
  establishDeskSession,
  validateDeskSession,
  recordDeviceVerification,
  touchDeskSession,
  revokeDeskSession,
  revokeAllForUser,
  rotateDeskSessionId,
  getActiveDeskSession,
  isMeaningfulActivity,
} from "../lib/desk-session";
import { issueAuthorization } from "../lib/authz-service";
import { deskSessionLimits, DESK_DEVICE_REVERIFY_MS } from "../lib/config";
import { SessionStatus, UserRole, DeskSessionStatus } from "@prisma/client";
import { createActiveCredential } from "./helpers/device";

async function setup(suffix: string) {
  const user = await prisma.user.create({
    data: {
      idpSubject: `test-idp|desk-${suffix}-${Date.now()}-${Math.random()}`,
      email: `desk-${suffix}-${Date.now()}-${Math.random()}@zerogate.test`,
      name: `Desk Test ${suffix}`,
      role: UserRole.EMPLOYEE,
    },
  });

  const session = await prisma.session.create({
    data: {
      userId: user.id,
      status: SessionStatus.ACTIVE,
      ipAddress: "10.0.0.1",
      userAgent: "hashed-ua",
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    },
  });

  const { credential } = await createActiveCredential({ userId: user.id });
  return { user, session, credential };
}

async function establish(ctx: Awaited<ReturnType<typeof setup>>) {
  const auth = await issueAuthorization({
    sessionId: ctx.session.id,
    userId: ctx.user.id,
    ipAddress: "10.0.0.1",
    userAgent: "test-agent",
    deviceCredentialId: ctx.credential.id,
  });

  return establishDeskSession({
    userId: ctx.user.id,
    deviceCredentialId: ctx.credential.id,
    authzTokenId: auth.tokenId,
    ipAddress: "10.0.0.1",
  });
}

describe("Single active session (§5, §11)", () => {
  it("a new session replaces the previous one", async () => {
    const ctx = await setup("single");
    const first = await establish(ctx);
    const second = await establish(ctx);

    expect(second.replacedSessionIds).toContain(first.session.id);

    const previous = await prisma.deskSession.findUnique({ where: { id: first.session.id } });
    expect(previous?.status).toBe(DeskSessionStatus.REVOKED);
    expect(previous?.revokedReason).toBe("REPLACED_BY_NEW_SESSION");

    const active = await getActiveDeskSession(ctx.user.id);
    expect(active?.id).toBe(second.session.id);
  });

  it("only one session is ever active for an employee", async () => {
    const ctx = await setup("count");
    await establish(ctx);
    await establish(ctx);
    await establish(ctx);

    const activeCount = await prisma.deskSession.count({
      where: { userId: ctx.user.id, status: DeskSessionStatus.ACTIVE },
    });
    expect(activeCount).toBe(1);
  });
});

describe("Session validation (§13, §14, §17, §18)", () => {
  it("validates a fresh session", async () => {
    const ctx = await setup("valid");
    const { session } = await establish(ctx);

    const result = await validateDeskSession({ sessionId: session.id });
    expect(result.valid).toBe(true);
  });

  it("expires a session that passed its inactivity ceiling (§17)", async () => {
    const ctx = await setup("inactive");
    const { session } = await establish(ctx);

    const limits = deskSessionLimits();
    await prisma.deskSession.update({
      where: { id: session.id },
      data: { lastActivityAt: new Date(Date.now() - limits.inactivityMs - 60_000) },
    });

    const result = await validateDeskSession({ sessionId: session.id });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("SESSION_EXPIRED");

    const stored = await prisma.deskSession.findUnique({ where: { id: session.id } });
    expect(stored?.revokedReason).toBe("INACTIVITY_TIMEOUT");
  });

  it("expires a session at its absolute lifetime regardless of activity (§18)", async () => {
    const ctx = await setup("absolute");
    const { session } = await establish(ctx);

    await prisma.deskSession.update({
      where: { id: session.id },
      data: {
        absoluteExpiresAt: new Date(Date.now() - 1000),
        // Active moments ago — only the absolute ceiling ends this session.
        lastActivityAt: new Date(),
      },
    });

    const result = await validateDeskSession({ sessionId: session.id });
    expect(result.valid).toBe(false);

    const stored = await prisma.deskSession.findUnique({ where: { id: session.id } });
    expect(stored?.revokedReason).toBe("ABSOLUTE_LIFETIME_REACHED");
  });

  it("rejects a session presented with the wrong device credential (§14)", async () => {
    const ctx = await setup("mismatch");
    const other = await setup("mismatch-other");
    const { session } = await establish(ctx);

    const result = await validateDeskSession({
      sessionId: session.id,
      deviceCredentialId: other.credential.id,
    });

    expect(result.valid).toBe(false);
    expect(result.reason).toBe("DEVICE_MISMATCH");
  });

  it("revokes the session when its device credential is revoked (§9)", async () => {
    const ctx = await setup("credrevoked");
    const { session } = await establish(ctx);

    await prisma.deviceCredential.update({
      where: { id: ctx.credential.id },
      data: { status: "REVOKED", revokedAt: new Date() },
    });

    const result = await validateDeskSession({ sessionId: session.id });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("DEVICE_CREDENTIAL_REVOKED");
  });

  it("an unknown session identifier resolves to nothing", async () => {
    const result = await validateDeskSession({ sessionId: "no-such-session" });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("SESSION_NOT_FOUND");
  });
});

describe("Session theft protection (§14)", () => {
  it("a freshly established session does not need re-verification yet", async () => {
    const ctx = await setup("reverify-fresh");
    const { session } = await establish(ctx);

    const result = await validateDeskSession({ sessionId: session.id });

    expect(result.valid).toBe(true);
    expect(result.deviceReverificationRequired).toBeFalsy();
  });

  it("demands a fresh device proof once the verification window lapses", async () => {
    // This is what makes a stolen session identifier insufficient on its own:
    // continuing requires the private key, which never left the real device.
    const ctx = await setup("reverify-stale");
    const { session } = await establish(ctx);

    await prisma.deskSession.update({
      where: { id: session.id },
      data: {
        deviceVerifiedAt: new Date(Date.now() - DESK_DEVICE_REVERIFY_MS - 60_000),
      },
    });

    const result = await validateDeskSession({ sessionId: session.id });

    expect(result.valid).toBe(true);
    expect(result.deviceReverificationRequired).toBe(true);
  });

  it("does not revoke the session — a legitimate device re-proves and continues", async () => {
    const ctx = await setup("reverify-survives");
    const { session } = await establish(ctx);

    await prisma.deskSession.update({
      where: { id: session.id },
      data: {
        deviceVerifiedAt: new Date(Date.now() - DESK_DEVICE_REVERIFY_MS - 60_000),
      },
    });

    await validateDeskSession({ sessionId: session.id });

    const stored = await prisma.deskSession.findUnique({ where: { id: session.id } });
    expect(stored?.status).toBe(DeskSessionStatus.ACTIVE);
  });

  it("recording a proof restarts the window", async () => {
    const ctx = await setup("reverify-record");
    const { session } = await establish(ctx);

    await prisma.deskSession.update({
      where: { id: session.id },
      data: {
        deviceVerifiedAt: new Date(Date.now() - DESK_DEVICE_REVERIFY_MS - 60_000),
      },
    });

    expect(
      (await validateDeskSession({ sessionId: session.id })).deviceReverificationRequired
    ).toBe(true);

    await recordDeviceVerification(session.id);

    expect(
      (await validateDeskSession({ sessionId: session.id })).deviceReverificationRequired
    ).toBeFalsy();
  });

  it("re-verification does not extend the absolute lifetime (§18)", async () => {
    // Re-verification is a theft control, not a way to outlive §17/§18.
    const ctx = await setup("reverify-no-extend");
    const { session } = await establish(ctx);
    const ceiling = session.absoluteExpiresAt.getTime();

    await recordDeviceVerification(session.id);

    const stored = await prisma.deskSession.findUnique({ where: { id: session.id } });
    expect(stored!.absoluteExpiresAt.getTime()).toBe(ceiling);
  });

  it("an expired session is refused outright, not merely asked to re-verify", async () => {
    const ctx = await setup("reverify-vs-expiry");
    const { session } = await establish(ctx);

    await prisma.deskSession.update({
      where: { id: session.id },
      data: {
        absoluteExpiresAt: new Date(Date.now() - 1000),
        deviceVerifiedAt: new Date(Date.now() - DESK_DEVICE_REVERIFY_MS - 60_000),
      },
    });

    const result = await validateDeskSession({ sessionId: session.id });

    expect(result.valid).toBe(false);
    expect(result.reason).toBe("SESSION_EXPIRED");
  });
});

describe("Meaningful activity (§17)", () => {
  it("background polling does not count as activity", () => {
    expect(isMeaningfulActivity("GET", "/api/desk/stats")).toBe(false);
    expect(isMeaningfulActivity("GET", "/api/desk/wire")).toBe(false);
    expect(isMeaningfulActivity("GET", "/api/desk/session")).toBe(false);
  });

  it("real application work does count", () => {
    expect(isMeaningfulActivity("POST", "/api/desk/assignments")).toBe(true);
    expect(isMeaningfulActivity("GET", "/api/desk/ledger")).toBe(true);
    expect(isMeaningfulActivity("PATCH", "/api/desk/roster/1")).toBe(true);
  });

  it("touching extends the inactivity window", async () => {
    const ctx = await setup("touch");
    const { session } = await establish(ctx);

    const past = new Date(Date.now() - 60_000);
    await prisma.deskSession.update({
      where: { id: session.id },
      data: { lastActivityAt: past },
    });

    await touchDeskSession(session.id);

    const stored = await prisma.deskSession.findUnique({ where: { id: session.id } });
    expect(stored!.lastActivityAt.getTime()).toBeGreaterThan(past.getTime());
  });
});

describe("Revocation (§19, §20, §21, §22)", () => {
  it("revoking a session also invalidates the authorization behind it", async () => {
    const ctx = await setup("revoke");
    const { session } = await establish(ctx);

    await revokeDeskSession(session.id, "USER_LOGOUT");

    const stored = await prisma.deskSession.findUnique({ where: { id: session.id } });
    expect(stored?.status).toBe(DeskSessionStatus.REVOKED);

    const authz = await prisma.authorizationToken.findUnique({
      where: { id: stored!.authzTokenId },
    });
    expect(authz?.status).toBe("REVOKED");
  });

  it("revokeAllForUser ends every session and pending authorization (§21)", async () => {
    const ctx = await setup("revokeall");
    await establish(ctx);

    // A second, still-pending grant that must not survive the sweep.
    await issueAuthorization({
      sessionId: ctx.session.id,
      userId: ctx.user.id,
      ipAddress: "10.0.0.1",
      userAgent: "test-agent",
      deviceCredentialId: ctx.credential.id,
    });

    await revokeAllForUser(ctx.user.id, "PASSWORD_CHANGED");

    const active = await prisma.deskSession.count({
      where: { userId: ctx.user.id, status: DeskSessionStatus.ACTIVE },
    });
    const pending = await prisma.authorizationToken.count({
      where: { userId: ctx.user.id, status: "ACTIVE" },
    });

    expect(active).toBe(0);
    expect(pending).toBe(0);
  });

  it("a credential-scoped sweep leaves another device's pending grant alone", async () => {
    // Regression: the session sweep honoured deviceCredentialIds but the
    // authorization sweep did not, so the DEVICE_REVOKED event for a replaced
    // device also killed the grant the NEW device had just obtained. Connect
    // appeared to succeed and then died at the handoff.
    const ctx = await setup("scoped-sweep");

    const replacement = await createActiveCredential({ userId: ctx.user.id });

    const newDeviceGrant = await issueAuthorization({
      sessionId: ctx.session.id,
      userId: ctx.user.id,
      ipAddress: "10.0.0.1",
      userAgent: "test-agent",
      deviceCredentialId: replacement.credential.id,
    });

    await revokeAllForUser(ctx.user.id, "DEVICE_REVOKED", {
      deviceCredentialIds: [ctx.credential.id],
    });

    const survivor = await prisma.authorizationToken.findUnique({
      where: { id: newDeviceGrant.tokenId },
    });
    expect(survivor?.status).toBe("ACTIVE");
  });

  it("an unscoped sweep still revokes every pending grant (§21)", async () => {
    const ctx = await setup("unscoped-sweep");

    const grant = await issueAuthorization({
      sessionId: ctx.session.id,
      userId: ctx.user.id,
      ipAddress: "10.0.0.1",
      userAgent: "test-agent",
      deviceCredentialId: ctx.credential.id,
    });

    await revokeAllForUser(ctx.user.id, "PASSWORD_CHANGED");

    const swept = await prisma.authorizationToken.findUnique({
      where: { id: grant.tokenId },
    });
    expect(swept?.status).toBe("REVOKED");
  });

  it("`except` spares the session that triggered the sweep (§11, W1 §22.3)", async () => {
    const ctx = await setup("except");
    const first = await establish(ctx);
    const second = await establish(ctx);

    await revokeAllForUser(ctx.user.id, "NEW_DEVICE_SESSION", {
      except: second.session.id,
    });

    const survivor = await prisma.deskSession.findUnique({ where: { id: second.session.id } });
    const swept = await prisma.deskSession.findUnique({ where: { id: first.session.id } });

    expect(survivor?.status).toBe(DeskSessionStatus.ACTIVE);
    expect(swept?.status).toBe(DeskSessionStatus.REVOKED);
  });
});

describe("Session identifier rotation (§16)", () => {
  it("the old identifier stops resolving after rotation", async () => {
    const ctx = await setup("rotate");
    const { session } = await establish(ctx);

    const rotated = await rotateDeskSessionId(session.id);

    expect(rotated).not.toBeNull();
    expect(rotated!.id).not.toBe(session.id);
    expect(rotated!.rotatedFromId).toBe(session.id);

    const old = await validateDeskSession({ sessionId: session.id });
    expect(old.valid).toBe(false);

    const current = await validateDeskSession({ sessionId: rotated!.id });
    expect(current.valid).toBe(true);
  });

  it("rotation does not extend the absolute lifetime", async () => {
    const ctx = await setup("rotate-ttl");
    const { session } = await establish(ctx);
    const before = session.absoluteExpiresAt.getTime();

    const rotated = await rotateDeskSessionId(session.id);
    expect(rotated!.absoluteExpiresAt.getTime()).toBe(before);
  });
});
