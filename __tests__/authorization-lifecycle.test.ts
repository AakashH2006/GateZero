/**
 * __tests__/authorization-lifecycle.test.ts
 * Gateway authorization — website-1-defense.md §8 / website-2-defense.md §3, §15, §24
 *
 * The four properties the spec attaches to an authorization, each tested here:
 * employee-specific, device-bound, one-time, short-lived.
 */

import { describe, it, expect } from "vitest";
import { prisma } from "../lib/db";
import {
  issueAuthorization,
  introspectTokenLive,
  consumeAuthorization,
  revokeAuthorization,
  getActiveAuthorization,
} from "../lib/authz-service";
import { redeemGatewayAuthorization, publicDenial } from "../lib/gateway";
import { SessionStatus, UserRole, AuthzStatus } from "@prisma/client";
import { createActiveCredential } from "./helpers/device";

async function setup(suffix: string) {
  const user = await prisma.user.create({
    data: {
      idpSubject: `test-idp|authz-${suffix}-${Date.now()}-${Math.random()}`,
      email: `authz-${suffix}-${Date.now()}-${Math.random()}@zerogate.test`,
      name: `Authz Test ${suffix}`,
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

  const { credential, key } = await createActiveCredential({ userId: user.id });
  return { user, session, credential, key };
}

async function issue(ctx: Awaited<ReturnType<typeof setup>>) {
  return issueAuthorization({
    sessionId: ctx.session.id,
    userId: ctx.user.id,
    ipAddress: "10.0.0.1",
    userAgent: "test-agent",
    deviceCredentialId: ctx.credential.id,
  });
}

describe("Authorization issuance (§8)", () => {
  it("binds the grant to the device credential", async () => {
    const ctx = await setup("bind");
    const auth = await issue(ctx);

    const record = await prisma.authorizationToken.findUnique({ where: { id: auth.tokenId } });
    expect(record?.deviceCredentialId).toBe(ctx.credential.id);
  });

  it("refuses to mint an unbound grant", async () => {
    // Without this refusal a caller could quietly produce a freely-copyable
    // authorization, which is exactly what device binding exists to prevent.
    const ctx = await setup("unbound");

    await expect(
      issueAuthorization({
        sessionId: ctx.session.id,
        userId: ctx.user.id,
        ipAddress: "10.0.0.1",
        userAgent: "test-agent",
        deviceCredentialId: "does-not-exist",
      })
    ).rejects.toThrow("DEVICE_CREDENTIAL_INVALID");
  });

  it("refuses a credential belonging to a different employee", async () => {
    const ctx = await setup("crossuser");
    const other = await setup("crossuser-other");

    await expect(
      issueAuthorization({
        sessionId: ctx.session.id,
        userId: ctx.user.id,
        ipAddress: "10.0.0.1",
        userAgent: "test-agent",
        deviceCredentialId: other.credential.id,
      })
    ).rejects.toThrow("DEVICE_CREDENTIAL_INVALID");
  });

  it("refuses an employee whose access has been administratively revoked (W2 §22)", async () => {
    const ctx = await setup("revokedaccess");
    await prisma.user.update({
      where: { id: ctx.user.id },
      data: { accessRevoked: true, accessRevokedAt: new Date() },
    });

    await expect(issue(ctx)).rejects.toThrow("ACCESS_REVOKED");
  });

  it("refuses a session that is not active", async () => {
    const ctx = await setup("deadsession");
    await prisma.session.update({
      where: { id: ctx.session.id },
      data: { status: SessionStatus.REVOKED, revokedAt: new Date() },
    });

    await expect(issue(ctx)).rejects.toThrow("SESSION_INVALID");
  });
});

describe("One-time consumption (§24)", () => {
  it("first use succeeds, second use is rejected", async () => {
    const ctx = await setup("onetime");
    const auth = await issue(ctx);

    const first = await consumeAuthorization({
      tokenId: auth.tokenId,
      deviceCredentialId: ctx.credential.id,
    });
    const second = await consumeAuthorization({
      tokenId: auth.tokenId,
      deviceCredentialId: ctx.credential.id,
    });

    expect(first.ok).toBe(true);
    expect(second.ok).toBe(false);
    expect(second.reason).toBe("TOKEN_ALREADY_CONSUMED");
  });

  it("a consumed grant no longer introspects as valid", async () => {
    const ctx = await setup("consumed");
    const auth = await issue(ctx);

    await consumeAuthorization({
      tokenId: auth.tokenId,
      deviceCredentialId: ctx.credential.id,
    });

    const check = await introspectTokenLive({ tokenId: auth.tokenId });
    expect(check.valid).toBe(false);
    expect(check.reason).toBe("TOKEN_ALREADY_CONSUMED");

    const record = await prisma.authorizationToken.findUnique({ where: { id: auth.tokenId } });
    expect(record?.status).toBe(AuthzStatus.CONSUMED);
    expect(record?.consumedAt).not.toBeNull();
  });

  it("only one of two concurrent redemptions wins", async () => {
    // The race is the whole point: a read-then-write consume would let both in.
    const ctx = await setup("race");
    const auth = await issue(ctx);

    const results = await Promise.all([
      consumeAuthorization({ tokenId: auth.tokenId, deviceCredentialId: ctx.credential.id }),
      consumeAuthorization({ tokenId: auth.tokenId, deviceCredentialId: ctx.credential.id }),
    ]);

    expect(results.filter((r) => r.ok)).toHaveLength(1);
  });

  it("a consumed grant is no longer offered as the session's active authorization", async () => {
    const ctx = await setup("active-after-consume");
    const auth = await issue(ctx);

    expect(await getActiveAuthorization(ctx.session.id)).not.toBeNull();

    await consumeAuthorization({
      tokenId: auth.tokenId,
      deviceCredentialId: ctx.credential.id,
    });

    expect(await getActiveAuthorization(ctx.session.id)).toBeNull();
  });
});

describe("Device binding at redemption (§8, §14)", () => {
  it("rejects redemption from a different device credential", async () => {
    const ctx = await setup("devicemismatch");
    const other = await setup("devicemismatch-other");
    const auth = await issue(ctx);

    const result = await redeemGatewayAuthorization({
      tokenId: auth.tokenId,
      deviceCredentialId: other.credential.id,
    });

    expect(result.granted).toBe(false);
    expect(result.reason).toBe("DEVICE_MISMATCH");

    // The failed attempt must not have spent the grant.
    const record = await prisma.authorizationToken.findUnique({ where: { id: auth.tokenId } });
    expect(record?.consumedAt).toBeNull();
  });

  it("rejects redemption once the bound credential is revoked", async () => {
    const ctx = await setup("revokedcred");
    const auth = await issue(ctx);

    await prisma.deviceCredential.update({
      where: { id: ctx.credential.id },
      data: { status: "REVOKED", revokedAt: new Date() },
    });

    const result = await introspectTokenLive({ tokenId: auth.tokenId });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("DEVICE_CREDENTIAL_REVOKED");
  });
});

describe("Expiry and revocation", () => {
  it("rejects an expired grant", async () => {
    const ctx = await setup("expired");
    const auth = await issue(ctx);

    await prisma.authorizationToken.update({
      where: { id: auth.tokenId },
      // Well beyond the permitted clock-skew tolerance.
      data: { expiresAt: new Date(Date.now() - 10 * 60 * 1000) },
    });

    const result = await introspectTokenLive({ tokenId: auth.tokenId });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("TOKEN_EXPIRED");
  });

  it("revocation takes effect immediately", async () => {
    const ctx = await setup("revoke");
    const auth = await issue(ctx);

    await revokeAuthorization(auth.tokenId);

    const result = await introspectTokenLive({ tokenId: auth.tokenId });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("TOKEN_REVOKED");
  });
});

describe("External response discipline (§15)", () => {
  it("the public denial reveals no reason", () => {
    const denial = publicDenial();
    expect(denial.code).toBe("ACCESS_DENIED");
    expect(JSON.stringify(denial)).not.toMatch(
      /expired|consumed|revoked|mismatch|not_found/i
    );
  });
});
