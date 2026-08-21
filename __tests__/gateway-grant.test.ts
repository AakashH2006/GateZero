/**
 * __tests__/gateway-grant.test.ts
 * Asymmetrically signed Gateway grants — gateway-defense.md §3, §4, §5
 *
 * The property that matters: Website 2 can establish that the Gateway approved
 * a grant using only a PUBLIC key. No shared secret, so possessing the channel
 * credential is not enough to forge an approval.
 */

import { describe, it, expect } from "vitest";
import {
  mintGrant,
  verifyGrant,
  grantPublicKeyPem,
  grantMatchesDevice,
  hashDevicePublicKey,
  GRANT_ALG,
  GRANT_ISSUER,
  type GrantAudience,
} from "../lib/gateway/grant";

const DEVICE_SPKI = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE-fake-device-key-for-tests";

async function mint(overrides: Partial<Parameters<typeof mintGrant>[0]> = {}) {
  return mintGrant({
    employeeId: "employee-1",
    deviceCredentialId: "credential-1",
    devicePublicKeySpki: DEVICE_SPKI,
    audience: "operations-desk",
    ...overrides,
  });
}

function decodeHeader(token: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(token.split(".")[0], "base64url").toString());
}

describe("Grant signing (§3)", () => {
  it("mints a verifiable ES256 grant", async () => {
    const grant = await mint();
    const result = await verifyGrant(grant.token, "operations-desk");

    expect(result.valid).toBe(true);
    expect(result.claims?.employeeId).toBe("employee-1");
    expect(result.claims?.deviceCredentialId).toBe("credential-1");
    expect(result.claims?.jti).toBe(grant.jti);
  });

  it("signs asymmetrically — the verification key is public", async () => {
    // This is the whole point of §3: a verifier needs no secret, so holding the
    // channel credential does not let you mint an approval.
    const pem = grantPublicKeyPem();
    expect(pem).toContain("BEGIN PUBLIC KEY");
    expect(pem).not.toContain("PRIVATE");
  });

  it("uses ES256 and names the Gateway as issuer", async () => {
    const grant = await mint();
    expect(decodeHeader(grant.token).alg).toBe(GRANT_ALG);

    const result = await verifyGrant(grant.token, "operations-desk");
    expect(result.valid).toBe(true);
    expect(GRANT_ISSUER).toBe("gatezero-gateway");
  });

  it("gives every grant a distinct single-use identifier", async () => {
    const a = await mint();
    const b = await mint();
    expect(a.jti).not.toBe(b.jti);
  });

  it("expires in 5 minutes by default", async () => {
    const grant = await mint();
    const ttlSeconds = Math.round(
      (grant.expiresAt.getTime() - grant.issuedAt.getTime()) / 1000
    );
    expect(ttlSeconds).toBe(300);
  });
});

describe("Audience binding (§3)", () => {
  it("rejects a grant presented to the wrong audience", async () => {
    // A valid signature is not enough — the grant names where it may be spent.
    const grant = await mint();
    const result = await verifyGrant(grant.token, "somewhere-else" as GrantAudience);

    expect(result.valid).toBe(false);
    expect(result.claims).toBeUndefined();
  });
});

describe("Signature integrity (§3, §5)", () => {
  it("rejects a tampered signature", async () => {
    const grant = await mint();
    const tampered = grant.token.slice(0, -6) + "AAAAAA";

    const result = await verifyGrant(tampered, "operations-desk");
    expect(result.valid).toBe(false);
  });

  it("rejects a tampered payload", async () => {
    const grant = await mint();
    const [header, , signature] = grant.token.split(".");

    const forgedPayload = Buffer.from(
      JSON.stringify({
        sub: "someone-else",
        jti: "forged",
        aud: "operations-desk",
        iss: GRANT_ISSUER,
        dcid: "credential-1",
        dpk: hashDevicePublicKey(DEVICE_SPKI),
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 300,
      })
    ).toString("base64url");

    const result = await verifyGrant(
      `${header}.${forgedPayload}.${signature}`,
      "operations-desk"
    );
    expect(result.valid).toBe(false);
  });

  it("refuses an unsigned token (alg: none)", async () => {
    // Algorithm is pinned, so a token asking to be verified some other way is
    // rejected rather than accepted on its own say-so.
    const header = Buffer.from(JSON.stringify({ alg: "none" })).toString("base64url");
    const payload = Buffer.from(
      JSON.stringify({
        sub: "employee-1",
        jti: "forged",
        aud: "operations-desk",
        iss: GRANT_ISSUER,
        dcid: "credential-1",
        dpk: hashDevicePublicKey(DEVICE_SPKI),
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 300,
      })
    ).toString("base64url");

    const result = await verifyGrant(`${header}.${payload}.`, "operations-desk");
    expect(result.valid).toBe(false);
  });

  it("rejects unparseable input rather than throwing (§5 fail closed)", async () => {
    for (const bad of ["", "not-a-token", "a.b.c", "..", "null"]) {
      const result = await verifyGrant(bad, "operations-desk");
      expect(result.valid).toBe(false);
      expect(result.reason).toBeTruthy();
    }
  });

  it("rejects an expired grant", async () => {
    const grant = await mint({ ttlSeconds: -600 });
    const result = await verifyGrant(grant.token, "operations-desk");
    expect(result.valid).toBe(false);
  });
});

describe("Device binding (§3)", () => {
  it("confirms the grant is bound to the presenting device", async () => {
    const grant = await mint();
    const result = await verifyGrant(grant.token, "operations-desk");

    expect(grantMatchesDevice(result.claims!, DEVICE_SPKI)).toBe(true);
  });

  it("rejects a different device's key", async () => {
    const grant = await mint();
    const result = await verifyGrant(grant.token, "operations-desk");

    expect(grantMatchesDevice(result.claims!, "a-completely-different-key")).toBe(false);
  });

  it("carries a hash of the device key, not the key itself", async () => {
    const grant = await mint();
    const result = await verifyGrant(grant.token, "operations-desk");

    expect(result.claims?.devicePublicKeyHash).toBe(hashDevicePublicKey(DEVICE_SPKI));
    expect(result.claims?.devicePublicKeyHash).not.toContain(DEVICE_SPKI);
  });
});

describe("Emergency grants (W1 §16)", () => {
  it("marks an emergency grant distinguishably", async () => {
    const normal = await mint();
    const emergency = await mint({ emergency: true });

    expect((await verifyGrant(normal.token, "operations-desk")).claims?.emergency).toBe(false);
    expect((await verifyGrant(emergency.token, "operations-desk")).claims?.emergency).toBe(true);
  });
});
