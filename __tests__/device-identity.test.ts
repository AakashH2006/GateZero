/**
 * __tests__/device-identity.test.ts
 * Cryptographic device identity — website-1-defense.md §8 / website-2-defense.md §4, §6, §9A
 *
 * The properties under test are the ones the spec relies on for device binding
 * to mean anything: challenges are unpredictable and single-use, signatures are
 * bound to the issuer and purpose that requested them, and a credential stops
 * working once revoked or past its grace period.
 */

import { describe, it, expect } from "vitest";
import { prisma } from "../lib/db";
import {
  issueDeviceChallenge,
  verifyDeviceProof,
  registerDeviceCredential,
  approveDeviceCredential,
  revokeDeviceCredential,
  rotateDeviceCredential,
  credentialUsability,
  isValidP256Spki,
  expireStaleCredentials,
} from "../lib/device";
import { UserRole, DeviceCredentialStatus } from "@prisma/client";
import {
  generateDeviceKey,
  signWith,
  proofFor,
  createActiveCredential,
} from "./helpers/device";

async function createUser(suffix: string) {
  return prisma.user.create({
    data: {
      idpSubject: `test-idp|device-${suffix}-${Date.now()}-${Math.random()}`,
      email: `device-${suffix}-${Date.now()}-${Math.random()}@zerogate.test`,
      name: `Device Test ${suffix}`,
      role: UserRole.EMPLOYEE,
    },
  });
}

describe("Device proof verification (§8)", () => {
  it("accepts a correctly signed challenge from the registered credential", async () => {
    const user = await createUser("valid");
    const { key } = await createActiveCredential({ userId: user.id });

    const proof = await proofFor({ key, userId: user.id, purpose: "CONNECT" });
    const result = await verifyDeviceProof({
      userId: user.id,
      proof,
      purpose: "CONNECT",
    });

    expect(result.valid).toBe(true);
    expect(result.credential?.userId).toBe(user.id);
  });

  it("rejects a signature made by a different key", async () => {
    const user = await createUser("wrongkey");
    await createActiveCredential({ userId: user.id });

    const attacker = generateDeviceKey();
    const proof = await proofFor({ key: attacker, userId: user.id, purpose: "CONNECT" });

    const result = await verifyDeviceProof({ userId: user.id, proof, purpose: "CONNECT" });

    expect(result.valid).toBe(false);
    expect(result.reason).toBe("INVALID_DEVICE_SIGNATURE");
  });

  it("consumes the challenge, so a captured proof cannot be replayed (§4)", async () => {
    const user = await createUser("replay");
    const { key } = await createActiveCredential({ userId: user.id });

    const proof = await proofFor({ key, userId: user.id, purpose: "CONNECT" });

    const first = await verifyDeviceProof({ userId: user.id, proof, purpose: "CONNECT" });
    const second = await verifyDeviceProof({ userId: user.id, proof, purpose: "CONNECT" });

    expect(first.valid).toBe(true);
    expect(second.valid).toBe(false);
    expect(second.reason).toBe("CHALLENGE_ALREADY_USED");
  });

  it("burns the challenge even when the signature is wrong", async () => {
    // Otherwise one live nonce would allow unlimited signature attempts.
    const user = await createUser("burn");
    await createActiveCredential({ userId: user.id });

    const attacker = generateDeviceKey();
    const challenge = await issueDeviceChallenge({ userId: user.id, purpose: "CONNECT" });

    await verifyDeviceProof({
      userId: user.id,
      proof: {
        nonce: challenge.nonce,
        signature: signWith(attacker, "website-1", "CONNECT", challenge.nonce),
      },
      purpose: "CONNECT",
    });

    const stored = await prisma.deviceChallenge.findUnique({
      where: { nonce: challenge.nonce },
    });
    expect(stored?.consumedAt).not.toBeNull();
  });

  it("refuses a Website 1 signature presented at Website 2's checkpoint (§8.1)", async () => {
    // The issuer is inside the signed bytes precisely so that the two
    // checkpoints cannot be satisfied by one signature.
    const user = await createUser("crossissuer");
    const { key } = await createActiveCredential({ userId: user.id });

    const challenge = await issueDeviceChallenge({
      userId: user.id,
      purpose: "W2_SESSION",
      issuer: "website-2",
    });

    const wrongIssuerSignature = signWith(key, "website-1", "W2_SESSION", challenge.nonce);

    const result = await verifyDeviceProof({
      userId: user.id,
      proof: { nonce: challenge.nonce, signature: wrongIssuerSignature },
      purpose: "W2_SESSION",
      issuer: "website-2",
    });

    expect(result.valid).toBe(false);
    expect(result.reason).toBe("INVALID_DEVICE_SIGNATURE");
  });

  it("refuses a challenge redeemed for a different purpose", async () => {
    const user = await createUser("crosspurpose");
    const { key } = await createActiveCredential({ userId: user.id });

    const challenge = await issueDeviceChallenge({ userId: user.id, purpose: "ROTATION" });

    const result = await verifyDeviceProof({
      userId: user.id,
      proof: {
        nonce: challenge.nonce,
        signature: signWith(key, "website-1", "CONNECT", challenge.nonce),
      },
      purpose: "CONNECT",
    });

    expect(result.valid).toBe(false);
    expect(result.reason).toBe("CHALLENGE_PURPOSE_MISMATCH");
  });

  it("refuses another employee's challenge", async () => {
    const owner = await createUser("owner");
    const other = await createUser("other");
    const { key } = await createActiveCredential({ userId: owner.id });

    const challenge = await issueDeviceChallenge({ userId: other.id, purpose: "CONNECT" });

    const result = await verifyDeviceProof({
      userId: owner.id,
      proof: {
        nonce: challenge.nonce,
        signature: signWith(key, "website-1", "CONNECT", challenge.nonce),
      },
      purpose: "CONNECT",
    });

    expect(result.valid).toBe(false);
    expect(result.reason).toBe("CHALLENGE_USER_MISMATCH");
  });

  it("rejects an expired challenge", async () => {
    const user = await createUser("expired");
    const { key } = await createActiveCredential({ userId: user.id });

    const challenge = await issueDeviceChallenge({ userId: user.id, purpose: "CONNECT" });
    await prisma.deviceChallenge.update({
      where: { nonce: challenge.nonce },
      data: { expiresAt: new Date(Date.now() - 1000) },
    });

    const result = await verifyDeviceProof({
      userId: user.id,
      proof: {
        nonce: challenge.nonce,
        signature: signWith(key, "website-1", "CONNECT", challenge.nonce),
      },
      purpose: "CONNECT",
    });

    expect(result.valid).toBe(false);
    expect(result.reason).toBe("CHALLENGE_EXPIRED");
  });
});

describe("Registration and approval (§6, §5)", () => {
  it("lands in PENDING_APPROVAL — enrolment alone does not authorize a device", async () => {
    const user = await createUser("register");
    const key = generateDeviceKey();
    const challenge = await issueDeviceChallenge({ userId: user.id, purpose: "REGISTRATION" });

    const result = await registerDeviceCredential({
      userId: user.id,
      label: "laptop",
      publicKeySpki: key.publicKeySpki,
      hardwareBacked: false,
      proof: {
        nonce: challenge.nonce,
        signature: signWith(key, "website-1", "REGISTRATION", challenge.nonce),
      },
    });

    expect(result.ok).toBe(true);
    expect(result.credential?.status).toBe(DeviceCredentialStatus.PENDING_APPROVAL);
  });

  it("refuses a public key the device cannot prove possession of", async () => {
    const user = await createUser("noproof");
    const claimedKey = generateDeviceKey();
    const actualKey = generateDeviceKey();
    const challenge = await issueDeviceChallenge({ userId: user.id, purpose: "REGISTRATION" });

    const result = await registerDeviceCredential({
      userId: user.id,
      label: "laptop",
      publicKeySpki: claimedKey.publicKeySpki,
      hardwareBacked: false,
      proof: {
        nonce: challenge.nonce,
        signature: signWith(actualKey, "website-1", "REGISTRATION", challenge.nonce),
      },
    });

    expect(result.ok).toBe(false);
    expect(result.reason).toBe("INVALID_DEVICE_SIGNATURE");
  });

  it("marks a non-hardware-backed device as lower assurance rather than rejecting it (§4)", async () => {
    const user = await createUser("assurance");
    const key = generateDeviceKey();
    const challenge = await issueDeviceChallenge({ userId: user.id, purpose: "REGISTRATION" });

    const result = await registerDeviceCredential({
      userId: user.id,
      label: "laptop",
      publicKeySpki: key.publicKeySpki,
      hardwareBacked: false,
      proof: {
        nonce: challenge.nonce,
        signature: signWith(key, "website-1", "REGISTRATION", challenge.nonce),
      },
    });

    expect(result.ok).toBe(true);
    expect(result.credential?.assurance).toBe("LOW");
  });

  it("approval retires the previous credential — one employee, one device (§5)", async () => {
    const user = await createUser("supersede");
    const { credential: old } = await createActiveCredential({ userId: user.id });

    const key = generateDeviceKey();
    const challenge = await issueDeviceChallenge({ userId: user.id, purpose: "REGISTRATION" });
    const registered = await registerDeviceCredential({
      userId: user.id,
      label: "new-laptop",
      publicKeySpki: key.publicKeySpki,
      hardwareBacked: false,
      proof: {
        nonce: challenge.nonce,
        signature: signWith(key, "website-1", "REGISTRATION", challenge.nonce),
      },
    });

    const approval = await approveDeviceCredential({
      credentialId: registered.credential!.id,
      adminUserId: "admin-1",
    });

    expect(approval.ok).toBe(true);
    expect(approval.supersededIds).toContain(old.id);

    const previous = await prisma.deviceCredential.findUnique({ where: { id: old.id } });
    expect(previous?.status).toBe(DeviceCredentialStatus.REVOKED);
  });

  it("refuses a public key already registered to someone else", async () => {
    const first = await createUser("shared-a");
    const second = await createUser("shared-b");
    const key = generateDeviceKey();

    await createActiveCredential({ userId: first.id, key });

    const challenge = await issueDeviceChallenge({ userId: second.id, purpose: "REGISTRATION" });
    const result = await registerDeviceCredential({
      userId: second.id,
      label: "cloned",
      publicKeySpki: key.publicKeySpki,
      hardwareBacked: false,
      proof: {
        nonce: challenge.nonce,
        signature: signWith(key, "website-1", "REGISTRATION", challenge.nonce),
      },
    });

    expect(result.ok).toBe(false);
    expect(result.reason).toBe("PUBLIC_KEY_ALREADY_REGISTERED");
  });

  it("rejects a malformed or non-P256 public key", () => {
    expect(isValidP256Spki("not-a-key")).toBe(false);
    expect(isValidP256Spki(generateDeviceKey().publicKeySpki)).toBe(true);
  });
});

describe("Revocation and rotation (§9, §9A)", () => {
  it("a revoked credential can never be used again", async () => {
    const user = await createUser("revoked");
    const { credential, key } = await createActiveCredential({ userId: user.id });

    await revokeDeviceCredential({ credentialId: credential.id, reason: "LOST_DEVICE" });

    const proof = await proofFor({ key, userId: user.id, purpose: "CONNECT" });
    const result = await verifyDeviceProof({
      userId: user.id,
      proof,
      purpose: "CONNECT",
      expectedCredentialId: credential.id,
    });

    expect(result.valid).toBe(false);
    expect(result.reason).toBe("CREDENTIAL_REVOKED");
  });

  it("rotation requires proof of the current key and enrols the new one", async () => {
    const user = await createUser("rotate");
    const { credential, key } = await createActiveCredential({ userId: user.id });

    const newKey = generateDeviceKey();
    const currentProof = await proofFor({
      key,
      userId: user.id,
      purpose: "ROTATION",
      deviceCredentialId: credential.id,
    });
    const newChallenge = await issueDeviceChallenge({
      userId: user.id,
      purpose: "REGISTRATION",
    });

    const result = await rotateDeviceCredential({
      userId: user.id,
      currentCredentialId: credential.id,
      currentProof,
      newPublicKeySpki: newKey.publicKeySpki,
      newProof: {
        nonce: newChallenge.nonce,
        signature: signWith(newKey, "website-1", "REGISTRATION", newChallenge.nonce),
      },
      hardwareBacked: false,
      label: "rotated",
    });

    expect(result.ok).toBe(true);
    expect(result.credential?.status).toBe(DeviceCredentialStatus.ACTIVE);
    expect(result.credential?.replacesId).toBe(credential.id);

    const retired = await prisma.deviceCredential.findUnique({ where: { id: credential.id } });
    expect(retired?.status).toBe(DeviceCredentialStatus.REVOKED);
  });

  it("rotation fails without possession of the current key", async () => {
    const user = await createUser("rotate-noproof");
    const { credential } = await createActiveCredential({ userId: user.id });

    const attacker = generateDeviceKey();
    const newKey = generateDeviceKey();

    const currentProof = await proofFor({
      key: attacker,
      userId: user.id,
      purpose: "ROTATION",
      deviceCredentialId: credential.id,
    });
    const newChallenge = await issueDeviceChallenge({
      userId: user.id,
      purpose: "REGISTRATION",
    });

    const result = await rotateDeviceCredential({
      userId: user.id,
      currentCredentialId: credential.id,
      currentProof,
      newPublicKeySpki: newKey.publicKeySpki,
      newProof: {
        nonce: newChallenge.nonce,
        signature: signWith(newKey, "website-1", "REGISTRATION", newChallenge.nonce),
      },
      hardwareBacked: false,
      label: "hijack",
    });

    expect(result.ok).toBe(false);

    const untouched = await prisma.deviceCredential.findUnique({ where: { id: credential.id } });
    expect(untouched?.status).toBe(DeviceCredentialStatus.ACTIVE);
  });

  it("stays usable past the rotation date until the grace period ends (§9A)", async () => {
    const user = await createUser("grace");
    const { credential } = await createActiveCredential({
      userId: user.id,
      rotationDueAt: new Date(Date.now() - 86_400_000),
      graceExpiresAt: new Date(Date.now() + 86_400_000),
    });

    const usability = credentialUsability(credential);
    expect(usability.usable).toBe(true);
    expect(usability.rotationDue).toBe(true);
  });

  it("becomes unusable once the grace period has expired", async () => {
    const user = await createUser("grace-over");
    const { credential } = await createActiveCredential({
      userId: user.id,
      rotationDueAt: new Date(Date.now() - 10 * 86_400_000),
      graceExpiresAt: new Date(Date.now() - 86_400_000),
    });

    expect(credentialUsability(credential).usable).toBe(false);

    await expireStaleCredentials();
    const swept = await prisma.deviceCredential.findUnique({ where: { id: credential.id } });
    expect(swept?.status).toBe(DeviceCredentialStatus.EXPIRED);
  });
});
