/**
 * lib/device/index.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * CRYPTOGRAPHIC DEVICE IDENTITY
 * website-1-defense.md §8, §22 / website-2-defense.md §4, §6-§9A
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * This module is the authoritative answer to "is this the employee's known
 * device". It replaces User-Agent fingerprinting, which W1 §5 explicitly
 * forbids treating as identity, and IP address, which W1 §6 confines to
 * telemetry.
 *
 * The device holds an ECDSA P-256 private key that it never transmits (W2 §4).
 * Proof of possession is a signature over a fresh, single-use, server-generated
 * nonce. Nothing in this module ever sees, stores, or transports a private key.
 *
 * SIGNED MESSAGE FORMAT
 * ─────────────────────
 *   gatezero:v1:<issuer>:<purpose>:<nonce>
 *
 * The issuer and purpose are inside the signed bytes on purpose. A signature
 * produced for a Website 1 Connect challenge therefore cannot be replayed as
 * the answer to Website 2's independent session challenge (§8.1), even in the
 * window where both nonces are live.
 */

import crypto from "crypto";
import { prisma } from "../db";
import {
  DEVICE_CHALLENGE_TTL_SECONDS,
  DEVICE_ROTATION_DAYS,
  DEVICE_ROTATION_GRACE_DAYS,
} from "../config";
import { DeviceCredentialStatus, type DeviceCredential } from "@prisma/client";

export type ChallengePurpose =
  | "REGISTRATION"
  | "CONNECT"
  | "W2_SESSION"
  | "ROTATION";

export type ChallengeIssuer = "website-1" | "website-2";

export interface DeviceChallengeGrant {
  nonce: string;
  expiresAt: Date;
  purpose: ChallengePurpose;
  issuer: ChallengeIssuer;
}

export interface DeviceProof {
  nonce: string;
  signature: string; // base64url, raw (r||s) ECDSA signature
}

export interface DeviceProofResult {
  valid: boolean;
  credential?: DeviceCredential;
  /** Internal reason. Callers must NOT surface this verbatim (W2 §15). */
  reason?: string;
}

// ── Encoding helpers ──────────────────────────────────────────────────────────

export function toBase64Url(buf: Buffer): string {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromBase64Url(value: string): Buffer {
  return Buffer.from(value.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

/** The exact bytes a device is required to sign. */
export function challengeMessage(
  issuer: ChallengeIssuer,
  purpose: ChallengePurpose,
  nonce: string
): string {
  return `gatezero:v1:${issuer}:${purpose}:${nonce}`;
}

// ── Raw signature verification ────────────────────────────────────────────────

/**
 * Verify a WebCrypto ECDSA-P256/SHA-256 signature against a registered SPKI
 * public key.
 *
 * WebCrypto emits the raw IEEE-P1363 (r||s) form rather than DER, so
 * `dsaEncoding` has to be set explicitly — Node defaults to DER and would
 * otherwise reject every legitimate browser signature.
 */
export function verifySignature(
  publicKeySpki: string,
  message: string,
  signatureB64Url: string
): boolean {
  try {
    const keyObject = crypto.createPublicKey({
      key: fromBase64Url(publicKeySpki),
      format: "der",
      type: "spki",
    });

    return crypto.verify(
      "sha256",
      Buffer.from(message, "utf8"),
      { key: keyObject, dsaEncoding: "ieee-p1363" },
      fromBase64Url(signatureB64Url)
    );
  } catch {
    // Malformed key or signature is a verification failure, never an exception
    // that could bubble up as a 500 and leak parser detail.
    return false;
  }
}

/** Reject anything that is not a well-formed uncompressed P-256 SPKI key. */
export function isValidP256Spki(publicKeySpki: string): boolean {
  try {
    const key = crypto.createPublicKey({
      key: fromBase64Url(publicKeySpki),
      format: "der",
      type: "spki",
    });
    if (key.asymmetricKeyType !== "ec") return false;
    const details = key.asymmetricKeyDetails as { namedCurve?: string } | undefined;
    return details?.namedCurve === "prime256v1";
  } catch {
    return false;
  }
}

// ── Challenges (W2 §4 "Cryptographic Challenge Freshness") ────────────────────

export async function issueDeviceChallenge(params: {
  userId: string;
  purpose: ChallengePurpose;
  issuer?: ChallengeIssuer;
  deviceCredentialId?: string | null;
}): Promise<DeviceChallengeGrant> {
  const issuer = params.issuer ?? "website-1";
  const nonce = toBase64Url(crypto.randomBytes(32));
  const expiresAt = new Date(Date.now() + DEVICE_CHALLENGE_TTL_SECONDS * 1000);

  await prisma.deviceChallenge.create({
    data: {
      nonce,
      userId: params.userId,
      deviceCredentialId: params.deviceCredentialId ?? null,
      purpose: params.purpose,
      issuer,
      expiresAt,
    },
  });

  return { nonce, expiresAt, purpose: params.purpose, issuer };
}

/**
 * Atomically consume a challenge.
 *
 * The consume is written as a conditional updateMany on `consumedAt: null`, so
 * two concurrent redemptions of the same nonce cannot both succeed — the second
 * one updates zero rows. A single-use nonce enforced by a read-then-write would
 * be racy, and a race here is exactly the replay the spec forbids.
 */
async function consumeChallenge(params: {
  nonce: string;
  userId: string;
  purpose: ChallengePurpose;
  issuer: ChallengeIssuer;
}): Promise<{ ok: boolean; reason?: string; deviceCredentialId?: string | null }> {
  const challenge = await prisma.deviceChallenge.findUnique({
    where: { nonce: params.nonce },
  });

  if (!challenge) return { ok: false, reason: "CHALLENGE_NOT_FOUND" };
  if (challenge.userId !== params.userId) return { ok: false, reason: "CHALLENGE_USER_MISMATCH" };
  if (challenge.purpose !== params.purpose) return { ok: false, reason: "CHALLENGE_PURPOSE_MISMATCH" };
  if (challenge.issuer !== params.issuer) return { ok: false, reason: "CHALLENGE_ISSUER_MISMATCH" };
  if (challenge.consumedAt) return { ok: false, reason: "CHALLENGE_ALREADY_USED" };
  if (challenge.expiresAt < new Date()) return { ok: false, reason: "CHALLENGE_EXPIRED" };

  const claimed = await prisma.deviceChallenge.updateMany({
    where: { nonce: params.nonce, consumedAt: null },
    data: { consumedAt: new Date() },
  });
  if (claimed.count !== 1) return { ok: false, reason: "CHALLENGE_ALREADY_USED" };

  return { ok: true, deviceCredentialId: challenge.deviceCredentialId };
}

// ── Credential state ──────────────────────────────────────────────────────────

/**
 * W2 §9A: a credential past its rotation date stays usable only until the
 * offline grace period runs out; after that the device must re-register or
 * recover. Returns the reason rather than a bare boolean so callers can log
 * precisely while still answering the client generically.
 */
export function credentialUsability(
  credential: DeviceCredential,
  now: Date = new Date()
): { usable: boolean; reason?: string; rotationDue: boolean } {
  if (credential.status === DeviceCredentialStatus.REVOKED) {
    return { usable: false, reason: "CREDENTIAL_REVOKED", rotationDue: false };
  }
  if (credential.status === DeviceCredentialStatus.PENDING_APPROVAL) {
    return { usable: false, reason: "CREDENTIAL_NOT_APPROVED", rotationDue: false };
  }
  if (credential.status === DeviceCredentialStatus.EXPIRED) {
    return { usable: false, reason: "CREDENTIAL_EXPIRED", rotationDue: true };
  }
  if (credential.graceExpiresAt < now) {
    return { usable: false, reason: "CREDENTIAL_ROTATION_GRACE_EXPIRED", rotationDue: true };
  }
  return { usable: true, rotationDue: credential.rotationDueAt < now };
}

/** The employee's single authorized credential (W2 §5: one employee → one device). */
export async function getActiveCredential(
  userId: string
): Promise<DeviceCredential | null> {
  return prisma.deviceCredential.findFirst({
    where: { userId, status: DeviceCredentialStatus.ACTIVE },
    orderBy: { createdAt: "desc" },
  });
}

// ── Proof verification ────────────────────────────────────────────────────────

/**
 * Verify that the caller controls the private key for the employee's
 * registered credential.
 *
 * The challenge is consumed BEFORE the signature is checked. A failed signature
 * therefore still burns the nonce, which denies an attacker unlimited signature
 * attempts against one live challenge.
 */
export async function verifyDeviceProof(params: {
  userId: string;
  proof: DeviceProof;
  purpose: ChallengePurpose;
  issuer?: ChallengeIssuer;
  /** Pin verification to one credential (rotation, or a session's bound device). */
  expectedCredentialId?: string;
}): Promise<DeviceProofResult> {
  const issuer = params.issuer ?? "website-1";

  const consumed = await consumeChallenge({
    nonce: params.proof.nonce,
    userId: params.userId,
    purpose: params.purpose,
    issuer,
  });
  if (!consumed.ok) return { valid: false, reason: consumed.reason };

  const credential = params.expectedCredentialId
    ? await prisma.deviceCredential.findUnique({
        where: { id: params.expectedCredentialId },
      })
    : await getActiveCredential(params.userId);

  if (!credential) return { valid: false, reason: "NO_REGISTERED_DEVICE" };
  if (credential.userId !== params.userId) {
    return { valid: false, reason: "CREDENTIAL_USER_MISMATCH" };
  }

  const usability = credentialUsability(credential);
  if (!usability.usable) return { valid: false, reason: usability.reason };

  const message = challengeMessage(issuer, params.purpose, params.proof.nonce);
  if (!verifySignature(credential.publicKeySpki, message, params.proof.signature)) {
    return { valid: false, reason: "INVALID_DEVICE_SIGNATURE" };
  }

  return { valid: true, credential };
}

// ── Registration (W2 §6) ──────────────────────────────────────────────────────

export interface RegisterResult {
  ok: boolean;
  credential?: DeviceCredential;
  reason?: string;
}

function rotationDates(now: Date = new Date()): {
  rotationDueAt: Date;
  graceExpiresAt: Date;
} {
  const rotationDueAt = new Date(now.getTime() + DEVICE_ROTATION_DAYS * 86_400_000);
  const graceExpiresAt = new Date(
    rotationDueAt.getTime() + DEVICE_ROTATION_GRACE_DAYS * 86_400_000
  );
  return { rotationDueAt, graceExpiresAt };
}

/**
 * Register a new device credential in PENDING_APPROVAL.
 *
 * The device proves possession of the new private key at registration time, so
 * an attacker cannot enrol a public key they do not hold the key for. Approval
 * is still an administrator's decision (W2 §6) — this call never activates.
 */
export async function registerDeviceCredential(params: {
  userId: string;
  label: string;
  publicKeySpki: string;
  hardwareBacked: boolean;
  proof: DeviceProof;
}): Promise<RegisterResult> {
  if (!isValidP256Spki(params.publicKeySpki)) {
    return { ok: false, reason: "INVALID_PUBLIC_KEY" };
  }

  const consumed = await consumeChallenge({
    nonce: params.proof.nonce,
    userId: params.userId,
    purpose: "REGISTRATION",
    issuer: "website-1",
  });
  if (!consumed.ok) return { ok: false, reason: consumed.reason };

  const message = challengeMessage("website-1", "REGISTRATION", params.proof.nonce);
  if (!verifySignature(params.publicKeySpki, message, params.proof.signature)) {
    return { ok: false, reason: "INVALID_DEVICE_SIGNATURE" };
  }

  // Refuse a public key already registered anywhere — two accounts sharing a
  // credential would break the one-employee-one-device invariant (W2 §5).
  const duplicate = await prisma.deviceCredential.findFirst({
    where: {
      publicKeySpki: params.publicKeySpki,
      status: { not: DeviceCredentialStatus.REVOKED },
    },
  });
  if (duplicate) return { ok: false, reason: "PUBLIC_KEY_ALREADY_REGISTERED" };

  const { rotationDueAt, graceExpiresAt } = rotationDates();

  const credential = await prisma.deviceCredential.create({
    data: {
      userId: params.userId,
      label: params.label.slice(0, 120),
      publicKeySpki: params.publicKeySpki,
      hardwareBacked: params.hardwareBacked,
      // W2 §4: a device without hardware-backed storage is admitted but is
      // explicitly treated as lower assurance.
      assurance: params.hardwareBacked ? "HIGH" : "LOW",
      status: DeviceCredentialStatus.PENDING_APPROVAL,
      rotationDueAt,
      graceExpiresAt,
    },
  });

  return { ok: true, credential };
}

/**
 * Administrator approval activates the credential and retires the employee's
 * previous one (W2 §5, §7): one employee, one authorized device.
 *
 * Returns the credentials that were superseded so the caller can propagate the
 * termination of any Website 2 session bound to them (W2 §7 step 7).
 */
export async function approveDeviceCredential(params: {
  credentialId: string;
  adminUserId: string;
}): Promise<{ ok: boolean; credential?: DeviceCredential; supersededIds: string[]; reason?: string }> {
  const credential = await prisma.deviceCredential.findUnique({
    where: { id: params.credentialId },
  });
  if (!credential) return { ok: false, supersededIds: [], reason: "CREDENTIAL_NOT_FOUND" };
  if (credential.status !== DeviceCredentialStatus.PENDING_APPROVAL) {
    return { ok: false, supersededIds: [], reason: "CREDENTIAL_NOT_PENDING" };
  }

  const previous = await prisma.deviceCredential.findMany({
    where: {
      userId: credential.userId,
      status: DeviceCredentialStatus.ACTIVE,
      id: { not: credential.id },
    },
    select: { id: true },
  });

  const now = new Date();
  await prisma.$transaction([
    prisma.deviceCredential.updateMany({
      where: {
        userId: credential.userId,
        status: DeviceCredentialStatus.ACTIVE,
        id: { not: credential.id },
      },
      data: {
        status: DeviceCredentialStatus.REVOKED,
        revokedAt: now,
        revokedReason: "SUPERSEDED_BY_NEW_DEVICE",
      },
    }),
    prisma.deviceCredential.update({
      where: { id: credential.id },
      data: {
        status: DeviceCredentialStatus.ACTIVE,
        approvedByAdminId: params.adminUserId,
        approvedAt: now,
        lastAttestedAt: now,
        replacesId: previous[0]?.id ?? null,
      },
    }),
  ]);

  const updated = await prisma.deviceCredential.findUnique({ where: { id: credential.id } });
  return { ok: true, credential: updated ?? undefined, supersededIds: previous.map((p) => p.id) };
}

/** W2 §9: revocation is permanent — a revoked credential is never reusable. */
export async function revokeDeviceCredential(params: {
  credentialId: string;
  reason: string;
}): Promise<void> {
  await prisma.deviceCredential.updateMany({
    where: { id: params.credentialId, status: { not: DeviceCredentialStatus.REVOKED } },
    data: {
      status: DeviceCredentialStatus.REVOKED,
      revokedAt: new Date(),
      revokedReason: params.reason,
    },
  });
}

// ── Rotation (W2 §9A) ─────────────────────────────────────────────────────────

/**
 * Rotate a credential: the device proves possession of the *current* private
 * key, a new credential is established, and the old one is revoked. The private
 * key never leaves the device on either side of the rotation.
 *
 * Rotation does not need administrator approval — possession of the current key
 * is the proof, which is precisely what recovery (§8) cannot rely on.
 */
export async function rotateDeviceCredential(params: {
  userId: string;
  currentCredentialId: string;
  currentProof: DeviceProof;
  newPublicKeySpki: string;
  newProof: DeviceProof;
  hardwareBacked: boolean;
  label: string;
}): Promise<RegisterResult> {
  if (!isValidP256Spki(params.newPublicKeySpki)) {
    return { ok: false, reason: "INVALID_PUBLIC_KEY" };
  }

  // 1. Prove possession of the credential being retired.
  const currentValid = await verifyDeviceProof({
    userId: params.userId,
    proof: params.currentProof,
    purpose: "ROTATION",
    issuer: "website-1",
    expectedCredentialId: params.currentCredentialId,
  });
  if (!currentValid.valid) return { ok: false, reason: currentValid.reason };

  // 2. Prove possession of the incoming key, so rotation cannot enrol a key
  //    the device does not actually hold.
  const consumed = await consumeChallenge({
    nonce: params.newProof.nonce,
    userId: params.userId,
    purpose: "REGISTRATION",
    issuer: "website-1",
  });
  if (!consumed.ok) return { ok: false, reason: consumed.reason };

  const message = challengeMessage("website-1", "REGISTRATION", params.newProof.nonce);
  if (!verifySignature(params.newPublicKeySpki, message, params.newProof.signature)) {
    return { ok: false, reason: "INVALID_DEVICE_SIGNATURE" };
  }

  const now = new Date();
  const { rotationDueAt, graceExpiresAt } = rotationDates(now);

  const [, credential] = await prisma.$transaction([
    prisma.deviceCredential.update({
      where: { id: params.currentCredentialId },
      data: {
        status: DeviceCredentialStatus.REVOKED,
        revokedAt: now,
        revokedReason: "ROTATED",
      },
    }),
    prisma.deviceCredential.create({
      data: {
        userId: params.userId,
        label: params.label.slice(0, 120),
        publicKeySpki: params.newPublicKeySpki,
        hardwareBacked: params.hardwareBacked,
        assurance: params.hardwareBacked ? "HIGH" : "LOW",
        // Rotation carries the existing administrator trust forward: the device
        // authenticated as the already-approved credential. Re-approval here
        // would lock out every employee whose admin is asleep at rotation time.
        status: DeviceCredentialStatus.ACTIVE,
        approvedByAdminId: currentValid.credential?.approvedByAdminId ?? null,
        approvedAt: currentValid.credential?.approvedAt ?? now,
        lastAttestedAt: now,
        rotationDueAt,
        graceExpiresAt,
        replacesId: params.currentCredentialId,
      },
    }),
  ]);

  return { ok: true, credential };
}

/** Mark a successful re-attestation without minting a new key. */
export async function recordAttestation(credentialId: string): Promise<void> {
  await prisma.deviceCredential.update({
    where: { id: credentialId },
    data: { lastAttestedAt: new Date() },
  }).catch(() => {});
}

/**
 * Sweep credentials whose grace period has run out (W2 §9A).
 * Called by the health monitor process rather than from a request path.
 */
export async function expireStaleCredentials(now: Date = new Date()): Promise<number> {
  const result = await prisma.deviceCredential.updateMany({
    where: {
      status: DeviceCredentialStatus.ACTIVE,
      graceExpiresAt: { lt: now },
    },
    data: {
      status: DeviceCredentialStatus.EXPIRED,
      revokedReason: "ROTATION_GRACE_EXPIRED",
    },
  });
  return result.count;
}
