/**
 * __tests__/helpers/device.ts
 * Test fixtures for cryptographic device identity.
 *
 * Generates a real ECDSA P-256 key pair and signs challenges in the same
 * IEEE-P1363 (r||s) form WebCrypto produces in the browser. The tests therefore
 * exercise the actual verification path rather than a stubbed one — a change
 * that broke signature encoding would fail here rather than only in a browser.
 */

import crypto from "crypto";
import { prisma } from "../../lib/db";
import {
  toBase64Url,
  challengeMessage,
  issueDeviceChallenge,
  type ChallengePurpose,
  type ChallengeIssuer,
} from "../../lib/device";
import { DeviceCredentialStatus } from "@prisma/client";

export interface TestDeviceKey {
  privateKey: crypto.KeyObject;
  publicKeySpki: string;
}

export function generateDeviceKey(): TestDeviceKey {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
  });

  return {
    privateKey,
    publicKeySpki: toBase64Url(publicKey.export({ format: "der", type: "spki" }) as Buffer),
  };
}

/** Sign a challenge exactly as the browser would. */
export function signWith(
  key: TestDeviceKey,
  issuer: ChallengeIssuer,
  purpose: ChallengePurpose,
  nonce: string
): string {
  const signature = crypto.sign(
    "sha256",
    Buffer.from(challengeMessage(issuer, purpose, nonce), "utf8"),
    { key: key.privateKey, dsaEncoding: "ieee-p1363" }
  );
  return toBase64Url(signature);
}

/** Issue a challenge and return a valid proof for it. */
export async function proofFor(params: {
  key: TestDeviceKey;
  userId: string;
  purpose: ChallengePurpose;
  issuer?: ChallengeIssuer;
  deviceCredentialId?: string;
}): Promise<{ nonce: string; signature: string }> {
  const issuer = params.issuer ?? "website-1";
  const challenge = await issueDeviceChallenge({
    userId: params.userId,
    purpose: params.purpose,
    issuer,
    deviceCredentialId: params.deviceCredentialId,
  });

  return {
    nonce: challenge.nonce,
    signature: signWith(params.key, issuer, params.purpose, challenge.nonce),
  };
}

/** Create an already-approved ACTIVE credential, skipping the enrolment flow. */
export async function createActiveCredential(params: {
  userId: string;
  key?: TestDeviceKey;
  label?: string;
  rotationDueAt?: Date;
  graceExpiresAt?: Date;
}) {
  const key = params.key ?? generateDeviceKey();
  const now = Date.now();

  const credential = await prisma.deviceCredential.create({
    data: {
      userId: params.userId,
      label: params.label ?? "test-device",
      publicKeySpki: key.publicKeySpki,
      hardwareBacked: false,
      assurance: "LOW",
      status: DeviceCredentialStatus.ACTIVE,
      approvedByAdminId: "test-admin",
      approvedAt: new Date(),
      lastAttestedAt: new Date(),
      rotationDueAt: params.rotationDueAt ?? new Date(now + 30 * 86_400_000),
      graceExpiresAt: params.graceExpiresAt ?? new Date(now + 37 * 86_400_000),
    },
  });

  return { credential, key };
}
