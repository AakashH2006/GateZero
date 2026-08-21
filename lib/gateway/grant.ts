/**
 * lib/gateway/grant.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * ASYMMETRICALLY SIGNED GATEWAY GRANTS
 * gateway-defense.md §3, §4
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * The problem this solves
 * ───────────────────────
 * Previously a grant was a database row, and Website 2 satisfied itself that
 * the Gateway had approved it by talking to the Gateway over a channel keyed
 * with a secret both sides held. Anything holding that secret could mint a
 * convincing approval.
 *
 * Now the Gateway signs each grant with an ES256 private key that never leaves
 * it (§4). Website 2 verifies with the corresponding public key and needs no
 * shared secret at all. "The Gateway really did approve this" becomes a
 * cryptographically verifiable claim that stands on its own.
 *
 * What this does NOT do
 * ─────────────────────
 * It does not replace Website 2's independent device check (W1 §8.1). Website 2
 * still issues its own nonce and verifies the device signature itself. A valid
 * grant signature says the Gateway approved; it says nothing about whether the
 * device presenting it holds the private key. Both checks are required, and
 * neither is a substitute for the other.
 *
 * Audience binding
 * ────────────────
 * The payload carries an audience/purpose string, the same pattern the device
 * proof already uses one layer down. A grant minted for redemption at Website 2
 * cannot be replayed anywhere else, even though the signature is genuinely
 * valid — a verifier that expects a different audience rejects it.
 *
 * Key custody
 * ───────────
 * `loadKeys()` is the HSM/KMS seam. In development the key is derived
 * deterministically from the Gateway's configured secret so no key files need
 * managing. In production it is replaced by a KMS handle and the private key is
 * never in process memory at all — which is why signing goes through this one
 * function rather than being inlined at call sites.
 */

import crypto from "crypto";
import { SignJWT, jwtVerify, importJWK, type JWTPayload } from "jose";
import { GATEWAY_GRANT_KEY_SEED, AUTHZ_TTL_SECONDS, CLOCK_SKEW_TOLERANCE_MS } from "../config";

export const GRANT_ISSUER = "gatezero-gateway";
export const GRANT_ALG = "ES256";

/** §3: purpose binding. A grant for one audience is not valid at another. */
export type GrantAudience = "operations-desk";

export interface GrantClaims {
  /** Employee the grant is for. */
  employeeId: string;
  /** Device credential id the grant is bound to. */
  deviceCredentialId: string;
  /**
   * Hash of the device's public key. Carried so a verifier can confirm the
   * grant is bound to the device it is actually looking at, without the
   * Gateway shipping the key itself around.
   */
  devicePublicKeyHash: string;
  /** Single-use identifier; consumption is tracked against this. */
  jti: string;
  audience: GrantAudience;
  /** True for administrative emergency grants (W1 §16). */
  emergency: boolean;
  issuedAt: Date;
  expiresAt: Date;
}

export interface VerifiedGrant {
  valid: boolean;
  claims?: GrantClaims;
  /** INTERNAL reason. Callers answer generically (W2 §15). */
  reason?: string;
}

export function hashDevicePublicKey(publicKeySpki: string): string {
  return crypto.createHash("sha256").update(publicKeySpki).digest("hex");
}

// ── Key custody (§4) ──────────────────────────────────────────────────────────

interface GrantKeys {
  privateJwk: crypto.JsonWebKey;
  publicJwk: crypto.JsonWebKey;
  publicKeyPem: string;
}

let cachedKeys: GrantKeys | null = null;

function b64u(buf: Buffer): string {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Derive the Gateway's grant-signing key pair.
 *
 * DEV: deterministic from a configured seed, so every process in a dev
 * environment agrees on the key without shipping key files around.
 *
 * PRODUCTION: replace this body with a KMS/HSM handle. Everything else in this
 * module goes through mintGrant/verifyGrant rather than touching key material,
 * so the swap is confined to this function.
 *
 * A deterministic seed is emphatically NOT how a production signing key should
 * be produced — it exists so the mock is runnable, and §4 names replacing it as
 * the first thing to change.
 *
 * The key is assembled as a JWK rather than hand-built DER. An earlier version
 * constructed SEC1 bytes by hand and silently encoded the secp256k1 curve OID
 * instead of P-256; letting Node do the encoding removes a whole class of that
 * mistake.
 */
function loadKeys(): GrantKeys {
  if (cachedKeys) return cachedKeys;

  // Deterministic P-256 private scalar from the seed.
  //
  // Rejection-sampled into [1, n-1] rather than reduced modulo n: reduction
  // would bias the low end of the range. Both values are 32-byte big-endian, so
  // Buffer.compare is an exact numeric comparison and no bignum is needed.
  const ORDER = Buffer.from(
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    "hex"
  );
  const ZERO = Buffer.alloc(32);

  let privateScalar: Buffer;
  let counter = 0;
  for (;;) {
    privateScalar = crypto
      .createHash("sha256")
      .update(`${GATEWAY_GRANT_KEY_SEED}:grant-signing:${counter}`)
      .digest();
    counter++;

    if (privateScalar.equals(ZERO)) continue; // scalar must be non-zero
    if (Buffer.compare(privateScalar, ORDER) < 0) break; // scalar < n
  }

  // Derive the public point: 0x04 || X(32) || Y(32).
  const ecdh = crypto.createECDH("prime256v1");
  ecdh.setPrivateKey(privateScalar);
  const point = ecdh.getPublicKey();

  const x = b64u(point.subarray(1, 33));
  const y = b64u(point.subarray(33, 65));

  const publicJwk: crypto.JsonWebKey = { kty: "EC", crv: "P-256", x, y };
  const privateJwk: crypto.JsonWebKey = { ...publicJwk, d: b64u(privateScalar) };

  cachedKeys = {
    privateJwk,
    publicJwk,
    publicKeyPem: crypto
      .createPublicKey({ key: publicJwk, format: "jwk" })
      .export({ format: "pem", type: "spki" })
      .toString(),
  };

  return cachedKeys;
}

/**
 * The Gateway's public verification key, PEM-encoded.
 *
 * Safe to publish — it verifies grants and cannot mint them. Website 2 fetches
 * it once and needs nothing else from the Gateway to check a grant's
 * authenticity.
 */
export function grantPublicKeyPem(): string {
  return loadKeys().publicKeyPem;
}

/** The same key as a JWK, for verifiers that prefer it. */
export function grantPublicJwk(): crypto.JsonWebKey {
  return loadKeys().publicJwk;
}

// ── Signing (§3) ──────────────────────────────────────────────────────────────

export interface MintParams {
  employeeId: string;
  deviceCredentialId: string;
  devicePublicKeySpki: string;
  audience: GrantAudience;
  emergency?: boolean;
  ttlSeconds?: number;
  /**
   * Tie the grant to an existing authorization record. Consumption is a
   * database fact (§6), so the signed assertion and the row that tracks
   * one-time use must name the same thing.
   */
  jti?: string;
}

export interface MintedGrant {
  jti: string;
  token: string;
  issuedAt: Date;
  expiresAt: Date;
}

/** Mint a signed, single-use, audience-bound grant. */
export async function mintGrant(params: MintParams): Promise<MintedGrant> {
  const key = await importJWK(loadKeys().privateJwk as Parameters<typeof importJWK>[0], GRANT_ALG);

  const jti = params.jti ?? crypto.randomUUID();
  const issuedAt = new Date();
  const ttl = params.ttlSeconds ?? AUTHZ_TTL_SECONDS;
  const expiresAt = new Date(issuedAt.getTime() + ttl * 1000);

  const token = await new SignJWT({
    dcid: params.deviceCredentialId,
    dpk: hashDevicePublicKey(params.devicePublicKeySpki),
    emg: params.emergency ?? false,
  })
    .setProtectedHeader({ alg: GRANT_ALG })
    .setSubject(params.employeeId)
    .setJti(jti)
    .setIssuer(GRANT_ISSUER)
    .setAudience(params.audience)
    .setIssuedAt(Math.floor(issuedAt.getTime() / 1000))
    .setExpirationTime(Math.floor(expiresAt.getTime() / 1000))
    .sign(key);

  return { jti, token, issuedAt, expiresAt };
}

// ── Verification ──────────────────────────────────────────────────────────────

/**
 * Verify a grant's signature and claims.
 *
 * Verification only — it says nothing about whether the grant has already been
 * consumed. One-time enforcement is a database fact, not a signature fact, and
 * lives in the Authorization Service where it can be made atomic.
 *
 * §5: every failure path here denies. An unparseable token, an unexpected
 * algorithm, a wrong audience and an expired grant are all refusals, and an
 * unrecognised error is a refusal too.
 */
export async function verifyGrant(
  token: string,
  expectedAudience: GrantAudience
): Promise<VerifiedGrant> {
  try {
    const key = await importJWK(
      loadKeys().publicJwk as Parameters<typeof importJWK>[0],
      GRANT_ALG
    );

    const { payload } = await jwtVerify(token, key, {
      issuer: GRANT_ISSUER,
      audience: expectedAudience,
      // Pinning the algorithm stops an attacker presenting a token that asks to
      // be verified some other way — the classic "alg" substitution.
      algorithms: [GRANT_ALG],
      clockTolerance: Math.floor(CLOCK_SKEW_TOLERANCE_MS / 1000),
    });

    const claims = toClaims(payload);
    if (!claims) return { valid: false, reason: "GRANT_CLAIMS_INCOMPLETE" };

    return { valid: true, claims };
  } catch (err) {
    const code =
      err && typeof err === "object" && "code" in err
        ? String((err as { code: unknown }).code)
        : "GRANT_VERIFICATION_FAILED";
    return { valid: false, reason: code };
  }
}

function toClaims(payload: JWTPayload): GrantClaims | null {
  const { sub, jti, aud, exp, iat, dcid, dpk, emg } = payload as JWTPayload & {
    dcid?: unknown;
    dpk?: unknown;
    emg?: unknown;
  };

  if (
    typeof sub !== "string" ||
    typeof jti !== "string" ||
    typeof dcid !== "string" ||
    typeof dpk !== "string" ||
    typeof exp !== "number" ||
    typeof iat !== "number"
  ) {
    return null;
  }

  const audience = Array.isArray(aud) ? aud[0] : aud;
  if (typeof audience !== "string") return null;

  return {
    employeeId: sub,
    deviceCredentialId: dcid,
    devicePublicKeyHash: dpk,
    jti,
    audience: audience as GrantAudience,
    emergency: emg === true,
    issuedAt: new Date(iat * 1000),
    expiresAt: new Date(exp * 1000),
  };
}

/**
 * Confirm the grant is bound to the device actually presenting it.
 *
 * The grant carries a hash of the public key it was minted for, so a verifier
 * that has the device's registered key can check the binding itself without
 * asking the Gateway anything.
 */
export function grantMatchesDevice(
  claims: GrantClaims,
  devicePublicKeySpki: string
): boolean {
  const expected = hashDevicePublicKey(devicePublicKeySpki);
  const a = Buffer.from(claims.devicePublicKeyHash, "hex");
  const b = Buffer.from(expected, "hex");
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}
