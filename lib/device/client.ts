/**
 * lib/device/client.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * BROWSER-SIDE DEVICE KEY CUSTODY
 * website-2-defense.md §4 "Hardware-Backed Key Storage"
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * The device's private key is generated with `extractable: false`, so the
 * browser will never hand the raw key material back to JavaScript — not to this
 * module, not to injected script, not to an XSS payload. The CryptoKey handle
 * is persisted in IndexedDB (structured-clone of a non-extractable key keeps
 * that property), which is what lets the same device re-prove itself across
 * page loads without ever exporting a secret.
 *
 * ASSURANCE LEVEL
 * ───────────────
 * A pure-WebCrypto key is software-protected: strong against exfiltration by
 * script, but not against an attacker with the OS-level ability to read browser
 * profile storage. The spec anticipates exactly this and says such a device is
 * admitted at *lower assurance* rather than rejected. `detectHardwareBacking()`
 * reports what we can actually determine, and the server records the resulting
 * assurance level — it never takes the client's word as a security decision,
 * because a compromised client would simply claim HIGH.
 *
 * A production deployment upgrades this path to WebAuthn/platform authenticator
 * (TPM, Secure Enclave), whose attestation is verifiable server-side. The
 * signing interface below is deliberately shaped to survive that swap.
 */

const DB_NAME = "gatezero-device";
const DB_VERSION = 1;
const STORE = "credentials";
const KEY_ID = "device-key";

export interface StoredDeviceKey {
  id: string;
  privateKey: CryptoKey;
  publicKeySpki: string;
  hardwareBacked: boolean;
  createdAt: number;
}

// ── Encoding ──────────────────────────────────────────────────────────────────

function toBase64Url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// ── IndexedDB ─────────────────────────────────────────────────────────────────

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE);
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function idbGet<T>(key: string): Promise<T | undefined> {
  return openDb().then(
    (db) =>
      new Promise<T | undefined>((resolve, reject) => {
        const tx = db.transaction(STORE, "readonly");
        const req = tx.objectStore(STORE).get(key);
        req.onsuccess = () => resolve(req.result as T | undefined);
        req.onerror = () => reject(req.error);
      })
  );
}

function idbPut(key: string, value: unknown): Promise<void> {
  return openDb().then(
    (db) =>
      new Promise<void>((resolve, reject) => {
        const tx = db.transaction(STORE, "readwrite");
        tx.objectStore(STORE).put(value, key);
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
      })
  );
}

function idbDelete(key: string): Promise<void> {
  return openDb().then(
    (db) =>
      new Promise<void>((resolve, reject) => {
        const tx = db.transaction(STORE, "readwrite");
        tx.objectStore(STORE).delete(key);
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
      })
  );
}

// ── Key lifecycle ─────────────────────────────────────────────────────────────

/**
 * Best-effort detection of platform-backed credential storage.
 *
 * Reported to the server as a hint only. The server decides the assurance level
 * it records; see the note at the top of this file.
 */
export async function detectHardwareBacking(): Promise<boolean> {
  try {
    const w = window as unknown as {
      PublicKeyCredential?: {
        isUserVerifyingPlatformAuthenticatorAvailable?: () => Promise<boolean>;
      };
    };
    const check = w.PublicKeyCredential?.isUserVerifyingPlatformAuthenticatorAvailable;
    if (typeof check === "function") return await check.call(w.PublicKeyCredential);
  } catch {
    /* fall through to the lower-assurance answer */
  }
  return false;
}

/** Generate a new non-extractable device key and persist it. Overwrites any existing key. */
export async function createDeviceKey(): Promise<StoredDeviceKey> {
  const pair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    /* extractable */ false,
    ["sign", "verify"]
  );

  const publicKeySpki = toBase64Url(await crypto.subtle.exportKey("spki", pair.publicKey));

  const stored: StoredDeviceKey = {
    id: KEY_ID,
    privateKey: pair.privateKey,
    publicKeySpki,
    hardwareBacked: await detectHardwareBacking(),
    createdAt: Date.now(),
  };

  await idbPut(KEY_ID, stored);
  return stored;
}

export async function getDeviceKey(): Promise<StoredDeviceKey | null> {
  try {
    return (await idbGet<StoredDeviceKey>(KEY_ID)) ?? null;
  } catch {
    return null;
  }
}

export async function clearDeviceKey(): Promise<void> {
  await idbDelete(KEY_ID).catch(() => {});
}

// ── Proof of possession ───────────────────────────────────────────────────────

/**
 * Sign a server challenge.
 *
 * The issuer and purpose are folded into the signed bytes, matching
 * `challengeMessage()` on the server. That binding is what stops a signature
 * obtained for one checkpoint being replayed at another.
 */
export async function signChallenge(
  key: StoredDeviceKey,
  issuer: "website-1" | "website-2",
  purpose: "REGISTRATION" | "CONNECT" | "W2_SESSION" | "ROTATION",
  nonce: string
): Promise<string> {
  const message = new TextEncoder().encode(`gatezero:v1:${issuer}:${purpose}:${nonce}`);
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    key.privateKey,
    message
  );
  return toBase64Url(signature);
}

/** Fetch a challenge from an endpoint, sign it, and return the proof envelope. */
export async function proveDevice(params: {
  challengeUrl: string;
  purpose: "REGISTRATION" | "CONNECT" | "W2_SESSION" | "ROTATION";
  issuer: "website-1" | "website-2";
  headers?: Record<string, string>;
  body?: Record<string, unknown>;
}): Promise<{ nonce: string; signature: string } | null> {
  const key = await getDeviceKey();
  if (!key) return null;

  const res = await fetch(params.challengeUrl, {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json", ...(params.headers ?? {}) },
    body: JSON.stringify({ purpose: params.purpose, ...(params.body ?? {}) }),
  });
  if (!res.ok) return null;

  const data = await res.json();
  if (!data?.nonce) return null;

  return {
    nonce: data.nonce,
    signature: await signChallenge(key, params.issuer, params.purpose, data.nonce),
  };
}
