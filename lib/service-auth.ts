/**
 * lib/service-auth.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * SERVICE-TO-SERVICE AUTHENTICATION
 * website-1-defense.md §9 / website-2-defense.md §25, §26
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * "Website 2 must not blindly trust requests merely because they originate from
 * the Gateway" (W2 §25). Network position is not identity — anything that can
 * reach the port would otherwise be the Gateway.
 *
 * Every call across a service boundary carries an HMAC over the caller
 * identity, the timestamp, the request path, and the body digest:
 *
 *   X-Service-Id     caller name        ("gateway" | "operations-desk" | "admin-oob")
 *   X-Service-Time   unix ms
 *   X-Service-Nonce  random, per request
 *   X-Service-Auth   hex HMAC-SHA256
 *
 * Binding the path stops a signature captured on a read endpoint being replayed
 * against a revoke endpoint; binding the body digest stops the body being
 * swapped under a valid signature; binding the timestamp bounds the replay
 * window to `SERVICE_AUTH_MAX_SKEW_MS`.
 *
 * PRODUCTION NOTE
 * ───────────────
 * The spec calls for a mutually authenticated channel (mTLS). A shared HMAC
 * secret gives message authentication but not the per-peer key separation of
 * real mutual TLS: any holder of the secret can impersonate any service. This
 * is the mock-appropriate stand-in, and the header shape survives the swap —
 * under mTLS the peer certificate replaces `X-Service-Id`.
 */

import crypto from "crypto";
import { SERVICE_SHARED_SECRET, SERVICE_AUTH_MAX_SKEW_MS } from "./config";

export const SERVICE_HEADERS = {
  id: "x-service-id",
  time: "x-service-time",
  nonce: "x-service-nonce",
  auth: "x-service-auth",
} as const;

export type ServiceId = "gateway" | "operations-desk" | "admin-oob" | "health-monitor";

function bodyDigest(body: string): string {
  return crypto.createHash("sha256").update(body ?? "", "utf8").digest("hex");
}

function computeSignature(params: {
  serviceId: string;
  timestamp: string;
  nonce: string;
  path: string;
  body: string;
}): string {
  const canonical = [
    params.serviceId,
    params.timestamp,
    params.nonce,
    params.path,
    bodyDigest(params.body),
  ].join("\n");

  return crypto.createHmac("sha256", SERVICE_SHARED_SECRET).update(canonical).digest("hex");
}

/** Build the headers for an outbound service call. */
export function signServiceRequest(params: {
  serviceId: ServiceId;
  path: string;
  body: string;
}): Record<string, string> {
  const timestamp = Date.now().toString();
  const nonce = crypto.randomBytes(16).toString("hex");

  return {
    [SERVICE_HEADERS.id]: params.serviceId,
    [SERVICE_HEADERS.time]: timestamp,
    [SERVICE_HEADERS.nonce]: nonce,
    [SERVICE_HEADERS.auth]: computeSignature({
      serviceId: params.serviceId,
      timestamp,
      nonce,
      path: params.path,
      body: params.body,
    }),
  };
}

export interface ServiceAuthResult {
  authorized: boolean;
  serviceId?: string;
  reason?: string;
}

/**
 * Verify an inbound service call.
 *
 * `allowedServices` is required rather than optional: an endpoint should always
 * name which peers may call it, so adding a new caller is a deliberate edit
 * instead of an accident of shared-secret possession.
 */
export function verifyServiceRequest(params: {
  headers: Record<string, string | undefined> | Headers;
  path: string;
  body: string;
  allowedServices: ServiceId[];
}): ServiceAuthResult {
  const get = (name: string): string | undefined => {
    if (params.headers instanceof Headers) return params.headers.get(name) ?? undefined;
    return params.headers[name] ?? params.headers[name.toLowerCase()];
  };

  const serviceId = get(SERVICE_HEADERS.id);
  const timestamp = get(SERVICE_HEADERS.time);
  const nonce = get(SERVICE_HEADERS.nonce);
  const provided = get(SERVICE_HEADERS.auth);

  if (!serviceId || !timestamp || !nonce || !provided) {
    return { authorized: false, reason: "MISSING_SERVICE_AUTH_HEADERS" };
  }

  if (!params.allowedServices.includes(serviceId as ServiceId)) {
    return { authorized: false, reason: "SERVICE_NOT_ALLOWED" };
  }

  const skew = Math.abs(Date.now() - Number(timestamp));
  if (!Number.isFinite(skew) || skew > SERVICE_AUTH_MAX_SKEW_MS) {
    return { authorized: false, reason: "SERVICE_AUTH_STALE" };
  }

  const expected = computeSignature({
    serviceId,
    timestamp,
    nonce,
    path: params.path,
    body: params.body,
  });

  const a = Buffer.from(expected, "hex");
  const b = Buffer.from(provided, "hex");
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return { authorized: false, reason: "SERVICE_AUTH_INVALID" };
  }

  return { authorized: true, serviceId };
}
