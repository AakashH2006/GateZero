/**
 * lib/gateway/client.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * WEBSITE 1'S CLIENT FOR THE GATEWAY PROCESS
 * gateway-defense.md §1, §2, §5, §8
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * Website 1 no longer mints grants in-process. It asks the Gateway, over an
 * authenticated backend call, and the Gateway decides.
 *
 * Two consequences worth naming:
 *
 *   - Website 1 has no code path that produces a grant. Compromising the portal
 *     no longer yields the ability to mint one, because the minting code is not
 *     there to abuse.
 *
 *   - Website 1 does not know where Website 2 lives (W1 §4, §9). It cannot even
 *     construct the handoff URL — it asks the Gateway for one. §8: resolving an
 *     address is not granting trust, and network ACLs decide reachability
 *     regardless of what any address string says.
 *
 * §5: every failure here denies. A Gateway that is unreachable, slow, or
 * erroring produces a refusal — never "connect anyway".
 */

import { signServiceRequest } from "../service-auth";
import { GATEWAY_URL } from "../config";

/** Bounded so an unresponsive Gateway fails closed instead of hanging Connect. */
const GATEWAY_TIMEOUT_MS = 5000;

export interface GatewayCallResult<T> {
  ok: boolean;
  status: number;
  data: T | null;
  /** INTERNAL reason for logging. */
  reason?: string;
}

async function callGateway<T>(
  path: string,
  body: unknown
): Promise<GatewayCallResult<T>> {
  const payload = JSON.stringify(body ?? {});
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), GATEWAY_TIMEOUT_MS);

  try {
    const res = await fetch(`${GATEWAY_URL}${path}`, {
      method: "POST",
      signal: controller.signal,
      headers: {
        "Content-Type": "application/json",
        ...signServiceRequest({ serviceId: "website-1", path, body: payload }),
      },
      body: payload,
    });

    const data = (await res.json().catch(() => null)) as T | null;
    return { ok: res.ok, status: res.status, data };
  } catch (err) {
    // Unreachable, timed out, DNS failure — all deny.
    return {
      ok: false,
      status: 0,
      data: null,
      reason: err instanceof Error ? err.message : "GATEWAY_UNREACHABLE",
    };
  } finally {
    clearTimeout(timer);
  }
}

// ── Grant issuance (§3) ───────────────────────────────────────────────────────

export interface IssueGrantParams {
  sessionId: string;
  userId: string;
  deviceCredentialId: string;
  ipAddress: string;
  userAgent: string;
  targetApp?: string;
  bindingNonce?: string;
}

export interface IssuedGrant {
  tokenId: string;
  expiresAt: string;
  ttlSeconds: number;
}

export type IssueOutcome =
  | { ok: true; grant: IssuedGrant }
  | { ok: false; reason: string };

/**
 * Ask the Gateway to issue an authorization.
 *
 * The caller must already have run the Connect-time risk assessment and
 * verified a device proof. The Gateway independently enforces the invariants
 * that must hold regardless of caller.
 */
export async function issueGrant(params: IssueGrantParams): Promise<IssueOutcome> {
  const result = await callGateway<IssuedGrant & { error?: string }>(
    "/grant/issue",
    params
  );

  if (!result.ok || !result.data?.tokenId) {
    // The Gateway distinguishes the two cases Website 1 must react to
    // differently; everything else collapses to a generic denial.
    const reason =
      result.data?.error ??
      result.reason ??
      (result.status === 429 ? "GATEWAY_RATE_LIMITED" : "GATEWAY_DENIED");
    return { ok: false, reason };
  }

  return { ok: true, grant: result.data };
}

// ── Handoff URL (§8) ──────────────────────────────────────────────────────────

/**
 * Ask the Gateway where to send the browser.
 *
 * Website 1 never resolves this itself — it holds no configuration naming
 * Website 2's address.
 */
export async function resolveHandoffUrl(params: {
  targetApp: string;
  code: string;
}): Promise<string | null> {
  const result = await callGateway<{ targetUrl?: string }>(
    "/grant/handoff-url",
    params
  );

  if (!result.ok || !result.data?.targetUrl) return null;
  return result.data.targetUrl;
}
