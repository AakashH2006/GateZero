/**
 * scripts/health-monitor.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * INDEPENDENT HEALTH MONITOR
 * website-1-defense.md §16, §17 / website-2-defense.md §27
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * Run with:  npm run health-monitor
 *
 * WHY THIS IS A SEPARATE PROCESS
 * ──────────────────────────────
 * §16: "Website 1 must never be able to declare itself unavailable."
 *
 * That is enforced by where this code runs, not by a check inside it. The
 * health table is written only from here. No route handler imports
 * `recordProbe`, and no API endpoint sets health state — so a fully compromised
 * Website 1 request path has no way to claim an outage and open the emergency
 * door. It can lie in its /api/health response, but lying *healthy* opens
 * nothing.
 *
 * WHAT IT DOES
 * ────────────
 *   - Probes Website 1 and the Gateway on a fixed interval.
 *   - Advances the trusted health state machine (multiple consecutive failures
 *     AND a sustained duration before an outage is CONFIRMED — a single failed
 *     check, or a brief blip, must never be enough).
 *   - Clears the outage and voids any human confirmation on first recovery, so
 *     the emergency path closes by itself the moment service returns (§17).
 *   - Sweeps expired device-credential grace periods (W2 §9A) and stale
 *     administrator step-up grants (§14), which are likewise housekeeping that
 *     should not depend on a request happening to arrive.
 *
 * A CONFIRMED outage still does not grant anything. It only makes the emergency
 * path *available* to an administrator, who must then explicitly confirm and
 * re-authenticate (§27, §28).
 */

import "dotenv/config";
import { recordProbe, getHealth, type ComponentName } from "../lib/health";
import { expireStaleCredentials } from "../lib/device";
import { expireStaleStepUps } from "../lib/admin-stepup";
import {
  HEALTH_PROBE_INTERVAL_MS,
  HEALTH_FAILURE_THRESHOLD,
  HEALTH_MIN_OUTAGE_MS,
  APP_URL,
} from "../lib/config";

const TARGETS: { component: ComponentName; url: string }[] = [
  { component: "website-1", url: `${APP_URL}/api/health` },
  {
    component: "gateway",
    // The Gateway is co-located with Website 1 in this mock; in production it
    // is a separate host with its own probe endpoint.
    url: `${process.env.GATEWAY_HEALTH_URL ?? `${APP_URL}/api/health`}`,
  },
];

const PROBE_TIMEOUT_MS = 5000;

/**
 * A probe is healthy only on an explicit 2xx.
 *
 * Timeouts, connection errors, and 5xx all count as failures — an instance that
 * accepts connections but cannot answer is not serving, and treating that as
 * healthy would hide exactly the outage this monitor exists to detect.
 */
async function probe(url: string): Promise<boolean> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), PROBE_TIMEOUT_MS);

  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { "Cache-Control": "no-store" },
    });
    return res.ok;
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
  }
}

async function tick(): Promise<void> {
  for (const target of TARGETS) {
    const healthy = await probe(target.url);
    const previous = await getHealth(target.component);
    const state = await recordProbe({ component: target.component, healthy });

    if (previous?.state !== state) {
      console.log(
        `[health-monitor] ${target.component}: ${previous?.state ?? "UNKNOWN"} -> ${state}`
      );

      if (state === "CONFIRMED_OUTAGE") {
        console.warn(
          `[health-monitor] ${target.component} outage CONFIRMED after ` +
            `${HEALTH_FAILURE_THRESHOLD} consecutive failures sustained for at least ` +
            `${HEALTH_MIN_OUTAGE_MS / 1000}s. Emergency access is now AVAILABLE, ` +
            `pending explicit administrator confirmation and re-authentication.`
        );
      }

      if (state === "HEALTHY" && previous?.state === "CONFIRMED_OUTAGE") {
        console.log(
          `[health-monitor] ${target.component} recovered — emergency access disabled ` +
            `and any administrator confirmation voided.`
        );
      }
    }
  }

  const expiredCredentials = await expireStaleCredentials().catch(() => 0);
  if (expiredCredentials > 0) {
    console.log(
      `[health-monitor] expired ${expiredCredentials} device credential(s) past their rotation grace period`
    );
  }

  const expiredStepUps = await expireStaleStepUps().catch(() => 0);
  if (expiredStepUps > 0) {
    console.log(`[health-monitor] expired ${expiredStepUps} unspent admin step-up grant(s)`);
  }
}

async function main(): Promise<void> {
  console.log(
    `[health-monitor] starting — probing every ${HEALTH_PROBE_INTERVAL_MS / 1000}s\n` +
      TARGETS.map((t) => `  ${t.component}: ${t.url}`).join("\n")
  );

  // Probe immediately so a monitor started during an outage does not wait a
  // full interval before reporting anything.
  await tick().catch((err) => console.error("[health-monitor] probe error:", err));

  setInterval(() => {
    void tick().catch((err) => console.error("[health-monitor] probe error:", err));
  }, HEALTH_PROBE_INTERVAL_MS);
}

void main();
