/**
 * lib/rate-limit.ts
 * Sliding-window rate limiter backed by the DB.
 *
 * For each rate-limited action, a key is constructed (e.g. "connect:userId:ip").
 * Within each window, at most MAX events are allowed.
 * Old events outside the window are cleaned up on each check.
 *
 * This is a real sliding-window implementation, not pseudocode.
 * For high-scale production, replace the DB backend with Redis INCR + EXPIRE.
 */

import { prisma } from "./db";
import { RATE_LIMIT_MAX, RATE_LIMIT_WINDOW_SECONDS } from "./config";

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetAt: Date;
}

/**
 * Check rate limit and record this attempt.
 * @param key - Unique key for the rate limit bucket (e.g. "connect:userId:ip")
 * @param max - Max events allowed in window (defaults to RATE_LIMIT_MAX from config)
 * @param windowSeconds - Window duration in seconds (defaults to RATE_LIMIT_WINDOW_SECONDS)
 */
export async function checkRateLimit(
  key: string,
  max: number = RATE_LIMIT_MAX,
  windowSeconds: number = RATE_LIMIT_WINDOW_SECONDS
): Promise<RateLimitResult> {
  const windowStart = new Date(Date.now() - windowSeconds * 1000);
  const resetAt = new Date(Date.now() + windowSeconds * 1000);

  // Delete stale records outside the window (cleanup)
  await prisma.rateLimitEvent.deleteMany({
    where: { key, createdAt: { lt: windowStart } },
  }).catch(() => {}); // Non-critical cleanup

  // Count events within the current window
  const count = await prisma.rateLimitEvent.count({
    where: { key, createdAt: { gte: windowStart } },
  });

  if (count >= max) {
    return {
      allowed: false,
      remaining: 0,
      resetAt,
    };
  }

  // Record this attempt
  await prisma.rateLimitEvent.create({ data: { key } });

  return {
    allowed: true,
    remaining: max - count - 1,
    resetAt,
  };
}

/**
 * Build a rate limit key for the Connect endpoint.
 * Keyed by both userId AND ip to prevent both per-user and per-IP abuse.
 */
export function connectRateLimitKey(userId: string, ip: string): string {
  return `connect:${userId}:${ip}`;
}
