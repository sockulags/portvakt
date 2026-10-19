import { ipRateLimitKey, RateLimiterSet, type RateLimit } from "@portvakt/http-kit";
import type { Request, Response } from "express";
import type { RateLimitName } from "../config/index.js";
import { METRICS, type Counter, type MetricRegistry } from "../metrics/registry.js";

export type RateLimitCheck = readonly [RateLimitName, string];

export type RateLimitOutcome =
  | { readonly allowed: true }
  | { readonly allowed: false; readonly limit: RateLimitName; readonly retryAfterSeconds: number };

/**
 * The server's rate limits (RATE_LIMIT_*): token buckets in memory, per replica. Keys are the
 * client IP as Express resolves it under TRUST_PROXY, a tenant's client_id, or an admin API
 * caller; nothing else from the request. A refusal is counted in `portvakt_rate_limited_total`
 * by limit name (never the key) and answered with 429 and `Retry-After` by the caller, in the
 * shape of the endpoint (OAuth error JSON, login UI page, problem+json).
 */
export class RequestLimits {
  readonly #limiters: RateLimiterSet<RateLimitName>;
  readonly #refused: Counter;

  constructor(limits: Readonly<Record<RateLimitName, RateLimit | null>>, metrics: MetricRegistry) {
    this.#limiters = new RateLimiterSet(limits);
    this.#refused = metrics.counter(METRICS.rateLimited, "Requests refused by a rate limit");
  }

  /** Takes a token for each check in order (stops at the first refusal, which is counted). */
  check(checks: readonly RateLimitCheck[]): RateLimitOutcome {
    const outcome = this.#limiters.check(checks);
    if (!outcome.allowed) this.#refused.inc({ limit: outcome.limit });
    return outcome;
  }
}

/**
 * The rate-limit key of the client IP Express resolved (TRUST_PROXY decides how many forwarded
 * hops count): the IPv4 address, or the /64 prefix of an IPv6 address (`ipRateLimitKey`).
 */
export const clientIpKey = (req: Request): string =>
  ipRateLimitKey(req.ip ?? req.socket.remoteAddress ?? "unknown");

/** 429 with `Retry-After` and no caching; the caller writes the body. */
export function tooManyRequests(res: Response, retryAfterSeconds: number): Response {
  return res
    .status(429)
    .set({ "Retry-After": String(retryAfterSeconds), "Cache-Control": "no-store" });
}
