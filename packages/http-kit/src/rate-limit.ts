/**
 * Token-bucket rate limiting in memory, per replica. A bucket holds up to `capacity` tokens and
 * refills `capacity` tokens per `periodSeconds` (continuously); each request takes one. Limits
 * therefore apply per replica: with N replicas a client gets up to N times the limit, which is why
 * the operations docs recommend an ingress limit in front as well.
 *
 * Buckets live in a bounded map (least recently used evicted first): a flood of distinct keys
 * cannot exhaust memory, it only forgets the oldest buckets (which then start full again).
 */

export interface RateLimit {
  /** Burst size: tokens a full bucket holds. */
  readonly capacity: number;
  /** The bucket refills `capacity` tokens over this many seconds. */
  readonly periodSeconds: number;
}

export interface RateLimitDecision {
  readonly allowed: boolean;
  /** Whole seconds until a token is available again (0 when allowed). */
  readonly retryAfterSeconds: number;
}

const UNIT_SECONDS: Readonly<Record<string, number>> = { s: 1, m: 60, h: 3600 };
const SPEC = /^(\d{1,7})\/(\d{0,5})([smh])$/;

/**
 * Parses `<count>/<period>` (`60/1m`, `10/30s`, `1000/1h`; the period number may be omitted:
 * `60/m`). `off` (or `0`) disables the limit: `null`. Anything else: `undefined`.
 */
export function parseRateLimit(input: string): RateLimit | null | undefined {
  const value = input.trim().toLowerCase();
  if (value === "off" || value === "0") return null;
  const match = SPEC.exec(value);
  if (match === null) return undefined;
  const capacity = Number(match[1]);
  const amount = match[2] === "" ? 1 : Number(match[2]);
  const periodSeconds = amount * (UNIT_SECONDS[match[3] ?? "s"] ?? 1);
  if (capacity < 1 || periodSeconds < 1) return undefined;
  return { capacity, periodSeconds };
}

/** The limit as `<count>/<seconds>s` (logs and docs). */
export const formatRateLimit = (limit: RateLimit | null): string =>
  limit === null ? "off" : `${limit.capacity}/${limit.periodSeconds}s`;

interface Bucket {
  tokens: number;
  updatedAt: number;
}

export interface TokenBucketOptions {
  /** Buckets kept at most (default 50,000); the least recently used are evicted first. */
  readonly maxKeys?: number;
  /** Monotonic clock in milliseconds (tests). */
  readonly now?: () => number;
}

export class TokenBucketLimiter {
  readonly limit: RateLimit;
  readonly #buckets = new Map<string, Bucket>();
  readonly #maxKeys: number;
  readonly #now: () => number;
  readonly #ratePerMs: number;

  constructor(limit: RateLimit, options: TokenBucketOptions = {}) {
    if (!(limit.capacity >= 1) || !(limit.periodSeconds > 0)) {
      throw new RangeError("a rate limit needs a capacity and a period");
    }
    this.limit = limit;
    this.#maxKeys = options.maxKeys ?? 50_000;
    this.#now = options.now ?? (() => performance.now());
    this.#ratePerMs = limit.capacity / (limit.periodSeconds * 1000);
  }

  /** Takes one token from `key`'s bucket. */
  take(key: string): RateLimitDecision {
    const now = this.#now();
    let bucket = this.#buckets.get(key);
    if (bucket === undefined) {
      bucket = { tokens: this.limit.capacity, updatedAt: now };
      if (this.#buckets.size >= this.#maxKeys) {
        const oldest = this.#buckets.keys().next();
        if (oldest.done !== true) this.#buckets.delete(oldest.value);
      }
    } else {
      // Most recently used last: Map keeps insertion order.
      this.#buckets.delete(key);
      const elapsed = Math.max(0, now - bucket.updatedAt);
      bucket.tokens = Math.min(this.limit.capacity, bucket.tokens + elapsed * this.#ratePerMs);
      bucket.updatedAt = now;
    }
    this.#buckets.set(key, bucket);
    if (bucket.tokens >= 1) {
      bucket.tokens -= 1;
      return { allowed: true, retryAfterSeconds: 0 };
    }
    const waitMs = (1 - bucket.tokens) / this.#ratePerMs;
    return { allowed: false, retryAfterSeconds: Math.max(1, Math.ceil(waitMs / 1000)) };
  }

  /** Buckets currently held (tests). */
  get size(): number {
    return this.#buckets.size;
  }
}

/**
 * Several named limits, each with its own buckets. `check` takes from each named bucket in turn
 * and stops at the first refusal, so a request refused by its per-IP limit does not also drain
 * a shared bucket (for example the per-client one) it never reached.
 */
export class RateLimiterSet<Name extends string> {
  readonly #limiters = new Map<Name, TokenBucketLimiter>();

  constructor(limits: Readonly<Record<Name, RateLimit | null>>, options: TokenBucketOptions = {}) {
    for (const [name, limit] of Object.entries(limits) as [Name, RateLimit | null][]) {
      if (limit !== null) this.#limiters.set(name, new TokenBucketLimiter(limit, options));
    }
  }

  /** Whether `name` is limited at all (`off` limits are not). */
  enabled(name: Name): boolean {
    return this.#limiters.has(name);
  }

  /**
   * Takes a token for each `[name, key]` in order; the first refusal names its limit. Disabled
   * limits always allow.
   */
  check(
    checks: readonly (readonly [Name, string])[],
  ):
    | { readonly allowed: true }
    | { readonly allowed: false; readonly limit: Name; readonly retryAfterSeconds: number } {
    for (const [name, key] of checks) {
      const limiter = this.#limiters.get(name);
      if (limiter === undefined) continue;
      const decision = limiter.take(key);
      if (!decision.allowed) {
        return { allowed: false, limit: name, retryAfterSeconds: decision.retryAfterSeconds };
      }
    }
    return { allowed: true };
  }
}
