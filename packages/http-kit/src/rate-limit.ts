/**
 * Token-bucket rate limiting in memory, per replica. A bucket holds up to `capacity` tokens and
 * refills `capacity` tokens per `periodSeconds` (continuously); each request takes one. Limits
 * therefore apply per replica: with N replicas a client gets up to N times the limit, which is why
 * the operations docs recommend an ingress limit in front as well.
 *
 * Buckets live in a bounded map (least recently used evicted first): a flood of distinct keys
 * cannot exhaust memory, it only forgets the oldest buckets (which then start full again).
 */

/**
 * The rate-limit key of a client IP: an IPv4 address as it is (also when it arrives IPv4-mapped,
 * `::ffff:192.0.2.1`), an IPv6 address by its /64 prefix (`2001:db8:1:2::/64`). One subscriber
 * or host usually holds a whole /64, so keying single IPv6 addresses would give it billions of
 * buckets. Anything that is not an IP address is returned unchanged.
 */
export function ipRateLimitKey(ip: string): string {
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(ip);
  if (mapped !== null) return mapped[1]!;
  if (!ip.includes(":")) return ip;
  const hextets = expandIpv6(ip);
  if (hextets === undefined) return ip;
  return `${hextets.slice(0, 4).join(":")}::/64`;
}

/** The eight hextets of an IPv6 address (lowercase, no leading zeros), or undefined. */
function expandIpv6(input: string): string[] | undefined {
  let address = input.toLowerCase();
  const zone = address.indexOf("%");
  if (zone >= 0) address = address.slice(0, zone);
  if (address.startsWith("[") && address.endsWith("]")) address = address.slice(1, -1);
  // An embedded IPv4 tail (`::1.2.3.4`) counts as two hextets.
  const v4 = /(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(address);
  if (v4 !== null) {
    const bytes = v4.slice(1).map(Number);
    if (bytes.some((byte) => byte > 255)) return undefined;
    const [a, b, c, d] = bytes as [number, number, number, number];
    address = `${address.slice(0, v4.index)}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }
  const halves = address.split("::");
  if (halves.length > 2) return undefined;
  const head = halves[0] === "" ? [] : halves[0]!.split(":");
  const tail = halves.length === 2 && halves[1] !== "" ? halves[1]!.split(":") : [];
  const missing = 8 - head.length - tail.length;
  if (halves.length === 1 ? missing !== 0 : missing < 1) return undefined;
  const hextets = [...head, ...Array<string>(halves.length === 2 ? missing : 0).fill("0"), ...tail];
  if (hextets.some((part) => !/^[0-9a-f]{1,4}$/.test(part))) return undefined;
  return hextets.map((part) => Number.parseInt(part, 16).toString(16));
}

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
