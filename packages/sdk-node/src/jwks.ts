import { importJWK, type CryptoKey, type JWK, type JWSHeaderParameters } from "jose";
import { z } from "zod";
import type { ResolvedConfig } from "./config.js";
import { PortvaktError, PortvaktUnavailableError } from "./errors.js";
import { errorDetails } from "./logger.js";

const MAX_JWKS_BYTES = 512 * 1024;
const ALG = "ES256";

const jwksSchema = z.object({
  keys: z.array(z.object({ kty: z.string() }).catchall(z.unknown())).max(100),
});

/** The token names a key that is not (or no longer) in Portvakt's JWKS. */
export class UnknownKeyError extends PortvaktError {
  constructor() {
    super("unknown_key", "the token's signing key is unknown", 401);
  }
}

interface CachedKeys {
  readonly keys: readonly JWK[];
  readonly fetchedAt: number;
}

/**
 * Portvakt's signing keys (ES256) for access token validation. Keys are cached for
 * `cacheMaxAgeSeconds`; an unknown `kid` triggers a refetch, at most once per
 * `cooldownSeconds` (so tokens with made-up kids cannot hammer Portvakt). A failed refetch keeps
 * the last keys (stale-if-error) until `cacheMaxAgeSeconds + staleMaxAgeSeconds` after their last
 * successful fetch, so a Portvakt outage does not stop token validation at once; past that limit
 * validation fails as unavailable, also within the cooldown. Without any keys, a failed fetch is
 * repeated at most once per `failureCacheSeconds`.
 */
export class JwksCache {
  readonly #config: ResolvedConfig;
  readonly #jwksUri: () => Promise<string>;
  readonly #imported = new Map<string, Promise<CryptoKey>>();
  #cached: CachedKeys | undefined;
  #lastAttempt = Number.NEGATIVE_INFINITY;
  #lastFailure = Number.NEGATIVE_INFINITY;
  #pending: Promise<CachedKeys> | undefined;

  constructor(config: ResolvedConfig, jwksUri: () => Promise<string>) {
    this.#config = config;
    this.#jwksUri = jwksUri;
  }

  /** The verification key for a token header (jose's key resolver). */
  async keyFor(header: JWSHeaderParameters): Promise<CryptoKey> {
    const kid = header.kid;
    if (typeof kid !== "string" || kid.length === 0 || kid.length > 255) {
      throw new UnknownKeyError();
    }
    const now = Date.now();
    const { cacheMaxAgeSeconds, staleMaxAgeSeconds } = this.#config.jwks;
    let keys = this.#cached;
    if (keys === undefined) {
      if (now - this.#lastFailure < this.#config.failureCacheSeconds * 1000) {
        throw new PortvaktUnavailableError("Portvakt's signing keys are unavailable");
      }
      keys = await this.#refetch();
    } else if (now - keys.fetchedAt >= cacheMaxAgeSeconds * 1000 && this.#mayRefetch(now)) {
      keys = await this.#refetch();
    }
    let jwk = findKey(keys.keys, kid);
    if (jwk === undefined && this.#mayRefetch(Date.now())) {
      keys = await this.#refetch();
      jwk = findKey(keys.keys, kid);
    }
    // Keys whose refetches kept failing are trusted only for a bounded time.
    if (Date.now() - keys.fetchedAt > (cacheMaxAgeSeconds + staleMaxAgeSeconds) * 1000) {
      throw new PortvaktUnavailableError("Portvakt's signing keys are too old to trust");
    }
    if (jwk === undefined) throw new UnknownKeyError();
    return this.#import(jwk);
  }

  #mayRefetch(now: number): boolean {
    return now - this.#lastAttempt >= this.#config.jwks.cooldownSeconds * 1000;
  }

  /** Fetches the JWKS; on failure the cached keys stay (keyFor bounds their age). */
  async #refetch(): Promise<CachedKeys> {
    this.#pending ??= this.#fetch().finally(() => {
      this.#pending = undefined;
    });
    try {
      return await this.#pending;
    } catch (error) {
      this.#lastFailure = Date.now();
      const cached = this.#cached;
      if (cached !== undefined) {
        this.#config.logger.warn(errorDetails(error), "Portvakt JWKS refetch failed; using cache");
        return cached;
      }
      this.#config.logger.error(errorDetails(error), "Portvakt JWKS unavailable");
      throw new PortvaktUnavailableError("Portvakt's signing keys are unavailable", {
        cause: error,
      });
    }
  }

  async #fetch(): Promise<CachedKeys> {
    this.#lastAttempt = Date.now();
    const uri = await this.#jwksUri();
    const target = new URL(uri);
    if (target.protocol !== "https:" && !this.#config.allowInsecureRequests) {
      throw new Error("jwks_uri must be https");
    }
    const fetchImpl = this.#config.fetch ?? fetch;
    const response = await fetchImpl(target, {
      headers: { accept: "application/json" },
      redirect: "error",
      signal: AbortSignal.timeout(this.#config.httpTimeoutSeconds * 1000),
    });
    if (!response.ok) throw new Error(`jwks_uri answered ${response.status}`);
    const text = await response.text();
    if (text.length > MAX_JWKS_BYTES) throw new Error("jwks_uri response too large");
    const parsed = jwksSchema.parse(JSON.parse(text));
    const keys: CachedKeys = { keys: parsed.keys, fetchedAt: Date.now() };
    this.#cached = keys;
    return keys;
  }

  #import(jwk: JWK): Promise<CryptoKey> {
    const id = JSON.stringify([jwk.kid, jwk.x, jwk.y, jwk.crv]);
    let key = this.#imported.get(id);
    if (key === undefined) {
      key = importJWK({ ...jwk, alg: ALG }, ALG).then((imported) => {
        if (imported instanceof Uint8Array) throw new UnknownKeyError();
        return imported;
      });
      key.catch(() => this.#imported.delete(id));
      this.#imported.set(id, key);
      if (this.#imported.size > 50) {
        const oldest = this.#imported.keys().next().value;
        if (oldest !== undefined) this.#imported.delete(oldest);
      }
    }
    return key;
  }
}

/** A public ES256 signing key with this kid. */
function findKey(keys: readonly JWK[], kid: string): JWK | undefined {
  return keys.find(
    (key) =>
      key.kid === kid &&
      key.kty === "EC" &&
      key.crv === "P-256" &&
      (key.alg === undefined || key.alg === ALG) &&
      (key.use === undefined || key.use === "sig") &&
      key.d === undefined,
  );
}
