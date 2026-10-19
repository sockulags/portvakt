import { importJWK } from "jose";
import * as client from "openid-client";
import type { ResolvedConfig } from "./config.js";
import { PortvaktConfigError, PortvaktError, PortvaktUnavailableError } from "./errors.js";
import { errorDetails } from "./logger.js";

/** After a failed refresh, stale metadata is used this long before discovery is tried again. */
const RETRY_AFTER_FAILURE_MS = 30_000;

/** openid-client's client authentication for the configured method. */
async function clientAuthFor(config: ResolvedConfig): Promise<client.ClientAuth> {
  const auth = config.clientAuth;
  switch (auth.method) {
    case "client_secret_basic":
      return client.ClientSecretBasic(auth.clientSecret);
    case "client_secret_post":
      return client.ClientSecretPost(auth.clientSecret);
    case "private_key_jwt": {
      const jwk = auth.privateJwk;
      const alg = typeof jwk.alg === "string" ? jwk.alg : jwk.kty === "EC" ? "ES256" : undefined;
      if (alg === undefined) {
        throw new PortvaktConfigError(["clientAuth.privateJwk: alg is required for this key type"]);
      }
      let key: Awaited<ReturnType<typeof importJWK>>;
      try {
        key = await importJWK({ ...jwk, alg }, alg);
      } catch {
        throw new PortvaktConfigError(["clientAuth.privateJwk: not a valid private key"]);
      }
      if (key instanceof Uint8Array || key.type !== "private") {
        throw new PortvaktConfigError(["clientAuth.privateJwk: must be an asymmetric private key"]);
      }
      return client.PrivateKeyJwt({ key, kid: String(jwk.kid) });
    }
  }
}

/** openid-client codes for a response it could not use (an HTML error page, a proxy's 502). */
const UNUSABLE_RESPONSE = new Set(["OAUTH_RESPONSE_IS_NOT_CONFORM", "OAUTH_RESPONSE_IS_NOT_JSON"]);

/**
 * Whether a failure means Portvakt is unreachable: a network error, a timeout, or a 5xx answer
 * (also one openid-client rejects as not conforming, whose `cause` is the Response itself).
 */
export function isUnavailable(error: unknown, depth = 0): boolean {
  if (depth > 5) return false;
  if (error instanceof PortvaktUnavailableError) return true;
  if (error instanceof Response) return error.status >= 500;
  if (error instanceof client.ResponseBodyError) return error.status >= 500;
  if (error instanceof client.WWWAuthenticateChallengeError) return error.status >= 500;
  if (!(error instanceof Error)) return false;
  if (error.name === "AbortError" || error.name === "TimeoutError") return true;
  if (error instanceof TypeError && /fetch failed|network/i.test(error.message)) return true;
  const cause = (error as { cause?: unknown }).cause;
  const code = (error as { code?: unknown }).code;
  if (typeof code === "string" && UNUSABLE_RESPONSE.has(code)) {
    // The cause is the Response: 5xx (502, 503, 504 from a proxy) is an outage; a 4xx that is
    // not JSON is not. Without a Response, openid-client could not read an answer at all.
    return cause instanceof Response ? cause.status >= 500 : true;
  }
  if (cause !== undefined && cause !== error) return isUnavailable(cause, depth + 1);
  return false;
}

/** Seconds of a `Retry-After` header (delta-seconds or an HTTP date), bounded to 1..3600. */
export function retryAfterSeconds(value: string | null | undefined): number | undefined {
  if (value === null || value === undefined || value.trim() === "") return undefined;
  const trimmed = value.trim();
  const seconds = /^\d{1,10}$/.test(trimmed)
    ? Number(trimmed)
    : Math.ceil((Date.parse(trimmed) - Date.now()) / 1000);
  if (!Number.isFinite(seconds)) return undefined;
  return Math.min(3600, Math.max(1, seconds));
}

/**
 * Whether Portvakt's token endpoint asked to be retried later: HTTP 429 (rate limited), or the
 * OAuth error `temporarily_unavailable` with any status. Such an answer is transient: a session
 * keeps its (unchanged, unused) refresh token and no outage starts. Returns the `Retry-After`
 * (seconds, when Portvakt sent one), or `undefined` when the failure is not transient.
 */
export async function transientRefusal(
  error: unknown,
  depth = 0,
): Promise<{ readonly retryAfterSeconds: number | undefined } | undefined> {
  if (depth > 5 || !(error instanceof Error || error instanceof Response)) return undefined;
  if (error instanceof Response) {
    const transient = { retryAfterSeconds: retryAfterSeconds(error.headers.get("retry-after")) };
    if (error.status === 429) return transient;
    // A 5xx answer is not parsed by openid-client: its body may still say temporarily_unavailable.
    if (!/json/i.test(error.headers.get("content-type") ?? "") || error.bodyUsed) return undefined;
    try {
      const text = await error.clone().text();
      if (text.length > 16_384) return undefined;
      const body = JSON.parse(text) as { error?: unknown } | null;
      return body?.error === "temporarily_unavailable" ? transient : undefined;
    } catch {
      return undefined;
    }
  }
  if (error instanceof client.ResponseBodyError) {
    if (error.status !== 429 && error.error !== "temporarily_unavailable") return undefined;
    return { retryAfterSeconds: retryAfterSeconds(error.response.headers.get("retry-after")) };
  }
  const cause = (error as { cause?: unknown }).cause;
  return cause !== undefined && cause !== error ? transientRefusal(cause, depth + 1) : undefined;
}

/**
 * Portvakt's discovery metadata as an openid-client `Configuration`, cached for
 * `discoveryCacheSeconds` and fetched once at a time. When a refresh fails the last good
 * metadata stays in use (stale-if-error); without any, requests fail with
 * {@link PortvaktUnavailableError}. openid-client checks that the discovered issuer is exactly
 * the configured one.
 */
export class DiscoveryCache {
  readonly #config: ResolvedConfig;
  #auth: Promise<client.ClientAuth> | undefined;
  #current: { readonly configuration: client.Configuration; fetchedAt: number } | undefined;
  #pending: Promise<client.Configuration> | undefined;
  #retryAt = 0;
  /** The last failure while nothing was cached, repeated without a request until `until`. */
  #failure: { readonly error: unknown; readonly until: number } | undefined;

  constructor(config: ResolvedConfig) {
    this.#config = config;
  }

  /** The client authentication (imports a private key once). */
  clientAuth(): Promise<client.ClientAuth> {
    this.#auth ??= clientAuthFor(this.#config);
    return this.#auth;
  }

  async get(): Promise<client.Configuration> {
    const now = Date.now();
    const current = this.#current;
    if (current !== undefined) {
      const fresh = now - current.fetchedAt < this.#config.discoveryCacheSeconds * 1000;
      if (fresh || now < this.#retryAt) return current.configuration;
    } else if (this.#failure !== undefined && now < this.#failure.until) {
      // Negative cache: requests during an outage do not each hit Portvakt.
      throw this.#failure.error;
    }
    this.#pending ??= this.#discover().finally(() => {
      this.#pending = undefined;
    });
    try {
      return await this.#pending;
    } catch (error) {
      if (current !== undefined) {
        this.#retryAt = Date.now() + RETRY_AFTER_FAILURE_MS;
        this.#config.logger.warn(
          errorDetails(error),
          "Portvakt discovery refresh failed; using cached metadata",
        );
        return current.configuration;
      }
      this.#failure = { error, until: Date.now() + this.#config.failureCacheSeconds * 1000 };
      throw error;
    }
  }

  async #discover(): Promise<client.Configuration> {
    const config = this.#config;
    const auth = await this.clientAuth();
    const options: client.DiscoveryRequestOptions = {
      timeout: config.httpTimeoutSeconds,
      ...(config.allowInsecureRequests ? { execute: [client.allowInsecureRequests] } : {}),
      ...(config.fetch === undefined ? {} : { [client.customFetch]: customFetchOf(config.fetch) }),
    };
    let configuration: client.Configuration;
    try {
      configuration = await client.discovery(
        new URL(config.issuer),
        config.clientId,
        {
          id_token_signed_response_alg: "ES256",
          [client.clockTolerance]: config.clockSkewSeconds,
        },
        auth,
        options,
      );
    } catch (error) {
      config.logger.error(errorDetails(error), "Portvakt discovery failed");
      if (isUnavailable(error)) {
        throw new PortvaktUnavailableError("Portvakt discovery failed", { cause: error });
      }
      throw new PortvaktError("discovery_failed", "Portvakt discovery failed", 502, {
        cause: error,
      });
    }
    configuration.timeout = config.httpTimeoutSeconds;
    if (config.fetch !== undefined) configuration[client.customFetch] = customFetchOf(config.fetch);
    // ID tokens from the token endpoint are verified against Portvakt's JWKS by the BFF itself
    // (`JwksCache`, bff.ts), not by openid-client's non-repudiation checks: their JWKS cache
    // refetches an unknown kid only once its copy is 60 s old, so a manual key rotation ended
    // every session refreshed within a minute of the BFF's last JWKS download.
    this.#current = { configuration, fetchedAt: Date.now() };
    this.#retryAt = 0;
    this.#failure = undefined;
    return configuration;
  }
}

/** openid-client's custom fetch hook over a plain fetch implementation. */
export function customFetchOf(fetchImpl: typeof fetch): client.CustomFetch {
  return (url, options) => fetchImpl(url, options);
}
