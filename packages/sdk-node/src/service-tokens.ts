import * as client from "openid-client";
import type { ResolvedConfig } from "./config.js";
import { DiscoveryCache, isUnavailable, oauthErrorOf, transientRefusal } from "./discovery.js";
import { PortvaktError, PortvaktUnavailableError } from "./errors.js";
import { errorDetails } from "./logger.js";

/** Portvakt's resource indicator (RFC 8707) of an application. */
export const resourceIndicatorFor = (clientId: string): string => `urn:portvakt:app:${clientId}`;

/** Cached client_credentials tokens for one target application. */
export interface ServiceTokenSource {
  /** The target application's client_id (the token's `aud`). */
  readonly audience: string;
  /** A valid access token, fetched again shortly before the cached one expires. */
  getToken(): Promise<string>;
  /** Drops the cached token (for example after the target answered 401). */
  clear(): void;
}

/** Fetches early: 10% of the lifetime, at least 30 seconds, at most half the lifetime. */
function refreshMargin(lifetimeSeconds: number): number {
  return Math.min(Math.max(30, lifetimeSeconds * 0.1), lifetimeSeconds / 2);
}

export class ClientCredentialsSource implements ServiceTokenSource {
  readonly audience: string;
  readonly #config: ResolvedConfig;
  readonly #discovery: DiscoveryCache;
  #cached: { readonly token: string; readonly refreshAt: number } | undefined;
  #pending: Promise<string> | undefined;

  constructor(config: ResolvedConfig, discovery: DiscoveryCache, audience: string) {
    this.#config = config;
    this.#discovery = discovery;
    this.audience = audience;
  }

  async getToken(): Promise<string> {
    const cached = this.#cached;
    if (cached !== undefined && Date.now() < cached.refreshAt) return cached.token;
    this.#pending ??= this.#fetch().finally(() => {
      this.#pending = undefined;
    });
    return this.#pending;
  }

  clear(): void {
    this.#cached = undefined;
  }

  async #fetch(): Promise<string> {
    const configuration = await this.#discovery.get();
    let response: Awaited<ReturnType<typeof client.clientCredentialsGrant>>;
    try {
      response = await client.clientCredentialsGrant(configuration, {
        resource: resourceIndicatorFor(this.audience),
      });
    } catch (error) {
      this.#config.logger.warn(
        { ...errorDetails(error), audience: this.audience },
        "client_credentials grant failed",
      );
      // 429 or temporarily_unavailable: Portvakt asked to be retried later, as at a refresh.
      const transient = await transientRefusal(error);
      if (transient !== undefined) {
        throw new PortvaktUnavailableError("Portvakt asked to retry later", {
          cause: error,
          retryAfterSeconds: transient.retryAfterSeconds,
        });
      }
      if (isUnavailable(error)) {
        throw new PortvaktUnavailableError("Portvakt is unavailable", { cause: error });
      }
      const code = oauthErrorOf(error) ?? "token_request_failed";
      throw new PortvaktError(code, "Portvakt refused the client_credentials grant", 502, {
        cause: error,
      });
    }
    const lifetime = response.expiresIn() ?? 60;
    this.#cached = {
      token: response.access_token,
      refreshAt: Date.now() + (lifetime - refreshMargin(lifetime)) * 1000,
    };
    return response.access_token;
  }
}
