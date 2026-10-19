import type { Request, RequestHandler } from "express";
import {
  accessTokenPrincipal,
  AccessTokenValidator,
  type AccessTokenRequirements,
} from "./access-token.js";
import { createBff, type BffOptions, type PortvaktBff } from "./bff/bff.js";
import { resolveConfig, type PortvaktClientConfig, type ResolvedConfig } from "./config.js";
import { DiscoveryCache } from "./discovery.js";
import { PortvaktConfigError } from "./errors.js";
import { JwksCache } from "./jwks.js";
import type { Principal } from "./principal.js";
import { ClientCredentialsSource, type ServiceTokenSource } from "./service-tokens.js";

/** One application's connection to its Portvakt tenant. Create it once per process. */
export interface PortvaktClient {
  /** The validated configuration with defaults applied. */
  readonly config: ResolvedConfig;
  /** Backend-for-frontend login for a web application: an Express router plus helpers. */
  bff(options: BffOptions): PortvaktBff;
  /**
   * Express middleware for APIs: validates the bearer access token and checks the route's
   * requirements; the principal is then available through {@link PortvaktClient.principal}.
   */
  requireAccessToken(requirements: AccessTokenRequirements): RequestHandler;
  /** Validates an access token for `audience` without Express (throws on failure). */
  verifyAccessToken(token: string, audience: string): Promise<Principal>;
  /** The principal {@link PortvaktClient.requireAccessToken} attached to the request. */
  principal(req: Request): Principal | undefined;
  /**
   * client_credentials tokens for calling another application of the tenant (`audience` is its
   * client_id, default this application), cached until shortly before they expire.
   */
  clientCredentials(options?: { readonly audience?: string }): ServiceTokenSource;
}

/**
 * Creates the client of one application. The configuration is validated now (throws
 * {@link PortvaktConfigError}); Portvakt itself is contacted lazily, on first use.
 */
export function createPortvaktClient(input: PortvaktClientConfig): PortvaktClient {
  const config = resolveConfig(input);
  const discovery = new DiscoveryCache(config);
  const jwks = new JwksCache(config, async () => {
    const uri = (await discovery.get()).serverMetadata().jwks_uri;
    if (uri === undefined) throw new Error("Portvakt's metadata has no jwks_uri");
    return uri;
  });
  const validator = new AccessTokenValidator(config, jwks);
  const sources = new Map<string, ServiceTokenSource>();
  return {
    config,
    bff: (options) => createBff({ config, discovery, jwks }, options),
    requireAccessToken: (requirements) => validator.middleware(requirements),
    verifyAccessToken: (token, audience) => validator.verify(token, audience),
    principal: (req) => accessTokenPrincipal(req),
    clientCredentials: (options = {}) => {
      const audience = options.audience ?? config.clientId;
      if (typeof audience !== "string" || !/^[\x21-\x7e]{1,255}$/.test(audience)) {
        throw new PortvaktConfigError(["clientCredentials.audience: invalid client_id"]);
      }
      let source = sources.get(audience);
      if (source === undefined) {
        source = new ClientCredentialsSource(config, discovery, audience);
        sources.set(audience, source);
      }
      return source;
    },
  };
}
