import { decodeJwt, importJWK } from "jose";
import * as client from "openid-client";
import type { OidcLoginMethod } from "../domain/login-method.js";
import type { Logger } from "../logging/logger.js";
import type { OutboundGuard } from "../net/outbound.js";
import type { LoginMethodRepository } from "../repositories/login-methods.js";

/**
 * ID token signature algorithms accepted from upstream IdPs: asymmetric only (no `none`, no
 * HMAC with the client secret).
 */
export const UPSTREAM_ID_TOKEN_ALGS: ReadonlySet<string> = new Set([
  "RS256",
  "RS384",
  "RS512",
  "PS256",
  "PS384",
  "PS512",
  "ES256",
  "ES384",
  "ES512",
  "EdDSA",
  "Ed25519",
]);

/** Placeholder of multi-tenant issuers (Entra ID `/common`, `/organizations` discovery). */
const TENANT_PLACEHOLDER = "{tenantid}";

/** The login method cannot be used as configured (missing secret, http issuer in production). */
export class UpstreamMisconfiguredError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UpstreamMisconfiguredError";
  }
}

/** Discovery failed a moment ago; it is not retried until the failure cache entry expires. */
export class UpstreamRecentlyFailedError extends Error {
  constructor() {
    super("upstream discovery failed recently");
    this.name = "UpstreamRecentlyFailedError";
  }
}

/** The ID token's upstream tenant (`tid`) is not one the login method allows. */
export class UpstreamTenantRefusedError extends Error {
  constructor() {
    super("upstream tenant not allowed");
    this.name = "UpstreamTenantRefusedError";
  }
}

export interface UpstreamClientsOptions {
  readonly loginMethods: LoginMethodRepository;
  readonly logger: Logger;
  /** Production refuses plain-http upstream issuers. */
  readonly production: boolean;
  readonly timeoutSeconds: number;
  /** Discovered metadata is reused this long, then fetched again. */
  readonly metadataTtlSeconds: number;
  /** A failed discovery is not retried for this long (0: always retried). */
  readonly failureCacheSeconds: number;
  /** Every upstream request (discovery, JWKS, token, userinfo) goes through the SSRF guard. */
  readonly outbound: OutboundGuard;
}

/** What a login method talks to upstream with. */
export interface UpstreamSetup {
  /** For authorization URLs (and, single-tenant, everything else). */
  readonly config: client.Configuration;
  /** The discovered issuer contains `{tenantid}`: every upstream tenant signs with its own. */
  readonly templated: boolean;
  readonly metadata: client.ServerMetadata;
  readonly auth: client.ClientAuth;
  readonly insecure: boolean;
}

interface CacheEntry {
  readonly key: string;
  readonly expiresAt: number;
  readonly setup: Promise<UpstreamSetup>;
}

/** Token endpoint response captured by the first pass of a templated-issuer exchange. */
class CapturedTokenResponse extends Error {
  readonly status: number;
  readonly headers: Headers;
  readonly body: string;

  constructor(status: number, headers: Headers, body: string) {
    super("captured token response");
    this.status = status;
    this.headers = headers;
    this.body = body;
  }
}

type CustomFetch = (url: string, options: client.CustomFetchOptions) => Promise<Response>;

/** The upstream tenant (`tid`) of a token response's ID token, read before validation. */
function unverifiedTenant(body: string): string | undefined {
  try {
    const parsed = JSON.parse(body) as { id_token?: unknown };
    if (typeof parsed.id_token !== "string") return undefined;
    const tid = decodeJwt(parsed.id_token).tid;
    return typeof tid === "string" && /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(tid)
      ? tid
      : undefined;
  } catch {
    return undefined;
  }
}

/**
 * openid-client configurations per login method: discovery of the upstream issuer (cached for
 * `metadataTtlSeconds`, dropped as soon as the login method changes, and a failure cached for
 * `failureCacheSeconds`), the client authentication the method uses, and ID token signature
 * checks against the upstream JWKS on every token response (`enableNonRepudiationChecks`).
 *
 * Multi-tenant issuers (discovered issuer with `{tenantid}`) sign every ID token with the issuer
 * of the user's tenant. The tenant is only known from the token response, and the code can be
 * redeemed once, so {@link exchangeCode} captures the token response once, reads its `tid`
 * (refused unless the login method allows it), and validates that same response against a
 * configuration whose issuer is the tenant's.
 */
export class UpstreamClients {
  readonly #options: UpstreamClientsOptions;
  readonly #cache = new Map<string, CacheEntry>();
  readonly #failures = new Map<string, { readonly key: string; readonly until: number }>();

  constructor(options: UpstreamClientsOptions) {
    this.#options = options;
  }

  async setupFor(method: OidcLoginMethod): Promise<UpstreamSetup> {
    // A changed login method (issuer, client, secret, auth method) has a new updatedAt.
    const key = `${method.updatedAt.toISOString()}|${method.clientAuthMethod}`;
    const failure = this.#failures.get(method.id);
    if (failure !== undefined && failure.key === key && failure.until > Date.now()) {
      throw new UpstreamRecentlyFailedError();
    }
    const cached = this.#cache.get(method.id);
    if (cached !== undefined && cached.key === key && cached.expiresAt > Date.now()) {
      return cached.setup;
    }
    const setup = this.#discover(method);
    this.#cache.set(method.id, {
      key,
      expiresAt: Date.now() + this.#options.metadataTtlSeconds * 1000,
      setup,
    });
    setup.catch((error: unknown) => {
      if (this.#cache.get(method.id)?.setup === setup) this.#cache.delete(method.id);
      if (!(error instanceof UpstreamMisconfiguredError) && this.#options.failureCacheSeconds > 0) {
        this.#failures.set(method.id, {
          key,
          until: Date.now() + this.#options.failureCacheSeconds * 1000,
        });
      }
    });
    return setup;
  }

  /** Drops the cached configuration of a login method (after an upstream failure). */
  forget(loginMethodId: string): void {
    this.#cache.delete(loginMethodId);
  }

  /**
   * Redeems the authorization code of `currentUrl` and validates the response (state, iss,
   * nonce, PKCE, max_age, ID token signature and claims). Returns the tokens and the
   * configuration to use for this login afterwards (userinfo).
   */
  async exchangeCode(
    method: OidcLoginMethod,
    currentUrl: URL,
    checks: client.AuthorizationCodeGrantChecks,
  ): Promise<{
    readonly tokens: Awaited<ReturnType<typeof client.authorizationCodeGrant>>;
    readonly config: client.Configuration;
  }> {
    const setup = await this.setupFor(method);
    if (!setup.templated) {
      return {
        tokens: await client.authorizationCodeGrant(setup.config, currentUrl, checks),
        config: setup.config,
      };
    }
    const template = setup.metadata.issuer;
    const [before = "", after = ""] = template.split(TENANT_PLACEHOLDER);
    const escape = (text: string): string => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const pattern = new RegExp(`^${escape(before)}[A-Za-z0-9._-]+${escape(after)}$`);
    const responseIss = currentUrl.searchParams.get("iss");
    // First pass: the authorization response checks and the token request; the response is
    // captured before any ID token validation.
    const firstIssuer =
      responseIss !== null && pattern.test(responseIss)
        ? responseIss
        : template.replace(TENANT_PLACEHOLDER, "common");
    const capture = this.#configuration(method, setup, firstIssuer, async (url, options) => {
      const response = await this.#fetch(url, options);
      if (url !== setup.metadata.token_endpoint) return response;
      throw new CapturedTokenResponse(response.status, response.headers, await response.text());
    });
    let captured: CapturedTokenResponse;
    try {
      await client.authorizationCodeGrant(capture, currentUrl, checks);
      throw new Error("token response was not captured");
    } catch (error) {
      // openid-client wraps errors thrown by a custom fetch in a ClientError.
      const signal = error instanceof client.ClientError ? error.cause : error;
      if (!(signal instanceof CapturedTokenResponse)) throw error;
      captured = signal;
    }
    const tid = unverifiedTenant(captured.body);
    if (tid === undefined || !method.allowedUpstreamTenants.includes(tid)) {
      throw new UpstreamTenantRefusedError();
    }
    // Second pass: the same response, validated against the tenant's issuer.
    let replayed = false;
    const config = this.#configuration(
      method,
      setup,
      template.replace(TENANT_PLACEHOLDER, tid),
      (url, options) => {
        if (url === setup.metadata.token_endpoint && !replayed) {
          replayed = true;
          return Promise.resolve(
            new Response(captured.body, { status: captured.status, headers: captured.headers }),
          );
        }
        return this.#fetch(url, options);
      },
    );
    return { tokens: await client.authorizationCodeGrant(config, currentUrl, checks), config };
  }

  #configuration(
    method: OidcLoginMethod,
    setup: UpstreamSetup,
    issuer: string,
    fetchImpl: CustomFetch,
  ): client.Configuration {
    const config = new client.Configuration(
      { ...setup.metadata, issuer },
      method.clientId,
      undefined,
      setup.auth,
    );
    this.#harden(config, setup.insecure);
    config[client.customFetch] = fetchImpl;
    return config;
  }

  /** Upstream requests through the outbound guard (SSRF, redirects, size). */
  readonly #fetch: CustomFetch = (url, options) => this.#options.outbound.fetch(url, options);

  #harden(config: client.Configuration, insecure: boolean): void {
    config[client.customFetch] = this.#fetch;
    if (insecure) client.allowInsecureRequests(config);
    config.timeout = this.#options.timeoutSeconds;
    client.enableNonRepudiationChecks(config);
  }

  async #discover(method: OidcLoginMethod): Promise<UpstreamSetup> {
    const issuer = new URL(method.issuer);
    const insecure = issuer.protocol === "http:";
    if (insecure && this.#options.production) {
      throw new UpstreamMisconfiguredError("upstream issuer must use https in production");
    }
    // The client assertion audience needs the token endpoint, known after discovery.
    const audience: { value?: string } = {};
    const auth = await this.#clientAuth(method, audience);
    let config: client.Configuration;
    try {
      // The redirect URI is sent per request (begin) and derived from the callback URL.
      config = await client.discovery(issuer, method.clientId, undefined, auth, {
        timeout: this.#options.timeoutSeconds,
        execute: insecure ? [client.allowInsecureRequests] : [],
        [client.customFetch]: this.#fetch,
      });
    } catch (error) {
      const templated = templatedMetadata(error);
      if (templated === undefined) throw error;
      config = new client.Configuration(templated, method.clientId, undefined, auth);
    }
    const discovered: client.ServerMetadata = { ...config.serverMetadata() };
    const templated = discovered.issuer.toLowerCase().includes(TENANT_PLACEHOLDER);
    if (templated && method.allowedUpstreamTenants.length === 0) {
      throw new UpstreamMisconfiguredError("multi-tenant issuer without allowed upstream tenants");
    }
    const metadata: client.ServerMetadata = templated
      ? { ...discovered, issuer: discovered.issuer.replace(/\{tenantid\}/i, TENANT_PLACEHOLDER) }
      : discovered;
    // The back channel goes through the outbound guard (https only in production), but browsers
    // are sent to the authorization endpoint directly: an https issuer may not hand them a plain
    // http one.
    const authorizationEndpoint = metadata.authorization_endpoint;
    if (
      this.#options.production &&
      (typeof authorizationEndpoint !== "string" ||
        new URL(authorizationEndpoint).protocol !== "https:")
    ) {
      throw new UpstreamMisconfiguredError(
        "upstream authorization endpoint must use https in production",
      );
    }
    if (templated) {
      // For authorization URLs only; tokens are validated per tenant (exchangeCode).
      config = new client.Configuration(
        { ...metadata, issuer: metadata.issuer.replace(TENANT_PLACEHOLDER, "common") },
        method.clientId,
        undefined,
        auth,
      );
    }
    this.#harden(config, insecure);
    audience.value =
      method.clientAssertionAudience === "issuer" ? undefined : metadata.token_endpoint;
    return { config, templated, metadata, auth, insecure };
  }

  async #clientAuth(
    method: OidcLoginMethod,
    audience: { value?: string },
  ): Promise<client.ClientAuth> {
    const repo = this.#options.loginMethods;
    switch (method.clientAuthMethod) {
      case "client_secret_basic":
      case "client_secret_post": {
        const secret = await repo.getClientSecret(method.tenantId, method.id);
        if (secret === null) {
          throw new UpstreamMisconfiguredError("login method has no client secret");
        }
        return method.clientAuthMethod === "client_secret_basic"
          ? client.ClientSecretBasic(secret)
          : client.ClientSecretPost(secret);
      }
      case "private_key_jwt": {
        const key = await repo.getClientKey(method.tenantId, method.id);
        if (key === null) throw new UpstreamMisconfiguredError("login method has no client key");
        const privateKey = await importJWK(key.privateJwk, key.privateJwk.alg);
        if (!(privateKey instanceof CryptoKey)) {
          throw new UpstreamMisconfiguredError("login method client key is not a private key");
        }
        return client.PrivateKeyJwt(
          { key: privateKey, kid: key.kid },
          {
            // The default audience is the issuer; Entra ID expects the token endpoint.
            [client.modifyAssertion]: (_header, payload) => {
              if (audience.value !== undefined) payload.aud = audience.value;
            },
          },
        );
      }
    }
  }
}

/**
 * openid-client refuses discovered metadata whose issuer differs from the URL it was fetched
 * from (except for login.microsoftonline.com). A `{tenantid}` issuer is the multi-tenant case:
 * its metadata is returned to be handled here; anything else stays an error.
 */
function templatedMetadata(error: unknown): client.ServerMetadata | undefined {
  if (!(error instanceof client.ClientError)) return undefined;
  const cause = error.cause as { attribute?: unknown; body?: unknown } | undefined;
  if (cause?.attribute !== "issuer" || typeof cause.body !== "object" || cause.body === null) {
    return undefined;
  }
  const metadata = cause.body as client.ServerMetadata;
  return typeof metadata.issuer === "string" &&
    metadata.issuer.toLowerCase().includes(TENANT_PLACEHOLDER)
    ? metadata
    : undefined;
}

export type UpstreamFailure = "upstream_unavailable" | "upstream_error";

/**
 * Classifies an openid-client failure: the IdP could not be reached or answered with a server
 * error (`upstream_unavailable`), or it answered with an error or a response that failed
 * validation (`upstream_error`).
 */
export function classifyUpstreamError(error: unknown): UpstreamFailure {
  if (error instanceof UpstreamRecentlyFailedError) return "upstream_unavailable";
  if (error instanceof client.ResponseBodyError) {
    return error.status >= 500 ? "upstream_unavailable" : "upstream_error";
  }
  if (error instanceof client.ClientError) {
    const status = (error.cause as { status?: unknown } | undefined)?.status;
    if (typeof status === "number" && status >= 500) return "upstream_unavailable";
    return "upstream_error";
  }
  if (error instanceof TypeError) return "upstream_unavailable"; // fetch failed
  if (
    error instanceof DOMException &&
    (error.name === "TimeoutError" || error.name === "AbortError")
  ) {
    return "upstream_unavailable";
  }
  return "upstream_error";
}
