import {
  createPortvaktClient,
  type PortvaktBff,
  type PortvaktLogger,
  type SessionStore,
} from "@portvakt/sdk-node";
import { TokenBucketLimiter } from "@portvakt/http-kit";
import type { AdminConfig } from "./config.js";

/** Tenant slugs as Portvakt accepts them (`/t/{slug}`). */
export const SLUG = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

/** The SDK's session cookie of the portal; scoped to `/t/{slug}`, one per tenant. */
export const SESSION_COOKIE = "pv_admin";

/** At most this many tenant clients are kept; the least recently used one is dropped. */
const MAX_CLIENTS = 200;
/** Unknown slugs remembered (negative cache), and for how long. */
const MAX_UNKNOWN = 1000;
const UNKNOWN_TTL_MS = 60_000;

/** Too many lookups of unknown tenant slugs from one client (ADMIN_RATE_LIMIT_TENANT_LOOKUP). */
export class TenantLookupLimitedError extends Error {
  readonly retryAfterSeconds: number;

  constructor(retryAfterSeconds: number) {
    super("too many tenant lookups");
    this.name = "TenantLookupLimitedError";
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

/** Portvakt could not say whether a tenant exists (unreachable or an unexpected answer). */
export class TenantLookupError extends Error {
  constructor(options?: ErrorOptions) {
    super("tenant lookup failed", options);
    this.name = "TenantLookupError";
  }
}

/**
 * Keeps one tenant's sessions apart from every other tenant's in a shared store: a session
 * cookie of tenant X presented below `/t/Y` finds nothing.
 */
export class TenantScopedStore implements SessionStore {
  readonly #store: SessionStore;
  readonly #prefix: string;

  constructor(store: SessionStore, slug: string) {
    this.#store = store;
    this.#prefix = `admin:${slug}:`;
  }

  get(key: string): Promise<string | undefined> {
    return this.#store.get(this.#prefix + key);
  }

  set(key: string, value: string, expiresAt: Date): Promise<void> {
    return this.#store.set(this.#prefix + key, value, expiresAt);
  }

  destroy(key: string): Promise<void> {
    return this.#store.destroy(this.#prefix + key);
  }

  withLock<T>(key: string, fn: () => Promise<T>): Promise<T> {
    const store = this.#store;
    return store.withLock === undefined ? fn() : store.withLock(this.#prefix + key, fn);
  }
}

/**
 * One SDK client and BFF per tenant issuer (`{PORTVAKT}/t/{slug}`), created lazily: an
 * administrator of tenant X signs in through tenant X's own login methods. Routes, cookies and
 * sessions live below `/t/{slug}`.
 */
export class TenantClients {
  readonly #config: AdminConfig;
  readonly #store: SessionStore;
  readonly #logger: PortvaktLogger | undefined;
  readonly #bffs = new Map<string, PortvaktBff>();
  /** Slugs Portvakt does not know, until when (epoch ms); bounded, oldest dropped first. */
  readonly #unknown = new Map<string, number>();
  readonly #lookups = new Map<string, Promise<boolean>>();
  readonly #fetch: typeof fetch;
  /** Lookups that ask Portvakt, per client (unknown slugs cost a request each). */
  readonly #lookupLimit: TokenBucketLimiter | undefined;

  constructor(
    config: AdminConfig,
    store: SessionStore,
    logger?: PortvaktLogger,
    fetcher: typeof fetch = (...args) => fetch(...args),
  ) {
    this.#config = config;
    this.#store = store;
    this.#logger = logger;
    this.#fetch = fetcher;
    this.#lookupLimit =
      config.tenantLookupRateLimit === null
        ? undefined
        : new TokenBucketLimiter(config.tenantLookupRateLimit);
  }

  /**
   * The BFF of a tenant, created once Portvakt confirmed the tenant exists (its discovery
   * answers). `undefined` for a malformed or unknown slug; unknown slugs are remembered for a
   * while in a bounded cache of their own, so they never evict real tenants' clients.
   * Throws {@link TenantLookupError} when Portvakt cannot be asked, and
   * {@link TenantLookupLimitedError} when `client` (the rate-limit key of the caller's IP) asked
   * about too many slugs the portal does not know.
   */
  async get(slug: string, client?: string): Promise<PortvaktBff | undefined> {
    if (!SLUG.test(slug)) return undefined;
    const cached = this.#bffs.get(slug);
    if (cached !== undefined) {
      // Most recently used last.
      this.#bffs.delete(slug);
      this.#bffs.set(slug, cached);
      return cached;
    }
    const unknownUntil = this.#unknown.get(slug);
    if (unknownUntil !== undefined && unknownUntil > Date.now()) return undefined;
    let lookup = this.#lookups.get(slug);
    if (lookup === undefined && client !== undefined && this.#lookupLimit !== undefined) {
      const decision = this.#lookupLimit.take(client);
      if (!decision.allowed) throw new TenantLookupLimitedError(decision.retryAfterSeconds);
    }
    if (lookup === undefined) {
      lookup = this.#exists(slug).finally(() => this.#lookups.delete(slug));
      this.#lookups.set(slug, lookup);
    }
    if (!(await lookup)) {
      this.#unknown.delete(slug);
      this.#unknown.set(slug, Date.now() + UNKNOWN_TTL_MS);
      if (this.#unknown.size > MAX_UNKNOWN) {
        const oldest = this.#unknown.keys().next().value;
        if (oldest !== undefined) this.#unknown.delete(oldest);
      }
      return undefined;
    }
    return this.#bffs.get(slug) ?? this.#create(slug);
  }

  /** Whether Portvakt serves the tenant's issuer (discovery 200; 404 for unknown or suspended). */
  async #exists(slug: string): Promise<boolean> {
    let response: Response;
    try {
      response = await this.#fetch(
        `${this.#config.portvaktUrl}/t/${slug}/.well-known/openid-configuration`,
        { signal: AbortSignal.timeout(5000), redirect: "manual" },
      );
    } catch (error) {
      throw new TenantLookupError({ cause: error });
    }
    await response.body?.cancel();
    if (response.status === 200) return true;
    if (response.status === 404) return false;
    throw new TenantLookupError();
  }

  #create(slug: string): PortvaktBff {
    const config = this.#config;
    const base = `/t/${slug}`;
    const client = createPortvaktClient({
      issuer: `${config.portvaktUrl}${base}`,
      clientId: config.clientId,
      clientAuth: { method: "client_secret_basic", clientSecret: config.clientSecret },
      redirectUri: `${config.publicUrl}${base}/auth/callback`,
      postLogoutRedirectUri: `${config.publicUrl}${base}/`,
      scopes: ["openid", "profile", "email"],
      // http to Portvakt only for local development; the SDK refuses it otherwise.
      allowInsecureRequests: !config.production && config.portvaktUrl.startsWith("http:"),
      ...(this.#logger === undefined ? {} : { logger: this.#logger }),
    });
    const bff = client.bff({
      sessionStore: new TenantScopedStore(this.#store, slug),
      encryptionKey: config.sessionEncryptionKeys,
      cookie: {
        name: SESSION_COOKIE,
        secrets: config.cookieSecrets,
        secure: config.cookieSecure,
        path: base,
      },
      mountPath: `${base}/auth`,
      defaultReturnTo: `${base}/`,
      idleTimeoutSeconds: config.idleTimeoutSeconds,
    });
    this.#bffs.set(slug, bff);
    if (this.#bffs.size > MAX_CLIENTS) {
      const oldest = this.#bffs.keys().next().value;
      if (oldest !== undefined) this.#bffs.delete(oldest);
    }
    return bff;
  }
}
