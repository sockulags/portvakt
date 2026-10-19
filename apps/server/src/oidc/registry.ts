import type { Tenant } from "../domain/tenant.js";
import { tenantSlugSchema } from "../domain/schemas.js";
import type { SigningKeyCache } from "../keys/key-cache.js";
import type { Logger } from "../logging/logger.js";
import type { Repositories } from "../repositories/index.js";
import type { TenantBuildInput, TenantProvider } from "./provider.js";

/** Raised when providers cannot be built yet (no signing key loaded); answered with 503. */
export class ProvidersNotReadyError extends Error {
  constructor() {
    super("Signing keys are not loaded");
    this.name = "ProvidersNotReadyError";
  }
}

export type ProviderBuilder = (input: TenantBuildInput) => TenantProvider;

/** No tenant has the slug at all (remembered in the negative cache). */
const UNKNOWN = Symbol("unknown tenant");

export interface ProviderRegistryOptions {
  readonly repos: Repositories;
  readonly keys: SigningKeyCache;
  readonly build: ProviderBuilder;
  readonly logger: Logger;
  /** How long a slug without any tenant is remembered as unknown (default 5 s; 0: never). */
  readonly unknownSlugSeconds?: number;
  /** At most this many unknown slugs are remembered (default 1000; the oldest go first). */
  readonly unknownSlugMax?: number;
  /** Clock in milliseconds (tests). */
  readonly now?: () => number;
}

/**
 * Per-tenant oidc-provider instances, built lazily on the first request for a tenant and cached.
 * A cached provider is dropped when its tenant, the tenant's applications or its login methods
 * change (change
 * notification, or the periodic {@link reconcile} fallback) and rebuilt on the next request; a
 * new signing key set makes every cached provider stale at once. An unknown or suspended tenant
 * builds nothing. A slug no tenant has at all is remembered briefly in a small bounded negative
 * cache, so a flood of requests for it (discovery, JWKS, any path below `/t/{slug}`) does not
 * reach the database each time; every invalidation (a tenant created or changed) clears it.
 */
export class ProviderRegistry {
  readonly #options: ProviderRegistryOptions;
  readonly #bySlug = new Map<string, TenantProvider>();
  readonly #building = new Map<string, Promise<TenantProvider | null>>();
  /** Slugs no tenant has, with when they are looked up again (insertion order: oldest first). */
  readonly #unknown = new Map<string, number>();
  readonly #unknownMs: number;
  readonly #unknownMax: number;
  readonly #now: () => number;
  /** Bumped by every invalidation; a build that started before one is not cached. */
  #epoch = 0;

  constructor(options: ProviderRegistryOptions) {
    this.#options = options;
    this.#unknownMs = (options.unknownSlugSeconds ?? 5) * 1000;
    this.#unknownMax = options.unknownSlugMax ?? 1000;
    this.#now = options.now ?? Date.now;
  }

  /** Number of slugs remembered as unknown (tests). */
  get unknownSlugs(): number {
    return this.#unknown.size;
  }

  /** Number of cached providers. */
  get size(): number {
    return this.#bySlug.size;
  }

  /** The cached provider of a slug, without building or checking anything. */
  peek(slug: string): TenantProvider | undefined {
    return this.#bySlug.get(slug);
  }

  /**
   * The provider of an active tenant, or `null` for an unknown or suspended tenant (and for
   * anything that is not a valid slug, without touching the database).
   */
  async get(slug: string): Promise<TenantProvider | null> {
    if (!tenantSlugSchema.safeParse(slug).success) return null;
    const keys = this.#options.keys.current;
    if (keys === undefined) throw new ProvidersNotReadyError();
    const cached = this.#bySlug.get(slug);
    if (cached !== undefined && cached.keysVersion === keys.version) return cached;
    const unknownUntil = this.#unknown.get(slug);
    if (unknownUntil !== undefined) {
      if (unknownUntil > this.#now()) return null;
      this.#unknown.delete(slug);
    }

    const inFlight = this.#building.get(slug);
    if (inFlight !== undefined) return inFlight;
    const epoch = this.#epoch;
    const build = this.#build(slug, keys)
      .then((entry) => {
        if (this.#epoch === epoch) {
          if (entry === null) this.#bySlug.delete(slug);
          else if (entry !== UNKNOWN) this.#bySlug.set(slug, entry);
          else {
            this.#bySlug.delete(slug);
            this.#rememberUnknown(slug);
          }
        }
        return entry === UNKNOWN ? null : entry;
      })
      .finally(() => {
        this.#building.delete(slug);
      });
    this.#building.set(slug, build);
    return build;
  }

  #rememberUnknown(slug: string): void {
    if (this.#unknownMs <= 0 || this.#unknownMax <= 0) return;
    while (this.#unknown.size >= this.#unknownMax) {
      const oldest = this.#unknown.keys().next();
      if (oldest.done === true) break;
      this.#unknown.delete(oldest.value);
    }
    this.#unknown.set(slug, this.#now() + this.#unknownMs);
  }

  invalidateTenant(tenantId: string): void {
    this.#epoch += 1;
    // A new tenant (or a renamed slug) must be found at once: forget every unknown slug.
    this.#unknown.clear();
    for (const [slug, entry] of this.#bySlug) {
      if (entry.tenant.id === tenantId) this.#bySlug.delete(slug);
    }
  }

  invalidateAll(): void {
    this.#epoch += 1;
    this.#bySlug.clear();
    this.#unknown.clear();
  }

  /**
   * Fallback for missed notifications: drops cached providers whose tenant or applications
   * changed (or whose tenant is gone). Stale key versions are handled on the next `get`.
   */
  async reconcile(): Promise<number> {
    const entries = [...this.#bySlug.values()];
    if (entries.length === 0) return 0;
    const fingerprints = await this.#options.repos.tenants.providerFingerprints(
      entries.map((entry) => entry.tenant.id),
    );
    let dropped = 0;
    for (const entry of entries) {
      if (fingerprints.get(entry.tenant.id) !== entry.fingerprint) {
        this.invalidateTenant(entry.tenant.id);
        dropped += 1;
      }
    }
    if (dropped > 0) this.#options.logger.info({ dropped }, "reloaded changed tenant providers");
    return dropped;
  }

  async #build(
    slug: string,
    keys: TenantBuildInput["keys"],
  ): Promise<TenantProvider | null | typeof UNKNOWN> {
    const { repos, build } = this.#options;
    const tenant: Tenant | null = await repos.tenants.findActiveBySlug(slug);
    if (tenant === null) {
      // A suspended tenant is not remembered: reactivating it must work at once.
      return (await repos.tenants.findBySlug(slug)) === null ? UNKNOWN : null;
    }
    // Fingerprint first: a change after it is read invalidates the entry built here.
    const fingerprint = (await repos.tenants.providerFingerprints([tenant.id])).get(tenant.id);
    if (fingerprint === undefined) return null;
    const loginMethods = await repos.loginMethods.list(tenant.id);
    return build({ tenant, keys, fingerprint, loginMethods });
  }
}
