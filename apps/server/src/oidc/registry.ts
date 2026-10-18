import type { Tenant } from "../domain/tenant.js";
import { tenantSlugSchema } from "../domain/schemas.js";
import type { LoadedKeys, SigningKeyCache } from "../keys/key-cache.js";
import type { Logger } from "../logging/logger.js";
import type { Repositories } from "../repositories/index.js";
import type { TenantProvider } from "./provider.js";

/** Raised when providers cannot be built yet (no signing key loaded); answered with 503. */
export class ProvidersNotReadyError extends Error {
  constructor() {
    super("Signing keys are not loaded");
    this.name = "ProvidersNotReadyError";
  }
}

export type ProviderBuilder = (
  tenant: Tenant,
  keys: LoadedKeys,
  fingerprint: string,
) => TenantProvider;

export interface ProviderRegistryOptions {
  readonly repos: Repositories;
  readonly keys: SigningKeyCache;
  readonly build: ProviderBuilder;
  readonly logger: Logger;
}

/**
 * Per-tenant oidc-provider instances, built lazily on the first request for a tenant and cached.
 * A cached provider is dropped when its tenant or the tenant's applications change (change
 * notification, or the periodic {@link reconcile} fallback) and rebuilt on the next request; a
 * new signing key set makes every cached provider stale at once. An unknown or suspended tenant
 * builds nothing.
 */
export class ProviderRegistry {
  readonly #options: ProviderRegistryOptions;
  readonly #bySlug = new Map<string, TenantProvider>();
  readonly #building = new Map<string, Promise<TenantProvider | null>>();
  /** Bumped by every invalidation; a build that started before one is not cached. */
  #epoch = 0;

  constructor(options: ProviderRegistryOptions) {
    this.#options = options;
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

    const inFlight = this.#building.get(slug);
    if (inFlight !== undefined) return inFlight;
    const epoch = this.#epoch;
    const build = this.#build(slug, keys)
      .then((entry) => {
        if (this.#epoch === epoch) {
          if (entry === null) this.#bySlug.delete(slug);
          else this.#bySlug.set(slug, entry);
        }
        return entry;
      })
      .finally(() => {
        this.#building.delete(slug);
      });
    this.#building.set(slug, build);
    return build;
  }

  invalidateTenant(tenantId: string): void {
    this.#epoch += 1;
    for (const [slug, entry] of this.#bySlug) {
      if (entry.tenant.id === tenantId) this.#bySlug.delete(slug);
    }
  }

  invalidateAll(): void {
    this.#epoch += 1;
    this.#bySlug.clear();
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

  async #build(slug: string, keys: LoadedKeys): Promise<TenantProvider | null> {
    const { repos, build } = this.#options;
    const tenant = await repos.tenants.findActiveBySlug(slug);
    if (tenant === null) return null;
    const fingerprint = (await repos.tenants.providerFingerprints([tenant.id])).get(tenant.id);
    if (fingerprint === undefined) return null;
    return build(tenant, keys, fingerprint);
  }
}
