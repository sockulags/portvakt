import {
  errors,
  type Adapter,
  type AdapterFactory,
  type AdapterPayload,
  type ClientMetadata,
} from "oidc-provider";
import type { OidcPayloadRepository } from "../repositories/oidc-payloads.js";

/** Models whose rows belong to a grant and are removed by `revokeByGrantId`. */
const GRANT_BOUND_MODELS = new Set([
  "AccessToken",
  "AuthorizationCode",
  "RefreshToken",
  "DeviceCode",
  "BackchannelAuthenticationRequest",
  "PreAuthorizedCode",
]);

/** Resolves a client_id to client metadata, or `undefined` when it may not be used here. */
export type ClientResolver = (clientId: string) => Promise<ClientMetadata | undefined>;

const stringOrUndefined = (value: unknown): string | undefined =>
  typeof value === "string" && value.length > 0 ? value : undefined;

/**
 * oidc-provider storage adapter over `oidc_payloads`, bound to one tenant (the tenant of the
 * provider instance that created it). One instance per model name.
 */
class PostgresAdapter implements Adapter {
  readonly #model: string;
  readonly #tenantId: string;
  readonly #payloads: OidcPayloadRepository;

  constructor(model: string, tenantId: string, payloads: OidcPayloadRepository) {
    this.#model = model;
    this.#tenantId = tenantId;
    this.#payloads = payloads;
  }

  async upsert(id: string, payload: AdapterPayload, expiresIn?: number): Promise<void> {
    if (this.#model === "ReplayDetection") {
      // oidc-provider checks find() and then saves; between the two a parallel request with the
      // same client assertion could pass as well. The insert decides instead.
      const fresh = await this.#payloads.insertOnce(
        this.#tenantId,
        this.#model,
        id,
        { ...payload },
        expiresIn,
      );
      if (!fresh) {
        throw new errors.InvalidClientAuth("client assertion tokens must only be used once");
      }
      return;
    }
    await this.#payloads.upsert(this.#tenantId, this.#model, id, { ...payload }, expiresIn, {
      grantId: GRANT_BOUND_MODELS.has(this.#model) ? stringOrUndefined(payload.grantId) : undefined,
      userCode: stringOrUndefined(payload.userCode),
      uid: this.#model === "Session" ? stringOrUndefined(payload.uid) : undefined,
    });
  }

  async find(id: string): Promise<AdapterPayload | undefined> {
    return await this.#payloads.find(this.#tenantId, this.#model, id);
  }

  async findByUid(uid: string): Promise<AdapterPayload | undefined> {
    return await this.#payloads.findByUid(this.#tenantId, this.#model, uid);
  }

  async findByUserCode(userCode: string): Promise<AdapterPayload | undefined> {
    return await this.#payloads.findByUserCode(this.#tenantId, this.#model, userCode);
  }

  /**
   * Single use, decided by the database: oidc-provider reads `consumed` and then consumes, so
   * parallel requests with one code or refresh token would all pass its own check. The losers
   * get invalid_grant and, as for a sequential replay, the grant is revoked.
   */
  async consume(id: string): Promise<void> {
    const result = await this.#payloads.consume(this.#tenantId, this.#model, id);
    if (result.consumed) return;
    if (!GRANT_BOUND_MODELS.has(this.#model)) {
      throw new errors.InvalidRequest("this request has already been used");
    }
    if (result.grantId !== null) await this.#payloads.revokeGrant(this.#tenantId, result.grantId);
    throw new errors.InvalidGrant("grant already used");
  }

  async destroy(id: string): Promise<void> {
    await this.#payloads.destroy(this.#tenantId, this.#model, id);
  }

  async revokeByGrantId(grantId: string): Promise<void> {
    await this.#payloads.revokeByGrantId(this.#tenantId, grantId);
  }
}

/**
 * Clients are not stored by the provider: they are the applications enabled for the tenant, read
 * live through {@link ClientResolver}. Dynamic registration is disabled, so writes never happen.
 */
class ClientAdapter implements Adapter {
  readonly #resolve: ClientResolver;

  constructor(resolve: ClientResolver) {
    this.#resolve = resolve;
  }

  async find(id: string): Promise<AdapterPayload | undefined> {
    return await this.#resolve(id);
  }

  upsert(): Promise<void> {
    return Promise.reject(new Error("Clients are managed as applications, not by the provider"));
  }

  destroy(): Promise<void> {
    return Promise.reject(new Error("Clients are managed as applications, not by the provider"));
  }

  findByUid(): Promise<undefined> {
    return Promise.resolve(undefined);
  }

  findByUserCode(): Promise<undefined> {
    return Promise.resolve(undefined);
  }

  consume(): Promise<void> {
    return Promise.resolve();
  }

  revokeByGrantId(): Promise<void> {
    return Promise.resolve();
  }
}

export function createAdapterFactory(options: {
  readonly tenantId: string;
  readonly payloads: OidcPayloadRepository;
  readonly resolveClient: ClientResolver;
}): AdapterFactory {
  return (model: string): Adapter =>
    model === "Client"
      ? new ClientAdapter(options.resolveClient)
      : new PostgresAdapter(model, options.tenantId, options.payloads);
}
