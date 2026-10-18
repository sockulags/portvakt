import { randomUUID } from "node:crypto";
import type { SecretBox } from "../crypto/envelope.js";
import {
  generateSigningKey,
  privateJwkSchema,
  publicJwkSchema,
  type PrivateJwk,
  type PublicJwk,
} from "../crypto/jwk.js";
import type { Db } from "../db/database.js";
import {
  claimMappingSchema,
  createLoginMethodInputSchema,
  type CreateLoginMethodInput,
  type ClientAssertionAudience,
  emailDomain,
  type LoginMethod,
  type LoginMethodKind,
  loginMethodRuleViolations,
  type UpstreamAuthMethod,
  updateLoginMethodInputSchema,
  type UpdateLoginMethodInput,
} from "../domain/login-method.js";
import { emailDomainSchema } from "../domain/schemas.js";
import { emitChange } from "./change-events.js";
import { mapDbErrors, NotFoundError, parseInput, requireUuids, ValidationError } from "./errors.js";

interface LoginMethodRow {
  id: string;
  tenant_id: string;
  kind: LoginMethodKind;
  display_name: string;
  issuer: string;
  client_id: string;
  has_client_secret: boolean;
  token_endpoint_auth_method: UpstreamAuthMethod;
  client_key_kid: string | null;
  use_userinfo: boolean;
  client_assertion_audience: ClientAssertionAudience;
  allowed_upstream_tenants: string[];
  trust_upstream_email: boolean;
  scopes: string[];
  claim_mapping: unknown;
  asserted_acr: string;
  home_realm_domains: string[];
  secret_expires_at: Date | null;
  max_age_seconds: number;
  idle_seconds: number;
  allow_sso: boolean;
  link_by_pin: boolean;
  enabled: boolean;
  created_at: Date;
  updated_at: Date;
}

const SELECT_LOGIN_METHOD = `
  SELECT lm.id, lm.tenant_id, lm.kind, lm.display_name, lm.issuer, lm.client_id,
         lm.client_secret_encrypted IS NOT NULL AS has_client_secret,
         lm.token_endpoint_auth_method, lm.client_key_kid, lm.use_userinfo,
         lm.client_assertion_audience, lm.allowed_upstream_tenants, lm.trust_upstream_email, lm.scopes,
         lm.claim_mapping, lm.asserted_acr, lm.secret_expires_at, lm.max_age_seconds,
         lm.idle_seconds, lm.allow_sso, lm.link_by_pin, lm.enabled, lm.created_at, lm.updated_at,
         ARRAY(SELECT d.domain FROM login_method_domains d
                WHERE d.tenant_id = lm.tenant_id AND d.login_method_id = lm.id
                ORDER BY d.domain) AS home_realm_domains
    FROM login_methods lm`;

function toLoginMethod(row: LoginMethodRow): LoginMethod {
  return {
    id: row.id,
    tenantId: row.tenant_id,
    kind: row.kind,
    displayName: row.display_name,
    issuer: row.issuer,
    clientId: row.client_id,
    hasClientSecret: row.has_client_secret,
    clientAuthMethod: row.token_endpoint_auth_method,
    clientKeyKid: row.client_key_kid,
    useUserinfo: row.use_userinfo,
    clientAssertionAudience: row.client_assertion_audience,
    allowedUpstreamTenants: row.allowed_upstream_tenants,
    trustUpstreamEmail: row.trust_upstream_email,
    scopes: row.scopes,
    claimMapping: claimMappingSchema.parse(row.claim_mapping),
    assertedAcr: row.asserted_acr,
    homeRealmDomains: row.home_realm_domains,
    secretExpiresAt: row.secret_expires_at,
    sessionPolicy: {
      maxAgeSeconds: row.max_age_seconds,
      idleSeconds: row.idle_seconds,
      allowSso: row.allow_sso,
    },
    linkByPin: row.link_by_pin,
    enabled: row.enabled,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

/** AAD context binding an encrypted upstream secret to its login method. */
export const clientSecretContext = (loginMethodId: string): string =>
  `login_method:${loginMethodId}:client_secret`;

/** AAD context binding the encrypted private client key (private_key_jwt) to its login method. */
export const clientPrivateJwkContext = (loginMethodId: string): string =>
  `login_method:${loginMethodId}:client_private_jwk`;

export interface LoginMethodRepositoryOptions {
  /**
   * Ceiling for `sessionPolicy.maxAgeSeconds` (SESSION_TTL): longer sessions are refused at write
   * time, because signing keys are only kept published for SESSION_TTL.
   */
  readonly maxSessionSeconds?: number;
  /**
   * ACR_RANKING: a login method asserting a ranked level must map the upstream acr (refused at
   * write time otherwise).
   */
  readonly acrRanking?: readonly string[];
}

/** The login method's client key pair, for signing private_key_jwt client assertions. */
export interface LoginMethodClientKey {
  readonly kid: string;
  readonly publicJwk: PublicJwk;
  readonly privateJwk: PrivateJwk;
}

interface EncryptedClientKey {
  readonly kid: string;
  readonly publicJwk: string;
  readonly privateJwkEncrypted: string;
}

/**
 * Login methods per tenant. Every write emits a `login_methods` change event: the tenant's
 * provider is built from its login methods (acr values) and is rebuilt on change.
 */
export class LoginMethodRepository {
  readonly #db: Db;
  readonly #secrets: SecretBox;
  readonly #maxSessionSeconds: number | undefined;
  readonly #acrRanking: readonly string[];

  constructor(db: Db, secrets: SecretBox, options: LoginMethodRepositoryOptions = {}) {
    this.#db = db;
    this.#secrets = secrets;
    this.#maxSessionSeconds = options.maxSessionSeconds;
    this.#acrRanking = options.acrRanking ?? [];
  }

  async create(tenantId: string, input: CreateLoginMethodInput): Promise<LoginMethod> {
    requireUuids({ tenantId });
    const data = parseInput(createLoginMethodInputSchema, input);
    this.#checkMaxAge(data.sessionPolicy.maxAgeSeconds);
    this.#checkRules(data);
    const id = randomUUID();
    const encryptedSecret =
      data.clientSecret === undefined
        ? null
        : this.#secrets.encrypt(data.clientSecret, clientSecretContext(id));
    const key = this.#newClientKey(id);

    await this.#db.transaction(async (tx) => {
      await mapDbErrors(() =>
        tx.query(
          `INSERT INTO login_methods
             (id, tenant_id, kind, display_name, issuer, client_id, client_secret_encrypted, scopes,
              claim_mapping, asserted_acr, secret_expires_at, max_age_seconds, idle_seconds,
              allow_sso, link_by_pin, enabled, token_endpoint_auth_method, use_userinfo,
              client_key_kid, client_public_jwk, client_private_jwk_encrypted,
              client_assertion_audience, allowed_upstream_tenants, trust_upstream_email)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10, $11, $12, $13, $14, $15, $16,
                   $17, $18, $19, $20::jsonb, $21, $22, $23, $24)`,
          [
            id,
            tenantId,
            data.kind,
            data.displayName,
            data.issuer,
            data.clientId,
            encryptedSecret,
            data.scopes,
            JSON.stringify(data.claimMapping),
            data.assertedAcr,
            data.secretExpiresAt,
            data.sessionPolicy.maxAgeSeconds,
            data.sessionPolicy.idleSeconds,
            data.sessionPolicy.allowSso,
            data.linkByPin,
            data.enabled,
            data.clientAuthMethod,
            data.useUserinfo,
            key.kid,
            key.publicJwk,
            key.privateJwkEncrypted,
            data.clientAssertionAudience,
            data.allowedUpstreamTenants,
            data.trustUpstreamEmail,
          ],
        ),
      );
      await this.#replaceDomains(tx, tenantId, id, data.homeRealmDomains);
      await emitChange(tx, { type: "login_methods", tenantId });
    });
    return this.#require(tenantId, id);
  }

  async update(tenantId: string, id: string, patch: UpdateLoginMethodInput): Promise<LoginMethod> {
    requireUuids({ tenantId, id });
    const data = parseInput(updateLoginMethodInputSchema, patch);
    if (data.sessionPolicy !== undefined) this.#checkMaxAge(data.sessionPolicy.maxAgeSeconds);
    const current = await this.#require(tenantId, id);
    this.#checkRules({
      issuer: data.issuer ?? current.issuer,
      allowedUpstreamTenants: data.allowedUpstreamTenants ?? current.allowedUpstreamTenants,
      assertedAcr: data.assertedAcr ?? current.assertedAcr,
      claimMapping: data.claimMapping ?? current.claimMapping,
    });
    const secretChanged = data.clientSecret !== undefined;
    const encryptedSecret =
      data.clientSecret === undefined || data.clientSecret === null
        ? null
        : this.#secrets.encrypt(data.clientSecret, clientSecretContext(id));

    await this.#db.transaction(async (tx) => {
      const rows = await mapDbErrors(() =>
        tx.query(
          `UPDATE login_methods SET
             kind = COALESCE($3, kind),
             display_name = COALESCE($4, display_name),
             issuer = COALESCE($5, issuer),
             client_id = COALESCE($6, client_id),
             client_secret_encrypted = CASE WHEN $7::boolean THEN $8 ELSE client_secret_encrypted END,
             scopes = COALESCE($9, scopes),
             claim_mapping = COALESCE($10::jsonb, claim_mapping),
             asserted_acr = COALESCE($11, asserted_acr),
             secret_expires_at = CASE WHEN $12::boolean THEN $13 ELSE secret_expires_at END,
             max_age_seconds = COALESCE($14, max_age_seconds),
             idle_seconds = COALESCE($15, idle_seconds),
             allow_sso = COALESCE($16, allow_sso),
             enabled = COALESCE($17, enabled),
             link_by_pin = COALESCE($18, link_by_pin),
             token_endpoint_auth_method = COALESCE($19, token_endpoint_auth_method),
             use_userinfo = COALESCE($20, use_userinfo),
             client_assertion_audience = COALESCE($21, client_assertion_audience),
             allowed_upstream_tenants = COALESCE($22, allowed_upstream_tenants),
             trust_upstream_email = COALESCE($23, trust_upstream_email)
           WHERE tenant_id = $1 AND id = $2
           RETURNING id`,
          [
            tenantId,
            id,
            data.kind ?? null,
            data.displayName ?? null,
            data.issuer ?? null,
            data.clientId ?? null,
            secretChanged,
            encryptedSecret,
            data.scopes ?? null,
            data.claimMapping === undefined ? null : JSON.stringify(data.claimMapping),
            data.assertedAcr ?? null,
            data.secretExpiresAt !== undefined,
            data.secretExpiresAt ?? null,
            data.sessionPolicy?.maxAgeSeconds ?? null,
            data.sessionPolicy?.idleSeconds ?? null,
            data.sessionPolicy?.allowSso ?? null,
            data.enabled ?? null,
            data.linkByPin ?? null,
            data.clientAuthMethod ?? null,
            data.useUserinfo ?? null,
            data.clientAssertionAudience ?? null,
            data.allowedUpstreamTenants ?? null,
            data.trustUpstreamEmail ?? null,
          ],
        ),
      );
      if (rows.length === 0) throw new NotFoundError("Login method");
      if (data.homeRealmDomains !== undefined) {
        await this.#replaceDomains(tx, tenantId, id, data.homeRealmDomains);
      }
      await emitChange(tx, { type: "login_methods", tenantId });
    });
    return this.#require(tenantId, id);
  }

  async findById(tenantId: string, id: string): Promise<LoginMethod | null> {
    requireUuids({ tenantId, id });
    const [row] = await this.#db.query<LoginMethodRow>(
      `${SELECT_LOGIN_METHOD} WHERE lm.tenant_id = $1 AND lm.id = $2`,
      [tenantId, id],
    );
    return row === undefined ? null : toLoginMethod(row);
  }

  async list(tenantId: string): Promise<LoginMethod[]> {
    requireUuids({ tenantId });
    const rows = await this.#db.query<LoginMethodRow>(
      `${SELECT_LOGIN_METHOD} WHERE lm.tenant_id = $1 ORDER BY lm.display_name, lm.id`,
      [tenantId],
    );
    return rows.map(toLoginMethod);
  }

  /** Login methods offered on the tenant's login page. */
  async listEnabled(tenantId: string): Promise<LoginMethod[]> {
    requireUuids({ tenantId });
    const rows = await this.#db.query<LoginMethodRow>(
      `${SELECT_LOGIN_METHOD} WHERE lm.tenant_id = $1 AND lm.enabled
        ORDER BY lm.display_name, lm.id`,
      [tenantId],
    );
    return rows.map(toLoginMethod);
  }

  /**
   * Home realm discovery: the enabled login method that owns the domain (or the domain of an
   * email address) in this tenant.
   */
  async findEnabledByHomeRealm(
    tenantId: string,
    domainOrEmail: string,
  ): Promise<LoginMethod | null> {
    requireUuids({ tenantId });
    const domain = domainOrEmail.includes("@")
      ? emailDomain(domainOrEmail)
      : emailDomainSchema.safeParse(domainOrEmail).data;
    if (domain === undefined) return null;
    const [row] = await this.#db.query<LoginMethodRow>(
      `${SELECT_LOGIN_METHOD}
         JOIN login_method_domains hr ON hr.tenant_id = lm.tenant_id AND hr.login_method_id = lm.id
        WHERE lm.tenant_id = $1 AND hr.domain = $2 AND lm.enabled`,
      [tenantId, domain],
    );
    return row === undefined ? null : toLoginMethod(row);
  }

  /** Login methods whose upstream secret expires before `before` (admin flagging). */
  async listSecretsExpiringBefore(tenantId: string, before: Date): Promise<LoginMethod[]> {
    requireUuids({ tenantId });
    const rows = await this.#db.query<LoginMethodRow>(
      `${SELECT_LOGIN_METHOD}
        WHERE lm.tenant_id = $1 AND lm.secret_expires_at IS NOT NULL AND lm.secret_expires_at < $2
        ORDER BY lm.secret_expires_at`,
      [tenantId, before],
    );
    return rows.map(toLoginMethod);
  }

  /** Decrypted upstream client secret, for the federation client only. Never log it. */
  async getClientSecret(tenantId: string, id: string): Promise<string | null> {
    requireUuids({ tenantId, id });
    const [row] = await this.#db.query<{ client_secret_encrypted: string | null }>(
      "SELECT client_secret_encrypted FROM login_methods WHERE tenant_id = $1 AND id = $2",
      [tenantId, id],
    );
    if (row === undefined) throw new NotFoundError("Login method");
    if (row.client_secret_encrypted === null) return null;
    return this.#secrets.decryptString(row.client_secret_encrypted, clientSecretContext(id));
  }

  /**
   * Public JWK of the login method's client key (what the tenant registers upstream for
   * private_key_jwt). Generates the key pair first if the method has none yet (rows created
   * before migration 0002). `null` for an unknown login method.
   */
  async ensureClientPublicJwk(tenantId: string, id: string): Promise<PublicJwk | null> {
    requireUuids({ tenantId, id });
    const read = async (): Promise<{ public: unknown } | undefined> =>
      (
        await this.#db.query<{ public: unknown }>(
          "SELECT client_public_jwk AS public FROM login_methods WHERE tenant_id = $1 AND id = $2",
          [tenantId, id],
        )
      )[0];
    let row = await read();
    if (row === undefined) return null;
    if (row.public === null) {
      const key = this.#newClientKey(id);
      // Of concurrent first requests, exactly one stores its key; the others read it back.
      await this.#db.query(
        `UPDATE login_methods
            SET client_key_kid = $3, client_public_jwk = $4::jsonb, client_private_jwk_encrypted = $5
          WHERE tenant_id = $1 AND id = $2 AND client_key_kid IS NULL`,
        [tenantId, id, key.kid, key.publicJwk, key.privateJwkEncrypted],
      );
      row = await read();
      if (row === undefined) return null;
    }
    return publicJwkSchema.parse(row.public);
  }

  /** Decrypted client key pair for private_key_jwt, for the federation client only. */
  async getClientKey(tenantId: string, id: string): Promise<LoginMethodClientKey | null> {
    requireUuids({ tenantId, id });
    await this.ensureClientPublicJwk(tenantId, id);
    const [row] = await this.#db.query<{
      kid: string | null;
      public: unknown;
      private: string | null;
    }>(
      `SELECT client_key_kid AS kid, client_public_jwk AS public,
              client_private_jwk_encrypted AS private
         FROM login_methods WHERE tenant_id = $1 AND id = $2`,
      [tenantId, id],
    );
    if (row === undefined || row.kid === null || row.private === null) return null;
    const privateJwk = privateJwkSchema.parse(
      JSON.parse(this.#secrets.decryptString(row.private, clientPrivateJwkContext(id))),
    );
    return { kid: row.kid, publicJwk: publicJwkSchema.parse(row.public), privateJwk };
  }

  /** Deleting a login method that still has identities is refused; disable it instead. */
  async delete(tenantId: string, id: string): Promise<boolean> {
    requireUuids({ tenantId, id });
    return this.#db.transaction(async (tx) => {
      const rows = await mapDbErrors(() =>
        tx.query("DELETE FROM login_methods WHERE tenant_id = $1 AND id = $2 RETURNING id", [
          tenantId,
          id,
        ]),
      );
      if (rows.length > 0) await emitChange(tx, { type: "login_methods", tenantId });
      return rows.length > 0;
    });
  }

  #checkMaxAge(maxAgeSeconds: number): void {
    if (this.#maxSessionSeconds !== undefined && maxAgeSeconds > this.#maxSessionSeconds) {
      throw new ValidationError([
        `sessionPolicy.maxAgeSeconds: must not exceed SESSION_TTL (${this.#maxSessionSeconds} seconds)`,
      ]);
    }
  }

  #checkRules(method: Parameters<typeof loginMethodRuleViolations>[0]): void {
    const issues = loginMethodRuleViolations(method, this.#acrRanking);
    if (issues.length > 0) throw new ValidationError(issues);
  }

  #newClientKey(id: string): EncryptedClientKey {
    const key = generateSigningKey();
    return {
      kid: key.kid,
      publicJwk: JSON.stringify(key.publicJwk),
      privateJwkEncrypted: this.#secrets.encrypt(
        JSON.stringify(key.privateJwk),
        clientPrivateJwkContext(id),
      ),
    };
  }

  async #replaceDomains(
    tx: Db,
    tenantId: string,
    id: string,
    domains: readonly string[],
  ): Promise<void> {
    await tx.query(
      "DELETE FROM login_method_domains WHERE tenant_id = $1 AND login_method_id = $2",
      [tenantId, id],
    );
    if (domains.length === 0) return;
    await mapDbErrors(() =>
      tx.query(
        `INSERT INTO login_method_domains (tenant_id, login_method_id, domain)
         SELECT $1, $2, unnest($3::text[])`,
        [tenantId, id, domains],
      ),
    );
  }

  async #require(tenantId: string, id: string): Promise<LoginMethod> {
    const method = await this.findById(tenantId, id);
    if (method === null) throw new NotFoundError("Login method");
    return method;
  }
}

/**
 * Re-wraps every upstream secret and private client key not encrypted under the current master
 * key. Returns the number of values re-wrapped.
 */
export async function rewrapLoginMethodSecrets(db: Db, secrets: SecretBox): Promise<number> {
  const rows = await db.query<{ id: string; client_secret_encrypted: string }>(
    `SELECT id, client_secret_encrypted FROM login_methods
      WHERE client_secret_encrypted IS NOT NULL AND split_part(client_secret_encrypted, '.', 2) <> $1`,
    [secrets.currentKeyId],
  );
  for (const row of rows) {
    const rewrapped = secrets.rewrap(row.client_secret_encrypted, clientSecretContext(row.id));
    await db.query(
      `UPDATE login_methods SET client_secret_encrypted = $2
        WHERE id = $1 AND client_secret_encrypted = $3`,
      [row.id, rewrapped, row.client_secret_encrypted],
    );
  }
  const keys = await db.query<{ id: string; client_private_jwk_encrypted: string }>(
    `SELECT id, client_private_jwk_encrypted FROM login_methods
      WHERE client_private_jwk_encrypted IS NOT NULL
        AND split_part(client_private_jwk_encrypted, '.', 2) <> $1`,
    [secrets.currentKeyId],
  );
  for (const row of keys) {
    const rewrapped = secrets.rewrap(
      row.client_private_jwk_encrypted,
      clientPrivateJwkContext(row.id),
    );
    await db.query(
      `UPDATE login_methods SET client_private_jwk_encrypted = $2
        WHERE id = $1 AND client_private_jwk_encrypted = $3`,
      [row.id, rewrapped, row.client_private_jwk_encrypted],
    );
  }
  return rows.length + keys.length;
}
