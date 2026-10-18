import { randomUUID } from "node:crypto";
import type { SecretBox } from "../crypto/envelope.js";
import type { Db } from "../db/database.js";
import {
  claimMappingSchema,
  createLoginMethodInputSchema,
  type CreateLoginMethodInput,
  emailDomain,
  type LoginMethod,
  type LoginMethodKind,
  updateLoginMethodInputSchema,
  type UpdateLoginMethodInput,
} from "../domain/login-method.js";
import { emailDomainSchema } from "../domain/schemas.js";
import { mapDbErrors, NotFoundError, parseInput, requireUuids } from "./errors.js";

interface LoginMethodRow {
  id: string;
  tenant_id: string;
  kind: LoginMethodKind;
  display_name: string;
  issuer: string;
  client_id: string;
  has_client_secret: boolean;
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
         lm.client_secret_encrypted IS NOT NULL AS has_client_secret, lm.scopes, lm.claim_mapping,
         lm.asserted_acr, lm.secret_expires_at, lm.max_age_seconds, lm.idle_seconds, lm.allow_sso,
         lm.link_by_pin, lm.enabled, lm.created_at, lm.updated_at,
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

export class LoginMethodRepository {
  readonly #db: Db;
  readonly #secrets: SecretBox;

  constructor(db: Db, secrets: SecretBox) {
    this.#db = db;
    this.#secrets = secrets;
  }

  async create(tenantId: string, input: CreateLoginMethodInput): Promise<LoginMethod> {
    requireUuids({ tenantId });
    const data = parseInput(createLoginMethodInputSchema, input);
    const id = randomUUID();
    const encryptedSecret =
      data.clientSecret === undefined
        ? null
        : this.#secrets.encrypt(data.clientSecret, clientSecretContext(id));

    await this.#db.transaction(async (tx) => {
      await mapDbErrors(() =>
        tx.query(
          `INSERT INTO login_methods
             (id, tenant_id, kind, display_name, issuer, client_id, client_secret_encrypted, scopes,
              claim_mapping, asserted_acr, secret_expires_at, max_age_seconds, idle_seconds,
              allow_sso, link_by_pin, enabled)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10, $11, $12, $13, $14, $15, $16)`,
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
          ],
        ),
      );
      await this.#replaceDomains(tx, tenantId, id, data.homeRealmDomains);
    });
    return this.#require(tenantId, id);
  }

  async update(tenantId: string, id: string, patch: UpdateLoginMethodInput): Promise<LoginMethod> {
    requireUuids({ tenantId, id });
    const data = parseInput(updateLoginMethodInputSchema, patch);
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
             link_by_pin = COALESCE($18, link_by_pin)
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
          ],
        ),
      );
      if (rows.length === 0) throw new NotFoundError("Login method");
      if (data.homeRealmDomains !== undefined) {
        await this.#replaceDomains(tx, tenantId, id, data.homeRealmDomains);
      }
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

  /** Deleting a login method that still has identities is refused; disable it instead. */
  async delete(tenantId: string, id: string): Promise<boolean> {
    requireUuids({ tenantId, id });
    const rows = await mapDbErrors(() =>
      this.#db.query("DELETE FROM login_methods WHERE tenant_id = $1 AND id = $2 RETURNING id", [
        tenantId,
        id,
      ]),
    );
    return rows.length > 0;
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

/** Re-wraps every upstream secret not encrypted under the current master key. */
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
  return rows.length;
}
