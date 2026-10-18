import { randomUUID } from "node:crypto";
import { z } from "zod";
import type { SecretBox } from "../crypto/envelope.js";
import type { Db } from "../db/database.js";
import {
  type Application,
  type ClientAuth,
  clientJwksSchema,
  createApplicationInputSchema,
  type CreateApplicationInput,
  declareAttributeKeyInputSchema,
  declareRoleInputSchema,
  EXTRA_SCOPES,
  type SecretAuthMethod,
  type TenantApplication,
  updateApplicationInputSchema,
  type UpdateApplicationInput,
} from "../domain/application.js";
import { attributeKeySchema, roleNameSchema } from "../domain/schemas.js";
import { mapDbErrors, NotFoundError, parseInput, requireUuids } from "./errors.js";

interface ApplicationRow {
  id: string;
  client_id: string;
  name: string;
  enabled: boolean;
  token_endpoint_auth_method: SecretAuthMethod | "private_key_jwt";
  jwks_uri: string | null;
  jwks: unknown;
  redirect_uris: string[];
  post_logout_redirect_uris: string[];
  allowed_extra_scopes: string[];
  roles: unknown;
  attribute_keys: unknown;
  created_at: Date;
  updated_at: Date;
}

interface TenantApplicationRow extends ApplicationRow {
  ta_tenant_id: string;
  ta_enabled: boolean;
  ta_created_at: Date;
}

const rolesColumnSchema = z.array(
  z.object({ role: z.string(), description: z.string().nullable() }),
);
const attributeKeysColumnSchema = z.array(
  z.object({ key: z.string(), description: z.string().nullable() }),
);
const extraScopesColumnSchema = z.array(z.enum(EXTRA_SCOPES));

const SELECT_APPLICATION = `
  SELECT a.id, a.client_id, a.name, a.enabled, a.token_endpoint_auth_method,
         a.jwks_uri, a.jwks, a.redirect_uris, a.post_logout_redirect_uris, a.allowed_extra_scopes,
         a.created_at, a.updated_at,
         COALESCE((SELECT json_agg(json_build_object('role', r.role, 'description', r.description)
                                   ORDER BY r.role)
                     FROM application_roles r WHERE r.application_id = a.id), '[]'::json) AS roles,
         COALESCE((SELECT json_agg(json_build_object('key', k.key, 'description', k.description)
                                   ORDER BY k.key)
                     FROM application_attribute_keys k WHERE k.application_id = a.id), '[]'::json)
           AS attribute_keys`;

/** Joins an application to its tenant attachment; only usable when everything is enabled. */
const USABLE_IN_TENANT = `
         FROM applications a
         JOIN tenant_applications ta ON ta.application_id = a.id
         JOIN tenants t ON t.id = ta.tenant_id
        WHERE ta.tenant_id = $1 AND a.enabled AND ta.enabled AND t.status = 'active'`;

/** AAD context binding an encrypted downstream client secret to its application. */
export const applicationSecretContext = (applicationId: string): string =>
  `application:${applicationId}:client_secret`;

function toClientAuth(row: ApplicationRow): ClientAuth {
  if (row.token_endpoint_auth_method === "private_key_jwt") {
    if (row.jwks_uri !== null) return { method: "private_key_jwt", jwksUri: row.jwks_uri };
    return { method: "private_key_jwt", jwks: clientJwksSchema.parse(row.jwks) };
  }
  return { method: row.token_endpoint_auth_method };
}

function toApplication(row: ApplicationRow): Application {
  return {
    id: row.id,
    clientId: row.client_id,
    name: row.name,
    enabled: row.enabled,
    clientAuth: toClientAuth(row),
    redirectUris: row.redirect_uris,
    postLogoutRedirectUris: row.post_logout_redirect_uris,
    roles: rolesColumnSchema.parse(row.roles),
    attributeKeys: attributeKeysColumnSchema.parse(row.attribute_keys),
    allowedExtraScopes: extraScopesColumnSchema.parse(row.allowed_extra_scopes),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function toTenantApplication(row: TenantApplicationRow): TenantApplication {
  return {
    tenantId: row.ta_tenant_id,
    application: toApplication(row),
    enabled: row.ta_enabled,
    createdAt: row.ta_created_at,
  };
}

interface ClientAuthColumns {
  method: string;
  secretEncrypted: string | null;
  jwksUri: string | null;
  jwks: string | null;
}

/**
 * Applications are registered once per install (global); tenant-specific access goes through
 * `tenant_applications`, and every tenant-scoped method takes the tenant id explicitly.
 * Downstream client secrets are stored encrypted (oidc-provider needs the plaintext to verify
 * `client_secret_basic` / `client_secret_post`) and only returned by {@link getClientSecret}.
 */
export class ApplicationRepository {
  readonly #db: Db;
  readonly #secrets: SecretBox;

  constructor(db: Db, secrets: SecretBox) {
    this.#db = db;
    this.#secrets = secrets;
  }

  async create(input: CreateApplicationInput): Promise<Application> {
    const data = parseInput(createApplicationInputSchema, input);
    const id = randomUUID();
    const auth = this.#clientAuthColumns(id, data.clientAuth);
    await this.#db.transaction(async (tx) => {
      await mapDbErrors(() =>
        tx.query(
          `INSERT INTO applications
             (id, client_id, name, enabled, token_endpoint_auth_method, client_secret_encrypted,
              jwks_uri, jwks, redirect_uris, post_logout_redirect_uris, allowed_extra_scopes)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10, $11)`,
          [
            id,
            data.clientId,
            data.name,
            data.enabled,
            auth.method,
            auth.secretEncrypted,
            auth.jwksUri,
            auth.jwks,
            data.redirectUris,
            data.postLogoutRedirectUris,
            data.allowedExtraScopes,
          ],
        ),
      );
      for (const role of data.roles) {
        await tx.query(
          "INSERT INTO application_roles (application_id, role, description) VALUES ($1, $2, $3)",
          [id, role.role, role.description],
        );
      }
      for (const key of data.attributeKeys) {
        await tx.query(
          "INSERT INTO application_attribute_keys (application_id, key, description) VALUES ($1, $2, $3)",
          [id, key.key, key.description],
        );
      }
    });
    return this.#require(id);
  }

  async findById(id: string): Promise<Application | null> {
    requireUuids({ id });
    const [row] = await this.#db.query<ApplicationRow>(
      `${SELECT_APPLICATION} FROM applications a WHERE a.id = $1`,
      [id],
    );
    return row === undefined ? null : toApplication(row);
  }

  /** Global lookup, for platform administration. Authentication must use the tenant variant. */
  async findByClientId(clientId: string): Promise<Application | null> {
    const [row] = await this.#db.query<ApplicationRow>(
      `${SELECT_APPLICATION} FROM applications a WHERE a.client_id = $1`,
      [clientId],
    );
    return row === undefined ? null : toApplication(row);
  }

  async list(): Promise<Application[]> {
    const rows = await this.#db.query<ApplicationRow>(
      `${SELECT_APPLICATION} FROM applications a ORDER BY a.client_id`,
    );
    return rows.map(toApplication);
  }

  /** Decrypted downstream client secret, for the OIDC provider only. Never log it. */
  async getClientSecret(id: string): Promise<string | null> {
    requireUuids({ id });
    const [row] = await this.#db.query<{ client_secret_encrypted: string | null }>(
      "SELECT client_secret_encrypted FROM applications WHERE id = $1",
      [id],
    );
    if (row === undefined) throw new NotFoundError("Application");
    if (row.client_secret_encrypted === null) return null;
    return this.#secrets.decryptString(row.client_secret_encrypted, applicationSecretContext(id));
  }

  async update(id: string, patch: UpdateApplicationInput): Promise<Application> {
    requireUuids({ id });
    const data = parseInput(updateApplicationInputSchema, patch);
    const auth =
      data.clientAuth === undefined ? undefined : this.#clientAuthColumns(id, data.clientAuth);
    const rows = await mapDbErrors(() =>
      this.#db.query<{ id: string }>(
        `UPDATE applications SET
           name = COALESCE($2, name),
           enabled = COALESCE($3, enabled),
           token_endpoint_auth_method = CASE WHEN $4::boolean THEN $5 ELSE token_endpoint_auth_method END,
           client_secret_encrypted = CASE WHEN $4::boolean THEN $6 ELSE client_secret_encrypted END,
           jwks_uri = CASE WHEN $4::boolean THEN $7 ELSE jwks_uri END,
           jwks = CASE WHEN $4::boolean THEN $8::jsonb ELSE jwks END,
           redirect_uris = COALESCE($9, redirect_uris),
           post_logout_redirect_uris = COALESCE($10, post_logout_redirect_uris),
           allowed_extra_scopes = COALESCE($11, allowed_extra_scopes)
         WHERE id = $1
         RETURNING id`,
        [
          id,
          data.name ?? null,
          data.enabled ?? null,
          auth !== undefined,
          auth?.method ?? null,
          auth?.secretEncrypted ?? null,
          auth?.jwksUri ?? null,
          auth?.jwks ?? null,
          data.redirectUris ?? null,
          data.postLogoutRedirectUris ?? null,
          data.allowedExtraScopes ?? null,
        ],
      ),
    );
    if (rows.length === 0) throw new NotFoundError("Application");
    return this.#require(id);
  }

  /** Deletes the application and, in every tenant, its assignments, rules and grant limits. */
  async delete(id: string): Promise<boolean> {
    requireUuids({ id });
    const rows = await mapDbErrors(() =>
      this.#db.query("DELETE FROM applications WHERE id = $1 RETURNING id", [id]),
    );
    return rows.length > 0;
  }

  async declareRole(
    applicationId: string,
    role: string,
    description: string | null = null,
  ): Promise<void> {
    requireUuids({ applicationId });
    const data = parseInput(declareRoleInputSchema, { role, description });
    await mapDbErrors(() =>
      this.#db.query(
        `INSERT INTO application_roles (application_id, role, description) VALUES ($1, $2, $3)
         ON CONFLICT (application_id, role) DO UPDATE SET description = EXCLUDED.description`,
        [applicationId, data.role, data.description],
      ),
    );
  }

  /** Removes a declared role together with every assignment and rule that grants it. */
  async removeRole(applicationId: string, role: string): Promise<boolean> {
    requireUuids({ applicationId });
    const rows = await this.#db.query(
      "DELETE FROM application_roles WHERE application_id = $1 AND role = $2 RETURNING role",
      [applicationId, parseInput(roleNameSchema, role)],
    );
    return rows.length > 0;
  }

  async declareAttributeKey(
    applicationId: string,
    key: string,
    description: string | null = null,
  ): Promise<void> {
    requireUuids({ applicationId });
    const data = parseInput(declareAttributeKeyInputSchema, { key, description });
    await mapDbErrors(() =>
      this.#db.query(
        `INSERT INTO application_attribute_keys (application_id, key, description) VALUES ($1, $2, $3)
         ON CONFLICT (application_id, key) DO UPDATE SET description = EXCLUDED.description`,
        [applicationId, data.key, data.description],
      ),
    );
  }

  /** Removes a declared attribute key together with every assignment of it. */
  async removeAttributeKey(applicationId: string, key: string): Promise<boolean> {
    requireUuids({ applicationId });
    const rows = await this.#db.query(
      "DELETE FROM application_attribute_keys WHERE application_id = $1 AND key = $2 RETURNING key",
      [applicationId, parseInput(attributeKeySchema, key)],
    );
    return rows.length > 0;
  }

  // Tenant scope --------------------------------------------------------------------------------

  /** Attaches the application to the tenant (or re-enables it). */
  async enableForTenant(tenantId: string, applicationId: string): Promise<void> {
    requireUuids({ tenantId, applicationId });
    await mapDbErrors(() =>
      this.#db.query(
        `INSERT INTO tenant_applications (tenant_id, application_id, enabled) VALUES ($1, $2, true)
         ON CONFLICT (tenant_id, application_id) DO UPDATE SET enabled = true`,
        [tenantId, applicationId],
      ),
    );
  }

  /**
   * Stops the application from authenticating in the tenant but keeps its assignments, rules and
   * grants, so it can be re-enabled.
   */
  async disableForTenant(tenantId: string, applicationId: string): Promise<boolean> {
    requireUuids({ tenantId, applicationId });
    const rows = await this.#db.query(
      `UPDATE tenant_applications SET enabled = false
        WHERE tenant_id = $1 AND application_id = $2 RETURNING application_id`,
      [tenantId, applicationId],
    );
    return rows.length > 0;
  }

  /**
   * Detaches the application from the tenant, deleting its tenant-specific assignments, rules,
   * attributes and grant limits. A grant limited to this application alone becomes valid for no
   * application.
   */
  async removeFromTenant(tenantId: string, applicationId: string): Promise<boolean> {
    requireUuids({ tenantId, applicationId });
    const rows = await this.#db.query(
      `DELETE FROM tenant_applications WHERE tenant_id = $1 AND application_id = $2
       RETURNING application_id`,
      [tenantId, applicationId],
    );
    return rows.length > 0;
  }

  /**
   * The application with this client_id, only if it is enabled globally and for the tenant and
   * the tenant is active. This is the lookup client authentication uses.
   */
  async findEnabledByClientId(tenantId: string, clientId: string): Promise<Application | null> {
    requireUuids({ tenantId });
    const [row] = await this.#db.query<ApplicationRow>(
      `${SELECT_APPLICATION} ${USABLE_IN_TENANT} AND a.client_id = $2`,
      [tenantId, clientId],
    );
    return row === undefined ? null : toApplication(row);
  }

  /** Applications that can authenticate in the tenant; empty for a suspended tenant. */
  async listEnabledForTenant(tenantId: string): Promise<Application[]> {
    requireUuids({ tenantId });
    const rows = await this.#db.query<ApplicationRow>(
      `${SELECT_APPLICATION} ${USABLE_IN_TENANT} ORDER BY a.client_id`,
      [tenantId],
    );
    return rows.map(toApplication);
  }

  /** Every application attached to the tenant, enabled or not (administration). */
  async listForTenant(tenantId: string): Promise<TenantApplication[]> {
    requireUuids({ tenantId });
    const rows = await this.#db.query<TenantApplicationRow>(
      `${SELECT_APPLICATION}, ta.tenant_id AS ta_tenant_id, ta.enabled AS ta_enabled,
              ta.created_at AS ta_created_at
         FROM applications a
         JOIN tenant_applications ta ON ta.application_id = a.id
        WHERE ta.tenant_id = $1
        ORDER BY a.client_id`,
      [tenantId],
    );
    return rows.map(toTenantApplication);
  }

  #clientAuthColumns(
    id: string,
    auth: z.output<typeof createApplicationInputSchema>["clientAuth"],
  ): ClientAuthColumns {
    if ("clientSecret" in auth) {
      return {
        method: auth.method,
        secretEncrypted: this.#secrets.encrypt(auth.clientSecret, applicationSecretContext(id)),
        jwksUri: null,
        jwks: null,
      };
    }
    if ("jwksUri" in auth) {
      return { method: auth.method, secretEncrypted: null, jwksUri: auth.jwksUri, jwks: null };
    }
    return {
      method: auth.method,
      secretEncrypted: null,
      jwksUri: null,
      jwks: JSON.stringify(auth.jwks),
    };
  }

  async #require(id: string): Promise<Application> {
    const application = await this.findById(id);
    if (application === null) throw new NotFoundError("Application");
    return application;
  }
}

/** Re-wraps every downstream client secret not encrypted under the current master key. */
export async function rewrapApplicationSecrets(db: Db, secrets: SecretBox): Promise<number> {
  const rows = await db.query<{ id: string; client_secret_encrypted: string }>(
    `SELECT id, client_secret_encrypted FROM applications
      WHERE client_secret_encrypted IS NOT NULL
        AND split_part(client_secret_encrypted, '.', 2) <> $1`,
    [secrets.currentKeyId],
  );
  for (const row of rows) {
    await db.query(
      `UPDATE applications SET client_secret_encrypted = $2
        WHERE id = $1 AND client_secret_encrypted = $3`,
      [
        row.id,
        secrets.rewrap(row.client_secret_encrypted, applicationSecretContext(row.id)),
        row.client_secret_encrypted,
      ],
    );
  }
  return rows.length;
}
