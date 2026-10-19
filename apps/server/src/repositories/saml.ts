import { createHash } from "node:crypto";
import type { SecretBox } from "../crypto/envelope.js";
import type { Db } from "../db/database.js";
import { idpMetadataSchema, type IdpMetadata } from "../federation/saml/metadata.js";
import { ConflictError, mapDbErrors, NotFoundError, requireUuids } from "./errors.js";

/**
 * SAML login method state beyond the configuration: the SP key pairs (`saml_sp_keys`), the IdP
 * metadata cache and its refresh bookkeeping (`login_method_saml`), and the assertion replay
 * cache (`saml_replay_cache`). The configuration itself is read and written through
 * `LoginMethodRepository` (`createSaml`, `updateSaml`).
 */

export const SP_KEY_PURPOSES = ["signing", "encryption"] as const;
export type SpKeyPurpose = (typeof SP_KEY_PURPOSES)[number];

export const SP_KEY_STATES = ["next", "active", "previous"] as const;
export type SpKeyState = (typeof SP_KEY_STATES)[number];

/** AAD context binding an SP private key to its row. */
export const spKeyContext = (keyId: string): string => `saml_sp_key:${keyId}:private_key`;

/** A freshly generated SP key pair (private key in plaintext until it is stored encrypted). */
export interface NewSpKey {
  readonly purpose: SpKeyPurpose;
  readonly certificate: string;
  readonly privateKey: string;
  readonly notAfter: Date;
}

/** An SP key as published (no private key). */
export interface SpKey {
  readonly id: string;
  readonly loginMethodId: string;
  readonly purpose: SpKeyPurpose;
  readonly state: SpKeyState;
  readonly certificate: string;
  readonly notAfter: Date;
  readonly createdAt: Date;
}

/** An SP key with its private key, for signing and decryption only. Never log it. */
export interface SpKeyPair extends SpKey {
  readonly privateKey: string;
}

interface SpKeyRow {
  id: string;
  login_method_id: string;
  purpose: SpKeyPurpose;
  state: SpKeyState;
  certificate: string;
  not_after: Date;
  created_at: Date;
}

const SP_KEY_COLUMNS = "id, login_method_id, purpose, state, certificate, not_after, created_at";
const STATE_ORDER = "CASE state WHEN 'active' THEN 0 WHEN 'next' THEN 1 ELSE 2 END";

const toSpKey = (row: SpKeyRow): SpKey => ({
  id: row.id,
  loginMethodId: row.login_method_id,
  purpose: row.purpose,
  state: row.state,
  certificate: row.certificate,
  notAfter: row.not_after,
  createdAt: row.created_at,
});

/** Inserts an SP key in `state` (inside the caller's transaction). */
export async function insertSpKey(
  tx: Db,
  secrets: SecretBox,
  tenantId: string,
  loginMethodId: string,
  key: NewSpKey,
  state: SpKeyState,
): Promise<string> {
  const [row] = await tx.query<{ id: string }>("SELECT gen_random_uuid() AS id");
  if (row === undefined) throw new Error("no uuid");
  await mapDbErrors(() =>
    tx.query(
      `INSERT INTO saml_sp_keys
         (id, tenant_id, login_method_id, purpose, state, certificate, private_key_encrypted,
          not_after)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        row.id,
        tenantId,
        loginMethodId,
        key.purpose,
        state,
        key.certificate,
        secrets.encrypt(key.privateKey, spKeyContext(row.id)),
        key.notAfter,
      ],
    ),
  );
  return row.id;
}

/** The cached IdP metadata of a login method and its refresh state. */
export interface MetadataCacheEntry {
  readonly metadata: IdpMetadata | null;
  readonly cachedAt: Date | null;
  readonly checkedAt: Date | null;
  /** Reason code of the last failed refresh (cleared by a successful one). */
  readonly error: string | null;
}

/** Where cached metadata came from (guards against racing a configuration change). */
export interface MetadataSource {
  readonly url: string | null;
  readonly xml: string | null;
  readonly signingCertificate: string | null;
  readonly entityId: string;
}

/** A login method whose metadata URL is due for a refresh (scheduled job, all tenants). */
export interface MetadataRefreshTarget {
  readonly tenantId: string;
  readonly loginMethodId: string;
  readonly idpEntityId: string;
  readonly metadataUrl: string;
  readonly signingCertificate: string | null;
}

/** An SP certificate (active or next) expiring soon, for the admin's "expiring" warning. */
export interface ExpiringSpCertificate {
  readonly loginMethodId: string;
  readonly purpose: SpKeyPurpose;
  readonly state: SpKeyState;
  readonly notAfter: Date;
}

export class SamlRepository {
  readonly #db: Db;
  readonly #secrets: SecretBox;

  constructor(db: Db, secrets: SecretBox) {
    this.#db = db;
    this.#secrets = secrets;
  }

  /** Published and retained SP keys of a login method: active first, then next, previous. */
  async listSpKeys(tenantId: string, loginMethodId: string): Promise<SpKey[]> {
    requireUuids({ tenantId, loginMethodId });
    const rows = await this.#db.query<SpKeyRow>(
      `SELECT ${SP_KEY_COLUMNS} FROM saml_sp_keys
        WHERE tenant_id = $1 AND login_method_id = $2
        ORDER BY purpose, ${STATE_ORDER}`,
      [tenantId, loginMethodId],
    );
    return rows.map(toSpKey);
  }

  /** Decrypted key pairs of one purpose, active first (then next, previous). Never log them. */
  async spKeyPairs(
    tenantId: string,
    loginMethodId: string,
    purpose: SpKeyPurpose,
  ): Promise<SpKeyPair[]> {
    requireUuids({ tenantId, loginMethodId });
    const rows = await this.#db.query<SpKeyRow & { private_key_encrypted: string }>(
      `SELECT ${SP_KEY_COLUMNS}, private_key_encrypted FROM saml_sp_keys
        WHERE tenant_id = $1 AND login_method_id = $2 AND purpose = $3
        ORDER BY ${STATE_ORDER}`,
      [tenantId, loginMethodId, purpose],
    );
    return rows.map((row) => ({
      ...toSpKey(row),
      privateKey: this.#secrets.decryptString(row.private_key_encrypted, spKeyContext(row.id)),
    }));
  }

  /**
   * Adds the `next` key of a purpose: published in SP metadata next to the active one, so IdPs
   * can pick it up before it signs or receives encryption. One next key per purpose.
   */
  async addNextSpKey(tenantId: string, loginMethodId: string, key: NewSpKey): Promise<SpKey> {
    requireUuids({ tenantId, loginMethodId });
    return this.#db.transaction(async (tx) => {
      const [method] = await tx.query(
        "SELECT 1 FROM login_method_saml WHERE tenant_id = $1 AND login_method_id = $2",
        [tenantId, loginMethodId],
      );
      if (method === undefined) throw new NotFoundError("SAML login method");
      const [existing] = await tx.query(
        `SELECT 1 FROM saml_sp_keys
          WHERE tenant_id = $1 AND login_method_id = $2 AND purpose = $3 AND state = 'next'`,
        [tenantId, loginMethodId, key.purpose],
      );
      if (existing !== undefined) {
        throw new ConflictError("A next SP key already exists for this purpose");
      }
      const id = await insertSpKey(tx, this.#secrets, tenantId, loginMethodId, key, "next");
      const [row] = await tx.query<SpKeyRow>(
        `SELECT ${SP_KEY_COLUMNS} FROM saml_sp_keys WHERE id = $1`,
        [id],
      );
      if (row === undefined) throw new Error("SP key vanished");
      return toSpKey(row);
    });
  }

  /**
   * Rotation: the next key becomes active, the active one previous (still accepted for
   * decryption, no longer published or used to sign), and the former previous key is deleted.
   * Returns false when the purpose has no next key.
   */
  async promoteNextSpKey(
    tenantId: string,
    loginMethodId: string,
    purpose: SpKeyPurpose,
  ): Promise<boolean> {
    requireUuids({ tenantId, loginMethodId });
    return this.#db.transaction(async (tx) => {
      const scope = [tenantId, loginMethodId, purpose];
      const [next] = await tx.query(
        `SELECT 1 FROM saml_sp_keys
          WHERE tenant_id = $1 AND login_method_id = $2 AND purpose = $3 AND state = 'next'
          FOR UPDATE`,
        scope,
      );
      if (next === undefined) return false;
      await tx.query(
        `DELETE FROM saml_sp_keys
          WHERE tenant_id = $1 AND login_method_id = $2 AND purpose = $3 AND state = 'previous'`,
        scope,
      );
      for (const [from, to] of [
        ["active", "previous"],
        ["next", "active"],
      ] as const) {
        await tx.query(
          `UPDATE saml_sp_keys SET state = $5, state_changed_at = now()
            WHERE tenant_id = $1 AND login_method_id = $2 AND purpose = $3 AND state = $4`,
          [...scope, from, to],
        );
      }
      return true;
    });
  }

  /** Drops the previous key of a purpose (after every IdP uses the new one). */
  async deletePreviousSpKey(
    tenantId: string,
    loginMethodId: string,
    purpose: SpKeyPurpose,
  ): Promise<boolean> {
    requireUuids({ tenantId, loginMethodId });
    const rows = await this.#db.query(
      `DELETE FROM saml_sp_keys
        WHERE tenant_id = $1 AND login_method_id = $2 AND purpose = $3 AND state = 'previous'
        RETURNING 1`,
      [tenantId, loginMethodId, purpose],
    );
    return rows.length > 0;
  }

  /** Active and next SP certificates of the tenant expiring before `before`, soonest first. */
  async listSpCertificatesExpiringBefore(
    tenantId: string,
    before: Date,
  ): Promise<ExpiringSpCertificate[]> {
    requireUuids({ tenantId });
    const rows = await this.#db.query<{
      login_method_id: string;
      purpose: SpKeyPurpose;
      state: SpKeyState;
      not_after: Date;
    }>(
      `SELECT login_method_id, purpose, state, not_after FROM saml_sp_keys
        WHERE tenant_id = $1 AND state <> 'previous' AND not_after < $2
        ORDER BY not_after, login_method_id, purpose`,
      [tenantId, before],
    );
    return rows.map((row) => ({
      loginMethodId: row.login_method_id,
      purpose: row.purpose,
      state: row.state,
      notAfter: row.not_after,
    }));
  }

  async metadataCache(tenantId: string, loginMethodId: string): Promise<MetadataCacheEntry> {
    requireUuids({ tenantId, loginMethodId });
    const [row] = await this.#db.query<{
      metadata_cache: unknown;
      metadata_cached_at: Date | null;
      metadata_checked_at: Date | null;
      metadata_error: string | null;
    }>(
      `SELECT metadata_cache, metadata_cached_at, metadata_checked_at, metadata_error
         FROM login_method_saml WHERE tenant_id = $1 AND login_method_id = $2`,
      [tenantId, loginMethodId],
    );
    if (row === undefined) throw new NotFoundError("SAML login method");
    const parsed =
      row.metadata_cache === null ? null : idpMetadataSchema.safeParse(row.metadata_cache);
    return {
      metadata: parsed?.success === true ? parsed.data : null,
      cachedAt: row.metadata_cached_at,
      checkedAt: row.metadata_checked_at,
      error: row.metadata_error,
    };
  }

  /**
   * Stores freshly fetched, checked metadata as the last good copy. `expected`: the source it
   * came from (URL or inline XML, signing certificate, entityID), so a refresh that raced a
   * configuration change never overwrites the new source's metadata.
   */
  async storeMetadata(
    tenantId: string,
    loginMethodId: string,
    metadata: IdpMetadata,
    expected: MetadataSource,
  ): Promise<boolean> {
    requireUuids({ tenantId, loginMethodId });
    const rows = await this.#db.query(
      `UPDATE login_method_saml
          SET metadata_cache = $3::jsonb, metadata_cached_at = now(), metadata_checked_at = now(),
              metadata_valid_until = $4, metadata_error = NULL
        WHERE tenant_id = $1 AND login_method_id = $2
          AND metadata_url IS NOT DISTINCT FROM $5 AND idp_entity_id = $6
          AND metadata_xml IS NOT DISTINCT FROM $7
          AND metadata_signing_certificate IS NOT DISTINCT FROM $8
        RETURNING 1`,
      [
        tenantId,
        loginMethodId,
        JSON.stringify(idpMetadataSchema.parse(metadata)),
        metadata.validUntil === null ? null : new Date(metadata.validUntil),
        expected.url,
        expected.entityId,
        expected.xml,
        expected.signingCertificate,
      ],
    );
    return rows.length > 0;
  }

  /**
   * Drops the cached metadata (the IdP was removed from its metadata): logins through the method
   * fail until a refresh finds it again. Guarded by the source like {@link storeMetadata}.
   */
  async dropMetadata(
    tenantId: string,
    loginMethodId: string,
    reason: string,
    expected: MetadataSource,
  ): Promise<boolean> {
    requireUuids({ tenantId, loginMethodId });
    const rows = await this.#db.query(
      `UPDATE login_method_saml
          SET metadata_cache = NULL, metadata_cached_at = NULL, metadata_valid_until = NULL,
              metadata_checked_at = now(), metadata_error = $3
        WHERE tenant_id = $1 AND login_method_id = $2
          AND metadata_url IS NOT DISTINCT FROM $4 AND idp_entity_id = $5
          AND metadata_xml IS NOT DISTINCT FROM $6
          AND metadata_signing_certificate IS NOT DISTINCT FROM $7
        RETURNING 1`,
      [
        tenantId,
        loginMethodId,
        reason,
        expected.url,
        expected.entityId,
        expected.xml,
        expected.signingCertificate,
      ],
    );
    return rows.length > 0;
  }

  /** Records a failed refresh: the last good metadata stays; the reason code is kept. */
  async recordMetadataFailure(
    tenantId: string,
    loginMethodId: string,
    reason: string,
  ): Promise<void> {
    requireUuids({ tenantId, loginMethodId });
    await this.#db.query(
      `UPDATE login_method_saml SET metadata_checked_at = now(), metadata_error = $3
        WHERE tenant_id = $1 AND login_method_id = $2`,
      [tenantId, loginMethodId, /^[a-z_]{1,64}$/.test(reason) ? reason : "refresh_failed"],
    );
  }

  /**
   * Login methods (all tenants) with a metadata URL due for refresh: never checked, or last
   * checked `metadata_refresh_seconds` ago, or failing and last checked `retrySeconds` ago.
   */
  async listMetadataDue(limit: number, retrySeconds: number): Promise<MetadataRefreshTarget[]> {
    const rows = await this.#db.query<{
      tenant_id: string;
      login_method_id: string;
      idp_entity_id: string;
      metadata_url: string;
      metadata_signing_certificate: string | null;
    }>(
      `SELECT s.tenant_id, s.login_method_id, s.idp_entity_id, s.metadata_url,
              s.metadata_signing_certificate
         FROM login_method_saml s
         JOIN login_methods lm ON lm.tenant_id = s.tenant_id AND lm.id = s.login_method_id
        WHERE s.metadata_url IS NOT NULL AND lm.enabled
          AND (s.metadata_checked_at IS NULL
               OR s.metadata_checked_at <= now() - make_interval(secs => s.metadata_refresh_seconds)
               OR (s.metadata_error IS NOT NULL
                   AND s.metadata_checked_at <= now() - make_interval(secs => $2::double precision)))
        ORDER BY s.metadata_checked_at NULLS FIRST
        LIMIT $1`,
      [limit, retrySeconds],
    );
    return rows.map((row) => ({
      tenantId: row.tenant_id,
      loginMethodId: row.login_method_id,
      idpEntityId: row.idp_entity_id,
      metadataUrl: row.metadata_url,
      signingCertificate: row.metadata_signing_certificate,
    }));
  }

  /**
   * Metadata freshness of every enabled SAML login method (all tenants, for metrics): when the
   * cached metadata was last refreshed, its validUntil, and whether the last refresh failed.
   */
  async metadataStatus(limit = 1000): Promise<
    {
      readonly loginMethodId: string;
      readonly tenantSlug: string;
      readonly cachedAt: Date | null;
      readonly validUntil: Date | null;
      readonly failing: boolean;
    }[]
  > {
    const rows = await this.#db.query<{
      login_method_id: string;
      slug: string;
      metadata_cached_at: Date | null;
      metadata_valid_until: Date | null;
      metadata_error: string | null;
    }>(
      `SELECT s.login_method_id, t.slug, s.metadata_cached_at, s.metadata_valid_until,
              s.metadata_error
         FROM login_method_saml s
         JOIN login_methods lm ON lm.tenant_id = s.tenant_id AND lm.id = s.login_method_id
         JOIN tenants t ON t.id = s.tenant_id
        WHERE lm.enabled
        ORDER BY s.login_method_id
        LIMIT $1`,
      [limit],
    );
    return rows.map((row) => ({
      loginMethodId: row.login_method_id,
      tenantSlug: row.slug,
      cachedAt: row.metadata_cached_at,
      validUntil: row.metadata_valid_until,
      failing: row.metadata_error !== null,
    }));
  }

  /**
   * Records an assertion ID as used until `expiresAt`. Insert-once: false when the ID was already
   * seen and has not expired (a replay). Decided by the database, so parallel posts of one
   * assertion cannot both pass.
   */
  async rememberAssertion(
    tenantId: string,
    loginMethodId: string,
    assertionId: string,
    expiresAt: Date,
  ): Promise<boolean> {
    requireUuids({ tenantId, loginMethodId });
    // Assertion IDs are opaque IdP values: the key is their hash, so length and characters
    // never matter.
    const key = createHash("sha256").update(assertionId, "utf8").digest("base64url");
    const rows = await this.#db.query(
      `INSERT INTO saml_replay_cache (tenant_id, login_method_id, assertion_id, expires_at)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (tenant_id, login_method_id, assertion_id) DO UPDATE
         SET expires_at = EXCLUDED.expires_at, created_at = now()
         WHERE saml_replay_cache.expires_at <= now()
       RETURNING 1`,
      [tenantId, loginMethodId, key, expiresAt],
    );
    return rows.length > 0;
  }

  /** Deletes up to `batchSize` expired replay cache entries (cleanup job). */
  async deleteExpiredReplayBatch(batchSize: number): Promise<number> {
    const rows = await this.#db.query<{ deleted: number }>(
      `WITH doomed AS (
           SELECT ctid FROM saml_replay_cache WHERE expires_at <= now() LIMIT $1
         ), deleted AS (
           DELETE FROM saml_replay_cache r USING doomed WHERE r.ctid = doomed.ctid RETURNING 1
         )
         SELECT count(*)::int AS deleted FROM deleted`,
      [batchSize],
    );
    return rows[0]?.deleted ?? 0;
  }
}

/** Re-wraps every SP private key not encrypted under the current master key. */
export async function rewrapSpKeys(db: Db, secrets: SecretBox): Promise<number> {
  const rows = await db.query<{ id: string; private_key_encrypted: string }>(
    `SELECT id, private_key_encrypted FROM saml_sp_keys
      WHERE split_part(private_key_encrypted, '.', 2) <> $1`,
    [secrets.currentKeyId],
  );
  for (const row of rows) {
    await db.query(
      `UPDATE saml_sp_keys SET private_key_encrypted = $2
        WHERE id = $1 AND private_key_encrypted = $3`,
      [
        row.id,
        secrets.rewrap(row.private_key_encrypted, spKeyContext(row.id)),
        row.private_key_encrypted,
      ],
    );
  }
  return rows.length;
}
