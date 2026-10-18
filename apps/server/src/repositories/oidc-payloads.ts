import { z } from "zod";
import type { Db } from "../db/database.js";
import { requireUuids } from "./errors.js";

/** Secondary lookup keys of a stored payload. */
export interface PayloadIndexes {
  /** Set for grant-bound tokens only, so `revokeByGrantId` removes exactly those. */
  readonly grantId?: string | undefined;
  readonly userCode?: string | undefined;
  readonly uid?: string | undefined;
}

const payloadSchema = z.record(z.string(), z.unknown());
export type StoredPayload = z.infer<typeof payloadSchema>;

/** Rows deleted per statement by the cleanup job. */
const DEFAULT_CLEANUP_BATCH = 5000;

/**
 * Storage for oidc-provider model instances (sessions, interactions, grants, codes, tokens, ...)
 * in `oidc_payloads`. Every method is scoped by tenant: each tenant has its own provider and its
 * rows are invisible to every other tenant's provider.
 *
 * Expiry: `expires_at` is computed from the database clock. Expired rows are never returned, even
 * before {@link deleteExpiredBatch} removes them. Payloads are tokens and personal data: never log them.
 */
export class OidcPayloadRepository {
  readonly #db: Db;

  constructor(db: Db) {
    this.#db = db;
  }

  /**
   * Inserts or replaces a payload. `expiresInSeconds` undefined means no expiry. A consumed
   * marker survives a re-save, so a consumed code or refresh token cannot be revived.
   */
  async upsert(
    tenantId: string,
    kind: string,
    id: string,
    payload: StoredPayload,
    expiresInSeconds: number | undefined,
    indexes: PayloadIndexes = {},
  ): Promise<void> {
    requireUuids({ tenantId });
    if (expiresInSeconds !== undefined && !(expiresInSeconds > 0)) {
      throw new TypeError("expiresInSeconds must be positive");
    }
    await this.#db.query(
      `INSERT INTO oidc_payloads
         (tenant_id, kind, id, payload, grant_id, user_code, uid, expires_at)
       VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7,
               CASE WHEN $8::double precision IS NULL THEN NULL
                    ELSE now() + make_interval(secs => $8::double precision) END)
       ON CONFLICT (tenant_id, kind, id) DO UPDATE SET
         payload = EXCLUDED.payload,
         grant_id = EXCLUDED.grant_id,
         user_code = EXCLUDED.user_code,
         uid = EXCLUDED.uid,
         expires_at = EXCLUDED.expires_at`,
      [
        tenantId,
        kind,
        id,
        JSON.stringify(payload),
        indexes.grantId ?? null,
        indexes.userCode ?? null,
        indexes.uid ?? null,
        expiresInSeconds ?? null,
      ],
    );
  }

  async find(tenantId: string, kind: string, id: string): Promise<StoredPayload | undefined> {
    return this.#findWhere(tenantId, kind, "id = $3", id);
  }

  async findByUid(tenantId: string, kind: string, uid: string): Promise<StoredPayload | undefined> {
    return this.#findWhere(tenantId, kind, "uid = $3", uid);
  }

  async findByUserCode(
    tenantId: string,
    kind: string,
    userCode: string,
  ): Promise<StoredPayload | undefined> {
    return this.#findWhere(tenantId, kind, "user_code = $3", userCode);
  }

  /**
   * Inserts a payload only if no live row with this id exists (an expired one is replaced).
   * Returns false when one does: the single-use check (client assertion `jti`) is then decided
   * by the database, so parallel requests cannot both pass it.
   */
  async insertOnce(
    tenantId: string,
    kind: string,
    id: string,
    payload: StoredPayload,
    expiresInSeconds: number | undefined,
  ): Promise<boolean> {
    requireUuids({ tenantId });
    const rows = await this.#db.query(
      `INSERT INTO oidc_payloads (tenant_id, kind, id, payload, expires_at)
       VALUES ($1, $2, $3, $4::jsonb,
               CASE WHEN $5::double precision IS NULL THEN NULL
                    ELSE now() + make_interval(secs => $5::double precision) END)
       ON CONFLICT (tenant_id, kind, id) DO UPDATE SET
         payload = EXCLUDED.payload, expires_at = EXCLUDED.expires_at, consumed_at = NULL,
         grant_id = NULL, user_code = NULL, uid = NULL, created_at = now()
       WHERE oidc_payloads.expires_at IS NOT NULL AND oidc_payloads.expires_at <= now()
       RETURNING 1`,
      [tenantId, kind, id, JSON.stringify(payload), expiresInSeconds ?? null],
    );
    return rows.length > 0;
  }

  /**
   * Marks a live payload consumed (single-use codes, rotated refresh tokens). Atomic: of any
   * number of parallel calls exactly one gets `consumed: true`. `grantId` is returned either way,
   * so the caller can revoke the grant of a replayed token.
   */
  async consume(
    tenantId: string,
    kind: string,
    id: string,
  ): Promise<{ readonly consumed: boolean; readonly grantId: string | null }> {
    requireUuids({ tenantId });
    const [won] = await this.#db.query<{ grant_id: string | null }>(
      `UPDATE oidc_payloads SET consumed_at = now()
        WHERE tenant_id = $1 AND kind = $2 AND id = $3 AND consumed_at IS NULL
          AND (expires_at IS NULL OR expires_at > now())
        RETURNING grant_id`,
      [tenantId, kind, id],
    );
    if (won !== undefined) return { consumed: true, grantId: won.grant_id };
    const [existing] = await this.#db.query<{ grant_id: string | null }>(
      "SELECT grant_id FROM oidc_payloads WHERE tenant_id = $1 AND kind = $2 AND id = $3",
      [tenantId, kind, id],
    );
    return { consumed: false, grantId: existing?.grant_id ?? null };
  }

  /**
   * Sets one top-level JSON field of a live payload, only when every `guards` field still has
   * the given value: a single atomic UPDATE, no read-modify-write of the whole payload. Field
   * names are fixed identifiers of the caller, never input. Returns whether a row changed.
   */
  async setFieldIf(
    tenantId: string,
    kind: string,
    id: string,
    field: string,
    value: string | number | boolean,
    guards: Readonly<Record<string, string | number | boolean>>,
  ): Promise<boolean> {
    requireUuids({ tenantId });
    const names = [field, ...Object.keys(guards)];
    if (names.some((name) => !/^[A-Za-z][A-Za-z0-9]{0,63}$/.test(name))) {
      throw new TypeError("invalid payload field name");
    }
    const params: unknown[] = [tenantId, kind, id, field, JSON.stringify(value)];
    const conditions = Object.entries(guards).map(([name, expected]) => {
      params.push(name, JSON.stringify(expected));
      return `payload -> $${params.length - 1}::text = $${params.length}::jsonb`;
    });
    const rows = await this.#db.query(
      `UPDATE oidc_payloads SET payload = jsonb_set(payload, ARRAY[$4::text], $5::jsonb)
        WHERE tenant_id = $1 AND kind = $2 AND id = $3
          AND (expires_at IS NULL OR expires_at > now())
          ${conditions.map((condition) => `AND ${condition}`).join(" ")}
        RETURNING 1`,
      params,
    );
    return rows.length > 0;
  }

  /** Revokes a grant: deletes its grant-bound tokens and the Grant itself. */
  async revokeGrant(tenantId: string, grantId: string): Promise<void> {
    requireUuids({ tenantId });
    await this.#db.query(
      `DELETE FROM oidc_payloads
        WHERE tenant_id = $1 AND (grant_id = $2 OR (kind = 'Grant' AND id = $2))`,
      [tenantId, grantId],
    );
  }

  async destroy(tenantId: string, kind: string, id: string): Promise<void> {
    requireUuids({ tenantId });
    await this.#db.query(
      "DELETE FROM oidc_payloads WHERE tenant_id = $1 AND kind = $2 AND id = $3",
      [tenantId, kind, id],
    );
  }

  /** Deletes every grant-bound token of the grant (codes, access and refresh tokens). */
  async revokeByGrantId(tenantId: string, grantId: string): Promise<void> {
    requireUuids({ tenantId });
    await this.#db.query("DELETE FROM oidc_payloads WHERE tenant_id = $1 AND grant_id = $2", [
      tenantId,
      grantId,
    ]);
  }

  /**
   * Deletes up to `batchSize` expired rows of any tenant and returns how many were removed.
   * Rows without an expiry are kept. Run it repeatedly, one transaction per batch, so locks are
   * never held for long.
   */
  async deleteExpiredBatch(batchSize: number = DEFAULT_CLEANUP_BATCH): Promise<number> {
    const rows = await this.#db.query<{ deleted: number }>(
      `WITH doomed AS (
           SELECT ctid FROM oidc_payloads WHERE expires_at <= now() LIMIT $1
         ), deleted AS (
           DELETE FROM oidc_payloads p USING doomed WHERE p.ctid = doomed.ctid RETURNING 1
         )
         SELECT count(*)::int AS deleted FROM deleted`,
      [batchSize],
    );
    return rows[0]?.deleted ?? 0;
  }

  async #findWhere(
    tenantId: string,
    kind: string,
    condition: string,
    value: string,
  ): Promise<StoredPayload | undefined> {
    requireUuids({ tenantId });
    const [row] = await this.#db.query<{ payload: unknown }>(
      `SELECT CASE WHEN consumed_at IS NULL THEN payload
                   ELSE payload || jsonb_build_object('consumed',
                                                      floor(extract(epoch FROM consumed_at))::bigint)
              END AS payload
         FROM oidc_payloads
        WHERE tenant_id = $1 AND kind = $2 AND ${condition}
          AND (expires_at IS NULL OR expires_at > now())
        ORDER BY created_at DESC
        LIMIT 1`,
      [tenantId, kind, value],
    );
    if (row === undefined) return undefined;
    return payloadSchema.parse(row.payload);
  }
}
