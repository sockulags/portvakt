import type { Db } from "../db/database.js";
import {
  createTenantInputSchema,
  type CreateTenantInput,
  type Tenant,
  type TenantStatus,
  updateTenantInputSchema,
  type UpdateTenantInput,
} from "../domain/tenant.js";
import { emitChange } from "./change-events.js";
import { mapDbErrors, NotFoundError, parseInput, requireUuids } from "./errors.js";
import { requireRow } from "./sql.js";

interface TenantRow {
  id: string;
  slug: string;
  name: string;
  status: TenantStatus;
  created_at: Date;
  updated_at: Date;
}

const COLUMNS = "id, slug, name, status, created_at, updated_at";

function toTenant(row: TenantRow): Tenant {
  return {
    id: row.id,
    slug: row.slug,
    name: row.name,
    status: row.status,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export class TenantRepository {
  readonly #db: Db;

  constructor(db: Db) {
    this.#db = db;
  }

  async create(input: CreateTenantInput): Promise<Tenant> {
    const data = parseInput(createTenantInputSchema, input);
    const rows = await mapDbErrors(() =>
      this.#db.query<TenantRow>(
        `INSERT INTO tenants (slug, name, status) VALUES ($1, $2, $3) RETURNING ${COLUMNS}`,
        [data.slug, data.name, data.status],
      ),
    );
    return toTenant(requireRow(rows));
  }

  async findById(id: string): Promise<Tenant | null> {
    requireUuids({ id });
    const [row] = await this.#db.query<TenantRow>(`SELECT ${COLUMNS} FROM tenants WHERE id = $1`, [
      id,
    ]);
    return row === undefined ? null : toTenant(row);
  }

  async findBySlug(slug: string): Promise<Tenant | null> {
    const [row] = await this.#db.query<TenantRow>(
      `SELECT ${COLUMNS} FROM tenants WHERE slug = $1`,
      [slug],
    );
    return row === undefined ? null : toTenant(row);
  }

  /** Active tenant by slug: what an issuer path `/t/{slug}` resolves to. */
  async findActiveBySlug(slug: string): Promise<Tenant | null> {
    const [row] = await this.#db.query<TenantRow>(
      `SELECT ${COLUMNS} FROM tenants WHERE slug = $1 AND status = 'active'`,
      [slug],
    );
    return row === undefined ? null : toTenant(row);
  }

  /**
   * Fingerprint of what a tenant's OIDC provider is built from: the tenant row, every attached
   * application (its client configuration and the attachment) and every login method (its acr
   * values and enabled state). It changes whenever one of them does, which lets replicas detect a
   * change whose notification they missed. Tenants that no longer exist are absent from the
   * result.
   */
  async providerFingerprints(tenantIds: readonly string[]): Promise<Map<string, string>> {
    for (const id of tenantIds) requireUuids({ id });
    if (tenantIds.length === 0) return new Map();
    const rows = await this.#db.query<{ id: string; fingerprint: string }>(
      `SELECT t.id,
              md5(concat_ws('|', t.slug, t.status, t.updated_at::text,
                (SELECT string_agg(concat_ws(':', a.client_id, a.enabled, a.updated_at::text,
                                             ta.enabled, ta.updated_at::text), ','
                                   ORDER BY a.client_id)
                   FROM tenant_applications ta JOIN applications a ON a.id = ta.application_id
                  WHERE ta.tenant_id = t.id),
                (SELECT string_agg(concat_ws(':', lm.id, lm.enabled, lm.updated_at::text), ','
                                   ORDER BY lm.id)
                   FROM login_methods lm
                  WHERE lm.tenant_id = t.id))) AS fingerprint
         FROM tenants t
        WHERE t.id = ANY ($1::uuid[])`,
      [[...tenantIds]],
    );
    return new Map(rows.map((row) => [row.id, row.fingerprint]));
  }

  async list(): Promise<Tenant[]> {
    const rows = await this.#db.query<TenantRow>(`SELECT ${COLUMNS} FROM tenants ORDER BY slug`);
    return rows.map(toTenant);
  }

  async update(id: string, patch: UpdateTenantInput): Promise<Tenant> {
    requireUuids({ id });
    const data = parseInput(updateTenantInputSchema, patch);
    const row = await this.#db.transaction(async (tx) => {
      const [updated] = await mapDbErrors(() =>
        tx.query<TenantRow>(
          `UPDATE tenants
              SET name = COALESCE($2, name), status = COALESCE($3, status)
            WHERE id = $1
          RETURNING ${COLUMNS}`,
          [id, data.name ?? null, data.status ?? null],
        ),
      );
      if (updated === undefined) throw new NotFoundError("Tenant");
      await emitChange(tx, { type: "tenant", tenantId: id });
      return updated;
    });
    return toTenant(row);
  }

  /** Deletes the tenant and every row it owns. Audit events are kept. */
  async delete(id: string): Promise<boolean> {
    requireUuids({ id });
    return this.#db.transaction(async (tx) => {
      const rows = await mapDbErrors(() =>
        tx.query("DELETE FROM tenants WHERE id = $1 RETURNING id", [id]),
      );
      if (rows.length > 0) await emitChange(tx, { type: "tenant", tenantId: id });
      return rows.length > 0;
    });
  }
}
