import type { Db } from "../db/database.js";
import {
  createTenantInputSchema,
  type CreateTenantInput,
  type Tenant,
  type TenantStatus,
  updateTenantInputSchema,
  type UpdateTenantInput,
} from "../domain/tenant.js";
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

  async list(): Promise<Tenant[]> {
    const rows = await this.#db.query<TenantRow>(`SELECT ${COLUMNS} FROM tenants ORDER BY slug`);
    return rows.map(toTenant);
  }

  async update(id: string, patch: UpdateTenantInput): Promise<Tenant> {
    requireUuids({ id });
    const data = parseInput(updateTenantInputSchema, patch);
    const [row] = await mapDbErrors(() =>
      this.#db.query<TenantRow>(
        `UPDATE tenants
            SET name = COALESCE($2, name), status = COALESCE($3, status)
          WHERE id = $1
        RETURNING ${COLUMNS}`,
        [id, data.name ?? null, data.status ?? null],
      ),
    );
    if (row === undefined) throw new NotFoundError("Tenant");
    return toTenant(row);
  }

  /** Deletes the tenant and every row it owns. Audit events are kept. */
  async delete(id: string): Promise<boolean> {
    requireUuids({ id });
    const rows = await mapDbErrors(() =>
      this.#db.query("DELETE FROM tenants WHERE id = $1 RETURNING id", [id]),
    );
    return rows.length > 0;
  }
}
