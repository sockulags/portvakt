import { randomUUID } from "node:crypto";
import type { KeyRing } from "../crypto/keyring.js";
import type { Db } from "../db/database.js";
import {
  createPendingAttributeInputSchema,
  type CreatePendingAttributeInput,
  createPendingRoleInputSchema,
  type CreatePendingRoleInput,
  type PendingAttributeAssignment,
  type PendingRoleAssignment,
  type PendingTarget,
  type ResolvedPendingAssignment,
} from "../domain/access.js";
import {
  ApplicationNotInTenantError,
  InvalidReferenceError,
  mapDbErrors,
  NotFoundError,
  parseInput,
  requireUuids,
  UndeclaredAttributeKeyError,
  UndeclaredRoleError,
  ValidationError,
} from "./errors.js";
import { requireRow, SqlParams } from "./sql.js";

/** AAD context binding the encrypted personal identity number of a pending role assignment. */
export const pendingRolePinContext = (id: string): string => `pending_role_assignment:${id}:pin`;
/** AAD context binding the encrypted personal identity number of a pending attribute. */
export const pendingAttributePinContext = (id: string): string =>
  `pending_attribute_assignment:${id}:pin`;

interface TargetColumns {
  login_method_id: string | null;
  subject: string | null;
}

interface PendingRoleRow extends TargetColumns {
  id: string;
  tenant_id: string;
  application_id: string;
  role: string;
  created_by: string | null;
  created_at: Date;
}

interface PendingAttributeRow extends TargetColumns {
  id: string;
  tenant_id: string;
  application_id: string;
  key: string;
  value: string;
  created_by: string | null;
  created_at: Date;
  updated_at: Date;
}

const ROLE_COLUMNS =
  "id, tenant_id, application_id, role, login_method_id, subject, created_by, created_at";
const ATTRIBUTE_COLUMNS =
  "id, tenant_id, application_id, key, value, login_method_id, subject, created_by, created_at, updated_at";

function targetOf(row: TargetColumns): PendingTarget {
  return row.login_method_id !== null && row.subject !== null
    ? { kind: "identity", loginMethodId: row.login_method_id, subject: row.subject }
    : { kind: "pin" };
}

const toRole = (row: PendingRoleRow): PendingRoleAssignment => ({
  id: row.id,
  tenantId: row.tenant_id,
  applicationId: row.application_id,
  role: row.role,
  target: targetOf(row),
  createdBy: row.created_by,
  createdAt: row.created_at,
});

const toAttribute = (row: PendingAttributeRow): PendingAttributeAssignment => ({
  id: row.id,
  tenantId: row.tenant_id,
  applicationId: row.application_id,
  key: row.key,
  value: row.value,
  target: targetOf(row),
  createdBy: row.created_by,
  createdAt: row.created_at,
  updatedAt: row.updated_at,
});

/** What a login offers to match pending assignments against (see {@link resolvePending}). */
export interface PendingMatch {
  readonly personId: string;
  readonly loginMethodId: string;
  /** The identity's subject candidates (a pin subject under every master key's index). */
  readonly subjects: readonly string[];
  /**
   * Blind indexes of the personal identity number this login asserted, under every master key;
   * empty when the login asserted none or the method is not trusted for personal identity
   * numbers (`trustPinForRepresentation`).
   */
  readonly trustedPinIndexes: readonly string[];
}

/**
 * Turns every pending assignment matching this login into an assignment of the person and
 * deletes it, inside the caller's (JIT) transaction. Duplicates of existing assignments are
 * dropped; a pending attribute replaces the value of an existing one (the later intent wins).
 */
export async function resolvePending(
  tx: Db,
  tenantId: string,
  match: PendingMatch,
): Promise<ResolvedPendingAssignment[]> {
  const params = [
    tenantId,
    match.loginMethodId,
    [...match.subjects],
    [...match.trustedPinIndexes],
    match.personId,
  ];
  const where = `p.tenant_id = $1
     AND ((p.login_method_id = $2 AND p.subject = ANY ($3::text[]))
          OR (p.pin_index IS NOT NULL AND p.pin_index = ANY ($4::text[])))`;
  const roles = await tx.query<{
    id: string;
    application_id: string;
    role: string;
    by_pin: boolean;
  }>(
    `WITH matched AS (
       DELETE FROM pending_role_assignments p WHERE ${where}
       RETURNING p.id, p.application_id, p.role, p.pin_index IS NOT NULL AS by_pin
     ), inserted AS (
       INSERT INTO role_assignments (tenant_id, person_id, application_id, role)
       SELECT $1, $5, application_id, role FROM matched
       ON CONFLICT (tenant_id, person_id, application_id, role) DO NOTHING
     )
     SELECT id, application_id, role, by_pin FROM matched ORDER BY id`,
    params,
  );
  const attributes = await tx.query<{
    id: string;
    application_id: string;
    key: string;
    by_pin: boolean;
  }>(
    `WITH matched AS (
       DELETE FROM pending_attribute_assignments p WHERE ${where}
       RETURNING p.id, p.application_id, p.key, p.value, p.updated_at,
                 p.pin_index IS NOT NULL AS by_pin
     ), latest AS (
       SELECT DISTINCT ON (application_id, key) application_id, key, value
         FROM matched ORDER BY application_id, key, updated_at DESC
     ), upserted AS (
       INSERT INTO attribute_assignments (tenant_id, person_id, application_id, key, value)
       SELECT $1, $5, application_id, key, value FROM latest
       ON CONFLICT (tenant_id, person_id, application_id, key) DO UPDATE SET value = EXCLUDED.value
     )
     SELECT id, application_id, key, by_pin FROM matched ORDER BY id`,
    params,
  );
  return [
    ...roles.map((row) => ({
      pendingId: row.id,
      kind: "role" as const,
      applicationId: row.application_id,
      name: row.role,
      targetKind: row.by_pin ? ("pin" as const) : ("identity" as const),
    })),
    ...attributes.map((row) => ({
      pendingId: row.id,
      kind: "attribute" as const,
      applicationId: row.application_id,
      name: row.key,
      targetKind: row.by_pin ? ("pin" as const) : ("identity" as const),
    })),
  ];
}

/**
 * Role and attribute assignments for people who have not signed in yet (see migration 0005).
 * The personal identity number of a pin target is stored encrypted with a blind index and is
 * never returned.
 */
export class PendingAssignmentRepository {
  readonly #db: Db;
  readonly #keys: KeyRing;

  constructor(db: Db, keys: KeyRing) {
    this.#db = db;
    this.#keys = keys;
  }

  async createRole(
    tenantId: string,
    input: CreatePendingRoleInput,
  ): Promise<PendingRoleAssignment> {
    requireUuids({ tenantId });
    const data = parseInput(createPendingRoleInputSchema, input);
    await this.#requireApplicationInTenant(tenantId, data.applicationId);
    const [declared] = await this.#db.query(
      "SELECT 1 FROM application_roles WHERE application_id = $1 AND role = $2",
      [data.applicationId, data.role],
    );
    if (declared === undefined) throw new UndeclaredRoleError(data.applicationId, data.role);
    const id = randomUUID();
    const target = this.#targetColumns(id, data.target, pendingRolePinContext);
    const rows = await this.#write(
      () =>
        this.#db.query<PendingRoleRow>(
          `INSERT INTO pending_role_assignments
             (id, tenant_id, application_id, role, login_method_id, subject, pin_encrypted,
              pin_index, pin_index_key, created_by)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
           RETURNING ${ROLE_COLUMNS}`,
          [id, tenantId, data.applicationId, data.role, ...target, data.createdBy],
        ),
      () => new UndeclaredRoleError(data.applicationId, data.role),
    );
    return toRole(requireRow(rows));
  }

  async createAttribute(
    tenantId: string,
    input: CreatePendingAttributeInput,
  ): Promise<PendingAttributeAssignment> {
    requireUuids({ tenantId });
    const data = parseInput(createPendingAttributeInputSchema, input);
    await this.#requireApplicationInTenant(tenantId, data.applicationId);
    const [declared] = await this.#db.query(
      "SELECT 1 FROM application_attribute_keys WHERE application_id = $1 AND key = $2",
      [data.applicationId, data.key],
    );
    if (declared === undefined) throw new UndeclaredAttributeKeyError(data.applicationId, data.key);
    const id = randomUUID();
    const target = this.#targetColumns(id, data.target, pendingAttributePinContext);
    const rows = await this.#write(
      () =>
        this.#db.query<PendingAttributeRow>(
          `INSERT INTO pending_attribute_assignments
             (id, tenant_id, application_id, key, value, login_method_id, subject, pin_encrypted,
              pin_index, pin_index_key, created_by)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
           RETURNING ${ATTRIBUTE_COLUMNS}`,
          [id, tenantId, data.applicationId, data.key, data.value, ...target, data.createdBy],
        ),
      () => new UndeclaredAttributeKeyError(data.applicationId, data.key),
    );
    return toAttribute(requireRow(rows));
  }

  async listRoles(
    tenantId: string,
    filter: { readonly applicationId?: string } = {},
  ): Promise<PendingRoleAssignment[]> {
    requireUuids({ tenantId, applicationId: filter.applicationId });
    const params = new SqlParams();
    const where = [`tenant_id = ${params.add(tenantId)}`];
    if (filter.applicationId !== undefined) {
      where.push(`application_id = ${params.add(filter.applicationId)}`);
    }
    const rows = await this.#db.query<PendingRoleRow>(
      `SELECT ${ROLE_COLUMNS} FROM pending_role_assignments WHERE ${where.join(" AND ")}
        ORDER BY created_at, id`,
      params.values,
    );
    return rows.map(toRole);
  }

  async listAttributes(
    tenantId: string,
    filter: { readonly applicationId?: string } = {},
  ): Promise<PendingAttributeAssignment[]> {
    requireUuids({ tenantId, applicationId: filter.applicationId });
    const params = new SqlParams();
    const where = [`tenant_id = ${params.add(tenantId)}`];
    if (filter.applicationId !== undefined) {
      where.push(`application_id = ${params.add(filter.applicationId)}`);
    }
    const rows = await this.#db.query<PendingAttributeRow>(
      `SELECT ${ATTRIBUTE_COLUMNS} FROM pending_attribute_assignments
        WHERE ${where.join(" AND ")} ORDER BY created_at, id`,
      params.values,
    );
    return rows.map(toAttribute);
  }

  async findRole(tenantId: string, id: string): Promise<PendingRoleAssignment | null> {
    requireUuids({ tenantId, id });
    const [row] = await this.#db.query<PendingRoleRow>(
      `SELECT ${ROLE_COLUMNS} FROM pending_role_assignments WHERE tenant_id = $1 AND id = $2`,
      [tenantId, id],
    );
    return row === undefined ? null : toRole(row);
  }

  async findAttribute(tenantId: string, id: string): Promise<PendingAttributeAssignment | null> {
    requireUuids({ tenantId, id });
    const [row] = await this.#db.query<PendingAttributeRow>(
      `SELECT ${ATTRIBUTE_COLUMNS} FROM pending_attribute_assignments
        WHERE tenant_id = $1 AND id = $2`,
      [tenantId, id],
    );
    return row === undefined ? null : toAttribute(row);
  }

  async setAttributeValue(
    tenantId: string,
    id: string,
    value: string,
  ): Promise<PendingAttributeAssignment> {
    requireUuids({ tenantId, id });
    if (value.length > 2000) throw new ValidationError(["value: at most 2000 characters"]);
    const [row] = await mapDbErrors(() =>
      this.#db.query<PendingAttributeRow>(
        `UPDATE pending_attribute_assignments SET value = $3 WHERE tenant_id = $1 AND id = $2
         RETURNING ${ATTRIBUTE_COLUMNS}`,
        [tenantId, id, value],
      ),
    );
    if (row === undefined) throw new NotFoundError("Pending attribute assignment");
    return toAttribute(row);
  }

  async deleteRole(tenantId: string, id: string): Promise<boolean> {
    requireUuids({ tenantId, id });
    const rows = await this.#db.query(
      "DELETE FROM pending_role_assignments WHERE tenant_id = $1 AND id = $2 RETURNING id",
      [tenantId, id],
    );
    return rows.length > 0;
  }

  async deleteAttribute(tenantId: string, id: string): Promise<boolean> {
    requireUuids({ tenantId, id });
    const rows = await this.#db.query(
      "DELETE FROM pending_attribute_assignments WHERE tenant_id = $1 AND id = $2 RETURNING id",
      [tenantId, id],
    );
    return rows.length > 0;
  }

  #targetColumns(
    id: string,
    target: { loginMethodId: string; subject: string } | { pin: string },
    context: (id: string) => string,
  ): [string | null, string | null, string | null, string | null, string | null] {
    if ("pin" in target) {
      const index = this.#keys.index.compute("pin", target.pin);
      return [
        null,
        null,
        this.#keys.secrets.encrypt(target.pin, context(id)),
        index.index,
        index.keyId,
      ];
    }
    return [target.loginMethodId, target.subject, null, null, null];
  }

  async #requireApplicationInTenant(tenantId: string, applicationId: string): Promise<void> {
    const [row] = await this.#db.query(
      "SELECT 1 FROM tenant_applications WHERE tenant_id = $1 AND application_id = $2",
      [tenantId, applicationId],
    );
    if (row === undefined) throw new ApplicationNotInTenantError(applicationId);
  }

  /** Runs a write; a lost race with a role or key removal becomes `undeclared()`. */
  async #write<T>(fn: () => Promise<T>, undeclared: () => Error): Promise<T> {
    try {
      return await mapDbErrors(fn);
    } catch (error) {
      if (
        error instanceof InvalidReferenceError &&
        (error.constraint?.endsWith("_application_id_role_fkey") === true ||
          error.constraint?.endsWith("_application_id_key_fkey") === true)
      ) {
        throw undeclared();
      }
      throw error;
    }
  }
}
