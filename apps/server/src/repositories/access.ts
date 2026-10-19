import type { Db } from "../db/database.js";
import {
  assignRoleInputSchema,
  type AssignRoleInput,
  type AttributeAssignment,
  createRoleRuleInputSchema,
  type CreateRoleRuleInput,
  type EffectiveAccess,
  effectiveAccessQuerySchema,
  type EffectiveAccessQuery,
  type RoleAssignment,
  type RoleRule,
  setAttributeInputSchema,
  type SetAttributeInput,
} from "../domain/access.js";
import {
  ApplicationNotInTenantError,
  InvalidReferenceError,
  mapDbErrors,
  NotFoundError,
  parseInput,
  UndeclaredAttributeKeyError,
  requireUuids,
  UndeclaredRoleError,
} from "./errors.js";
import { requireRow, SqlParams } from "./sql.js";

interface RoleAssignmentRow {
  id: string;
  tenant_id: string;
  person_id: string;
  application_id: string;
  role: string;
  created_at: Date;
}

interface RoleRuleRow {
  id: string;
  tenant_id: string;
  application_id: string;
  login_method_id: string;
  group_value: string;
  role: string;
  created_at: Date;
}

interface AttributeRow {
  id: string;
  tenant_id: string;
  person_id: string;
  application_id: string;
  key: string;
  value: string;
  created_at: Date;
  updated_at: Date;
}

const ASSIGNMENT_COLUMNS = "id, tenant_id, person_id, application_id, role, created_at";
const RULE_COLUMNS =
  "id, tenant_id, application_id, login_method_id, group_value, role, created_at";
const ATTRIBUTE_COLUMNS =
  "id, tenant_id, person_id, application_id, key, value, created_at, updated_at";

const toAssignment = (row: RoleAssignmentRow): RoleAssignment => ({
  id: row.id,
  tenantId: row.tenant_id,
  personId: row.person_id,
  applicationId: row.application_id,
  role: row.role,
  createdAt: row.created_at,
});

const toRule = (row: RoleRuleRow): RoleRule => ({
  id: row.id,
  tenantId: row.tenant_id,
  applicationId: row.application_id,
  loginMethodId: row.login_method_id,
  groupValue: row.group_value,
  role: row.role,
  createdAt: row.created_at,
});

const toAttribute = (row: AttributeRow): AttributeAssignment => ({
  id: row.id,
  tenantId: row.tenant_id,
  personId: row.person_id,
  applicationId: row.application_id,
  key: row.key,
  value: row.value,
  createdAt: row.created_at,
  updatedAt: row.updated_at,
});

/**
 * Role assignments, role rules and attribute assignments. Roles and attribute keys must be
 * declared by the application: checked here for a clear error, and enforced again by foreign keys
 * so a concurrent removal cannot slip through.
 */
export class AccessRepository {
  readonly #db: Db;

  constructor(db: Db) {
    this.#db = db;
  }

  async assignRole(tenantId: string, input: AssignRoleInput): Promise<RoleAssignment> {
    requireUuids({ tenantId });
    const data = parseInput(assignRoleInputSchema, input);
    await this.#requireDeclaredRole(tenantId, data.applicationId, data.role);
    const rows = await this.#write(
      () =>
        this.#db.query<RoleAssignmentRow>(
          `INSERT INTO role_assignments (tenant_id, person_id, application_id, role)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (tenant_id, person_id, application_id, role)
           DO UPDATE SET role = EXCLUDED.role
         RETURNING ${ASSIGNMENT_COLUMNS}`,
          [tenantId, data.personId, data.applicationId, data.role],
        ),
      data.applicationId,
      data.role,
    );
    return toAssignment(requireRow(rows));
  }

  async unassignRole(tenantId: string, input: AssignRoleInput): Promise<boolean> {
    requireUuids({ tenantId });
    const data = parseInput(assignRoleInputSchema, input);
    const rows = await this.#db.query(
      `DELETE FROM role_assignments
        WHERE tenant_id = $1 AND person_id = $2 AND application_id = $3 AND role = $4
        RETURNING id`,
      [tenantId, data.personId, data.applicationId, data.role],
    );
    return rows.length > 0;
  }

  async listAssignments(
    tenantId: string,
    filter: { personId?: string; applicationId?: string } = {},
  ): Promise<RoleAssignment[]> {
    requireUuids({ tenantId, personId: filter.personId, applicationId: filter.applicationId });
    const params = new SqlParams();
    const where = [`tenant_id = ${params.add(tenantId)}`];
    if (filter.personId !== undefined) where.push(`person_id = ${params.add(filter.personId)}`);
    if (filter.applicationId !== undefined) {
      where.push(`application_id = ${params.add(filter.applicationId)}`);
    }
    const rows = await this.#db.query<RoleAssignmentRow>(
      `SELECT ${ASSIGNMENT_COLUMNS} FROM role_assignments WHERE ${where.join(" AND ")}
        ORDER BY application_id, role, person_id`,
      params.values,
    );
    return rows.map(toAssignment);
  }

  /**
   * The person's roles in one application now, in one query: direct assignments plus every rule
   * of the login method used whose group is among the groups stored on the person's identity
   * at that method (the latest login's groups). The admin API intersects the token's roles with
   * these, so a removed role stops working at once instead of when the token expires.
   */
  async currentRoles(
    tenantId: string,
    personId: string,
    applicationId: string,
    loginMethodId: string,
  ): Promise<string[]> {
    requireUuids({ tenantId, personId, applicationId, loginMethodId });
    const rows = await this.#db.query<{ role: string }>(
      `SELECT role FROM role_assignments
        WHERE tenant_id = $1 AND person_id = $2 AND application_id = $3
       UNION
       SELECT r.role FROM role_rules r
         JOIN identities i ON i.tenant_id = r.tenant_id AND i.login_method_id = r.login_method_id
        WHERE r.tenant_id = $1 AND r.application_id = $3 AND r.login_method_id = $4
          AND i.person_id = $2 AND (i.attributes -> 'groups') ? r.group_value`,
      [tenantId, personId, applicationId, loginMethodId],
    );
    return rows.map((row) => row.role);
  }

  async findAssignment(tenantId: string, id: string): Promise<RoleAssignment | null> {
    requireUuids({ tenantId, id });
    const [row] = await this.#db.query<RoleAssignmentRow>(
      `SELECT ${ASSIGNMENT_COLUMNS} FROM role_assignments WHERE tenant_id = $1 AND id = $2`,
      [tenantId, id],
    );
    return row === undefined ? null : toAssignment(row);
  }

  async deleteAssignment(tenantId: string, id: string): Promise<boolean> {
    requireUuids({ tenantId, id });
    const rows = await this.#db.query(
      "DELETE FROM role_assignments WHERE tenant_id = $1 AND id = $2 RETURNING id",
      [tenantId, id],
    );
    return rows.length > 0;
  }

  async findRule(tenantId: string, id: string): Promise<RoleRule | null> {
    requireUuids({ tenantId, id });
    const [row] = await this.#db.query<RoleRuleRow>(
      `SELECT ${RULE_COLUMNS} FROM role_rules WHERE tenant_id = $1 AND id = $2`,
      [tenantId, id],
    );
    return row === undefined ? null : toRule(row);
  }

  async findAttribute(tenantId: string, id: string): Promise<AttributeAssignment | null> {
    requireUuids({ tenantId, id });
    const [row] = await this.#db.query<AttributeRow>(
      `SELECT ${ATTRIBUTE_COLUMNS} FROM attribute_assignments WHERE tenant_id = $1 AND id = $2`,
      [tenantId, id],
    );
    return row === undefined ? null : toAttribute(row);
  }

  async setAttributeValue(
    tenantId: string,
    id: string,
    value: string,
  ): Promise<AttributeAssignment> {
    requireUuids({ tenantId, id });
    const [row] = await mapDbErrors(() =>
      this.#db.query<AttributeRow>(
        `UPDATE attribute_assignments SET value = $3 WHERE tenant_id = $1 AND id = $2
         RETURNING ${ATTRIBUTE_COLUMNS}`,
        [tenantId, id, value],
      ),
    );
    if (row === undefined) throw new NotFoundError("Attribute assignment");
    return toAttribute(row);
  }

  async deleteAttribute(tenantId: string, id: string): Promise<boolean> {
    requireUuids({ tenantId, id });
    const rows = await this.#db.query(
      "DELETE FROM attribute_assignments WHERE tenant_id = $1 AND id = $2 RETURNING id",
      [tenantId, id],
    );
    return rows.length > 0;
  }

  async createRule(tenantId: string, input: CreateRoleRuleInput): Promise<RoleRule> {
    requireUuids({ tenantId });
    const data = parseInput(createRoleRuleInputSchema, input);
    await this.#requireDeclaredRole(tenantId, data.applicationId, data.role);
    const rows = await this.#write(
      () =>
        this.#db.query<RoleRuleRow>(
          `INSERT INTO role_rules (tenant_id, application_id, login_method_id, group_value, role)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING ${RULE_COLUMNS}`,
          [tenantId, data.applicationId, data.loginMethodId, data.groupValue, data.role],
        ),
      data.applicationId,
      data.role,
    );
    return toRule(requireRow(rows));
  }

  async deleteRule(tenantId: string, ruleId: string): Promise<boolean> {
    requireUuids({ tenantId, ruleId });
    const rows = await this.#db.query(
      "DELETE FROM role_rules WHERE tenant_id = $1 AND id = $2 RETURNING id",
      [tenantId, ruleId],
    );
    return rows.length > 0;
  }

  async listRules(tenantId: string, filter: { applicationId?: string } = {}): Promise<RoleRule[]> {
    requireUuids({ tenantId, applicationId: filter.applicationId });
    const params = new SqlParams();
    const where = [`tenant_id = ${params.add(tenantId)}`];
    if (filter.applicationId !== undefined) {
      where.push(`application_id = ${params.add(filter.applicationId)}`);
    }
    const rows = await this.#db.query<RoleRuleRow>(
      `SELECT ${RULE_COLUMNS} FROM role_rules WHERE ${where.join(" AND ")}
        ORDER BY application_id, group_value, role, id`,
      params.values,
    );
    return rows.map(toRule);
  }

  async setAttribute(tenantId: string, input: SetAttributeInput): Promise<AttributeAssignment> {
    requireUuids({ tenantId });
    const data = parseInput(setAttributeInputSchema, input);
    await this.#requireApplicationInTenant(tenantId, data.applicationId);
    const [declared] = await this.#db.query(
      "SELECT 1 FROM application_attribute_keys WHERE application_id = $1 AND key = $2",
      [data.applicationId, data.key],
    );
    if (declared === undefined) throw new UndeclaredAttributeKeyError(data.applicationId, data.key);
    const rows = await mapDbErrors(() =>
      this.#db.query<AttributeRow>(
        `INSERT INTO attribute_assignments (tenant_id, person_id, application_id, key, value)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (tenant_id, person_id, application_id, key)
           DO UPDATE SET value = EXCLUDED.value
         RETURNING ${ATTRIBUTE_COLUMNS}`,
        [tenantId, data.personId, data.applicationId, data.key, data.value],
      ),
    ).catch((error: unknown) => {
      if (
        error instanceof InvalidReferenceError &&
        error.constraint === "attribute_assignments_application_id_key_fkey"
      ) {
        throw new UndeclaredAttributeKeyError(data.applicationId, data.key);
      }
      throw error;
    });
    return toAttribute(requireRow(rows));
  }

  async removeAttribute(
    tenantId: string,
    input: { personId: string; applicationId: string; key: string },
  ): Promise<boolean> {
    requireUuids({ tenantId, personId: input.personId, applicationId: input.applicationId });
    const rows = await this.#db.query(
      `DELETE FROM attribute_assignments
        WHERE tenant_id = $1 AND person_id = $2 AND application_id = $3 AND key = $4
        RETURNING id`,
      [tenantId, input.personId, input.applicationId, input.key],
    );
    return rows.length > 0;
  }

  async listAttributes(
    tenantId: string,
    filter: { personId?: string; applicationId?: string } = {},
  ): Promise<AttributeAssignment[]> {
    requireUuids({ tenantId, personId: filter.personId, applicationId: filter.applicationId });
    const params = new SqlParams();
    const where = [`tenant_id = ${params.add(tenantId)}`];
    if (filter.personId !== undefined) where.push(`person_id = ${params.add(filter.personId)}`);
    if (filter.applicationId !== undefined) {
      where.push(`application_id = ${params.add(filter.applicationId)}`);
    }
    const rows = await this.#db.query<AttributeRow>(
      `SELECT ${ATTRIBUTE_COLUMNS} FROM attribute_assignments WHERE ${where.join(" AND ")}
        ORDER BY application_id, key, person_id`,
      params.values,
    );
    return rows.map(toAttribute);
  }

  /**
   * Roles and attributes for one application at login: direct role assignments plus every rule
   * of the tenant for the login method used whose group value is among the person's upstream
   * groups. Attributes come from direct assignments. Empty when the application is disabled
   * (globally or for the tenant) or the tenant is suspended.
   */
  async effectiveAccess(tenantId: string, query: EffectiveAccessQuery): Promise<EffectiveAccess> {
    requireUuids({ tenantId });
    const data = parseInput(effectiveAccessQuerySchema, query);
    const [usable] = await this.#db.query(
      `SELECT 1
         FROM tenant_applications ta
         JOIN applications a ON a.id = ta.application_id
         JOIN tenants t ON t.id = ta.tenant_id
        WHERE ta.tenant_id = $1 AND ta.application_id = $2
          AND ta.enabled AND a.enabled AND t.status = 'active'`,
      [tenantId, data.applicationId],
    );
    if (usable === undefined) return { roles: [], attributes: {} };
    const roleRows = await this.#db.query<{ role: string }>(
      `SELECT role FROM role_assignments
        WHERE tenant_id = $1 AND person_id = $2 AND application_id = $3
       UNION
       SELECT role FROM role_rules
        WHERE tenant_id = $1 AND application_id = $3
          AND login_method_id = $4
          AND group_value = ANY ($5::text[])
       ORDER BY role`,
      [tenantId, data.personId, data.applicationId, data.loginMethodId, data.groups],
    );
    const attributeRows = await this.#db.query<{ key: string; value: string }>(
      `SELECT key, value FROM attribute_assignments
        WHERE tenant_id = $1 AND person_id = $2 AND application_id = $3
        ORDER BY key`,
      [tenantId, data.personId, data.applicationId],
    );
    const attributes: Record<string, string> = {};
    for (const row of attributeRows) attributes[row.key] = row.value;
    return { roles: roleRows.map((row) => row.role), attributes };
  }

  async #requireApplicationInTenant(tenantId: string, applicationId: string): Promise<void> {
    const [row] = await this.#db.query(
      "SELECT 1 FROM tenant_applications WHERE tenant_id = $1 AND application_id = $2",
      [tenantId, applicationId],
    );
    if (row === undefined) throw new ApplicationNotInTenantError(applicationId);
  }

  async #requireDeclaredRole(tenantId: string, applicationId: string, role: string): Promise<void> {
    await this.#requireApplicationInTenant(tenantId, applicationId);
    const [row] = await this.#db.query(
      "SELECT 1 FROM application_roles WHERE application_id = $1 AND role = $2",
      [applicationId, role],
    );
    if (row === undefined) throw new UndeclaredRoleError(applicationId, role);
  }

  /** Runs a write, turning a lost race with a role removal into {@link UndeclaredRoleError}. */
  async #write<T>(fn: () => Promise<T>, applicationId: string, role: string): Promise<T> {
    try {
      return await mapDbErrors(fn);
    } catch (error) {
      if (
        error instanceof InvalidReferenceError &&
        error.constraint?.endsWith("_application_id_role_fkey") === true
      ) {
        throw new UndeclaredRoleError(applicationId, role);
      }
      throw error;
    }
  }
}
