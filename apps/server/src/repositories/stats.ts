import type { Db } from "../db/database.js";
import { requireUuids } from "./errors.js";

export interface LoginCounts {
  readonly successLast24h: number;
  readonly successLast7d: number;
  readonly failureLast24h: number;
}

/** What depends on an application's roles and attribute keys (counts only, no personal data). */
export interface ApplicationUsage {
  readonly roleAssignments: number;
  readonly pendingRoleAssignments: number;
  readonly roleRules: number;
  readonly attributeAssignments: number;
  readonly pendingAttributeAssignments: number;
  /** Representation grants limited to the application (detach only). */
  readonly grantLimits: number;
}

/** Counts for the admin dashboard, from the audit log and the session store. */
export class StatsRepository {
  readonly #db: Db;

  constructor(db: Db) {
    this.#db = db;
  }

  /** Logins of the tenant (`login.success`, `login.failure`) in the last day and week. */
  async loginCounts(tenantId: string, now: Date = new Date()): Promise<LoginCounts> {
    requireUuids({ tenantId });
    const day = new Date(now.getTime() - 24 * 3600 * 1000);
    const week = new Date(now.getTime() - 7 * 24 * 3600 * 1000);
    const [row] = await this.#db.query<{ day: string; week: string; failed: string }>(
      `SELECT count(*) FILTER (WHERE action = 'login.success' AND occurred_at >= $2) AS day,
              count(*) FILTER (WHERE action = 'login.success') AS week,
              count(*) FILTER (WHERE action = 'login.failure' AND occurred_at >= $2) AS failed
         FROM audit_events
        WHERE tenant_id = $1 AND action IN ('login.success', 'login.failure')
          AND occurred_at >= $3`,
      [tenantId, day, week],
    );
    return {
      successLast24h: Number(row?.day ?? 0),
      successLast7d: Number(row?.week ?? 0),
      failureLast24h: Number(row?.failed ?? 0),
    };
  }

  /**
   * What removing roles or attribute keys from an application deletes, in every tenant
   * (`tenantId` null) or in one tenant (with every role and key when the lists are null: what
   * detaching the application from the tenant deletes).
   */
  async applicationUsage(
    applicationId: string,
    scope: {
      readonly tenantId: string | null;
      readonly roles: readonly string[] | null;
      readonly keys: readonly string[] | null;
    },
  ): Promise<ApplicationUsage> {
    requireUuids({ applicationId, tenantId: scope.tenantId });
    const [row] = await this.#db.query<Record<keyof ApplicationUsage, string>>(
      `SELECT
         (SELECT count(*) FROM role_assignments WHERE application_id = $1
            AND ($2::uuid IS NULL OR tenant_id = $2) AND ($3::text[] IS NULL OR role = ANY ($3))) AS "roleAssignments",
         (SELECT count(*) FROM pending_role_assignments WHERE application_id = $1
            AND ($2::uuid IS NULL OR tenant_id = $2) AND ($3::text[] IS NULL OR role = ANY ($3))) AS "pendingRoleAssignments",
         (SELECT count(*) FROM role_rules WHERE application_id = $1
            AND ($2::uuid IS NULL OR tenant_id = $2) AND ($3::text[] IS NULL OR role = ANY ($3))) AS "roleRules",
         (SELECT count(*) FROM attribute_assignments WHERE application_id = $1
            AND ($2::uuid IS NULL OR tenant_id = $2) AND ($4::text[] IS NULL OR key = ANY ($4))) AS "attributeAssignments",
         (SELECT count(*) FROM pending_attribute_assignments WHERE application_id = $1
            AND ($2::uuid IS NULL OR tenant_id = $2) AND ($4::text[] IS NULL OR key = ANY ($4))) AS "pendingAttributeAssignments",
         (SELECT count(*) FROM representation_grant_applications WHERE application_id = $1
            AND ($2::uuid IS NULL OR tenant_id = $2)) AS "grantLimits"`,
      [
        applicationId,
        scope.tenantId,
        scope.roles === null ? null : [...scope.roles],
        scope.keys === null ? null : [...scope.keys],
      ],
    );
    return {
      roleAssignments: Number(row?.roleAssignments ?? 0),
      pendingRoleAssignments: Number(row?.pendingRoleAssignments ?? 0),
      roleRules: Number(row?.roleRules ?? 0),
      attributeAssignments: Number(row?.attributeAssignments ?? 0),
      pendingAttributeAssignments: Number(row?.pendingAttributeAssignments ?? 0),
      grantLimits: Number(row?.grantLimits ?? 0),
    };
  }

  /** Broker sessions of the tenant that have not expired (oidc-provider `Session` rows). */
  async activeSessions(tenantId: string): Promise<number> {
    requireUuids({ tenantId });
    const [row] = await this.#db.query<{ count: string }>(
      `SELECT count(*) AS count FROM oidc_payloads
        WHERE tenant_id = $1 AND kind = 'Session' AND (expires_at IS NULL OR expires_at > now())`,
      [tenantId],
    );
    return Number(row?.count ?? 0);
  }
}
