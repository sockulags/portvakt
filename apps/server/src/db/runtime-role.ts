import type { Db } from "./database.js";

export interface RuntimeRoleCheck {
  readonly role: string;
  readonly superuser: boolean;
  /** The role owns audit_events (directly or through membership), so it could alter or drop it. */
  readonly ownsAuditEvents: boolean;
  /** The role can UPDATE or DELETE audit rows. */
  readonly canChangeAuditEvents: boolean;
}

export class RuntimeRoleError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RuntimeRoleError";
  }
}

/** Inspects the privileges of the role the connection runs as. */
export async function checkRuntimeRole(db: Db): Promise<RuntimeRoleCheck> {
  const [row] = await db.query<{
    role: string;
    superuser: boolean;
    owns_audit_events: boolean | null;
    can_change_audit_events: boolean | null;
  }>(
    `SELECT current_user AS role,
            r.rolsuper AS superuser,
            pg_has_role(current_user, c.relowner, 'MEMBER') AS owns_audit_events,
            has_table_privilege(c.oid, 'UPDATE') OR has_table_privilege(c.oid, 'DELETE')
              OR has_table_privilege(c.oid, 'TRUNCATE') AS can_change_audit_events
       FROM pg_roles r
       LEFT JOIN pg_class c ON c.oid = to_regclass('audit_events')
      WHERE r.rolname = current_user`,
  );
  if (row === undefined) throw new RuntimeRoleError("Could not inspect the database role");
  if (row.owns_audit_events === null || row.can_change_audit_events === null) {
    throw new RuntimeRoleError("audit_events does not exist; run the migrations first");
  }
  return {
    role: row.role,
    superuser: row.superuser,
    ownsAuditEvents: row.owns_audit_events,
    canChangeAuditEvents: row.can_change_audit_events,
  };
}

/**
 * Refuses a runtime connection that could rewrite the audit log: a superuser, the owner of
 * audit_events, or a role with UPDATE/DELETE/TRUNCATE on it. Production start-up calls this;
 * the DATABASE_URL user must be the restricted runtime role, not the migration owner.
 */
export async function assertRestrictedRuntimeRole(db: Db): Promise<RuntimeRoleCheck> {
  const check = await checkRuntimeRole(db);
  if (check.superuser || check.ownsAuditEvents || check.canChangeAuditEvents) {
    throw new RuntimeRoleError(
      `DATABASE_URL role "${check.role}" can modify audit_events; ` +
        "use the restricted runtime role and keep the owner for MIGRATION_DATABASE_URL",
    );
  }
  return check;
}
