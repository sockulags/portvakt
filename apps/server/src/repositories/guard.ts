import type { Db } from "../db/database.js";
import { requireUuids } from "./errors.js";

export interface PlatformAccess {
  /** Enabled login methods of the system tenant. */
  readonly enabledLoginMethods: number;
  /**
   * Ways someone can still become a platform admin: assignments of persons who can sign in
   * (an identity at an enabled method), pending assignments that can resolve (identity at an
   * enabled method; a number with an enabled trusted method), and rules of enabled methods.
   * 0 when `portvakt-admin` is disabled (globally or in the system tenant).
   */
  readonly platformAdminPaths: number;
}

/**
 * What keeps the platform administrable: checked inside a change's transaction, after the
 * change, so the admin API can refuse a change that would lock every platform admin out.
 * `orphanedLoginMethodId`: a method whose issuer is being changed; identities at it (and pending
 * targets naming it) no longer count, since its subjects belonged to the old issuer.
 */
export async function platformAccess(
  db: Db,
  systemTenantId: string,
  adminApplicationId: string,
  role: string,
  orphanedLoginMethodId: string | null = null,
): Promise<PlatformAccess> {
  requireUuids({ systemTenantId, adminApplicationId, orphanedLoginMethodId });
  const [row] = await db.query<{ methods: string; paths: string }>(
    `WITH usable_app AS (
       SELECT 1 FROM tenant_applications ta JOIN applications a ON a.id = ta.application_id
        WHERE ta.tenant_id = $1 AND ta.application_id = $2 AND ta.enabled AND a.enabled
     ), methods AS (
       SELECT id, trust_pin_for_representation FROM login_methods WHERE tenant_id = $1 AND enabled
     )
     SELECT (SELECT count(*) FROM methods) AS methods,
            CASE WHEN NOT EXISTS (SELECT 1 FROM usable_app) THEN 0 ELSE
              (SELECT count(*) FROM role_assignments ra
                WHERE ra.tenant_id = $1 AND ra.application_id = $2 AND ra.role = $3
                  AND EXISTS (SELECT 1 FROM identities i JOIN methods m ON m.id = i.login_method_id
                               WHERE i.tenant_id = $1 AND i.person_id = ra.person_id
                                 AND i.login_method_id IS DISTINCT FROM $4::uuid))
              + (SELECT count(*) FROM pending_role_assignments p
                  WHERE p.tenant_id = $1 AND p.application_id = $2 AND p.role = $3
                    AND ((p.login_method_id IN (SELECT id FROM methods)
                          AND p.login_method_id IS DISTINCT FROM $4::uuid)
                         OR (p.pin_index IS NOT NULL
                             AND EXISTS (SELECT 1 FROM methods WHERE trust_pin_for_representation))))
              + (SELECT count(*) FROM role_rules r
                  WHERE r.tenant_id = $1 AND r.application_id = $2 AND r.role = $3
                    AND r.login_method_id IN (SELECT id FROM methods))
            END AS paths`,
    [systemTenantId, adminApplicationId, role, orphanedLoginMethodId],
  );
  return {
    enabledLoginMethods: Number(row?.methods ?? 0),
    platformAdminPaths: Number(row?.paths ?? 0),
  };
}
