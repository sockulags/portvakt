import type { AuditLog } from "../../audit/audit-log.js";
import type { AuditAction, AuditDetails, CatalogueEvent } from "../../audit/catalogue.js";
import type { Config } from "../../config/index.js";
import type { KeyRing } from "../../crypto/keyring.js";
import type { Db } from "../../db/database.js";
import type { AuditEvent } from "../../domain/audit.js";
import { SYSTEM_TENANT_SLUG, type Tenant } from "../../domain/tenant.js";
import { SamlLoginMethodAdmin } from "../../federation/saml/admin.js";
import type { SamlFederation } from "../../federation/saml/service.js";
import type { UpstreamClients } from "../../federation/upstream.js";
import type { SigningKeyCache } from "../../keys/key-cache.js";
import type { RequestLimits } from "../../http/rate-limits.js";
import type { KeyRotationService } from "../../keys/rotation.js";
import type { Logger } from "../../logging/logger.js";
import type { OutboundGuard } from "../../net/outbound.js";
import {
  createRepositories,
  requireUuids,
  type Repositories,
  type RepositoryOptions,
} from "../../repositories/index.js";
import type {
  LoginRevocationResult,
  LoginRevocationScope,
} from "../../repositories/oidc-payloads.js";
import type { Caller } from "./auth.js";
import { platformAccess } from "../../repositories/guard.js";
import { ADMIN_CLIENT_ID, PLATFORM_ADMIN_ROLE } from "../constants.js";
import { ApiError, fieldError, notFound } from "./problem.js";

/** What the admin API is built from (the composition root passes these). */
export interface AdminDeps {
  readonly config: Config;
  readonly db: Db;
  readonly keys: KeyRing;
  /** Pool-backed repositories, for reads outside a transaction. */
  readonly repos: Repositories;
  readonly repositoryOptions: RepositoryOptions;
  readonly keyCache: SigningKeyCache;
  readonly rotation: KeyRotationService;
  readonly saml: SamlFederation;
  /** Pool-backed SAML admin operations (SP certificate expiry and warnings). */
  readonly samlAdmin: SamlLoginMethodAdmin;
  readonly auditLog: AuditLog;
  /** Upstream OIDC discovery (cached), for warnings that depend on the upstream's metadata. */
  readonly upstream?: Pick<UpstreamClients, "setupFor">;
  /** Checks administrator-configured URLs (upstream issuers) before they are saved. */
  readonly outbound: OutboundGuard;
  readonly logger: Logger;
  /** Rate limits (RATE_LIMIT_ADMIN_API); none in some tests. */
  readonly limits?: RequestLimits;
}

/** A unit of work: repositories over one transaction, and the audit events it commits with. */
export interface Tx {
  readonly db: Db;
  readonly repos: Repositories;
  readonly samlAdmin: SamlLoginMethodAdmin;
  /** Writes a catalogue event in this transaction (forwarded to the sink after the commit). */
  record<A extends AuditAction>(event: CatalogueEvent<A>): Promise<void>;
}

/**
 * Runs `fn` in one transaction: the change and its `admin.*` audit event commit together or not
 * at all. Committed events are then handed to the audit sink.
 */
export async function inTransaction<T>(deps: AdminDeps, fn: (tx: Tx) => Promise<T>): Promise<T> {
  const written: AuditEvent[] = [];
  const result = await deps.db.transaction(async (db) => {
    const repos = createRepositories(db, deps.keys, deps.repositoryOptions);
    // Its events commit with the transaction and reach the sink after it, like `record`.
    const samlAdmin = new SamlLoginMethodAdmin({
      repos,
      saml: deps.saml,
      production: deps.config.isProduction,
      auditLog: deps.auditLog,
      onWritten: (event) => written.push(event),
    });
    return fn({
      db,
      repos,
      samlAdmin,
      record: async (event) => {
        written.push(await deps.auditLog.recordIn(repos.audit, event));
      },
    });
  });
  deps.auditLog.forward(written);
  return result;
}

/**
 * Locks one row for the rest of the transaction (`SELECT ... FOR UPDATE`), so the version an
 * `If-Match` names cannot change between the check and the write. `table` and `where` are
 * constants of the caller, never input. Throws 404 when there is no such row.
 */
export async function lockRow(
  tx: Tx,
  table: string,
  where: string,
  values: readonly unknown[],
): Promise<void> {
  const rows = await tx.db.query(`SELECT 1 FROM ${table} WHERE ${where} FOR UPDATE`, values);
  if (rows.length === 0) throw notFound();
}

/**
 * The tenant a request addresses. A platform administrator may address any tenant; a tenant
 * administrator only their own: any other id is 404 (not 403), so tenants cannot be enumerated.
 */
export async function targetTenant(
  deps: AdminDeps,
  caller: Caller,
  tenantId: string,
): Promise<Tenant> {
  requireUuids({ tenantId });
  if (!caller.platform) {
    // The system tenant is administered by platform administrators only.
    if (tenantId !== caller.tenant.id || caller.tenant.slug === SYSTEM_TENANT_SLUG)
      throw notFound();
    return caller.tenant;
  }
  const tenant = await deps.repos.tenants.findById(tenantId);
  if (tenant === null) throw notFound();
  return tenant;
}

/** The audit actor of an admin change. */
export const actorOf = (caller: Caller): { readonly type: "person"; readonly id: string } => ({
  type: "person",
  id: caller.personId,
});

export const requirePlatform = (caller: Caller): void => {
  if (!caller.platform) throw new ApiError("forbidden");
};

/**
 * `platform-admin` of `portvakt-admin` administers every tenant: only a platform administrator
 * may give it, and only in the system tenant (in any other tenant it would mean nothing, and it
 * must never be granted from below).
 */
export async function guardPlatformAdminRole(
  tx: Pick<Tx, "repos">,
  caller: Caller,
  tenant: Tenant,
  applicationId: string,
  role: string,
): Promise<void> {
  if (role !== PLATFORM_ADMIN_ROLE) return;
  const application = await tx.repos.applications.findById(applicationId);
  if (application?.clientId !== ADMIN_CLIENT_ID) return;
  if (caller.platform && tenant.slug === SYSTEM_TENANT_SLUG) return;
  throw fieldError(
    "role",
    "platform-admin can only be given in the system tenant, by a platform administrator",
  );
}

/**
 * Refuses (409 `self_lockout`) a change of the system tenant that leaves no enabled login method
 * or no way for anyone to be a platform admin. Call inside the change's transaction, after the
 * change; the transaction then rolls back. A no-op for other tenants.
 */
export async function assertPlatformReachable(
  tx: Tx,
  tenant: Tenant,
  options: { readonly orphanedLoginMethodId?: string } = {},
): Promise<void> {
  if (tenant.slug !== SYSTEM_TENANT_SLUG) return;
  const application = await tx.repos.applications.findByClientId(ADMIN_CLIENT_ID);
  if (application === null) throw new ApiError("self_lockout");
  const access = await platformAccess(
    tx.db,
    tenant.id,
    application.id,
    PLATFORM_ADMIN_ROLE,
    options.orphanedLoginMethodId ?? null,
  );
  if (access.enabledLoginMethods === 0 || access.platformAdminPaths === 0) {
    throw new ApiError("self_lockout");
  }
}

/**
 * A kill switch: ends the logins `scope` names at once, in the change's transaction, and audits
 * it (`sessions.revoked`, with how many sessions and grants ended). Refresh tokens of those
 * grants never work again, also after whatever was switched off is switched on again.
 */
export async function endLogins(
  tx: Tx,
  caller: Caller,
  tenantId: string,
  scope: LoginRevocationScope,
  audit: {
    readonly reason: AuditDetails<"sessions.revoked">["reason"];
    readonly subject: { readonly type: string; readonly id: string };
    readonly clientId?: string;
    readonly loginMethodId?: string;
  },
): Promise<LoginRevocationResult> {
  const ended = await tx.repos.oidcPayloads.revokeLogins(tenantId, scope);
  await tx.record({
    action: "sessions.revoked",
    tenantId,
    actor: actorOf(caller),
    subject: audit.subject,
    details: {
      actorTenantId: caller.tenant.id,
      reason: audit.reason,
      sessions: ended.sessions,
      grants: ended.grants,
      ...(audit.clientId === undefined ? {} : { clientId: audit.clientId }),
      ...(audit.loginMethodId === undefined ? {} : { loginMethodId: audit.loginMethodId }),
    },
  });
  return ended;
}
