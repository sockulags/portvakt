import type { AuditLog } from "../audit/audit-log.js";
import { auditEvent } from "../audit/catalogue.js";
import type { BootstrapIdpConfig, Config } from "../config/index.js";
import type { KeyRing } from "../crypto/keyring.js";
import { generateClientSecret } from "../crypto/secrets.js";
import type { Db } from "../db/database.js";
import type { Application } from "../domain/application.js";
import type { AuditEvent } from "../domain/audit.js";
import type { ClaimMapping, CreateLoginMethodInput } from "../domain/login-method.js";
import { SYSTEM_TENANT_SLUG } from "../domain/tenant.js";
import { JOB_LOCKS, runExclusive } from "../jobs/exclusive.js";
import type { Logger } from "../logging/logger.js";
import { OutboundRefusedError, type OutboundGuard } from "../net/outbound.js";
import {
  createRepositories,
  type Repositories,
  type RepositoryOptions,
} from "../repositories/index.js";
import {
  ADMIN_CLIENT_ID,
  ADMIN_ROLES,
  adminRedirectUris,
  PLATFORM_ADMIN_ROLE,
} from "./constants.js";

/**
 * First-start bootstrap (docs/plan.md, "Admin"): on a database without tenants, creates the
 * `system` tenant, the `portvakt-admin` application (enabled in `system`), the login method of
 * BOOTSTRAP_IDP_* and a pending platform-admin assignment for BOOTSTRAP_ADMIN_SUBJECT (the
 * upstream subject at that method) or BOOTSTRAP_ADMIN_PIN, all in one transaction under an
 * advisory lock, audited as `admin.bootstrap`. It never runs again once any tenant exists.
 */
export interface BootstrapDeps {
  readonly config: Config;
  readonly db: Db;
  readonly keys: KeyRing;
  readonly repositoryOptions: RepositoryOptions;
  readonly auditLog: AuditLog;
  readonly outbound: OutboundGuard;
  readonly logger: Logger;
}

export type BootstrapResult =
  | { readonly ran: false; readonly reason: "tenants_exist" | "not_configured" }
  | {
      readonly ran: true;
      readonly tenantId: string;
      readonly applicationId: string;
      readonly loginMethodId: string;
      readonly pendingAssignmentId: string;
      /** Set when no ADMIN_CLIENT_SECRET was configured (development only): shown once. */
      readonly generatedClientSecret: string | undefined;
    };

export class BootstrapError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BootstrapError";
  }
}

/** The `portvakt-admin` application: roles, templated redirect URIs, client secret. */
export async function ensureAdminApplication(
  repos: Repositories,
  adminPublicUrl: string,
  clientSecret: string,
): Promise<{ readonly application: Application; readonly created: boolean }> {
  const uris = adminRedirectUris(adminPublicUrl);
  let application = await repos.applications.findByClientId(ADMIN_CLIENT_ID);
  let created = false;
  if (application === null) {
    application = await repos.applications.create({
      clientId: ADMIN_CLIENT_ID,
      name: "Portvakt administration",
      clientAuth: { method: "client_secret_basic", clientSecret },
      ...uris,
      roles: ADMIN_ROLES.map((role) => ({ ...role })),
      representationMode: "none",
    });
    created = true;
  } else {
    const secretChanged =
      (await repos.applications.getClientSecret(application.id)) !== clientSecret;
    application = await repos.applications.update(application.id, {
      ...uris,
      enabled: true,
      representationMode: "none",
      ...(secretChanged ? { clientAuth: { method: "client_secret_basic", clientSecret } } : {}),
    });
    for (const role of ADMIN_ROLES) {
      await repos.applications.declareRole(application.id, role.role, role.description);
    }
  }
  return { application, created };
}

/** The login method input of BOOTSTRAP_IDP_*. */
export function bootstrapLoginMethodInput(
  idp: BootstrapIdpConfig,
  options: { readonly trustPin: boolean },
): CreateLoginMethodInput {
  const claimMapping: ClaimMapping = {
    subject: idp.claims.subject,
    ...(idp.claims.name === undefined ? {} : { name: idp.claims.name }),
    ...(idp.claims.email === undefined ? {} : { email: idp.claims.email }),
    ...(idp.claims.pin === undefined ? {} : { pin: idp.claims.pin }),
    ...(idp.claims.acr === undefined ? {} : { acr: idp.claims.acr }),
  };
  return {
    kind: idp.kind,
    displayName: idp.displayName,
    issuer: idp.issuer,
    clientId: idp.clientId,
    ...(idp.clientSecret === undefined ? {} : { clientSecret: idp.clientSecret }),
    scopes: [...idp.scopes],
    claimMapping,
    assertedAcr: idp.acr,
    trustUpstreamEmail: idp.trustEmail,
    trustPinForRepresentation: options.trustPin,
    sessionPolicy: { maxAgeSeconds: 8 * 3600, idleSeconds: 3600, allowSso: true },
  };
}

/** Checks the issuer with the outbound guard and tries its discovery (a warning on failure). */
async function checkIssuer(deps: BootstrapDeps, issuer: string): Promise<void> {
  try {
    deps.outbound.check(new URL(issuer));
    const response = await deps.outbound.fetch(
      `${issuer.replace(/\/+$/, "")}/.well-known/openid-configuration`,
      { maxBytes: 512 * 1024 },
    );
    if (!response.ok) {
      deps.logger.warn(
        { status: response.status },
        "bootstrap: the IdP's discovery did not answer 200",
      );
    }
  } catch (error) {
    if (error instanceof OutboundRefusedError) {
      throw new BootstrapError(
        `BOOTSTRAP_IDP_ISSUER refused by the outbound policy (${error.reason})`,
      );
    }
    // Unreachable now: the login method is still created; logins fail until the IdP answers.
    deps.logger.warn({ err: error }, "bootstrap: the IdP's discovery could not be fetched");
  }
}

export async function runBootstrap(deps: BootstrapDeps): Promise<BootstrapResult> {
  const { config, logger } = deps;
  const [existing] = await deps.db.query<{ found: boolean }>(
    "SELECT EXISTS (SELECT 1 FROM tenants) AS found",
  );
  if (existing?.found === true) return { ran: false, reason: "tenants_exist" };

  const idp = config.bootstrap.idp;
  if (idp === undefined) {
    logger.warn(
      "no tenants and no BOOTSTRAP_IDP_* configured: nothing can be administered " +
        "(set BOOTSTRAP_IDP_* and BOOTSTRAP_ADMIN_SUBJECT, or run seed:dev in development)",
    );
    return { ran: false, reason: "not_configured" };
  }
  const adminPublicUrl = config.admin.publicUrl;
  if (adminPublicUrl === undefined) throw new BootstrapError("ADMIN_PUBLIC_URL is required");
  let secret = config.admin.clientSecret;
  let generated: string | undefined;
  if (secret === undefined) {
    if (config.isProduction) throw new BootstrapError("ADMIN_CLIENT_SECRET is required");
    secret = generateClientSecret();
    generated = secret;
  }
  await checkIssuer(deps, idp.issuer);

  const written: AuditEvent[] = [];
  const outcome = await runExclusive(deps.db, JOB_LOCKS.bootstrap, { wait: true }, async (tx) => {
    // Another replica may have bootstrapped while this one waited for the lock.
    const [again] = await tx.query<{ found: boolean }>(
      "SELECT EXISTS (SELECT 1 FROM tenants) AS found",
    );
    if (again?.found === true) return undefined;
    const repos = createRepositories(tx, deps.keys, deps.repositoryOptions);
    const tenant = await repos.tenants.create({ slug: SYSTEM_TENANT_SLUG, name: "Portvakt" });
    const { application } = await ensureAdminApplication(repos, adminPublicUrl, secret);
    await repos.applications.enableForTenant(tenant.id, application.id);
    const byPin = config.bootstrap.adminPin !== undefined;
    const method = await repos.loginMethods.create(
      tenant.id,
      bootstrapLoginMethodInput(idp, { trustPin: byPin }),
    );
    const pending = await repos.pending.createRole(tenant.id, {
      applicationId: application.id,
      role: PLATFORM_ADMIN_ROLE,
      target: byPin
        ? { pin: config.bootstrap.adminPin }
        : { loginMethodId: method.id, subject: config.bootstrap.adminSubject! },
    });
    written.push(
      await repos.audit.append(
        auditEvent({
          action: "admin.bootstrap",
          tenantId: tenant.id,
          actor: { type: "system", id: "bootstrap" },
          subject: { type: "tenant", id: tenant.id },
          details: {
            applicationId: application.id,
            loginMethodId: method.id,
            pendingAssignmentId: pending.id,
            targetKind: byPin ? "pin" : "identity",
          },
        }),
      ),
    );
    return {
      tenantId: tenant.id,
      applicationId: application.id,
      loginMethodId: method.id,
      pendingAssignmentId: pending.id,
    };
  });
  if (!outcome.ran || outcome.value === undefined) return { ran: false, reason: "tenants_exist" };
  deps.auditLog.forward(written);
  logger.info(
    { tenantId: outcome.value.tenantId, loginMethodId: outcome.value.loginMethodId },
    "bootstrap: created the system tenant and portvakt-admin",
  );
  if (generated !== undefined && config.nodeEnv === "development") {
    // Development only, never through the logger: the portal needs this secret once.
    console.log(
      `[portvakt] bootstrap generated the portvakt-admin client secret (development only; set ` +
        `ADMIN_CLIENT_SECRET to choose it): ${generated}`,
    );
  }
  return { ran: true, ...outcome.value, generatedClientSecret: generated };
}
