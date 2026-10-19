import { z } from "zod";
import {
  CLIENT_ASSERTION_AUDIENCES,
  createLoginMethodInputSchema,
  createSamlLoginMethodInputSchema,
  LOGIN_METHOD_KINDS,
  sessionPolicySchema,
  UPSTREAM_AUTH_METHODS,
  updateLoginMethodInputSchema,
  type LoginMethod,
  type UpdateLoginMethodInput,
  type UpdateSamlLoginMethodInput,
} from "../../../domain/login-method.js";
import {
  SAML_BINDINGS,
  SAML_COMPARISONS,
  SAML_SUBJECT_SOURCES,
  samlSettingsPatchSchema,
} from "../../../domain/saml.js";
import type { Tenant } from "../../../domain/tenant.js";
import { SP_CERTIFICATE_WARNING_SECONDS } from "../../../federation/saml/admin.js";
import { samlBasePath } from "../../../federation/saml/service.js";
import { federationCallbackPath, federationJwksPath } from "../../../federation/service.js";
import { OutboundRefusedError } from "../../../net/outbound.js";
import { SP_KEY_PURPOSES, type SpKey } from "../../../repositories/saml.js";
import type { Caller } from "../auth.js";
import {
  actorOf,
  assertPlatformReachable,
  inTransaction,
  lockRow,
  targetTenant,
  type AdminDeps,
  type Tx,
} from "../context.js";
import { diff } from "../diff.js";
import { etagOf, requireMatch } from "../etag.js";
import { ApiError, fieldError, notFound } from "../problem.js";
import { route, type AdminRoute } from "../registry.js";
import { etag, iso, isoDateTime, isoOrNull, listOf, strictBody, tenantParams } from "../schemas.js";

/** Login methods whose upstream secret expires within this window are flagged. */
export const SECRET_WARNING_SECONDS = 30 * 24 * 3600;

export const WARNING_CODES = [
  "client_secret_expiring",
  "client_secret_expired",
  "sp_certificate_expiring",
  "saml_metadata_error",
  "saml_metadata_missing",
  "saml_unsigned_metadata",
  "saml_unencrypted_assertions",
  "saml_unsigned_response",
  "saml_minimum_comparison",
  "saml_missing_logo",
  "saml_missing_description",
] as const;
export type WarningCode = (typeof WARNING_CODES)[number];

export const warningSchema = z
  .object({
    code: z.enum(WARNING_CODES),
    field: z.string().optional(),
    /** English description; the portal shows its own text per code. */
    message: z.string(),
    /** When the expiring secret or certificate expires. */
    expiresAt: isoDateTime.optional(),
    purpose: z.enum(SP_KEY_PURPOSES).optional(),
  })
  .meta({ id: "LoginMethodWarning" });
export type Warning = z.input<typeof warningSchema>;

/** SAML settings warnings of `SamlLoginMethodAdmin.warningsFor`, by the field they name. */
const SAML_WARNING_CODES: Readonly<Record<string, WarningCode>> = {
  "saml.allowUnsignedMetadata": "saml_unsigned_metadata",
  "saml.requireEncryptedAssertions": "saml_unencrypted_assertions",
  "saml.requireSignedResponse": "saml_unsigned_response",
  "saml.authnContextComparison": "saml_minimum_comparison",
  "saml.uiInfo.logos": "saml_missing_logo",
  "saml.uiInfo.description": "saml_missing_description",
};

const sessionPolicyView = z.object({
  maxAgeSeconds: z.number().int(),
  idleSeconds: z.number().int(),
  allowSso: z.boolean(),
});

const spKeySchema = z.object({
  id: z.uuid(),
  purpose: z.enum(SP_KEY_PURPOSES),
  state: z.enum(["next", "active", "previous"]),
  notAfter: isoDateTime,
  createdAt: isoDateTime,
});

const oidcViewSchema = z.object({
  issuer: z.string(),
  clientId: z.string(),
  hasClientSecret: z.boolean().describe("The secret itself is write-only."),
  clientAuthMethod: z.enum(UPSTREAM_AUTH_METHODS),
  useUserinfo: z.boolean(),
  clientAssertionAudience: z.enum(CLIENT_ASSERTION_AUDIENCES),
  allowedUpstreamTenants: z.array(z.string()),
  trustUpstreamEmail: z.boolean(),
  pinLoginHint: z.boolean(),
  scopes: z.array(z.string()),
  claimMapping: z.record(z.string(), z.string()),
  redirectUri: z.string().describe("Register this redirect URI at the upstream IdP."),
  jwksUri: z.string().describe("The public key for private_key_jwt client authentication."),
});

const samlViewSchema = z.object({
  idpEntityId: z.string(),
  metadataUrl: z.string().nullable(),
  hasInlineMetadata: z.boolean(),
  metadataSigningCertificate: z.string().nullable(),
  metadataRefreshSeconds: z.number().int(),
  requestedLoa: z.array(z.string()),
  authnContextComparison: z.enum(SAML_COMPARISONS),
  entityCategories: z.array(z.string()),
  requestedAttributes: z.array(z.object({ name: z.string(), required: z.boolean() })),
  subjectSource: z.enum(SAML_SUBJECT_SOURCES),
  attributeMapping: z.record(z.string(), z.unknown()),
  authnRequestBinding: z.enum(SAML_BINDINGS),
  requireEncryptedAssertions: z.boolean(),
  requireSignedResponse: z.boolean(),
  signMetadata: z.boolean(),
  clockSkewSeconds: z.number().int(),
  trustEmail: z.boolean(),
  allowUnsignedMetadata: z.boolean(),
  requireGcm: z.boolean(),
  uiInfo: z.record(z.string(), z.unknown()),
  orgAffiliationScopes: z.array(z.string()),
  spEntityId: z.string(),
  spMetadataUrl: z.string().describe("Register this SP metadata with the IdP or federation."),
  acsUrl: z.string(),
  spKeys: z.array(spKeySchema),
  metadataStatus: z.object({
    cachedAt: isoDateTime.nullable(),
    checkedAt: isoDateTime.nullable(),
    validUntil: isoDateTime.nullable(),
    error: z.string().nullable(),
  }),
});

export const loginMethodSchema = z
  .object({
    id: z.uuid(),
    tenantId: z.uuid(),
    protocol: z.enum(["oidc", "saml"]),
    kind: z.enum(LOGIN_METHOD_KINDS),
    displayName: z.string(),
    assertedAcr: z.string(),
    homeRealmDomains: z.array(z.string()),
    secretExpiresAt: isoDateTime.nullable(),
    sessionPolicy: sessionPolicyView,
    linkByPin: z.boolean(),
    trustPinForRepresentation: z.boolean(),
    enabled: z.boolean(),
    createdAt: isoDateTime,
    updatedAt: isoDateTime,
    oidc: oidcViewSchema.optional(),
    saml: samlViewSchema.optional(),
    warnings: z.array(warningSchema),
    etag,
  })
  .meta({ id: "LoginMethod" });
export type LoginMethodView = z.input<typeof loginMethodSchema>;

/** The configuration as audited: OIDC fields at the top, SAML settings below `saml`. */
function audited(method: LoginMethod, secretChanged = false): Record<string, unknown> {
  const common = {
    protocol: method.protocol,
    kind: method.kind,
    displayName: method.displayName,
    assertedAcr: method.assertedAcr,
    homeRealmDomains: [...method.homeRealmDomains],
    secretExpiresAt: isoOrNull(method.secretExpiresAt),
    sessionPolicy: { ...method.sessionPolicy },
    linkByPin: method.linkByPin,
    trustPinForRepresentation: method.trustPinForRepresentation,
    enabled: method.enabled,
  };
  if (method.protocol === "saml") {
    return { ...common, saml: { ...method.saml, requestedLoa: [...method.saml.requestedLoa] } };
  }
  return {
    ...common,
    issuer: method.issuer,
    clientId: method.clientId,
    // Never the secret: a marker that differs when it was set or replaced.
    clientSecret: secretChanged ? "replaced" : method.hasClientSecret ? "set" : null,
    clientAuthMethod: method.clientAuthMethod,
    useUserinfo: method.useUserinfo,
    clientAssertionAudience: method.clientAssertionAudience,
    allowedUpstreamTenants: [...method.allowedUpstreamTenants],
    trustUpstreamEmail: method.trustUpstreamEmail,
    pinLoginHint: method.pinLoginHint,
    scopes: [...method.scopes],
    claimMapping: { ...method.claimMapping },
  };
}
const REDACTED = ["clientSecret", "saml.metadataXml", "saml.metadataSigningCertificate"];

/** Configuration and SP keys: what the entity tag covers (not the refresh state or warnings). */
const tagOf = (method: LoginMethod, spKeys: readonly SpKey[]): string =>
  etagOf({
    updatedAt: iso(method.updatedAt),
    config: audited(method),
    spKeys: spKeys.map((key) => `${key.id}:${key.state}`),
  });

export async function loginMethodView(
  deps: AdminDeps,
  tx: Pick<Tx, "repos" | "samlAdmin"> | AdminDeps,
  tenant: Tenant,
  method: LoginMethod,
  now = new Date(),
): Promise<LoginMethodView> {
  const { repos, samlAdmin } = tx;
  const publicUrl = deps.config.publicUrl;
  const warnings: Warning[] = [];
  if (method.secretExpiresAt !== null) {
    const left = method.secretExpiresAt.getTime() - now.getTime();
    if (left <= 0) {
      warnings.push({
        code: "client_secret_expired",
        field: "secretExpiresAt",
        message: "the upstream client secret has expired",
        expiresAt: iso(method.secretExpiresAt),
      });
    } else if (left <= SECRET_WARNING_SECONDS * 1000) {
      warnings.push({
        code: "client_secret_expiring",
        field: "secretExpiresAt",
        message: "the upstream client secret expires within 30 days",
        expiresAt: iso(method.secretExpiresAt),
      });
    }
  }
  const base = {
    id: method.id,
    tenantId: method.tenantId,
    protocol: method.protocol,
    kind: method.kind,
    displayName: method.displayName,
    assertedAcr: method.assertedAcr,
    homeRealmDomains: [...method.homeRealmDomains],
    secretExpiresAt: isoOrNull(method.secretExpiresAt),
    sessionPolicy: { ...method.sessionPolicy },
    linkByPin: method.linkByPin,
    trustPinForRepresentation: method.trustPinForRepresentation,
    enabled: method.enabled,
    createdAt: iso(method.createdAt),
    updatedAt: iso(method.updatedAt),
  };
  if (method.protocol === "oidc") {
    return {
      ...base,
      oidc: {
        issuer: method.issuer,
        clientId: method.clientId,
        hasClientSecret: method.hasClientSecret,
        clientAuthMethod: method.clientAuthMethod,
        useUserinfo: method.useUserinfo,
        clientAssertionAudience: method.clientAssertionAudience,
        allowedUpstreamTenants: [...method.allowedUpstreamTenants],
        trustUpstreamEmail: method.trustUpstreamEmail,
        pinLoginHint: method.pinLoginHint,
        scopes: [...method.scopes],
        claimMapping: { ...method.claimMapping },
        redirectUri: `${publicUrl}${federationCallbackPath(tenant.slug, method.id)}`,
        jwksUri: `${publicUrl}${federationJwksPath(tenant.slug, method.id)}`,
      },
      warnings,
      etag: tagOf(method, []),
    };
  }

  // One after the other: `repos` may be a transaction's, and one client runs one query at a time.
  const spKeys = await repos.saml.listSpKeys(tenant.id, method.id);
  const cache = await repos.saml.metadataCache(tenant.id, method.id);
  const settingWarnings = await samlAdmin.warningsFor(method, now);
  const expiring = await samlAdmin.expiringSpCertificates(
    tenant.id,
    SP_CERTIFICATE_WARNING_SECONDS,
    now,
  );
  for (const text of settingWarnings) {
    const field = text.slice(0, text.indexOf(":"));
    const code = SAML_WARNING_CODES[field];
    if (code !== undefined) warnings.push({ code, field, message: text.slice(field.length + 2) });
  }
  for (const entry of expiring.filter((item) => item.loginMethodId === method.id)) {
    warnings.push({
      code: "sp_certificate_expiring",
      field: `spKeys.${entry.purpose}`,
      message: `the ${entry.state} SP ${entry.purpose} certificate expires within 30 days`,
      expiresAt: iso(entry.notAfter),
      purpose: entry.purpose,
    });
  }
  if (cache.error !== null) {
    warnings.push({
      code: "saml_metadata_error",
      field: "saml.metadataUrl",
      message: `the last metadata refresh failed (${cache.error})`,
    });
  } else if (cache.metadata === null) {
    warnings.push({
      code: "saml_metadata_missing",
      field: "saml.metadataUrl",
      message: "no valid IdP metadata is cached; logins through this method fail",
    });
  }
  const sp = deps.saml.spEndpoints(tenant.slug, method.id);
  const { metadataXml, ...settings } = method.saml;
  return {
    ...base,
    saml: {
      ...settings,
      requestedLoa: [...settings.requestedLoa],
      entityCategories: [...settings.entityCategories],
      requestedAttributes: settings.requestedAttributes.map((attribute) => ({ ...attribute })),
      attributeMapping: { ...settings.attributeMapping },
      uiInfo: { ...settings.uiInfo },
      orgAffiliationScopes: [...settings.orgAffiliationScopes],
      hasInlineMetadata: metadataXml !== null,
      spEntityId: sp.entityId,
      spMetadataUrl: `${publicUrl}${samlBasePath(tenant.slug, method.id)}/metadata`,
      acsUrl: sp.acsUrl,
      spKeys: spKeys.map((key) => ({
        id: key.id,
        purpose: key.purpose,
        state: key.state,
        notAfter: iso(key.notAfter),
        createdAt: iso(key.createdAt),
      })),
      metadataStatus: {
        cachedAt: isoOrNull(cache.cachedAt),
        checkedAt: isoOrNull(cache.checkedAt),
        validUntil:
          cache.metadata?.validUntil === null || cache.metadata === null
            ? null
            : new Date(cache.metadata.validUntil).toISOString(),
        error: cache.error,
      },
    },
    warnings,
    etag: tagOf(method, spKeys),
  };
}

// Request bodies -------------------------------------------------------------------------------

const createOidcBody = createLoginMethodInputSchema
  .omit({ secretExpiresAt: true })
  .extend({
    protocol: z.literal("oidc"),
    clientSecret: z.string().min(1).max(4096).optional().describe("Write-only."),
    secretExpiresAt: isoDateTime.nullable().default(null),
  })
  .catchall(z.never({ error: "unknown or immutable field" }));

const createSamlBody = createSamlLoginMethodInputSchema
  .extend({ protocol: z.literal("saml") })
  .catchall(z.never({ error: "unknown or immutable field" }));

const createBody = z.discriminatedUnion("protocol", [createOidcBody, createSamlBody]);

const { secretExpiresAt: _secretExpiresAt, ...updateShape } = updateLoginMethodInputSchema.shape;
void _secretExpiresAt;
const updateBody = strictBody({
  ...updateShape,
  clientSecret: z
    .string()
    .min(1)
    .max(4096)
    .nullable()
    .optional()
    .describe("Write-only; null removes the secret."),
  secretExpiresAt: isoDateTime.nullable().optional(),
  saml: samlSettingsPatchSchema.optional(),
});

/** Fields of the update body that only OIDC login methods have. */
const OIDC_ONLY = [
  "issuer",
  "clientId",
  "clientSecret",
  "clientAuthMethod",
  "useUserinfo",
  "clientAssertionAudience",
  "allowedUpstreamTenants",
  "trustUpstreamEmail",
  "pinLoginHint",
  "scopes",
  "claimMapping",
  "secretExpiresAt",
] as const;

const methodParams = z.object({ tenantId: z.uuid(), loginMethodId: z.uuid() });

const keysBody = strictBody({
  purposes: z
    .array(z.enum(SP_KEY_PURPOSES))
    .min(1)
    .max(2)
    .transform((purposes) => [...new Set(purposes)])
    .default([...SP_KEY_PURPOSES]),
});

/** An issuer must pass the outbound guard (scheme, no special-use literal address). */
function checkIssuer(deps: AdminDeps, issuer: string | undefined): void {
  if (issuer === undefined) return;
  try {
    deps.outbound.check(new URL(issuer));
  } catch (error) {
    if (error instanceof OutboundRefusedError) {
      throw fieldError("issuer", `refused by the outbound policy (${error.reason})`);
    }
    throw fieldError("issuer", "must be an absolute URL");
  }
}

async function lockedMethod(
  tx: Tx,
  deps: AdminDeps,
  tenant: Tenant,
  id: string,
  ifMatch: string | undefined,
): Promise<LoginMethod> {
  await lockRow(tx, "login_methods", "tenant_id = $1 AND id = $2", [tenant.id, id]);
  const current = await tx.repos.loginMethods.findById(tenant.id, id);
  if (current === null) throw notFound();
  const spKeys = current.protocol === "saml" ? await tx.repos.saml.listSpKeys(tenant.id, id) : [];
  requireMatch(ifMatch, tagOf(current, spKeys));
  void deps;
  return current;
}

async function recordChange(
  tx: Tx,
  caller: Caller,
  tenant: Tenant,
  before: LoginMethod | null,
  after: LoginMethod,
  secretChanged: boolean,
): Promise<void> {
  await tx.record({
    action: before === null ? "admin.login_method.create" : "admin.login_method.update",
    tenantId: tenant.id,
    actor: actorOf(caller),
    subject: { type: "login_method", id: after.id },
    details: {
      actorTenantId: caller.tenant.id,
      protocol: after.protocol,
      changes: diff(
        before === null ? {} : audited(before),
        audited(after, secretChanged),
        REDACTED,
      ),
    },
  });
}

async function update(
  deps: AdminDeps,
  caller: Caller,
  tenant: Tenant,
  id: string,
  ifMatch: string | undefined,
  body: z.output<typeof updateBody>,
): Promise<LoginMethodView> {
  return inTransaction(deps, async (tx) => {
    const current = await lockedMethod(tx, deps, tenant, id, ifMatch);
    let updated: LoginMethod;
    let secretChanged = false;
    if (current.protocol === "saml") {
      const misplaced = OIDC_ONLY.filter((field) => body[field] !== undefined);
      if (misplaced.length > 0)
        throw fieldError(misplaced[0]!, "not a setting of a SAML login method");
      const { saml, ...rest } = body;
      const patch: UpdateSamlLoginMethodInput = {
        ...pick(rest, [
          "kind",
          "displayName",
          "assertedAcr",
          "homeRealmDomains",
          "sessionPolicy",
          "linkByPin",
          "trustPinForRepresentation",
          "enabled",
        ]),
        ...(saml === undefined ? {} : { saml }),
      };
      updated = await tx.samlAdmin.update(tenant.id, current.id, patch, actorOf(caller));
    } else {
      if (body.saml !== undefined)
        throw fieldError("saml", "not a setting of an OIDC login method");
      checkIssuer(deps, body.issuer);
      const { saml: _saml, secretExpiresAt, ...rest } = body;
      void _saml;
      const patch: UpdateLoginMethodInput = {
        ...rest,
        ...(secretExpiresAt === undefined
          ? {}
          : { secretExpiresAt: secretExpiresAt === null ? null : new Date(secretExpiresAt) }),
      };
      secretChanged = body.clientSecret !== undefined;
      updated = await tx.repos.loginMethods.update(tenant.id, current.id, patch);
    }
    // A new issuer (or IdP) means the identities at this method belonged to another one.
    const orphaned =
      (current.protocol === "oidc" &&
        updated.protocol === "oidc" &&
        current.issuer !== updated.issuer) ||
      (current.protocol === "saml" &&
        updated.protocol === "saml" &&
        current.saml.idpEntityId !== updated.saml.idpEntityId);
    await assertPlatformReachable(
      tx,
      tenant,
      orphaned ? { orphanedLoginMethodId: current.id } : {},
    );
    await recordChange(tx, caller, tenant, current, updated, secretChanged);
    return loginMethodView(deps, tx, tenant, updated);
  });
}

function pick<T extends object, K extends keyof T>(
  value: T,
  keys: readonly K[],
): Partial<Pick<T, K>> {
  const out: Partial<Pick<T, K>> = {};
  for (const key of keys) if (value[key] !== undefined) out[key] = value[key];
  return out;
}

export function loginMethodRoutes(deps: AdminDeps): AdminRoute[] {
  return [
    route({
      method: "get",
      path: "/tenants/{tenantId}/login-methods",
      operationId: "listLoginMethods",
      summary: "The tenant's login methods, with warnings",
      tag: "Login methods",
      params: tenantParams,
      response: listOf(loginMethodSchema),
      handler: async ({ caller, params }) => {
        const tenant = await targetTenant(deps, caller, params.tenantId);
        const methods = await deps.repos.loginMethods.list(tenant.id);
        const items = [];
        for (const method of methods) items.push(await loginMethodView(deps, deps, tenant, method));
        return { body: { items } };
      },
    }),
    route({
      method: "post",
      path: "/tenants/{tenantId}/login-methods",
      operationId: "createLoginMethod",
      summary: "Create an OIDC or SAML login method",
      description:
        "SAML: the IdP metadata is fetched (or parsed) and checked, and Portvakt generates the " +
        "SP signing and encryption keys; their private keys never leave Portvakt.",
      tag: "Login methods",
      status: 201,
      params: tenantParams,
      body: createBody,
      response: loginMethodSchema,
      errors: ["conflict"],
      handler: async ({ caller, params, body }) => {
        const tenant = await targetTenant(deps, caller, params.tenantId);
        const view = await inTransaction(deps, async (tx) => {
          let created: LoginMethod;
          if (body.protocol === "oidc") {
            checkIssuer(deps, body.issuer);
            const { protocol: _protocol, secretExpiresAt, ...input } = body;
            void _protocol;
            created = await tx.repos.loginMethods.create(tenant.id, {
              ...input,
              secretExpiresAt: secretExpiresAt === null ? null : new Date(secretExpiresAt),
            });
          } else {
            const { protocol: _protocol, ...input } = body;
            void _protocol;
            created = await tx.samlAdmin.create(tenant.id, input, actorOf(caller));
          }
          await recordChange(
            tx,
            caller,
            tenant,
            null,
            created,
            body.protocol === "oidc" && body.clientSecret !== undefined,
          );
          return loginMethodView(deps, tx, tenant, created);
        });
        return { status: 201, body: view };
      },
    }),
    route({
      method: "get",
      path: "/tenants/{tenantId}/login-methods/{loginMethodId}",
      operationId: "getLoginMethod",
      summary: "A login method",
      tag: "Login methods",
      params: methodParams,
      response: loginMethodSchema,
      handler: async ({ caller, params }) => {
        const tenant = await targetTenant(deps, caller, params.tenantId);
        const method = await deps.repos.loginMethods.findById(tenant.id, params.loginMethodId);
        if (method === null) throw notFound();
        return { body: await loginMethodView(deps, deps, tenant, method) };
      },
    }),
    route({
      method: "patch",
      path: "/tenants/{tenantId}/login-methods/{loginMethodId}",
      operationId: "updateLoginMethod",
      summary: "Change a login method",
      description:
        "Fields of the other protocol are refused. A changed SAML IdP (entityID, metadata " +
        "source or signing certificate) is fetched and checked again.",
      tag: "Login methods",
      ifMatch: true,
      params: methodParams,
      body: updateBody,
      response: loginMethodSchema,
      handler: async ({ caller, params, body, ifMatch }) => {
        const tenant = await targetTenant(deps, caller, params.tenantId);
        return { body: await update(deps, caller, tenant, params.loginMethodId, ifMatch, body) };
      },
    }),
    route({
      method: "put",
      path: "/tenants/{tenantId}/login-methods/{loginMethodId}/session-policy",
      operationId: "setSessionPolicy",
      summary: "Set a login method's session policy (maxAge, idle, SSO)",
      tag: "Login methods",
      ifMatch: true,
      params: methodParams,
      body: sessionPolicySchema,
      response: loginMethodSchema,
      handler: async ({ caller, params, body, ifMatch }) => {
        const tenant = await targetTenant(deps, caller, params.tenantId);
        return {
          body: await update(deps, caller, tenant, params.loginMethodId, ifMatch, {
            sessionPolicy: body,
          }),
        };
      },
    }),
    route({
      method: "post",
      path: "/tenants/{tenantId}/login-methods/{loginMethodId}/sp-keys/prepare",
      operationId: "prepareSpKeyRotation",
      summary: "Add next SAML SP keys, published next to the active ones",
      description:
        "Give the IdP or federation time to fetch the SP metadata with the new certificates, " +
        "then rotate.",
      tag: "Login methods",
      ifMatch: true,
      params: methodParams,
      body: keysBody,
      response: loginMethodSchema,
      errors: ["conflict"],
      handler: async ({ caller, params, body, ifMatch }) => {
        const tenant = await targetTenant(deps, caller, params.tenantId);
        const view = await inTransaction(deps, async (tx) => {
          const current = await lockedMethod(tx, deps, tenant, params.loginMethodId, ifMatch);
          if (current.protocol !== "saml") throw fieldError("protocol", "not a SAML login method");
          const added = await tx.samlAdmin.prepareSpKeyRotation(
            tenant.id,
            current.id,
            body.purposes,
          );
          await tx.record({
            action: "admin.login_method.sp_keys_prepare",
            tenantId: tenant.id,
            actor: actorOf(caller),
            subject: { type: "login_method", id: current.id },
            details: {
              actorTenantId: caller.tenant.id,
              purposes: body.purposes,
              keyIds: added.map((key) => key.id),
            },
          });
          return loginMethodView(deps, tx, tenant, current);
        });
        return { body: view };
      },
    }),
    route({
      method: "post",
      path: "/tenants/{tenantId}/login-methods/{loginMethodId}/sp-keys/rotate",
      operationId: "rotateSpKeys",
      summary: "Make the next SAML SP keys active",
      tag: "Login methods",
      ifMatch: true,
      params: methodParams,
      body: keysBody,
      response: loginMethodSchema,
      handler: async ({ caller, params, body, ifMatch }) => {
        const tenant = await targetTenant(deps, caller, params.tenantId);
        const view = await inTransaction(deps, async (tx) => {
          const current = await lockedMethod(tx, deps, tenant, params.loginMethodId, ifMatch);
          if (current.protocol !== "saml") throw fieldError("protocol", "not a SAML login method");
          const rotated = await tx.samlAdmin.rotateSpKeys(tenant.id, current.id, body.purposes);
          if (rotated.length === 0)
            throw fieldError("purposes", "no next key to activate; prepare first");
          await tx.record({
            action: "admin.login_method.sp_keys_rotate",
            tenantId: tenant.id,
            actor: actorOf(caller),
            subject: { type: "login_method", id: current.id },
            details: { actorTenantId: caller.tenant.id, purposes: rotated },
          });
          return loginMethodView(deps, tx, tenant, current);
        });
        return { body: view };
      },
    }),
    route({
      method: "delete",
      path: "/tenants/{tenantId}/login-methods/{loginMethodId}",
      operationId: "deleteLoginMethod",
      summary: "Delete a login method that no person has signed in with",
      description:
        "A method with identities cannot be deleted (409 in_use): disable it instead, so the " +
        "persons keep their links. Its rules and pending assignments are deleted with it.",
      tag: "Login methods",
      ifMatch: true,
      params: methodParams,
      errors: ["in_use", "self_lockout"],
      handler: async ({ caller, params, ifMatch }) => {
        const tenant = await targetTenant(deps, caller, params.tenantId);
        await inTransaction(deps, async (tx) => {
          const current = await lockedMethod(tx, deps, tenant, params.loginMethodId, ifMatch);
          if ((await tx.repos.loginMethods.identityCount(tenant.id, current.id)) > 0) {
            throw new ApiError("in_use", {
              detail: "persons have signed in with this login method; disable it instead",
            });
          }
          await tx.repos.loginMethods.delete(tenant.id, current.id);
          await assertPlatformReachable(tx, tenant);
          await tx.record({
            action: "admin.login_method.delete",
            tenantId: tenant.id,
            actor: actorOf(caller),
            subject: { type: "login_method", id: current.id },
            details: { actorTenantId: caller.tenant.id, protocol: current.protocol },
          });
        });
        return {};
      },
    }),
  ];
}
