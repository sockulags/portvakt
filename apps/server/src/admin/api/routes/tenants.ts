import { z } from "zod";
import { REPRESENTATION_SOURCE_IDS } from "../../../domain/representation.js";
import { displayNameSchema, tenantSlugSchema } from "../../../domain/schemas.js";
import { SYSTEM_TENANT_SLUG, TENANT_STATUSES, type Tenant } from "../../../domain/tenant.js";
import type { Caller } from "../auth.js";
import { actorOf, inTransaction, lockRow, targetTenant, type AdminDeps } from "../context.js";
import { diff } from "../diff.js";
import { requireMatch, withEtag } from "../etag.js";
import { ApiError } from "../problem.js";
import { route, type AdminRoute } from "../registry.js";
import { etag, iso, isoDateTime, listOf, strictBody, tenantParams } from "../schemas.js";

export const tenantSchema = z
  .object({
    id: z.uuid(),
    slug: z.string(),
    name: z.string(),
    status: z.enum(TENANT_STATUSES),
    representationSources: z.array(z.enum(REPRESENTATION_SOURCE_IDS)),
    createdAt: isoDateTime,
    updatedAt: isoDateTime,
    etag,
  })
  .meta({ id: "Tenant" });
export type TenantView = z.input<typeof tenantSchema>;

export const tenantView = (tenant: Tenant): TenantView =>
  withEtag({
    id: tenant.id,
    slug: tenant.slug,
    name: tenant.name,
    status: tenant.status,
    representationSources: [...tenant.representationSources],
    createdAt: iso(tenant.createdAt),
    updatedAt: iso(tenant.updatedAt),
  });

/** Audited fields of a tenant (diffs). */
const audited = (tenant: Tenant) => ({
  slug: tenant.slug,
  name: tenant.name,
  status: tenant.status,
  representationSources: [...tenant.representationSources],
});

const UUID_LIKE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

const createBody = strictBody({
  slug: tenantSlugSchema
    .min(2)
    .refine((slug) => !UUID_LIKE.test(slug), "must not look like a UUID")
    .describe("Lowercase letters, digits and hyphens; immutable once created."),
  name: displayNameSchema,
});

const meSchema = z
  .object({
    personId: z.uuid(),
    tenant: tenantSchema,
    platform: z.boolean().describe("platform-admin in the system tenant: every tenant."),
    roles: z.array(z.string()),
  })
  .meta({ id: "Me" });

async function changeStatus(
  deps: AdminDeps,
  caller: Caller,
  tenantId: string,
  ifMatch: string | undefined,
  status: Tenant["status"],
): Promise<TenantView> {
  const tenant = await targetTenant(deps, caller, tenantId);
  if (
    status === "suspended" &&
    (tenant.slug === SYSTEM_TENANT_SLUG || tenant.id === caller.tenant.id)
  ) {
    // Suspending the system tenant (or one's own) would lock the administrators out.
    throw new ApiError("self_lockout");
  }
  return inTransaction(deps, async (tx) => {
    await lockRow(tx, "tenants", "id = $1", [tenant.id]);
    const current = await tx.repos.tenants.findById(tenant.id);
    if (current === null) throw new ApiError("not_found");
    requireMatch(ifMatch, tenantView(current).etag);
    if (current.status === status) return tenantView(current);
    const updated = await tx.repos.tenants.update(tenant.id, { status });
    await tx.record({
      action: status === "suspended" ? "admin.tenant.suspend" : "admin.tenant.reactivate",
      tenantId: tenant.id,
      actor: actorOf(caller),
      subject: { type: "tenant", id: tenant.id },
      details: { actorTenantId: caller.tenant.id },
    });
    return tenantView(updated);
  });
}

export function tenantRoutes(deps: AdminDeps): AdminRoute[] {
  return [
    route({
      method: "get",
      path: "/me",
      operationId: "getMe",
      summary: "The calling administrator and their scope",
      tag: "Session",
      response: meSchema,
      handler: ({ caller }) =>
        Promise.resolve({
          body: {
            personId: caller.personId,
            tenant: tenantView(caller.tenant),
            platform: caller.platform,
            roles: [...caller.roles],
          },
        }),
    }),
    route({
      method: "get",
      path: "/tenants",
      operationId: "listTenants",
      summary: "Tenants (a tenant administrator sees only their own)",
      tag: "Tenants",
      response: listOf(tenantSchema),
      handler: async ({ caller }) => {
        const tenants = caller.platform ? await deps.repos.tenants.list() : [caller.tenant];
        return { body: { items: tenants.map(tenantView) } };
      },
    }),
    route({
      method: "post",
      path: "/tenants",
      operationId: "createTenant",
      summary: "Create a tenant",
      tag: "Tenants",
      platformOnly: true,
      status: 201,
      body: createBody,
      response: tenantSchema,
      errors: ["conflict"],
      handler: async ({ caller, body }) => {
        const tenant = await inTransaction(deps, async (tx) => {
          const created = await tx.repos.tenants.create({ slug: body.slug, name: body.name });
          await tx.record({
            action: "admin.tenant.create",
            tenantId: created.id,
            actor: actorOf(caller),
            subject: { type: "tenant", id: created.id },
            details: { actorTenantId: caller.tenant.id, changes: diff({}, audited(created)) },
          });
          return created;
        });
        return { status: 201, body: tenantView(tenant) };
      },
    }),
    route({
      method: "get",
      path: "/tenants/{tenantId}",
      operationId: "getTenant",
      summary: "A tenant",
      tag: "Tenants",
      params: tenantParams,
      response: tenantSchema,
      handler: async ({ caller, params }) => ({
        body: tenantView(await targetTenant(deps, caller, params.tenantId)),
      }),
    }),
    route({
      method: "patch",
      path: "/tenants/{tenantId}",
      operationId: "updateTenant",
      summary: "Rename a tenant or set its representation sources (the slug is immutable)",
      tag: "Tenants",
      platformOnly: true,
      ifMatch: true,
      params: tenantParams,
      body: strictBody({
        name: displayNameSchema.optional(),
        representationSources: z
          .array(z.enum(REPRESENTATION_SOURCE_IDS))
          .max(REPRESENTATION_SOURCE_IDS.length)
          .refine((sources) => new Set(sources).size === sources.length, "sources must be unique")
          .optional()
          .describe("Representation sources registered in this installation (v1: internal)."),
      }),
      response: tenantSchema,
      handler: async ({ caller, params, body, ifMatch }) => {
        const tenant = await targetTenant(deps, caller, params.tenantId);
        const updated = await inTransaction(deps, async (tx) => {
          await lockRow(tx, "tenants", "id = $1", [tenant.id]);
          const current = await tx.repos.tenants.findById(tenant.id);
          if (current === null) throw new ApiError("not_found");
          requireMatch(ifMatch, tenantView(current).etag);
          const patch = {
            ...(body.name === undefined || body.name === current.name ? {} : { name: body.name }),
            ...(body.representationSources === undefined
              ? {}
              : { representationSources: body.representationSources }),
          };
          if (Object.keys(patch).length === 0) return current;
          const next = await tx.repos.tenants.update(tenant.id, patch);
          const changes = diff(audited(current), audited(next));
          if (Object.keys(changes).length === 0) return next;
          await tx.record({
            action: "admin.tenant.update",
            tenantId: tenant.id,
            actor: actorOf(caller),
            subject: { type: "tenant", id: tenant.id },
            details: {
              actorTenantId: caller.tenant.id,
              changes,
            },
          });
          return next;
        });
        return { body: tenantView(updated) };
      },
    }),
    route({
      method: "post",
      path: "/tenants/{tenantId}/suspend",
      operationId: "suspendTenant",
      summary: "Suspend a tenant: its issuer answers 404 until it is reactivated",
      tag: "Tenants",
      platformOnly: true,
      ifMatch: true,
      params: tenantParams,
      response: tenantSchema,
      errors: ["self_lockout"],
      handler: async ({ caller, params, ifMatch }) => ({
        body: await changeStatus(deps, caller, params.tenantId, ifMatch, "suspended"),
      }),
    }),
    route({
      method: "post",
      path: "/tenants/{tenantId}/reactivate",
      operationId: "reactivateTenant",
      summary: "Reactivate a suspended tenant",
      tag: "Tenants",
      platformOnly: true,
      ifMatch: true,
      params: tenantParams,
      response: tenantSchema,
      handler: async ({ caller, params, ifMatch }) => ({
        body: await changeStatus(deps, caller, params.tenantId, ifMatch, "active"),
      }),
    }),
  ];
}
