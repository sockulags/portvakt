import { z } from "zod";
import { AUDIT_ACTOR_TYPES, AUDIT_OUTCOMES, type AuditEvent } from "../../../domain/audit.js";
import type { AuditScope } from "../../../repositories/audit.js";
import { targetTenant, type AdminDeps } from "../context.js";
import { fieldError } from "../problem.js";
import { route, type AdminRoute } from "../registry.js";
import { iso, isoDateTime, tenantParams } from "../schemas.js";

const auditEventSchema = z
  .object({
    id: z.uuid(),
    seq: z.string(),
    occurredAt: isoDateTime,
    tenantId: z.uuid().nullable(),
    actor: z.object({ type: z.enum(AUDIT_ACTOR_TYPES), id: z.string().nullable() }),
    subject: z.object({ type: z.string(), id: z.string() }).nullable(),
    action: z.string(),
    outcome: z.enum(AUDIT_OUTCOMES),
    details: z.record(z.string(), z.unknown()).describe("Ids and codes only (the catalogue)."),
  })
  .meta({ id: "AuditEvent" });

const auditPageSchema = z
  .object({
    items: z.array(auditEventSchema),
    nextCursor: z
      .string()
      .nullable()
      .describe("Pass as `cursor` for the next, older page; null on the last page."),
  })
  .meta({ id: "AuditEventPage" });

const actionName = z.string().regex(/^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/);

const filterQuery = z.object({
  action: actionName.optional().describe("Exact action, such as `login.success`."),
  actionPrefix: z
    .string()
    .regex(/^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$/)
    .optional()
    .describe("The action and everything below it: `admin` matches `admin.tenant.create`."),
  actorId: z.string().min(1).max(255).optional(),
  subjectId: z.string().min(1).max(255).optional(),
  outcome: z.enum(AUDIT_OUTCOMES).optional(),
  from: isoDateTime.optional().describe("Inclusive."),
  to: isoDateTime.optional().describe("Exclusive."),
  cursor: z
    .string()
    .regex(/^\d{1,19}$/)
    .optional(),
  limit: z.coerce.number().int().min(1).max(200).default(50),
});
type FilterQuery = z.output<typeof filterQuery>;

const eventView = (event: AuditEvent) => ({
  id: event.id,
  seq: event.seq,
  occurredAt: iso(event.occurredAt),
  tenantId: event.tenantId,
  actor: { ...event.actor },
  subject: event.subject === null ? null : { ...event.subject },
  action: event.action,
  outcome: event.outcome,
  details: { ...event.details },
});

async function page(deps: AdminDeps, scope: AuditScope, query: FilterQuery) {
  const from = query.from === undefined ? undefined : new Date(query.from);
  const to = query.to === undefined ? undefined : new Date(query.to);
  if (from !== undefined && to !== undefined && from >= to)
    throw fieldError("query.to", "must be after from");
  const result = await deps.repos.audit.query(
    scope,
    {
      ...(query.action === undefined ? {} : { actions: [query.action] }),
      ...(query.actionPrefix === undefined ? {} : { actionPrefix: query.actionPrefix }),
      ...(query.actorId === undefined ? {} : { actorId: query.actorId }),
      ...(query.subjectId === undefined ? {} : { subjectId: query.subjectId }),
      ...(query.outcome === undefined ? {} : { outcome: query.outcome }),
      ...(from === undefined ? {} : { from }),
      ...(to === undefined ? {} : { to }),
    },
    { limit: query.limit, ...(query.cursor === undefined ? {} : { cursor: query.cursor }) },
  );
  return { items: result.events.map(eventView), nextCursor: result.nextCursor };
}

export function auditRoutes(deps: AdminDeps): AdminRoute[] {
  return [
    route({
      method: "get",
      path: "/tenants/{tenantId}/audit-events",
      operationId: "listTenantAuditEvents",
      summary: "The tenant's audit events, newest first (keyset pagination)",
      tag: "Audit",
      params: tenantParams,
      query: filterQuery,
      response: auditPageSchema,
      handler: async ({ caller, params, query }) => {
        const tenant = await targetTenant(deps, caller, params.tenantId);
        return { body: await page(deps, { tenantId: tenant.id }, query) };
      },
    }),
    route({
      method: "get",
      path: "/audit-events",
      operationId: "listAuditEvents",
      summary: "Audit events of every tenant and the platform, newest first",
      tag: "Audit",
      platformOnly: true,
      query: filterQuery.extend({
        tenantId: z
          .union([z.uuid(), z.literal("platform")])
          .optional()
          .describe("One tenant, or `platform` for events without a tenant (signing keys)."),
      }),
      response: auditPageSchema,
      handler: async ({ query }) => {
        const { tenantId, ...filter } = query;
        const scope: AuditScope =
          tenantId === undefined
            ? { allTenants: true }
            : { allTenants: true, tenantId: tenantId === "platform" ? null : tenantId };
        return { body: await page(deps, scope, filter) };
      },
    }),
  ];
}
