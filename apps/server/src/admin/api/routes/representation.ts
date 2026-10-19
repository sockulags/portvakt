import { z } from "zod";
import { personnummerSchema } from "../../../domain/personnummer.js";
import {
  PARTY_TYPES,
  type Party,
  type RepresentationGrant,
} from "../../../domain/representation.js";
import { displayNameSchema } from "../../../domain/schemas.js";
import type { Tenant } from "../../../domain/tenant.js";
import type { Caller } from "../auth.js";
import {
  actorOf,
  inTransaction,
  lockRow,
  targetTenant,
  type AdminDeps,
  type Tx,
} from "../context.js";
import { diff } from "../diff.js";
import { requireMatch, withEtag } from "../etag.js";
import { fieldError, notFound } from "../problem.js";
import { route, type AdminRoute } from "../registry.js";
import { etag, iso, isoDateTime, isoOrNull, listOf, strictBody, tenantParams } from "../schemas.js";

export const partySchema = z
  .object({
    id: z.uuid(),
    type: z.enum(PARTY_TYPES),
    identifier: z
      .string()
      .nullable()
      .describe(
        "Organisations: the organisation number. Persons: only the date part (YYYYMMDD-****); " +
          "null for a protected identity.",
      ),
    displayName: z.string(),
    protectedIdentity: z.boolean(),
    createdAt: isoDateTime,
    updatedAt: isoDateTime,
    etag,
  })
  .meta({ id: "Party" });

/** A person party's number is never shown in full (as the representation chooser). */
function maskedIdentifier(party: Party): string | null {
  if (party.type === "organisation") {
    return `${party.identifier.slice(0, 6)}-${party.identifier.slice(6)}`;
  }
  if (party.protectedIdentity) return null;
  return `${party.identifier.slice(0, 8)}-****`;
}

export const partyView = (party: Party) =>
  withEtag({
    id: party.id,
    type: party.type,
    identifier: maskedIdentifier(party),
    displayName: party.displayName,
    protectedIdentity: party.protectedIdentity,
    createdAt: iso(party.createdAt),
    updatedAt: iso(party.updatedAt),
  });

export const grantSchema = z
  .object({
    id: z.uuid(),
    party: z.object({
      id: z.uuid(),
      type: z.enum(PARTY_TYPES),
      displayName: z.string(),
      protectedIdentity: z.boolean(),
    }),
    agent: z
      .discriminatedUnion("kind", [
        z.object({ kind: z.literal("person"), personId: z.uuid() }),
        z.object({ kind: z.literal("pin").describe("A personal identity number (never shown).") }),
      ])
      .describe("Who may act for the party."),
    allApplications: z.boolean(),
    applicationIds: z.array(z.uuid()),
    validFrom: isoDateTime,
    validTo: isoDateTime.nullable(),
    revokedAt: isoDateTime.nullable(),
    revokedBy: z.uuid().nullable(),
    createdBy: z.uuid().nullable(),
    createdAt: isoDateTime,
    status: z.enum(["active", "scheduled", "expired", "revoked"]),
    etag,
  })
  .meta({ id: "RepresentationGrant" });

export function grantView(grant: RepresentationGrant, now = new Date()) {
  const status =
    grant.revokedAt !== null
      ? "revoked"
      : grant.validFrom.getTime() > now.getTime()
        ? "scheduled"
        : grant.validTo !== null && grant.validTo.getTime() <= now.getTime()
          ? "expired"
          : "active";
  const view = {
    id: grant.id,
    party: {
      id: grant.party.id,
      type: grant.party.type,
      displayName: grant.party.displayName,
      protectedIdentity: grant.party.protectedIdentity,
    },
    agent:
      grant.agent.type === "person"
        ? { kind: "person" as const, personId: grant.agent.personId }
        : { kind: "pin" as const },
    allApplications: grant.allApplications,
    applicationIds: [...grant.applicationIds],
    validFrom: iso(grant.validFrom),
    validTo: isoOrNull(grant.validTo),
    revokedAt: isoOrNull(grant.revokedAt),
    revokedBy: grant.revokedBy,
    createdBy: grant.createdBy,
    createdAt: iso(grant.createdAt),
  };
  // The tag covers the grant itself, not its time-dependent status.
  return { ...withEtag(view), status } as const;
}

const auditedGrant = (grant: RepresentationGrant) => ({
  allApplications: grant.allApplications,
  applicationIds: [...grant.applicationIds],
  validFrom: iso(grant.validFrom),
  validTo: isoOrNull(grant.validTo),
});

const partyParams = z.object({ tenantId: z.uuid(), partyId: z.uuid() });
const grantParams = z.object({ tenantId: z.uuid(), grantId: z.uuid() });

const createGrantBody = strictBody({
  agent: z
    .union([
      z.object({ personId: z.uuid() }).strict(),
      z.object({ pin: personnummerSchema }).strict(),
    ])
    .describe("A person, or the personal identity number of someone who has not signed in yet."),
  partyId: z.uuid(),
  allApplications: z.boolean(),
  applicationIds: z.array(z.uuid()).max(100).default([]),
  validFrom: isoDateTime.optional(),
  validTo: isoDateTime.nullable().default(null),
});

const grantUpdateBody = strictBody({
  allApplications: z.boolean().optional(),
  applicationIds: z
    .array(z.uuid())
    .max(100)
    .optional()
    .describe("With allApplications false: the applications the grant covers (at least one)."),
  validFrom: isoDateTime.optional(),
  validTo: isoDateTime.nullable().optional().describe("null: valid until revoked."),
});

async function lockedGrant(
  tx: Tx,
  tenant: Tenant,
  grantId: string,
  ifMatch: string | undefined,
): Promise<RepresentationGrant> {
  await lockRow(tx, "representation_grants", "tenant_id = $1 AND id = $2", [tenant.id, grantId]);
  const grant = await tx.repos.grants.findById(tenant.id, grantId);
  if (grant === null) throw notFound();
  requireMatch(ifMatch, grantView(grant).etag);
  return grant;
}

/** Every listed application must be attached to the tenant. */
async function checkApplications(tx: Tx, tenant: Tenant, ids: readonly string[]): Promise<void> {
  if (ids.length === 0) return;
  const attached = new Set(
    (await tx.repos.applications.listForTenant(tenant.id)).map((entry) => entry.application.id),
  );
  ids.forEach((id, index) => {
    if (!attached.has(id))
      throw fieldError(`applicationIds.${index}`, "not attached to the tenant");
  });
}

const recordGrant = (
  tx: Tx,
  caller: Caller,
  tenant: Tenant,
  action: "admin.grant.update" | "admin.grant.revoke",
  before: RepresentationGrant,
  after: RepresentationGrant,
) =>
  tx.record({
    action,
    tenantId: tenant.id,
    actor: actorOf(caller),
    subject: { type: "representation_grant", id: after.id },
    details:
      action === "admin.grant.update"
        ? {
            actorTenantId: caller.tenant.id,
            partyId: after.party.id,
            changes: diff(auditedGrant(before), auditedGrant(after)),
          }
        : { actorTenantId: caller.tenant.id, partyId: after.party.id },
  });

export function representationRoutes(deps: AdminDeps): AdminRoute[] {
  return [
    route({
      method: "get",
      path: "/tenants/{tenantId}/parties",
      operationId: "listParties",
      summary: "Parties (persons and organisations) that can be represented",
      tag: "Representation",
      params: tenantParams,
      response: listOf(partySchema),
      handler: async ({ caller, params }) => {
        const tenant = await targetTenant(deps, caller, params.tenantId);
        return { body: { items: (await deps.repos.parties.list(tenant.id)).map(partyView) } };
      },
    }),
    route({
      method: "post",
      path: "/tenants/{tenantId}/parties",
      operationId: "createParty",
      summary: "Create a party",
      tag: "Representation",
      status: 201,
      params: tenantParams,
      body: strictBody({
        type: z.enum(PARTY_TYPES),
        identifier: z
          .string()
          .trim()
          .min(1)
          .max(100)
          .describe("Personnummer for a person, organisationsnummer for an organisation."),
        displayName: displayNameSchema,
        protectedIdentity: z.boolean().default(false),
      }),
      response: partySchema,
      errors: ["conflict"],
      handler: async ({ caller, params, body }) => {
        const tenant = await targetTenant(deps, caller, params.tenantId);
        const party = await inTransaction(deps, async (tx) => {
          const created = await tx.repos.parties.create(tenant.id, body);
          await tx.record({
            action: "admin.party.create",
            tenantId: tenant.id,
            actor: actorOf(caller),
            subject: { type: "party", id: created.id },
            details: {
              actorTenantId: caller.tenant.id,
              partyType: created.type,
              changes: diff(
                {},
                {
                  type: created.type,
                  identifier: created.identifier,
                  displayName: created.displayName,
                  protectedIdentity: created.protectedIdentity,
                },
                ["identifier", "displayName"],
              ),
            },
          });
          return created;
        });
        return { status: 201, body: partyView(party) };
      },
    }),
    route({
      method: "patch",
      path: "/tenants/{tenantId}/parties/{partyId}",
      operationId: "updateParty",
      summary: "Rename a party or mark a person party as protected",
      tag: "Representation",
      ifMatch: true,
      params: partyParams,
      body: strictBody({
        displayName: displayNameSchema.optional(),
        protectedIdentity: z.boolean().optional(),
      }),
      response: partySchema,
      handler: async ({ caller, params, body, ifMatch }) => {
        const tenant = await targetTenant(deps, caller, params.tenantId);
        const party = await inTransaction(deps, async (tx) => {
          await lockRow(tx, "parties", "tenant_id = $1 AND id = $2", [tenant.id, params.partyId]);
          const current = await tx.repos.parties.findById(tenant.id, params.partyId);
          if (current === null) throw notFound();
          requireMatch(ifMatch, partyView(current).etag);
          if (body.protectedIdentity === true && current.type !== "person") {
            throw fieldError(
              "protectedIdentity",
              "only a person party can have a protected identity",
            );
          }
          let next = current;
          if (body.displayName !== undefined && body.displayName !== current.displayName) {
            next = await tx.repos.parties.rename(tenant.id, current.id, body.displayName);
          }
          if (
            body.protectedIdentity !== undefined &&
            body.protectedIdentity !== current.protectedIdentity
          ) {
            next = await tx.repos.parties.setProtectedIdentity(
              tenant.id,
              current.id,
              body.protectedIdentity,
            );
          }
          if (next === current) return current;
          await tx.record({
            action: "admin.party.update",
            tenantId: tenant.id,
            actor: actorOf(caller),
            subject: { type: "party", id: current.id },
            details: {
              actorTenantId: caller.tenant.id,
              partyType: current.type,
              changes: diff(
                { displayName: current.displayName, protectedIdentity: current.protectedIdentity },
                { displayName: next.displayName, protectedIdentity: next.protectedIdentity },
                ["displayName"],
              ),
            },
          });
          return next;
        });
        return { body: partyView(party) };
      },
    }),
    route({
      method: "get",
      path: "/tenants/{tenantId}/grants",
      operationId: "listGrants",
      summary: "Representation grants, newest first",
      tag: "Representation",
      params: tenantParams,
      query: z.object({ partyId: z.uuid().optional(), agentPersonId: z.uuid().optional() }),
      response: listOf(grantSchema),
      handler: async ({ caller, params, query }) => {
        const tenant = await targetTenant(deps, caller, params.tenantId);
        const { repos } = deps;
        let grants: RepresentationGrant[];
        if (query.agentPersonId !== undefined) {
          const pins = await repos.persons.pinIndexCandidates(tenant.id, query.agentPersonId);
          grants = await repos.grants.listForAgent(tenant.id, query.agentPersonId, pins);
          if (query.partyId !== undefined)
            grants = grants.filter((grant) => grant.party.id === query.partyId);
        } else if (query.partyId !== undefined) {
          grants = await repos.grants.listForParty(tenant.id, query.partyId);
        } else {
          grants = await repos.grants.list(tenant.id);
        }
        return { body: { items: grants.map((grant) => grantView(grant)) } };
      },
    }),
    route({
      method: "post",
      path: "/tenants/{tenantId}/grants",
      operationId: "createGrant",
      summary: "Let an agent act for a party",
      tag: "Representation",
      status: 201,
      params: tenantParams,
      body: createGrantBody,
      response: grantSchema,
      handler: async ({ caller, params, body }) => {
        const tenant = await targetTenant(deps, caller, params.tenantId);
        const grant = await inTransaction(deps, async (tx) => {
          if ((await tx.repos.parties.findById(tenant.id, body.partyId)) === null) {
            throw fieldError("partyId", "no such party in the tenant");
          }
          if (
            "personId" in body.agent &&
            (await tx.repos.persons.findById(tenant.id, body.agent.personId)) === null
          ) {
            throw fieldError("agent.personId", "no such person in the tenant");
          }
          if (body.allApplications === body.applicationIds.length > 0) {
            throw fieldError(
              "applicationIds",
              "set allApplications, or list at least one application, but not both",
            );
          }
          await checkApplications(tx, tenant, body.applicationIds);
          const created = await tx.repos.grants.create(tenant.id, {
            agent: body.agent,
            partyId: body.partyId,
            allApplications: body.allApplications,
            applicationIds: body.applicationIds,
            ...(body.validFrom === undefined ? {} : { validFrom: new Date(body.validFrom) }),
            validTo: body.validTo === null ? null : new Date(body.validTo),
            createdBy: caller.personId,
          });
          await tx.record({
            action: "admin.grant.create",
            tenantId: tenant.id,
            actor: actorOf(caller),
            subject: { type: "representation_grant", id: created.id },
            details: {
              actorTenantId: caller.tenant.id,
              partyId: created.party.id,
              agentKind: created.agent.type,
              ...(created.agent.type === "person" ? { agentPersonId: created.agent.personId } : {}),
              changes: diff({}, auditedGrant(created)),
            },
          });
          return created;
        });
        return { status: 201, body: grantView(grant) };
      },
    }),
    route({
      method: "patch",
      path: "/tenants/{tenantId}/grants/{grantId}",
      operationId: "updateGrant",
      summary: "Change which applications a grant covers, or its validity window",
      tag: "Representation",
      ifMatch: true,
      params: grantParams,
      body: grantUpdateBody,
      response: grantSchema,
      handler: async ({ caller, params, body, ifMatch }) => {
        const tenant = await targetTenant(deps, caller, params.tenantId);
        const grant = await inTransaction(deps, async (tx) => {
          const current = await lockedGrant(tx, tenant, params.grantId, ifMatch);
          if (current.revokedAt !== null) throw fieldError("grantId", "the grant is revoked");
          let updated = current;
          if (body.allApplications !== undefined || body.applicationIds !== undefined) {
            const allApplications = body.allApplications ?? current.allApplications;
            const applicationIds = allApplications
              ? []
              : (body.applicationIds ?? [...current.applicationIds]);
            if (!allApplications && applicationIds.length === 0) {
              throw fieldError("applicationIds", "list at least one application");
            }
            await checkApplications(tx, tenant, applicationIds);
            updated = await tx.repos.grants.setApplications(tenant.id, current.id, {
              allApplications,
              applicationIds,
            });
          }
          if (body.validFrom !== undefined || body.validTo !== undefined) {
            updated = await tx.repos.grants.setValidity(tenant.id, current.id, {
              validFrom:
                body.validFrom === undefined ? current.validFrom : new Date(body.validFrom),
              validTo:
                body.validTo === undefined
                  ? current.validTo
                  : body.validTo === null
                    ? null
                    : new Date(body.validTo),
            });
          }
          await recordGrant(tx, caller, tenant, "admin.grant.update", current, updated);
          return updated;
        });
        return { body: grantView(grant) };
      },
    }),
    route({
      method: "post",
      path: "/tenants/{tenantId}/grants/{grantId}/revoke",
      operationId: "revokeGrant",
      summary: "Revoke a grant; the next refresh of tokens issued with it fails",
      tag: "Representation",
      ifMatch: true,
      params: grantParams,
      response: grantSchema,
      handler: async ({ caller, params, ifMatch }) => {
        const tenant = await targetTenant(deps, caller, params.tenantId);
        const grant = await inTransaction(deps, async (tx) => {
          const current = await lockedGrant(tx, tenant, params.grantId, ifMatch);
          if (current.revokedAt !== null) return current;
          // revoked_by holds the acting administrator, who may be of the system tenant.
          const revoked = await tx.repos.grants.revoke(tenant.id, current.id, caller.personId);
          await recordGrant(tx, caller, tenant, "admin.grant.revoke", current, revoked);
          return revoked;
        });
        return { body: grantView(grant) };
      },
    }),
  ];
}
