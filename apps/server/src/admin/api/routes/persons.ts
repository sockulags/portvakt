import { z } from "zod";
import { LOGIN_METHOD_KINDS } from "../../../domain/login-method.js";
import { PIN_INDEX_SUBJECT_PREFIX, type Person } from "../../../domain/person.js";
import { personnummerSchema } from "../../../domain/personnummer.js";
import type { Tenant } from "../../../domain/tenant.js";
import type { PersonSummary } from "../../../repositories/persons.js";
import {
  actorOf,
  assertPlatformReachable,
  endLogins,
  inTransaction,
  lockRow,
  targetTenant,
  type AdminDeps,
  type Tx,
} from "../context.js";
import { etagOf, requireMatch } from "../etag.js";
import { ApiError, notFound } from "../problem.js";
import { route, type AdminRoute } from "../registry.js";
import { etag, iso, isoDateTime, isoOrNull, listOf, tenantParams } from "../schemas.js";
import {
  attributeAssignmentSchema,
  attributeAssignmentView,
  roleAssignmentSchema,
  roleAssignmentView,
} from "./access.js";
import { grantSchema, grantView } from "./representation.js";

const personSummarySchema = z
  .object({
    id: z.uuid(),
    displayName: z.string().nullable().describe("null for a protected identity."),
    email: z.string().nullable(),
    protectedIdentity: z.boolean(),
    createdAt: isoDateTime,
    lastLoginAt: isoDateTime.nullable(),
  })
  .meta({ id: "PersonSummary" });

const identitySchema = z.object({
  id: z.uuid(),
  loginMethodId: z.uuid(),
  loginMethodName: z.string().nullable(),
  kind: z.enum(LOGIN_METHOD_KINDS).nullable(),
  protocol: z.enum(["oidc", "saml"]).nullable(),
  subject: z
    .string()
    .nullable()
    .describe("The upstream subject; null when it is the personal identity number."),
  hasPin: z.boolean().describe("The identity carries a personal identity number (never shown)."),
  createdAt: isoDateTime,
  lastLoginAt: isoDateTime,
});

const personSchema = z
  .object({
    id: z.uuid(),
    displayName: z.string().nullable(),
    email: z.string().nullable(),
    protectedIdentity: z.boolean(),
    createdAt: isoDateTime,
    lastLoginAt: isoDateTime.nullable(),
    identities: z.array(identitySchema),
    roleAssignments: z.array(roleAssignmentSchema),
    attributeAssignments: z.array(attributeAssignmentSchema),
    grants: z.array(grantSchema).describe("Representation grants the person may use as agent."),
    etag,
  })
  .meta({ id: "Person" });

const summaryView = (summary: PersonSummary) => ({
  id: summary.id,
  displayName: summary.displayName,
  email: summary.email,
  protectedIdentity: summary.protectedIdentity,
  createdAt: iso(summary.createdAt),
  lastLoginAt: isoOrNull(summary.lastLoginAt),
});

/** The tag covers the person record only (assignments have their own endpoints). */
const personTag = (person: Person): string =>
  etagOf({
    id: person.id,
    protectedIdentity: person.protectedIdentity,
    updatedAt: iso(person.updatedAt),
  });

async function personView(deps: AdminDeps, tenant: Tenant, person: Person) {
  const { repos } = deps;
  const [summary, identities, methods, roles, attributes, pins] = await Promise.all([
    repos.persons.summary(tenant.id, person.id),
    repos.persons.listIdentities(tenant.id, person.id),
    repos.loginMethods.list(tenant.id),
    repos.access.listAssignments(tenant.id, { personId: person.id }),
    repos.access.listAttributes(tenant.id, { personId: person.id }),
    repos.persons.pinIndexCandidates(tenant.id, person.id),
  ]);
  const grants = await repos.grants.listForAgent(tenant.id, person.id, pins);
  const byId = new Map(methods.map((method) => [method.id, method]));
  return {
    id: person.id,
    displayName: summary?.displayName ?? null,
    email: summary?.email ?? null,
    protectedIdentity: person.protectedIdentity,
    createdAt: iso(person.createdAt),
    lastLoginAt: isoOrNull(person.lastLoginAt),
    identities: identities.map((identity) => {
      const method = byId.get(identity.loginMethodId);
      return {
        id: identity.id,
        loginMethodId: identity.loginMethodId,
        loginMethodName: method?.displayName ?? null,
        kind: method?.kind ?? null,
        protocol: method?.protocol ?? null,
        subject: identity.subject.startsWith(PIN_INDEX_SUBJECT_PREFIX) ? null : identity.subject,
        hasPin: identity.pinIndex !== null,
        createdAt: iso(identity.createdAt),
        lastLoginAt: iso(identity.lastLoginAt),
      };
    }),
    roleAssignments: roles.map(roleAssignmentView),
    attributeAssignments: attributes.map(attributeAssignmentView),
    grants: grants.map((grant) => grantView(grant)),
    etag: personTag(person),
  };
}

const searchBody = z.union([
  z
    .object({
      query: z
        .string()
        .trim()
        .min(2)
        .max(100)
        .describe("A name or email prefix (also the start of a later word of the name)."),
    })
    .strict(),
  z.object({ pin: personnummerSchema.describe("Exact personal identity number.") }).strict(),
]);

const personParams = z.object({ tenantId: z.uuid(), personId: z.uuid() });

async function lockedPerson(
  tx: Tx,
  tenant: Tenant,
  personId: string,
  ifMatch: string | undefined,
): Promise<Person> {
  await lockRow(tx, "persons", "tenant_id = $1 AND id = $2", [tenant.id, personId]);
  const current = await tx.repos.persons.findById(tenant.id, personId);
  if (current === null) throw notFound();
  requireMatch(ifMatch, personTag(current));
  return current;
}

export function personRoutes(deps: AdminDeps): AdminRoute[] {
  return [
    route({
      method: "post",
      path: "/tenants/{tenantId}/persons/search",
      operationId: "searchPersons",
      summary: "Find persons by name or email prefix, or by exact personal identity number",
      description:
        "A POST, so names and numbers never appear in URLs. Personal identity numbers are " +
        "matched through the blind index and never listed.",
      tag: "Persons",
      params: tenantParams,
      body: searchBody,
      response: listOf(personSummarySchema),
      handler: async ({ caller, params, body }) => {
        const tenant = await targetTenant(deps, caller, params.tenantId);
        const found =
          "pin" in body
            ? await deps.repos.persons.findByPin(tenant.id, body.pin)
            : await deps.repos.persons.search(tenant.id, body.query, 50);
        return { body: { items: found.map(summaryView) } };
      },
    }),
    route({
      method: "get",
      path: "/tenants/{tenantId}/persons/{personId}",
      operationId: "getPerson",
      summary: "A person: identities, assignments and representation grants",
      tag: "Persons",
      params: personParams,
      response: personSchema,
      handler: async ({ caller, params }) => {
        const tenant = await targetTenant(deps, caller, params.tenantId);
        const person = await deps.repos.persons.findById(tenant.id, params.personId);
        if (person === null) throw notFound();
        return { body: await personView(deps, tenant, person) };
      },
    }),
    route({
      method: "post",
      path: "/tenants/{tenantId}/persons/{personId}/clear-protected-identity",
      operationId: "clearProtectedIdentity",
      summary: "Clear a person's protected identity flag",
      description:
        "Only an administrator can clear it; a later login flagged upstream sets it again.",
      tag: "Persons",
      ifMatch: true,
      params: personParams,
      response: personSchema,
      handler: async ({ caller, params, ifMatch }) => {
        const tenant = await targetTenant(deps, caller, params.tenantId);
        const person = await inTransaction(deps, async (tx) => {
          await lockRow(tx, "persons", "tenant_id = $1 AND id = $2", [tenant.id, params.personId]);
          const current = await tx.repos.persons.findById(tenant.id, params.personId);
          if (current === null) throw notFound();
          requireMatch(ifMatch, personTag(current));
          if (!current.protectedIdentity) return current;
          await tx.repos.persons.clearProtectedIdentity(tenant.id, current.id);
          await tx.record({
            action: "admin.person.protected_identity_clear",
            tenantId: tenant.id,
            actor: actorOf(caller),
            subject: { type: "person", id: current.id },
            details: { actorTenantId: caller.tenant.id },
          });
          const updated = await tx.repos.persons.findById(tenant.id, current.id);
          if (updated === null) throw notFound();
          return updated;
        });
        return { body: await personView(deps, tenant, person) };
      },
    }),
    route({
      method: "post",
      path: "/tenants/{tenantId}/persons/{personId}/identities/{identityId}/unlink",
      operationId: "unlinkIdentity",
      summary: "Remove one identity of a person",
      description:
        "The person keeps their other identities, assignments and grants; a later login with the " +
        "removed identity creates a new person (or links by personal identity number). The " +
        "person's only identity cannot be removed (409 last_identity): delete the person instead.",
      tag: "Persons",
      ifMatch: true,
      params: personParams.extend({ identityId: z.uuid() }),
      response: personSchema,
      errors: ["last_identity", "self_lockout"],
      handler: async ({ caller, params, ifMatch }) => {
        const tenant = await targetTenant(deps, caller, params.tenantId);
        const person = await inTransaction(deps, async (tx) => {
          const current = await lockedPerson(tx, tenant, params.personId, ifMatch);
          const identities = await tx.repos.persons.listIdentities(tenant.id, current.id);
          const identity = identities.find((item) => item.id === params.identityId);
          if (identity === undefined) throw notFound();
          if (identities.length === 1) throw new ApiError("last_identity");
          await tx.repos.persons.deleteIdentity(tenant.id, current.id, identity.id);
          await assertPlatformReachable(tx, tenant);
          // The person's logins through that identity end now.
          await endLogins(
            tx,
            caller,
            tenant.id,
            { personId: current.id, loginMethodId: identity.loginMethodId },
            {
              reason: "identity_unlinked",
              subject: { type: "person", id: current.id },
              loginMethodId: identity.loginMethodId,
            },
          );
          await tx.record({
            action: "admin.person.identity_unlink",
            tenantId: tenant.id,
            actor: actorOf(caller),
            subject: { type: "person", id: current.id },
            details: { actorTenantId: caller.tenant.id, loginMethodId: identity.loginMethodId },
          });
          return current;
        });
        return { body: await personView(deps, tenant, person) };
      },
    }),
    route({
      method: "post",
      path: "/tenants/{tenantId}/persons/{personId}/end-sessions",
      operationId: "endPersonSessions",
      summary: "End every session and grant of a person",
      description:
        "Signs the person out everywhere in the tenant at once: every broker session whose " +
        "login is the person's ends, and every grant of the person is revoked with its codes " +
        "and refresh tokens, so applications must send the person to a new login at their next " +
        "refresh. Access tokens already issued stay valid until they expire (ACCESS_TOKEN_TTL). " +
        "Audited as `sessions.revoked` (reason `ended_by_admin`) with the counts.",
      tag: "Persons",
      params: personParams,
      response: z.object({ sessions: z.number().int(), grants: z.number().int() }).strict(),
      handler: async ({ caller, params }) => {
        const tenant = await targetTenant(deps, caller, params.tenantId);
        const ended = await inTransaction(deps, async (tx) => {
          await lockRow(tx, "persons", "tenant_id = $1 AND id = $2", [tenant.id, params.personId]);
          return endLogins(
            tx,
            caller,
            tenant.id,
            { personId: params.personId },
            {
              reason: "ended_by_admin",
              subject: { type: "person", id: params.personId },
            },
          );
        });
        return { body: { sessions: ended.sessions, grants: ended.grants } };
      },
    }),
    route({
      method: "delete",
      path: "/tenants/{tenantId}/persons/{personId}",
      operationId: "deletePerson",
      summary: "Delete a person with their identities, assignments and grants as agent",
      tag: "Persons",
      ifMatch: true,
      params: personParams,
      errors: ["self_lockout"],
      handler: async ({ caller, params, ifMatch }) => {
        const tenant = await targetTenant(deps, caller, params.tenantId);
        await inTransaction(deps, async (tx) => {
          const current = await lockedPerson(tx, tenant, params.personId, ifMatch);
          const identities = await tx.repos.persons.listIdentities(tenant.id, current.id);
          await tx.repos.persons.delete(tenant.id, current.id);
          await assertPlatformReachable(tx, tenant);
          await endLogins(
            tx,
            caller,
            tenant.id,
            { personId: current.id },
            {
              reason: "person_deleted",
              subject: { type: "person", id: current.id },
            },
          );
          await tx.record({
            action: "admin.person.delete",
            tenantId: tenant.id,
            actor: actorOf(caller),
            subject: { type: "person", id: current.id },
            details: { actorTenantId: caller.tenant.id, identities: identities.length },
          });
        });
        return {};
      },
    }),
  ];
}
