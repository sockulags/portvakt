import { z } from "zod";
import type {
  AttributeAssignment,
  PendingAttributeAssignment,
  PendingRoleAssignment,
  PendingTarget,
  RoleAssignment,
  RoleRule,
} from "../../../domain/access.js";
import { personnummerSchema } from "../../../domain/personnummer.js";
import { attributeKeySchema, roleNameSchema } from "../../../domain/schemas.js";
import type { Tenant } from "../../../domain/tenant.js";
import type { Caller } from "../auth.js";
import {
  actorOf,
  assertPlatformReachable,
  guardPlatformAdminRole,
  inTransaction,
  lockRow,
  targetTenant,
  type AdminDeps,
  type Tx,
} from "../context.js";
import { requireMatch, withEtag } from "../etag.js";
import { ApiError, fieldError, notFound } from "../problem.js";
import { route, type AdminRoute } from "../registry.js";
import { etag, iso, isoDateTime, listOf, strictBody, tenantParams } from "../schemas.js";

const targetViewSchema = z
  .discriminatedUnion("kind", [
    z.object({ kind: z.literal("person"), personId: z.uuid() }),
    z.object({
      kind: z.literal("identity"),
      loginMethodId: z.uuid(),
      subject: z.string().describe("The upstream subject at that login method."),
    }),
    z.object({ kind: z.literal("pin").describe("A personal identity number (never shown).") }),
  ])
  .meta({ id: "AssignmentTarget" });
type TargetView = z.input<typeof targetViewSchema>;

const targetInput = z
  .union([
    z.object({ personId: z.uuid() }).strict(),
    z.object({ loginMethodId: z.uuid(), subject: z.string().trim().min(1).max(255) }).strict(),
    z.object({ pin: personnummerSchema }).strict(),
  ])
  .describe(
    "A person, or someone who has not signed in yet: an identity reference (login method and " +
      "upstream subject) or a personal identity number (resolved only through a login method " +
      "trusted for personal identity numbers).",
  );

export const roleAssignmentSchema = z
  .object({
    id: z.uuid(),
    applicationId: z.uuid(),
    role: z.string(),
    target: targetViewSchema,
    pending: z.boolean().describe("Not resolved yet: the person has not signed in."),
    createdAt: isoDateTime,
  })
  .meta({ id: "RoleAssignment" });
type RoleAssignmentView = z.input<typeof roleAssignmentSchema>;

export const attributeAssignmentSchema = z
  .object({
    id: z.uuid(),
    applicationId: z.uuid(),
    key: z.string(),
    value: z.string(),
    target: targetViewSchema,
    pending: z.boolean(),
    createdAt: isoDateTime,
    updatedAt: isoDateTime,
    etag,
  })
  .meta({ id: "AttributeAssignment" });
type AttributeAssignmentView = z.input<typeof attributeAssignmentSchema>;

const roleRuleSchema = z
  .object({
    id: z.uuid(),
    applicationId: z.uuid(),
    loginMethodId: z.uuid(),
    groupValue: z.string(),
    role: z.string(),
    createdAt: isoDateTime,
  })
  .meta({ id: "RoleRule" });

const catalogueSchema = z
  .object({
    applications: z.array(
      z.object({
        applicationId: z.uuid(),
        clientId: z.string(),
        name: z.string(),
        enabled: z.boolean(),
        roles: z.array(z.object({ role: z.string(), description: z.string().nullable() })),
        attributeKeys: z.array(z.object({ key: z.string(), description: z.string().nullable() })),
      }),
    ),
  })
  .meta({ id: "RoleCatalogue" });

const pendingTargetView = (target: PendingTarget): TargetView =>
  target.kind === "identity"
    ? { kind: "identity", loginMethodId: target.loginMethodId, subject: target.subject }
    : { kind: "pin" };

export const roleAssignmentView = (assignment: RoleAssignment): RoleAssignmentView => ({
  id: assignment.id,
  applicationId: assignment.applicationId,
  role: assignment.role,
  target: { kind: "person", personId: assignment.personId },
  pending: false,
  createdAt: iso(assignment.createdAt),
});

const pendingRoleView = (assignment: PendingRoleAssignment): RoleAssignmentView => ({
  id: assignment.id,
  applicationId: assignment.applicationId,
  role: assignment.role,
  target: pendingTargetView(assignment.target),
  pending: true,
  createdAt: iso(assignment.createdAt),
});

export const attributeAssignmentView = (assignment: AttributeAssignment): AttributeAssignmentView =>
  withEtag({
    id: assignment.id,
    applicationId: assignment.applicationId,
    key: assignment.key,
    value: assignment.value,
    target: { kind: "person", personId: assignment.personId },
    pending: false,
    createdAt: iso(assignment.createdAt),
    updatedAt: iso(assignment.updatedAt),
  });

const pendingAttributeView = (assignment: PendingAttributeAssignment): AttributeAssignmentView =>
  withEtag({
    id: assignment.id,
    applicationId: assignment.applicationId,
    key: assignment.key,
    value: assignment.value,
    target: pendingTargetView(assignment.target),
    pending: true,
    createdAt: iso(assignment.createdAt),
    updatedAt: iso(assignment.updatedAt),
  });

const ruleView = (rule: RoleRule) => ({
  id: rule.id,
  applicationId: rule.applicationId,
  loginMethodId: rule.loginMethodId,
  groupValue: rule.groupValue,
  role: rule.role,
  createdAt: iso(rule.createdAt),
});

const filterQuery = z.object({
  applicationId: z.uuid().optional(),
  personId: z.uuid().optional(),
});

const targetKindOf = (target: z.output<typeof targetInput>): "person" | "identity" | "pin" =>
  "personId" in target ? "person" : "pin" in target ? "pin" : "identity";

/** A login method target must be a login method of the tenant. */
async function checkTarget(
  tx: Tx,
  tenant: Tenant,
  target: z.output<typeof targetInput>,
): Promise<void> {
  if ("personId" in target) {
    if ((await tx.repos.persons.findById(tenant.id, target.personId)) === null) {
      throw fieldError("target.personId", "no such person in the tenant");
    }
  } else if ("loginMethodId" in target) {
    if ((await tx.repos.loginMethods.findById(tenant.id, target.loginMethodId)) === null) {
      throw fieldError("target.loginMethodId", "no such login method in the tenant");
    }
  }
}

/**
 * The persons a target names now: the person itself, or those who already signed in with the
 * referenced identity (then the assignment is made for them right away instead of pending).
 */
async function personsOf(
  tx: Tx,
  tenant: Tenant,
  target: z.output<typeof targetInput>,
): Promise<string[]> {
  if ("personId" in target) return [target.personId];
  return tx.repos.persons.matchPendingTarget(tenant.id, target);
}

async function createRoleAssignment(
  deps: AdminDeps,
  caller: Caller,
  tenant: Tenant,
  body: { applicationId: string; role: string; target: z.output<typeof targetInput> },
): Promise<RoleAssignmentView[]> {
  return inTransaction(deps, async (tx) => {
    await guardPlatformAdminRole(tx, caller, tenant, body.applicationId, body.role);
    await checkTarget(tx, tenant, body.target);
    const persons = await personsOf(tx, tenant, body.target);
    const targetKind = targetKindOf(body.target);
    const loginMethodId = "loginMethodId" in body.target ? body.target.loginMethodId : undefined;
    const created: RoleAssignmentView[] = [];
    if (persons.length > 0) {
      for (const personId of persons) {
        const assignment = await tx.repos.access.assignRole(tenant.id, {
          personId,
          applicationId: body.applicationId,
          role: body.role,
        });
        created.push(roleAssignmentView(assignment));
        await tx.record({
          action: "admin.role_assignment.create",
          tenantId: tenant.id,
          actor: actorOf(caller),
          subject: { type: "person", id: personId },
          details: {
            actorTenantId: caller.tenant.id,
            applicationId: body.applicationId,
            role: body.role,
            targetKind,
            pending: false,
            ...(loginMethodId === undefined ? {} : { loginMethodId }),
          },
        });
      }
      return created;
    }
    if ("personId" in body.target) return created;
    const pending = await tx.repos.pending.createRole(tenant.id, {
      applicationId: body.applicationId,
      role: body.role,
      target: body.target,
      createdBy: caller.personId,
    });
    await tx.record({
      action: "admin.role_assignment.create",
      tenantId: tenant.id,
      actor: actorOf(caller),
      subject: { type: "pending_role_assignment", id: pending.id },
      details: {
        actorTenantId: caller.tenant.id,
        applicationId: body.applicationId,
        role: body.role,
        targetKind,
        pending: true,
        ...(loginMethodId === undefined ? {} : { loginMethodId }),
      },
    });
    return [pendingRoleView(pending)];
  });
}

const ruleParams = z.object({ tenantId: z.uuid(), ruleId: z.uuid() });
const assignmentParams = z.object({ tenantId: z.uuid(), assignmentId: z.uuid() });

export function accessRoutes(deps: AdminDeps): AdminRoute[] {
  return [
    route({
      method: "get",
      path: "/tenants/{tenantId}/roles",
      operationId: "getRoleCatalogue",
      summary: "Roles and attribute keys the tenant's applications declare",
      tag: "Roles",
      params: tenantParams,
      response: catalogueSchema,
      handler: async ({ caller, params }) => {
        const tenant = await targetTenant(deps, caller, params.tenantId);
        const entries = await deps.repos.applications.listForTenant(tenant.id);
        return {
          body: {
            applications: entries.map((entry) => ({
              applicationId: entry.application.id,
              clientId: entry.application.clientId,
              name: entry.application.name,
              enabled: entry.enabled,
              roles: entry.application.roles.map((role) => ({ ...role })),
              attributeKeys: entry.application.attributeKeys.map((key) => ({ ...key })),
            })),
          },
        };
      },
    }),
    route({
      method: "get",
      path: "/tenants/{tenantId}/role-rules",
      operationId: "listRoleRules",
      summary: "Role rules: upstream group of a login method gives a role",
      tag: "Roles",
      params: tenantParams,
      query: z.object({ applicationId: z.uuid().optional() }),
      response: listOf(roleRuleSchema),
      handler: async ({ caller, params, query }) => {
        const tenant = await targetTenant(deps, caller, params.tenantId);
        const rules = await deps.repos.access.listRules(tenant.id, {
          ...(query.applicationId === undefined ? {} : { applicationId: query.applicationId }),
        });
        return { body: { items: rules.map(ruleView) } };
      },
    }),
    route({
      method: "post",
      path: "/tenants/{tenantId}/role-rules",
      operationId: "createRoleRule",
      summary: "Create a role rule",
      tag: "Roles",
      status: 201,
      params: tenantParams,
      body: strictBody({
        applicationId: z.uuid(),
        loginMethodId: z.uuid(),
        groupValue: z.string().min(1).max(512),
        role: roleNameSchema,
      }),
      response: roleRuleSchema,
      errors: ["conflict"],
      handler: async ({ caller, params, body }) => {
        const tenant = await targetTenant(deps, caller, params.tenantId);
        const rule = await inTransaction(deps, async (tx) => {
          if ((await tx.repos.loginMethods.findById(tenant.id, body.loginMethodId)) === null) {
            throw fieldError("loginMethodId", "no such login method in the tenant");
          }
          await guardPlatformAdminRole(tx, caller, tenant, body.applicationId, body.role);
          const created = await tx.repos.access.createRule(tenant.id, body);
          await tx.record({
            action: "admin.role_rule.create",
            tenantId: tenant.id,
            actor: actorOf(caller),
            subject: { type: "role_rule", id: created.id },
            details: {
              actorTenantId: caller.tenant.id,
              applicationId: created.applicationId,
              loginMethodId: created.loginMethodId,
              role: created.role,
            },
          });
          return created;
        });
        return { status: 201, body: ruleView(rule) };
      },
    }),
    route({
      method: "delete",
      path: "/tenants/{tenantId}/role-rules/{ruleId}",
      operationId: "deleteRoleRule",
      summary: "Delete a role rule",
      tag: "Roles",
      params: ruleParams,
      handler: async ({ caller, params }) => {
        const tenant = await targetTenant(deps, caller, params.tenantId);
        await inTransaction(deps, async (tx) => {
          const rule = await tx.repos.access.findRule(tenant.id, params.ruleId);
          if (rule === null || !(await tx.repos.access.deleteRule(tenant.id, rule.id))) {
            throw notFound();
          }
          await assertPlatformReachable(tx, tenant);
          await tx.record({
            action: "admin.role_rule.delete",
            tenantId: tenant.id,
            actor: actorOf(caller),
            subject: { type: "role_rule", id: rule.id },
            details: {
              actorTenantId: caller.tenant.id,
              applicationId: rule.applicationId,
              loginMethodId: rule.loginMethodId,
              role: rule.role,
            },
          });
        });
        return {};
      },
    }),
    route({
      method: "get",
      path: "/tenants/{tenantId}/role-assignments",
      operationId: "listRoleAssignments",
      summary: "Role assignments, pending ones included (unless filtered by person)",
      tag: "Roles",
      params: tenantParams,
      query: filterQuery,
      response: listOf(roleAssignmentSchema),
      handler: async ({ caller, params, query }) => {
        const tenant = await targetTenant(deps, caller, params.tenantId);
        const filter = {
          ...(query.applicationId === undefined ? {} : { applicationId: query.applicationId }),
        };
        const assignments = await deps.repos.access.listAssignments(tenant.id, {
          ...filter,
          ...(query.personId === undefined ? {} : { personId: query.personId }),
        });
        const pending =
          query.personId === undefined ? await deps.repos.pending.listRoles(tenant.id, filter) : [];
        return {
          body: {
            items: [...assignments.map(roleAssignmentView), ...pending.map(pendingRoleView)],
          },
        };
      },
    }),
    route({
      method: "post",
      path: "/tenants/{tenantId}/role-assignments",
      operationId: "createRoleAssignment",
      summary: "Assign a role to a person, or pending to someone who has not signed in yet",
      description:
        "An identity reference or personal identity number that already belongs to a person " +
        "is assigned to that person at once; otherwise the assignment is pending and resolves " +
        "at the first matching login.",
      tag: "Roles",
      status: 201,
      params: tenantParams,
      body: strictBody({ applicationId: z.uuid(), role: roleNameSchema, target: targetInput }),
      response: listOf(roleAssignmentSchema),
      errors: ["conflict"],
      handler: async ({ caller, params, body }) => {
        const tenant = await targetTenant(deps, caller, params.tenantId);
        return {
          status: 201,
          body: { items: await createRoleAssignment(deps, caller, tenant, body) },
        };
      },
    }),
    route({
      method: "delete",
      path: "/tenants/{tenantId}/role-assignments/{assignmentId}",
      operationId: "deleteRoleAssignment",
      summary: "Remove a role assignment (or a pending one)",
      tag: "Roles",
      params: assignmentParams,
      handler: async ({ caller, params }) => {
        const tenant = await targetTenant(deps, caller, params.tenantId);
        await inTransaction(deps, async (tx) => {
          const assignment = await tx.repos.access.findAssignment(tenant.id, params.assignmentId);
          if (assignment !== null) {
            await tx.repos.access.deleteAssignment(tenant.id, assignment.id);
            await assertPlatformReachable(tx, tenant);
            await tx.record({
              action: "admin.role_assignment.delete",
              tenantId: tenant.id,
              actor: actorOf(caller),
              subject: { type: "person", id: assignment.personId },
              details: {
                actorTenantId: caller.tenant.id,
                applicationId: assignment.applicationId,
                role: assignment.role,
                targetKind: "person",
                pending: false,
              },
            });
            return;
          }
          const pending = await tx.repos.pending.findRole(tenant.id, params.assignmentId);
          if (pending === null || !(await tx.repos.pending.deleteRole(tenant.id, pending.id))) {
            throw notFound();
          }
          await assertPlatformReachable(tx, tenant);
          await tx.record({
            action: "admin.role_assignment.delete",
            tenantId: tenant.id,
            actor: actorOf(caller),
            subject: { type: "pending_role_assignment", id: pending.id },
            details: {
              actorTenantId: caller.tenant.id,
              applicationId: pending.applicationId,
              role: pending.role,
              targetKind: pending.target.kind,
              pending: true,
            },
          });
        });
        return {};
      },
    }),
    route({
      method: "get",
      path: "/tenants/{tenantId}/attribute-assignments",
      operationId: "listAttributeAssignments",
      summary: "Attribute assignments, pending ones included (unless filtered by person)",
      tag: "Roles",
      params: tenantParams,
      query: filterQuery,
      response: listOf(attributeAssignmentSchema),
      handler: async ({ caller, params, query }) => {
        const tenant = await targetTenant(deps, caller, params.tenantId);
        const filter = {
          ...(query.applicationId === undefined ? {} : { applicationId: query.applicationId }),
        };
        const assignments = await deps.repos.access.listAttributes(tenant.id, {
          ...filter,
          ...(query.personId === undefined ? {} : { personId: query.personId }),
        });
        const pending =
          query.personId === undefined
            ? await deps.repos.pending.listAttributes(tenant.id, filter)
            : [];
        return {
          body: {
            items: [
              ...assignments.map(attributeAssignmentView),
              ...pending.map(pendingAttributeView),
            ],
          },
        };
      },
    }),
    route({
      method: "post",
      path: "/tenants/{tenantId}/attribute-assignments",
      operationId: "createAttributeAssignment",
      summary: "Set an attribute for a person, or pending for someone who has not signed in yet",
      tag: "Roles",
      status: 201,
      params: tenantParams,
      body: strictBody({
        applicationId: z.uuid(),
        key: attributeKeySchema,
        value: z.string().max(2000),
        target: targetInput,
      }),
      response: listOf(attributeAssignmentSchema),
      errors: ["conflict"],
      handler: async ({ caller, params, body }) => {
        const tenant = await targetTenant(deps, caller, params.tenantId);
        const items = await inTransaction(deps, async (tx) => {
          await checkTarget(tx, tenant, body.target);
          const persons = await personsOf(tx, tenant, body.target);
          const targetKind = targetKindOf(body.target);
          const result: AttributeAssignmentView[] = [];
          const changes = { value: { changed: true as const } };
          if (persons.length > 0) {
            for (const personId of persons) {
              const existing = await tx.repos.access.listAttributes(tenant.id, {
                personId,
                applicationId: body.applicationId,
              });
              if (existing.some((item) => item.key === body.key)) throw new ApiError("conflict");
              const assignment = await tx.repos.access.setAttribute(tenant.id, {
                personId,
                applicationId: body.applicationId,
                key: body.key,
                value: body.value,
              });
              result.push(attributeAssignmentView(assignment));
              await tx.record({
                action: "admin.attribute_assignment.create",
                tenantId: tenant.id,
                actor: actorOf(caller),
                subject: { type: "person", id: personId },
                details: {
                  actorTenantId: caller.tenant.id,
                  applicationId: body.applicationId,
                  key: body.key,
                  targetKind,
                  pending: false,
                  changes,
                },
              });
            }
            return result;
          }
          if ("personId" in body.target) return result;
          const pending = await tx.repos.pending.createAttribute(tenant.id, {
            applicationId: body.applicationId,
            key: body.key,
            value: body.value,
            target: body.target,
            createdBy: caller.personId,
          });
          await tx.record({
            action: "admin.attribute_assignment.create",
            tenantId: tenant.id,
            actor: actorOf(caller),
            subject: { type: "pending_attribute_assignment", id: pending.id },
            details: {
              actorTenantId: caller.tenant.id,
              applicationId: body.applicationId,
              key: body.key,
              targetKind,
              pending: true,
              changes,
            },
          });
          return [pendingAttributeView(pending)];
        });
        return { status: 201, body: { items } };
      },
    }),
    route({
      method: "patch",
      path: "/tenants/{tenantId}/attribute-assignments/{assignmentId}",
      operationId: "updateAttributeAssignment",
      summary: "Change an attribute value",
      tag: "Roles",
      ifMatch: true,
      params: assignmentParams,
      body: strictBody({ value: z.string().max(2000) }),
      response: attributeAssignmentSchema,
      handler: async ({ caller, params, body, ifMatch }) => {
        const tenant = await targetTenant(deps, caller, params.tenantId);
        const view = await inTransaction(deps, async (tx) => {
          const direct = await tx.repos.access.findAttribute(tenant.id, params.assignmentId);
          const pendingId = direct === null ? params.assignmentId : undefined;
          if (direct !== null) {
            await lockRow(tx, "attribute_assignments", "tenant_id = $1 AND id = $2", [
              tenant.id,
              direct.id,
            ]);
          } else {
            await lockRow(tx, "pending_attribute_assignments", "tenant_id = $1 AND id = $2", [
              tenant.id,
              params.assignmentId,
            ]);
          }
          const current =
            direct === null
              ? await tx.repos.pending.findAttribute(tenant.id, params.assignmentId)
              : await tx.repos.access.findAttribute(tenant.id, direct.id);
          if (current === null) throw notFound();
          const currentView =
            "personId" in current
              ? attributeAssignmentView(current)
              : pendingAttributeView(current);
          requireMatch(ifMatch, currentView.etag);
          if (current.value === body.value) return currentView;
          const updated =
            pendingId === undefined
              ? attributeAssignmentView(
                  await tx.repos.access.setAttributeValue(tenant.id, current.id, body.value),
                )
              : pendingAttributeView(
                  await tx.repos.pending.setAttributeValue(tenant.id, current.id, body.value),
                );
          await tx.record({
            action: "admin.attribute_assignment.update",
            tenantId: tenant.id,
            actor: actorOf(caller),
            subject:
              "personId" in current
                ? { type: "person", id: current.personId }
                : { type: "pending_attribute_assignment", id: current.id },
            details: {
              actorTenantId: caller.tenant.id,
              applicationId: current.applicationId,
              key: current.key,
              pending: pendingId !== undefined,
              changes: { value: { changed: true } },
            },
          });
          return updated;
        });
        return { body: view };
      },
    }),
    route({
      method: "delete",
      path: "/tenants/{tenantId}/attribute-assignments/{assignmentId}",
      operationId: "deleteAttributeAssignment",
      summary: "Remove an attribute assignment (or a pending one)",
      tag: "Roles",
      params: assignmentParams,
      handler: async ({ caller, params }) => {
        const tenant = await targetTenant(deps, caller, params.tenantId);
        await inTransaction(deps, async (tx) => {
          const direct = await tx.repos.access.findAttribute(tenant.id, params.assignmentId);
          if (direct !== null) {
            await tx.repos.access.deleteAttribute(tenant.id, direct.id);
            await tx.record({
              action: "admin.attribute_assignment.delete",
              tenantId: tenant.id,
              actor: actorOf(caller),
              subject: { type: "person", id: direct.personId },
              details: {
                actorTenantId: caller.tenant.id,
                applicationId: direct.applicationId,
                key: direct.key,
                pending: false,
              },
            });
            return;
          }
          const pending = await tx.repos.pending.findAttribute(tenant.id, params.assignmentId);
          if (
            pending === null ||
            !(await tx.repos.pending.deleteAttribute(tenant.id, pending.id))
          ) {
            throw notFound();
          }
          await tx.record({
            action: "admin.attribute_assignment.delete",
            tenantId: tenant.id,
            actor: actorOf(caller),
            subject: { type: "pending_attribute_assignment", id: pending.id },
            details: {
              actorTenantId: caller.tenant.id,
              applicationId: pending.applicationId,
              key: pending.key,
              pending: true,
            },
          });
        });
        return {};
      },
    }),
  ];
}
