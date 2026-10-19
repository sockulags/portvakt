import { z } from "zod";
import { personnummerSchema } from "./personnummer.js";
import { attributeKeySchema, roleNameSchema } from "./schemas.js";

export interface RoleAssignment {
  readonly id: string;
  readonly tenantId: string;
  readonly personId: string;
  readonly applicationId: string;
  readonly role: string;
  readonly createdAt: Date;
}

export interface RoleRule {
  readonly id: string;
  readonly tenantId: string;
  readonly applicationId: string;
  /** Group values are only meaningful per upstream IdP, so every rule names its login method. */
  readonly loginMethodId: string;
  readonly groupValue: string;
  readonly role: string;
  readonly createdAt: Date;
}

export interface AttributeAssignment {
  readonly id: string;
  readonly tenantId: string;
  readonly personId: string;
  readonly applicationId: string;
  readonly key: string;
  readonly value: string;
  readonly createdAt: Date;
  readonly updatedAt: Date;
}

/** Roles and attributes for one application, as they go into `roles` and `attrs` claims. */
export interface EffectiveAccess {
  readonly roles: readonly string[];
  readonly attributes: Readonly<Record<string, string>>;
}

export const assignRoleInputSchema = z.object({
  personId: z.uuid(),
  applicationId: z.uuid(),
  role: roleNameSchema,
});
export type AssignRoleInput = z.input<typeof assignRoleInputSchema>;

export const createRoleRuleInputSchema = z.object({
  applicationId: z.uuid(),
  loginMethodId: z.uuid(),
  groupValue: z.string().min(1).max(512),
  role: roleNameSchema,
});
export type CreateRoleRuleInput = z.input<typeof createRoleRuleInputSchema>;

export const setAttributeInputSchema = z.object({
  personId: z.uuid(),
  applicationId: z.uuid(),
  key: attributeKeySchema,
  value: z.string().max(2000),
});
export type SetAttributeInput = z.input<typeof setAttributeInputSchema>;

export const effectiveAccessQuerySchema = z.object({
  personId: z.uuid(),
  applicationId: z.uuid(),
  loginMethodId: z.uuid(),
  groups: z.array(z.string()).max(1000),
});
export type EffectiveAccessQuery = z.input<typeof effectiveAccessQuerySchema>;

/**
 * Who a pending assignment is for, before that person has signed in: an identity reference
 * (login method and upstream subject) or a personal identity number. As stored and returned, a
 * pin target never carries the number.
 */
export type PendingTarget =
  | { readonly kind: "identity"; readonly loginMethodId: string; readonly subject: string }
  | { readonly kind: "pin" };

/** A role assignment for someone who has not signed in yet; resolved at their login. */
export interface PendingRoleAssignment {
  readonly id: string;
  readonly tenantId: string;
  readonly applicationId: string;
  readonly role: string;
  readonly target: PendingTarget;
  readonly createdBy: string | null;
  readonly createdAt: Date;
}

/** An attribute assignment for someone who has not signed in yet; resolved at their login. */
export interface PendingAttributeAssignment {
  readonly id: string;
  readonly tenantId: string;
  readonly applicationId: string;
  readonly key: string;
  readonly value: string;
  readonly target: PendingTarget;
  readonly createdBy: string | null;
  readonly createdAt: Date;
  readonly updatedAt: Date;
}

/** Target of a pending assignment as given on create. */
export const pendingTargetInputSchema = z.union([
  z
    .object({
      loginMethodId: z.uuid(),
      subject: z.string().trim().min(1).max(255),
    })
    .strict(),
  z.object({ pin: personnummerSchema }).strict(),
]);
export type PendingTargetInput = z.input<typeof pendingTargetInputSchema>;

export const createPendingRoleInputSchema = z.object({
  applicationId: z.uuid(),
  role: roleNameSchema,
  target: pendingTargetInputSchema,
  createdBy: z.uuid().nullable().default(null),
});
export type CreatePendingRoleInput = z.input<typeof createPendingRoleInputSchema>;

export const createPendingAttributeInputSchema = z.object({
  applicationId: z.uuid(),
  key: attributeKeySchema,
  value: z.string().max(2000),
  target: pendingTargetInputSchema,
  createdBy: z.uuid().nullable().default(null),
});
export type CreatePendingAttributeInput = z.input<typeof createPendingAttributeInputSchema>;

/** A pending assignment that a login turned into an assignment of the person (audit: ids only). */
export interface ResolvedPendingAssignment {
  readonly pendingId: string;
  readonly kind: "role" | "attribute";
  readonly applicationId: string;
  /** The role (role assignments) or the attribute key (attribute assignments). */
  readonly name: string;
  readonly targetKind: PendingTarget["kind"];
}
