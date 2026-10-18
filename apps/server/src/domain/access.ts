import { z } from "zod";
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
