import { z } from "zod";
import { displayNameSchema, tenantSlugSchema } from "./schemas.js";

export const TENANT_STATUSES = ["active", "suspended"] as const;
export type TenantStatus = (typeof TENANT_STATUSES)[number];

/** Slug of the tenant that hosts platform administration. */
export const SYSTEM_TENANT_SLUG = "system";

export interface Tenant {
  readonly id: string;
  readonly slug: string;
  readonly name: string;
  readonly status: TenantStatus;
  readonly createdAt: Date;
  readonly updatedAt: Date;
}

export const createTenantInputSchema = z.object({
  slug: tenantSlugSchema,
  name: displayNameSchema,
  status: z.enum(TENANT_STATUSES).default("active"),
});
export type CreateTenantInput = z.input<typeof createTenantInputSchema>;

export const updateTenantInputSchema = z
  .object({ name: displayNameSchema, status: z.enum(TENANT_STATUSES) })
  .partial();
export type UpdateTenantInput = z.input<typeof updateTenantInputSchema>;
