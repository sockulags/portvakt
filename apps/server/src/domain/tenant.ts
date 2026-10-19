import { z } from "zod";
import { REPRESENTATION_SOURCE_IDS, type RepresentationSourceId } from "./representation.js";
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
  /** Representation sources the tenant uses, in order (v1: the internal register). */
  readonly representationSources: readonly RepresentationSourceId[];
  readonly createdAt: Date;
  readonly updatedAt: Date;
}

const representationSourcesSchema = z
  .array(z.enum(REPRESENTATION_SOURCE_IDS))
  .max(REPRESENTATION_SOURCE_IDS.length)
  .transform((sources) => [...new Set(sources)]);

export const createTenantInputSchema = z.object({
  slug: tenantSlugSchema,
  name: displayNameSchema,
  status: z.enum(TENANT_STATUSES).default("active"),
  representationSources: representationSourcesSchema.default(["internal"]),
});
export type CreateTenantInput = z.input<typeof createTenantInputSchema>;

export const updateTenantInputSchema = z
  .object({
    name: displayNameSchema,
    status: z.enum(TENANT_STATUSES),
    representationSources: representationSourcesSchema,
  })
  .partial();
export type UpdateTenantInput = z.input<typeof updateTenantInputSchema>;
