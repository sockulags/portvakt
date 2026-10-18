import { z } from "zod";
import { organisationsnummerSchema, personnummerSchema } from "./personnummer.js";
import { displayNameSchema } from "./schemas.js";

export const PARTY_TYPES = ["person", "organisation"] as const;
export type PartyType = (typeof PARTY_TYPES)[number];

/** Someone an agent can act for: a person or an organisation. */
export interface Party {
  readonly id: string;
  readonly tenantId: string;
  readonly type: PartyType;
  /**
   * Canonical personnummer (12 digits) or organisationsnummer (10 digits), decrypted.
   * Personal data: never log.
   */
  readonly identifier: string;
  readonly displayName: string;
  readonly createdAt: Date;
  readonly updatedAt: Date;
}

/** Who may use a grant: a known person, or a personal identity number before first sign-in. */
export type GrantAgent =
  | { readonly type: "person"; readonly personId: string }
  | { readonly type: "pin"; readonly pinIndex: string };

export interface RepresentationGrant {
  readonly id: string;
  readonly tenantId: string;
  readonly agent: GrantAgent;
  readonly party: Party;
  /** `true`: valid for every application of the tenant. */
  readonly allApplications: boolean;
  /** Applications the grant is limited to when `allApplications` is false. */
  readonly applicationIds: readonly string[];
  readonly validFrom: Date;
  readonly validTo: Date | null;
  readonly revokedAt: Date | null;
  readonly revokedBy: string | null;
  readonly createdBy: string | null;
  readonly createdAt: Date;
}

export const createPartyInputSchema = z
  .object({
    type: z.enum(PARTY_TYPES),
    identifier: z.string().trim().min(1).max(100),
    displayName: displayNameSchema,
  })
  .transform((party, ctx) => {
    const schema = party.type === "person" ? personnummerSchema : organisationsnummerSchema;
    const identifier = schema.safeParse(party.identifier);
    if (!identifier.success) {
      ctx.addIssue({
        code: "custom",
        path: ["identifier"],
        message:
          party.type === "person"
            ? "must be a valid personnummer or samordningsnummer"
            : "must be a valid organisationsnummer",
      });
      return z.NEVER;
    }
    return { ...party, identifier: identifier.data };
  });
export type CreatePartyInput = z.input<typeof createPartyInputSchema>;

const grantAgentInputSchema = z.union([
  z.object({ personId: z.uuid() }).strict(),
  z.object({ pin: personnummerSchema }).strict(),
]);

export const createGrantInputSchema = z
  .object({
    /** A known person, or the personal identity number of someone who has not signed in yet. */
    agent: grantAgentInputSchema,
    partyId: z.uuid(),
    /** `true`, or a non-empty list of applications in `applicationIds`; never both. */
    allApplications: z.boolean(),
    applicationIds: z
      .array(z.uuid())
      .max(100)
      .default([])
      .transform((ids) => [...new Set(ids)]),
    validFrom: z.date().optional(),
    validTo: z.date().nullable().default(null),
    createdBy: z.uuid().nullable().default(null),
  })
  .refine((grant) => grant.allApplications === (grant.applicationIds.length === 0), {
    message: "set allApplications, or list at least one application, but not both",
    path: ["applicationIds"],
  })
  .refine(
    (grant) =>
      grant.validTo === null || grant.validTo.getTime() > (grant.validFrom ?? new Date()).getTime(),
    { message: "validTo must be after validFrom", path: ["validTo"] },
  );
export type CreateGrantInput = z.input<typeof createGrantInputSchema>;
