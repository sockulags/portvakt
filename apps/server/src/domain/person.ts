import { z } from "zod";
import { personnummerSchema } from "./personnummer.js";

/**
 * Latest attributes mapped from the upstream IdP at login. Personal data: never log these.
 * Stored as JSON on the identity and validated on every read and write. The personal identity
 * number is not part of it: it is stored encrypted, with a blind index, in its own columns.
 * For a protected identity, name and email are never stored.
 */
export const identityAttributesSchema = z
  .object({
    name: z.string().max(500).optional(),
    email: z.string().max(320).optional(),
    groups: z.array(z.string().min(1).max(512)).max(1000).default([]),
    protectedIdentity: z.boolean().default(false),
    upstreamAcr: z.string().max(255).optional(),
  })
  .strict();
export type IdentityAttributes = z.output<typeof identityAttributesSchema>;
export type IdentityAttributesInput = z.input<typeof identityAttributesSchema>;

export interface Person {
  readonly id: string;
  readonly tenantId: string;
  readonly createdAt: Date;
  readonly updatedAt: Date;
  readonly lastLoginAt: Date | null;
}

export interface Identity {
  readonly id: string;
  readonly tenantId: string;
  readonly personId: string;
  readonly loginMethodId: string;
  readonly subject: string;
  readonly attributes: IdentityAttributes;
  /** Blind index of the personal identity number, `null` when upstream sent none. */
  readonly pinIndex: string | null;
  readonly createdAt: Date;
  readonly updatedAt: Date;
  readonly lastLoginAt: Date;
}

export const jitLoginInputSchema = z.object({
  loginMethodId: z.uuid(),
  subject: z.string().min(1).max(255),
  /** The acr this login was asserted with (the login method's acr when the upstream met it). */
  acr: z.string().min(1).max(255),
  attributes: identityAttributesSchema,
  /** Personal identity number as sent upstream, in any accepted format. */
  pin: personnummerSchema.optional(),
});
export type JitLoginInput = z.input<typeof jitLoginInputSchema>;

export interface JitLoginResult {
  readonly person: Person;
  readonly identity: Identity;
  /** True when this login created the person (first login, not linked). */
  readonly created: boolean;
  /** True when this first login linked the identity to an existing person by pin. */
  readonly linked: boolean;
}
