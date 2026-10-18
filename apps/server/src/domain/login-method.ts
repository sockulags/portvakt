import { z } from "zod";
import {
  absoluteUrlSchema,
  displayNameSchema,
  emailDomainSchema,
  positiveSecondsSchema,
} from "./schemas.js";

export const LOGIN_METHOD_KINDS = ["employee", "citizen"] as const;
export type LoginMethodKind = (typeof LOGIN_METHOD_KINDS)[number];

/** Upstream claim name, optionally a dotted path into a nested claim (`realm_access.roles`). */
const claimNameSchema = z
  .string()
  .min(1)
  .max(255)
  .regex(/^[A-Za-z0-9_:/-]+(?:\.[A-Za-z0-9_:/-]+)*$/, "must be a claim name or dotted path");

/**
 * Which upstream ID token / userinfo claims feed which Portvakt attribute. Stored as JSON and
 * validated on every read and write.
 */
export const claimMappingSchema = z
  .object({
    subject: claimNameSchema.default("sub"),
    name: claimNameSchema.optional(),
    email: claimNameSchema.optional(),
    pin: claimNameSchema.optional(),
    groups: claimNameSchema.optional(),
    acr: claimNameSchema.optional(),
    protectedIdentity: claimNameSchema.optional(),
  })
  .strict();
export type ClaimMapping = z.output<typeof claimMappingSchema>;

export interface SessionPolicy {
  readonly maxAgeSeconds: number;
  readonly idleSeconds: number;
  readonly allowSso: boolean;
}

export const sessionPolicySchema = z
  .object({
    maxAgeSeconds: positiveSecondsSchema,
    idleSeconds: positiveSecondsSchema,
    allowSso: z.boolean(),
  })
  .refine((policy) => policy.idleSeconds <= policy.maxAgeSeconds, {
    message: "idleSeconds must not exceed maxAgeSeconds",
    path: ["idleSeconds"],
  });

/** Login method as seen by the rest of the server. The client secret is never part of it. */
export interface LoginMethod {
  readonly id: string;
  readonly tenantId: string;
  readonly kind: LoginMethodKind;
  readonly displayName: string;
  readonly issuer: string;
  readonly clientId: string;
  readonly hasClientSecret: boolean;
  readonly scopes: readonly string[];
  readonly claimMapping: ClaimMapping;
  readonly assertedAcr: string;
  readonly homeRealmDomains: readonly string[];
  readonly secretExpiresAt: Date | null;
  readonly sessionPolicy: SessionPolicy;
  /**
   * Link identities to an existing person of the tenant by personal identity number, when another
   * login method with this flag already knows the number (citizen methods only in practice).
   */
  readonly linkByPin: boolean;
  readonly enabled: boolean;
  readonly createdAt: Date;
  readonly updatedAt: Date;
}

const scopesSchema = z
  .array(z.string().regex(/^[\x21\x23-\x5B\x5D-\x7E]+$/, "invalid scope"))
  .max(50)
  .refine((scopes) => scopes.includes("openid"), "scopes must include openid")
  .transform((scopes) => [...new Set(scopes)]);

const domainsSchema = z
  .array(emailDomainSchema)
  .max(100)
  .transform((domains) => [...new Set(domains)].sort());

export const createLoginMethodInputSchema = z.object({
  kind: z.enum(LOGIN_METHOD_KINDS),
  displayName: displayNameSchema,
  issuer: absoluteUrlSchema,
  clientId: z.string().min(1).max(512),
  /** Plaintext upstream client secret; stored encrypted, never returned. */
  clientSecret: z.string().min(1).max(4096).optional(),
  scopes: scopesSchema.default(["openid"]),
  claimMapping: claimMappingSchema,
  assertedAcr: z.string().min(1).max(255),
  homeRealmDomains: domainsSchema.default([]),
  secretExpiresAt: z.date().nullable().default(null),
  sessionPolicy: sessionPolicySchema,
  linkByPin: z.boolean().default(false),
  enabled: z.boolean().default(true),
});
export type CreateLoginMethodInput = z.input<typeof createLoginMethodInputSchema>;

export const updateLoginMethodInputSchema = z
  .object({
    kind: z.enum(LOGIN_METHOD_KINDS),
    displayName: displayNameSchema,
    issuer: absoluteUrlSchema,
    clientId: z.string().min(1).max(512),
    /** `null` removes the secret. */
    clientSecret: z.string().min(1).max(4096).nullable(),
    scopes: scopesSchema,
    claimMapping: claimMappingSchema,
    assertedAcr: z.string().min(1).max(255),
    homeRealmDomains: domainsSchema,
    secretExpiresAt: z.date().nullable(),
    sessionPolicy: sessionPolicySchema,
    linkByPin: z.boolean(),
    enabled: z.boolean(),
  })
  .partial();
export type UpdateLoginMethodInput = z.input<typeof updateLoginMethodInputSchema>;

/** Extracts the lowercased domain of an email address, or undefined if it is not one. */
export function emailDomain(email: string): string | undefined {
  const at = email.lastIndexOf("@");
  if (at <= 0 || at === email.length - 1) return undefined;
  const parsed = emailDomainSchema.safeParse(email.slice(at + 1));
  return parsed.success ? parsed.data : undefined;
}
