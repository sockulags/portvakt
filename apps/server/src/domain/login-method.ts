import { z } from "zod";
import { samlSettingsInputSchema, samlSettingsPatchSchema, type SamlSettings } from "./saml.js";
import {
  absoluteUrlSchema,
  displayNameSchema,
  emailDomainSchema,
  positiveSecondsSchema,
} from "./schemas.js";

export const LOGIN_METHOD_KINDS = ["employee", "citizen"] as const;
export type LoginMethodKind = (typeof LOGIN_METHOD_KINDS)[number];

export const LOGIN_METHOD_PROTOCOLS = ["oidc", "saml"] as const;
export type LoginMethodProtocol = (typeof LOGIN_METHOD_PROTOCOLS)[number];

/** How Portvakt authenticates at the upstream token endpoint. */
export const UPSTREAM_AUTH_METHODS = [
  "client_secret_basic",
  "client_secret_post",
  "private_key_jwt",
] as const;
export type UpstreamAuthMethod = (typeof UPSTREAM_AUTH_METHODS)[number];

/** `aud` of private_key_jwt client assertions (Entra ID expects the token endpoint). */
export const CLIENT_ASSERTION_AUDIENCES = ["token_endpoint", "issuer"] as const;
export type ClientAssertionAudience = (typeof CLIENT_ASSERTION_AUDIENCES)[number];

/** Upstream tenant id (Entra `tid`): a GUID or similar identifier. */
const upstreamTenantSchema = z
  .string()
  .regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/, "must be an upstream tenant id");

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

/** What every login method has, whichever protocol it speaks upstream. */
interface LoginMethodBase {
  readonly id: string;
  readonly tenantId: string;
  readonly kind: LoginMethodKind;
  readonly displayName: string;
  /**
   * The acr Portvakt asserts for logins through this method. For SAML it is the lowest level a
   * login must reach; the ID token carries the requested level the IdP returned.
   */
  readonly assertedAcr: string;
  readonly homeRealmDomains: readonly string[];
  readonly secretExpiresAt: Date | null;
  readonly sessionPolicy: SessionPolicy;
  /**
   * Link identities to an existing person of the tenant by personal identity number, when another
   * login method with this flag already knows the number (citizen methods only in practice).
   */
  readonly linkByPin: boolean;
  /**
   * A login through this method may use representation grants made out to the personal identity
   * number this login asserted (grants made out to the person id need no such trust). Allowed
   * only for a method asserting at least loa3 that maps a personal identity number.
   */
  readonly trustPinForRepresentation: boolean;
  readonly enabled: boolean;
  readonly createdAt: Date;
  readonly updatedAt: Date;
}

/**
 * Upstream SAML 2.0 login method (Swedish eID Framework). Its SP entityID is
 * `{PUBLIC_URL}/t/{slug}/saml/{id}`; SP keys and the IdP metadata cache are read separately.
 */
export interface SamlLoginMethod extends LoginMethodBase {
  readonly protocol: "saml";
  readonly saml: SamlSettings;
}

/** Login method as seen by the rest of the server. Secrets and keys are never part of it. */
export type LoginMethod = OidcLoginMethod | SamlLoginMethod;

/** Upstream OIDC login method. The client secret is never part of it. */
export interface OidcLoginMethod extends LoginMethodBase {
  readonly protocol: "oidc";
  readonly issuer: string;
  readonly clientId: string;
  readonly hasClientSecret: boolean;
  /**
   * Upstream token endpoint authentication. `private_key_jwt` signs with the login method's own
   * key pair, whose public JWKS is published at `/t/{slug}/federation/{id}/jwks`.
   */
  readonly clientAuthMethod: UpstreamAuthMethod;
  /** kid of the login method's client key pair (`null` until one is generated). */
  readonly clientKeyKid: string | null;
  /** Call the upstream userinfo endpoint after the token exchange and merge its claims. */
  readonly useUserinfo: boolean;
  /** `aud` of private_key_jwt client assertions. */
  readonly clientAssertionAudience: ClientAssertionAudience;
  /**
   * For a multi-tenant issuer (Entra `/common`, `/organizations`, `/consumers` or a discovered
   * `{tenantid}` issuer): the upstream tenant ids allowed to sign in. Required there.
   */
  readonly allowedUpstreamTenants: readonly string[];
  /**
   * Map the email claim without `email_verified`: the upstream verifies addresses itself (Entra
   * ID work accounts). Email is never an identifier either way.
   */
  readonly trustUpstreamEmail: boolean;
  /**
   * The upstream accepts the personal identity number as `login_hint`: a step-up of a person
   * whose number Portvakt knows sends it, so the upstream signs in that person only. Off by
   * default (the number then never leaves Portvakt in a front-channel URL).
   */
  readonly pinLoginHint: boolean;
  readonly scopes: readonly string[];
  readonly claimMapping: ClaimMapping;
}

const scopesSchema = z
  .array(z.string().regex(/^[\x21\x23-\x5B\x5D-\x7E]+$/, "invalid scope"))
  .max(50)
  .refine((scopes) => scopes.includes("openid"), "scopes must include openid")
  .transform((scopes) => [...new Set(scopes)]);

const upstreamTenantsSchema = z
  .array(upstreamTenantSchema)
  .max(100)
  .transform((tenants) => [...new Set(tenants)]);

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
  clientAuthMethod: z.enum(UPSTREAM_AUTH_METHODS).default("client_secret_basic"),
  useUserinfo: z.boolean().default(false),
  clientAssertionAudience: z.enum(CLIENT_ASSERTION_AUDIENCES).default("token_endpoint"),
  allowedUpstreamTenants: upstreamTenantsSchema.default([]),
  trustUpstreamEmail: z.boolean().default(false),
  pinLoginHint: z.boolean().default(false),
  scopes: scopesSchema.default(["openid"]),
  claimMapping: claimMappingSchema,
  assertedAcr: z.string().min(1).max(255),
  homeRealmDomains: domainsSchema.default([]),
  secretExpiresAt: z.date().nullable().default(null),
  sessionPolicy: sessionPolicySchema,
  linkByPin: z.boolean().default(false),
  trustPinForRepresentation: z.boolean().default(false),
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
    clientAuthMethod: z.enum(UPSTREAM_AUTH_METHODS),
    useUserinfo: z.boolean(),
    clientAssertionAudience: z.enum(CLIENT_ASSERTION_AUDIENCES),
    allowedUpstreamTenants: upstreamTenantsSchema,
    trustUpstreamEmail: z.boolean(),
    pinLoginHint: z.boolean(),
    scopes: scopesSchema,
    claimMapping: claimMappingSchema,
    assertedAcr: z.string().min(1).max(255),
    homeRealmDomains: domainsSchema,
    secretExpiresAt: z.date().nullable(),
    sessionPolicy: sessionPolicySchema,
    linkByPin: z.boolean(),
    trustPinForRepresentation: z.boolean(),
    enabled: z.boolean(),
  })
  .partial();
export type UpdateLoginMethodInput = z.input<typeof updateLoginMethodInputSchema>;

/** A SAML login method (Swedish eID Framework); SP keys are generated by Portvakt. */
export const createSamlLoginMethodInputSchema = z.object({
  kind: z.enum(LOGIN_METHOD_KINDS),
  displayName: displayNameSchema,
  assertedAcr: z.string().min(1).max(255),
  homeRealmDomains: domainsSchema.default([]),
  sessionPolicy: sessionPolicySchema,
  linkByPin: z.boolean().default(false),
  trustPinForRepresentation: z.boolean().default(false),
  enabled: z.boolean().default(true),
  saml: samlSettingsInputSchema,
});
export type CreateSamlLoginMethodInput = z.input<typeof createSamlLoginMethodInputSchema>;
export type ParsedCreateSamlLoginMethod = z.output<typeof createSamlLoginMethodInputSchema>;

export const updateSamlLoginMethodInputSchema = z
  .object({
    kind: z.enum(LOGIN_METHOD_KINDS),
    displayName: displayNameSchema,
    assertedAcr: z.string().min(1).max(255),
    homeRealmDomains: domainsSchema,
    sessionPolicy: sessionPolicySchema,
    linkByPin: z.boolean(),
    trustPinForRepresentation: z.boolean(),
    enabled: z.boolean(),
    saml: samlSettingsPatchSchema,
  })
  .partial();
export type UpdateSamlLoginMethodInput = z.input<typeof updateSamlLoginMethodInputSchema>;

const MULTI_TENANT_SEGMENTS = new Set(["common", "organizations", "consumers"]);

/**
 * Whether an issuer serves many upstream tenants: Entra ID's `/common`, `/organizations` and
 * `/consumers` endpoints, or an issuer with a `{tenantid}` placeholder (as Entra ID discovery
 * returns for them). Such a login method must list its allowed upstream tenants.
 */
export function isMultiTenantIssuer(issuer: string): boolean {
  try {
    if (decodeURIComponent(issuer).toLowerCase().includes("{tenantid}")) return true;
    const segments = new URL(issuer).pathname.split("/").map((part) => part.toLowerCase());
    return segments.some((segment) => MULTI_TENANT_SEGMENTS.has(segment));
  } catch {
    return false;
  }
}

/**
 * Rules over a whole login method (create, and the merged result of an update), as messages for
 * a validation error. `acrRanking`: ACR_RANKING.
 */
export function loginMethodRuleViolations(
  method: {
    readonly issuer: string;
    readonly allowedUpstreamTenants: readonly string[];
    readonly assertedAcr: string;
    readonly claimMapping: ClaimMapping;
  },
  acrRanking: readonly string[],
): string[] {
  const issues: string[] = [];
  if (isMultiTenantIssuer(method.issuer) && method.allowedUpstreamTenants.length === 0) {
    issues.push(
      "allowedUpstreamTenants: required for a multi-tenant issuer (only the listed upstream tenants may sign in)",
    );
  }
  if (acrRanking.includes(method.assertedAcr) && method.claimMapping.acr === undefined) {
    issues.push(
      "claimMapping.acr: required when assertedAcr is a ranked level (the upstream must prove it)",
    );
  }
  return issues;
}

/** The level a method must assert to be trusted with pin-addressed representation grants. */
export const PIN_REPRESENTATION_MIN_ACR = "http://id.elegnamnden.se/loa/1.0/loa3";

/**
 * `trustPinForRepresentation` needs a method that maps a personal identity number and asserts
 * an acr ranked at least loa3 (`acrRanking`: ACR_RANKING). Returns the violation messages.
 */
export function pinTrustViolations(
  method: {
    readonly trustPinForRepresentation: boolean;
    readonly assertedAcr: string;
    readonly mapsPin: boolean;
  },
  acrRanking: readonly string[],
): string[] {
  if (!method.trustPinForRepresentation) return [];
  const issues: string[] = [];
  if (!method.mapsPin) {
    issues.push("trustPinForRepresentation: the method must map a personal identity number");
  }
  const rank = acrRanking.indexOf(method.assertedAcr);
  const minimum = acrRanking.indexOf(PIN_REPRESENTATION_MIN_ACR);
  if (minimum < 0 || rank < minimum) {
    issues.push("trustPinForRepresentation: the method must assert at least loa3");
  }
  return issues;
}

/** Extracts the lowercased domain of an email address, or undefined if it is not one. */
export function emailDomain(email: string): string | undefined {
  const at = email.lastIndexOf("@");
  if (at <= 0 || at === email.length - 1) return undefined;
  const parsed = emailDomainSchema.safeParse(email.slice(at + 1));
  return parsed.success ? parsed.data : undefined;
}
