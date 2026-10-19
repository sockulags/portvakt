import { z } from "zod";

/**
 * Default assurance level ordering, lowest first: the Swedish eID Framework levels, the same
 * default as Portvakt's `ACR_RANKING`. Pass the tenant's ranking if Portvakt is configured with
 * another one.
 */
export const DEFAULT_ACR_RANKING: readonly string[] = Object.freeze([
  "http://id.elegnamnden.se/loa/1.0/loa2",
  "http://id.elegnamnden.se/loa/1.0/loa3",
  "http://id.elegnamnden.se/loa/1.0/loa4",
]);

export type IdpKind = "employee" | "citizen";

/**
 * The party a person acts for (representation, ombud). `name` is only known in BFF sessions
 * (from the ID token) and never for a person party with a protected identity. Applications must
 * authorise every action on behalf of `rep.sub` with their own rules: Portvakt only attests that
 * the signed-in person holds a representation right for the party in this application.
 */
export interface Representation {
  readonly sub: string;
  readonly type: "person" | "organisation";
  readonly name?: string;
}

/** A signed-in person (BFF session or person access token). */
export interface PersonPrincipal {
  readonly isService: false;
  /** The signed-in person's UUID, also when representing someone. */
  readonly sub: string;
  /** Tenant slug (`tid`). */
  readonly tenant: string;
  /** Id of the login method used (`idp`). */
  readonly idp: string;
  readonly idpKind: IdpKind;
  readonly acr: string;
  /** Epoch seconds of the authentication (`auth_time`). */
  readonly authTime: number;
  /** The person's roles in this application. Never the represented party's. */
  readonly roles: readonly string[];
  readonly attrs: Readonly<Record<string, string>>;
  /** Present only when acting for a party. */
  readonly rep?: Representation;
  /** The application the token was issued to. */
  readonly clientId?: string;
  /** ID token only (BFF sessions), with scope `profile`; never for a protected identity. */
  readonly name?: string;
  /** ID token only, with scope `email`; never an identifier, never for a protected identity. */
  readonly email?: string;
  /** ID token only, with scope `pin` when the application is allowed it. */
  readonly pin?: string;
  /** ID token only, with scope `hsa` when the application is allowed it. */
  readonly hsaId?: string;
  readonly orgAffiliation?: readonly string[];
  /**
   * `true` for a person with a protected identity (skyddad identitet): applications must
   * minimise what they display and store about the person.
   */
  readonly protectedIdentity?: boolean;
}

/** An application calling with a client_credentials token. */
export interface ServicePrincipal {
  readonly isService: true;
  /** The calling application's client_id (oidc-provider sets `sub` to it). */
  readonly sub: string;
  readonly tenant: string;
  readonly clientId: string;
  readonly roles: readonly string[];
  readonly attrs: Readonly<Record<string, string>>;
}

export type Principal = PersonPrincipal | ServicePrincipal;

/** Whether the principal has the role in this application. Service principals have none. */
export function hasRole(principal: Principal | undefined, role: string): boolean {
  return principal?.roles.includes(role) === true;
}

/**
 * Whether an acr (or a person principal's acr) meets `required`, with Portvakt's semantics:
 * equal values always match; otherwise both must be in `ranking` and the acr must rank at
 * least as high. Values outside the ranking only ever match themselves. A service principal
 * never meets an acr.
 */
export function acrAtLeast(
  acrOrPrincipal: string | Principal | undefined,
  required: string,
  ranking: readonly string[] = DEFAULT_ACR_RANKING,
): boolean {
  if (acrOrPrincipal === undefined) return false;
  let acr: string;
  if (typeof acrOrPrincipal === "string") acr = acrOrPrincipal;
  else if (acrOrPrincipal.isService) return false;
  else acr = acrOrPrincipal.acr;
  if (acr === required) return true;
  const have = ranking.indexOf(acr);
  const need = ranking.indexOf(required);
  return have >= 0 && need >= 0 && have >= need;
}

const shortString = z.string().min(1).max(512);
const rolesSchema = z.array(z.string().max(255)).max(1000);
const attrsSchema = z.record(z.string().max(255), z.string().max(4000));

const repClaimSchema = z.object({
  sub: shortString,
  type: z.enum(["person", "organisation"]),
  name: z.string().max(1000).optional(),
});

const personCoreSchema = {
  sub: shortString,
  tid: shortString,
  idp: shortString,
  idp_kind: z.enum(["employee", "citizen"]),
  acr: shortString,
  auth_time: z.number().int().nonnegative(),
  roles: rolesSchema.default([]),
  attrs: attrsSchema.default({}),
  rep: repClaimSchema.optional(),
};

/** ID token claims of the claims contract v1 (docs/claims.md). Unknown claims are ignored. */
export const idTokenClaimsSchema = z.object({
  ...personCoreSchema,
  aud: z.union([shortString, z.array(shortString)]),
  session_exp: z.number().int().positive().optional(),
  name: z.string().max(1000).optional(),
  email: z.string().max(1000).optional(),
  pin: z.string().max(32).optional(),
  hsa_id: z.string().max(255).optional(),
  org_affiliation: z.array(z.string().max(512)).max(100).optional(),
  protected_identity: z.literal(true).optional(),
});
export type IdTokenClaims = z.infer<typeof idTokenClaimsSchema>;

/** A person's access token: minimal claims only (never name, email or pin; rep without name). */
export const personAccessTokenClaimsSchema = z.object({
  ...personCoreSchema,
  client_id: shortString,
  rep: repClaimSchema.omit({ name: true }).optional(),
});

/** A client_credentials token: `sub` is the calling client, no person claims at all. */
export const serviceAccessTokenClaimsSchema = z.object({
  sub: shortString,
  client_id: shortString,
  tid: shortString,
});

const without = <T extends object>(value: T): T =>
  Object.fromEntries(Object.entries(value).filter(([, item]) => item !== undefined)) as T;

/** The principal of a BFF session, from its validated ID token claims. */
export function principalFromIdToken(claims: IdTokenClaims): PersonPrincipal {
  const audience = Array.isArray(claims.aud) ? claims.aud[0] : claims.aud;
  const protectedIdentity = claims.protected_identity === true;
  return without({
    isService: false as const,
    sub: claims.sub,
    tenant: claims.tid,
    idp: claims.idp,
    idpKind: claims.idp_kind,
    acr: claims.acr,
    authTime: claims.auth_time,
    roles: [...claims.roles],
    attrs: { ...claims.attrs },
    rep:
      claims.rep === undefined
        ? undefined
        : without({ sub: claims.rep.sub, type: claims.rep.type, name: claims.rep.name }),
    clientId: audience,
    // Portvakt never issues name or email for a protected identity; never keep them anyway.
    name: protectedIdentity ? undefined : claims.name,
    email: protectedIdentity ? undefined : claims.email,
    pin: claims.pin,
    hsaId: claims.hsa_id,
    orgAffiliation: claims.org_affiliation === undefined ? undefined : [...claims.org_affiliation],
    protectedIdentity: protectedIdentity ? true : undefined,
  });
}

/**
 * Person or service token, by the claims Portvakt issues: person tokens always carry the login
 * claims (`idp`, `idp_kind`, `acr`, `auth_time`, `roles`, `attrs`) and their `sub` is the
 * person's UUID; client_credentials tokens carry none of them and oidc-provider sets their `sub`
 * to the calling client_id. Anything else is refused.
 */
export function principalFromAccessToken(payload: Record<string, unknown>): Principal | null {
  const loginClaims = ["idp", "idp_kind", "acr", "auth_time", "roles", "attrs", "rep"];
  const hasLoginClaims = loginClaims.some((claim) => payload[claim] !== undefined);
  if (!hasLoginClaims) {
    const service = serviceAccessTokenClaimsSchema.safeParse(payload);
    if (!service.success || service.data.sub !== service.data.client_id) return null;
    return {
      isService: true,
      sub: service.data.sub,
      tenant: service.data.tid,
      clientId: service.data.client_id,
      roles: [],
      attrs: {},
    };
  }
  const person = personAccessTokenClaimsSchema.safeParse(payload);
  if (!person.success || person.data.sub === person.data.client_id) return null;
  if (!Array.isArray(payload.roles) || typeof payload.attrs !== "object") return null;
  const claims = person.data;
  return without({
    isService: false as const,
    sub: claims.sub,
    tenant: claims.tid,
    idp: claims.idp,
    idpKind: claims.idp_kind,
    acr: claims.acr,
    authTime: claims.auth_time,
    roles: [...claims.roles],
    attrs: { ...claims.attrs },
    rep: claims.rep === undefined ? undefined : { sub: claims.rep.sub, type: claims.rep.type },
    clientId: claims.client_id,
  });
}
