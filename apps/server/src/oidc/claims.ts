import type { Application } from "../domain/application.js";
import type { Identity, Person } from "../domain/person.js";
import type { Tenant } from "../domain/tenant.js";
import type { Repositories } from "../repositories/index.js";
import type { LoginContext } from "./login-context.js";

/**
 * Claims contract v1 (docs/claims.md, docs/plan.md "Claims contract (v1)"), built per token
 * from contributors:
 *
 * | Claim                 | ID token                       | Access token |
 * | --------------------- | ------------------------------ | ------------ |
 * | `tid`                 | yes                            | yes          |
 * | `idp`, `idp_kind`     | yes                            | yes          |
 * | `acr`, `auth_time`    | yes (from the login itself)    | yes          |
 * | `amr`                 | yes (from the login itself)    | never        |
 * | `roles`, `attrs`      | yes, for the audience app only | yes, same    |
 * | `session_exp`         | yes                            | never        |
 * | `name`, `email`       | with `profile` / `email`       | never        |
 * | `pin`                 | with `pin`, if the app may     | never        |
 * | `hsa_id`, `org_affiliation` | with `hsa`, if the app may | never        |
 * | `protected_identity`  | `true` for a protected person  | never        |
 * | `rep`                 | `{ sub, type, name }`          | `{ sub, type }` |
 *
 * `sub` is always the signed-in person (also when representing) and is set by oidc-provider
 * from the account id (the person UUID). `rep` is the party the grant's login acts for, only
 * for an application whose representation mode is not `none`; its `name` is ID token only and
 * never issued for a person party with a protected identity. In ID tokens oidc-provider sets
 * `acr`, `amr` and `auth_time` from the grant's login; for access tokens the contributors below
 * add `acr` and `auth_time`.
 *
 * Every ID token claim must also be listed under a scope in {@link CLAIMS_BY_SCOPE}, or
 * oidc-provider filters it out.
 */
export const CLAIMS_BY_SCOPE = {
  openid: [
    "sub",
    "tid",
    "idp",
    "idp_kind",
    "acr",
    "amr",
    "auth_time",
    "session_exp",
    "roles",
    "attrs",
    "protected_identity",
    "rep",
  ],
  profile: ["name"],
  email: ["email"],
  pin: ["pin"],
  hsa: ["hsa_id", "org_affiliation"],
} as const;

export type ClaimsTarget = "id_token" | "userinfo" | "access_token";

export interface ClaimsRequest {
  readonly tenant: Tenant;
  readonly personId: string;
  /** The login of the token's grant. */
  readonly login: LoginContext;
  /** client_id of the application the token is for (ID token `aud`, access token `aud`). */
  readonly audienceClientId: string;
  readonly scopes: ReadonlySet<string>;
  readonly target: ClaimsTarget;
}

export type Claims = Record<string, unknown>;

interface ClaimSources {
  /** The person (protected identity is sticky on the person). */
  readonly person: Person | null;
  /** The identity of the login method used, with the latest upstream attributes. */
  readonly identity: Identity | undefined;
  /** The audience application, if it is (still) enabled in the tenant. */
  readonly audience: Application | null;
}

type ClaimContributor = (
  request: ClaimsRequest,
  sources: ClaimSources,
  repos: Repositories,
) => Promise<Claims> | Claims;

const userInformation = (request: ClaimsRequest): boolean => request.target !== "access_token";

const tenantClaims: ClaimContributor = (request) => ({ tid: request.tenant.slug });

/** How the person signed in: login method, its kind, and (access tokens) acr and auth_time. */
const loginClaims: ClaimContributor = ({ login, target }) => ({
  idp: login.loginMethodId,
  idp_kind: login.loginMethodKind,
  ...(target === "access_token"
    ? { acr: login.acr, auth_time: login.authTime }
    : { session_exp: login.sessionExpiresAt }),
});

/** Roles and attributes for the audience application only: direct assignments and rules. */
const accessClaims: ClaimContributor = async (request, sources, repos) => {
  if (sources.audience === null) return { roles: [], attrs: {} };
  const access = await repos.access.effectiveAccess(request.tenant.id, {
    personId: request.personId,
    applicationId: sources.audience.id,
    loginMethodId: request.login.loginMethodId,
    groups: [...(sources.identity?.attributes.groups ?? [])],
  });
  return { roles: [...access.roles], attrs: { ...access.attributes } };
};

/**
 * Name and email are user information: ID token only, never in access tokens. A protected
 * person never gets them, whichever login method was used (none is stored either).
 */
const profileClaims: ClaimContributor = (request, sources) => {
  if (!userInformation(request) || sources.identity === undefined) return {};
  if (sources.person?.protectedIdentity !== false) return {};
  const { name, email } = sources.identity.attributes;
  return {
    ...(request.scopes.has("profile") && name !== undefined ? { name } : {}),
    ...(request.scopes.has("email") && email !== undefined ? { email } : {}),
  };
};

/**
 * The personal identity number: ID token only, with scope `pin`, and only for an application
 * allowed to request it (oidc-provider already drops the scope for other applications; this is
 * the second check).
 */
const pinClaims: ClaimContributor = async (request, sources, repos) => {
  if (request.target !== "id_token" || !request.scopes.has("pin")) return {};
  if (sources.identity === undefined || sources.identity.pinIndex === null) return {};
  if (sources.audience?.allowedExtraScopes.includes("pin") !== true) return {};
  const pin = await repos.persons.getPin(request.tenant.id, sources.identity.id);
  return pin === null ? {} : { pin };
};

/**
 * SITHS identifiers (ID token only, scope `hsa`, only for an application allowed it):
 * `hsa_id` (employeeHsaId) and `org_affiliation` (the scope-checked orgAffiliation values).
 */
const hsaClaims: ClaimContributor = (request, sources) => {
  if (request.target !== "id_token" || !request.scopes.has("hsa")) return {};
  if (sources.identity === undefined) return {};
  if (sources.audience?.allowedExtraScopes.includes("hsa") !== true) return {};
  const { hsaId, orgAffiliation } = sources.identity.attributes;
  return {
    ...(hsaId === undefined ? {} : { hsa_id: hsaId }),
    ...(orgAffiliation === undefined ? {} : { org_affiliation: [...orgAffiliation] }),
  };
};

/**
 * `rep`: the party this grant acts for (chosen in the representation chooser), when the
 * audience application offers representation. Access tokens carry `{ sub, type }` only (data
 * minimisation); ID tokens add `name`, except for a person party with a protected identity.
 * The right itself is re-checked at every refresh and re-authorization (provider.ts).
 */
const representationClaims: ClaimContributor = async (request, sources, repos) => {
  const choice = request.login.representation;
  if (choice?.type !== "party") return {};
  if (sources.audience === null || sources.audience.representationMode === "none") return {};
  const party = await repos.parties.findById(request.tenant.id, choice.partyId);
  if (party === null) return {};
  const rep: Claims = { sub: party.id, type: party.type };
  if (userInformation(request)) {
    const hidden =
      party.protectedIdentity ||
      (party.type === "person" &&
        (await repos.persons.isProtectedByPin(request.tenant.id, party.identifier)));
    if (!hidden) rep.name = party.displayName;
  }
  return { rep };
};

/** `protected_identity: true` (ID token only) when the person is protected. */
const protectedIdentityClaims: ClaimContributor = (request, sources) =>
  userInformation(request) && sources.person?.protectedIdentity === true
    ? { protected_identity: true }
    : {};

const CONTRIBUTORS: readonly ClaimContributor[] = [
  tenantClaims,
  loginClaims,
  accessClaims,
  profileClaims,
  pinClaims,
  hsaClaims,
  protectedIdentityClaims,
  representationClaims,
];

export class ClaimsService {
  readonly #repos: Repositories;

  constructor(repos: Repositories) {
    this.#repos = repos;
  }

  async claimsFor(request: ClaimsRequest): Promise<Claims> {
    const [person, identities, audience] = await Promise.all([
      this.#repos.persons.findById(request.tenant.id, request.personId),
      this.#repos.persons.listIdentities(request.tenant.id, request.personId),
      this.#repos.applications.findEnabledByClientId(request.tenant.id, request.audienceClientId),
    ]);
    const sources: ClaimSources = {
      person,
      identity: identities.find(
        (identity) => identity.loginMethodId === request.login.loginMethodId,
      ),
      audience,
    };
    const parts = await Promise.all(
      CONTRIBUTORS.map(async (contributor) => contributor(request, sources, this.#repos)),
    );
    return Object.assign({}, ...parts) as Claims;
  }
}
