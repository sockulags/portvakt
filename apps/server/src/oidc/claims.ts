import type { Application } from "../domain/application.js";
import type { Identity } from "../domain/person.js";
import type { Tenant } from "../domain/tenant.js";
import type { Repositories } from "../repositories/index.js";
import type { LoginContext } from "./login-context.js";

/**
 * Claims contract (docs/plan.md, "Claims contract (v1)"), built per token from contributors.
 * M2 emits `tid`, `roles` and `attrs` (for the audience application only) and `name` / `email`
 * with the `profile` / `email` scopes. M3 adds contributors for `idp`, `idp_kind`, `acr`,
 * `session_exp` and `protected_identity`; M4 for `rep` and `pin`. `sub` is always the signed-in
 * person (also when representing: the represented party is `rep.sub`) and is set by
 * oidc-provider from the account id (the person UUID).
 *
 * Every claim listed here must also be listed under a scope in the provider's `claims`
 * configuration, or oidc-provider filters it out of ID tokens. `acr` and `amr` come from the
 * login itself (oidc-provider copies them from the session): oidc-provider only emits `acr` once
 * `acrValues` lists the values, and `amr` once it is declared, which M3 configures from the
 * tenant's login methods.
 */
export const CLAIMS_BY_SCOPE = {
  openid: ["sub", "tid", "roles", "attrs"],
  profile: ["name"],
  email: ["email"],
} as const;

export type ClaimsTarget = "id_token" | "userinfo" | "access_token";

export interface ClaimsRequest {
  readonly tenant: Tenant;
  readonly personId: string;
  readonly login: LoginContext;
  /** client_id of the application the token is for (ID token `aud`, access token `aud`). */
  readonly audienceClientId: string;
  readonly scopes: ReadonlySet<string>;
  readonly target: ClaimsTarget;
}

export type Claims = Record<string, unknown>;

interface ClaimSources {
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

const tenantClaims: ClaimContributor = (request) => ({ tid: request.tenant.slug });

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

/** Name and email are user information: ID token and userinfo only, never in access tokens. */
const profileClaims: ClaimContributor = (request, sources) => {
  if (request.target === "access_token" || sources.identity === undefined) return {};
  const { name, email } = sources.identity.attributes;
  return {
    ...(request.scopes.has("profile") && name !== undefined ? { name } : {}),
    ...(request.scopes.has("email") && email !== undefined ? { email } : {}),
  };
};

const CONTRIBUTORS: readonly ClaimContributor[] = [tenantClaims, accessClaims, profileClaims];

export class ClaimsService {
  readonly #repos: Repositories;

  constructor(repos: Repositories) {
    this.#repos = repos;
  }

  async claimsFor(request: ClaimsRequest): Promise<Claims> {
    const [identities, audience] = await Promise.all([
      this.#repos.persons.listIdentities(request.tenant.id, request.personId),
      this.#repos.applications.findEnabledByClientId(request.tenant.id, request.audienceClientId),
    ]);
    const sources: ClaimSources = {
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
