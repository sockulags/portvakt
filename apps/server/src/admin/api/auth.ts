import { createLocalJWKSet, decodeJwt, errors as joseErrors, jwtVerify, type JWK } from "jose";
import { z } from "zod";
import type { Tenant } from "../../domain/tenant.js";
import { SYSTEM_TENANT_SLUG } from "../../domain/tenant.js";
import type { SigningKeyCache } from "../../keys/key-cache.js";
import type { Repositories } from "../../repositories/index.js";
import { ADMIN_CLIENT_ID, PLATFORM_ADMIN_ROLE, TENANT_ADMIN_ROLE } from "../constants.js";
import { ApiError } from "./problem.js";

/** Who calls the admin API, derived from a verified access token. */
export interface Caller {
  /** The administrator (a person of `tenant`). */
  readonly personId: string;
  /** The tenant whose issuer issued the token (the administrator's own tenant). */
  readonly tenant: Tenant;
  /** `platform-admin` in the system tenant: every tenant; otherwise `tenant-admin` of `tenant`. */
  readonly platform: boolean;
  readonly roles: readonly string[];
}

const SLUG = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const MAX_TOKEN_LENGTH = 8192;
const CLOCK_TOLERANCE_SECONDS = 5;

/**
 * The claims a person's access token always carries (docs/claims.md). Service tokens carry none
 * of `idp`, `idp_kind`, `acr`, `auth_time`, `roles` and `attrs`, and `sub` is their client_id.
 */
const personTokenSchema = z.object({
  sub: z.uuid(),
  tid: z.string().regex(SLUG),
  client_id: z.literal(ADMIN_CLIENT_ID),
  idp: z.uuid(),
  idp_kind: z.enum(["employee", "citizen"]),
  acr: z.string().min(1),
  auth_time: z.number().int(),
  roles: z.array(z.string()).max(200),
  attrs: z.record(z.string(), z.unknown()),
});

export interface AdminAuthOptions {
  /** `PUBLIC_URL`: issuers are `{publicUrl}/t/{slug}`. */
  readonly publicUrl: string;
  readonly keyCache: SigningKeyCache;
  readonly repos: Repositories;
  /**
   * ADMIN_MIN_ACR: tokens whose `acr` ranks lower in `acrRanking` (or is unranked) are refused
   * (`acr_too_low`). Undefined: no minimum.
   */
  readonly minAcr?: string | undefined;
  /** ACR_RANKING, lowest first. */
  readonly acrRanking?: readonly string[];
}

/**
 * Verifies admin API bearer tokens. Every active tenant's issuer is accepted, but the token's
 * `iss` must be exactly `{PUBLIC_URL}/t/{tid}` (Portvakt signs every tenant's tokens with the same
 * keys, so a token's tenant is only proven by the issuer it names), the audience exactly
 * `portvakt-admin`, `typ` `at+jwt` and the algorithm ES256. The tenant must be active and still
 * have `portvakt-admin` enabled. Service tokens and representation tokens are refused, and so
 * are tokens below ADMIN_MIN_ACR when it is set. The
 * token's roles are intersected with the roles the person holds right now (direct assignments
 * and rules against the groups stored on the identity used to sign in), so a removed role stops
 * working at the next request.
 */
export class AdminAuthenticator {
  readonly #options: AdminAuthOptions;
  #jwks: { version: string; set: ReturnType<typeof createLocalJWKSet> } | undefined;

  constructor(options: AdminAuthOptions) {
    this.#options = options;
  }

  async authenticate(authorization: string | undefined): Promise<Caller> {
    if (authorization === undefined || authorization === "") throw new ApiError("unauthorized");
    const match = /^Bearer ([A-Za-z0-9._~+/-]+=*)$/.exec(authorization);
    if (match === null || match[1]!.length > MAX_TOKEN_LENGTH) throw new ApiError("invalid_token");
    const token = match[1]!;

    let issuer: string;
    try {
      const unverified = decodeJwt(token);
      if (typeof unverified.iss !== "string") throw new ApiError("invalid_token");
      issuer = unverified.iss;
    } catch {
      throw new ApiError("invalid_token");
    }
    const prefix = `${this.#options.publicUrl}/t/`;
    const slug = issuer.startsWith(prefix) ? issuer.slice(prefix.length) : "";
    if (!SLUG.test(slug)) throw new ApiError("invalid_token");

    let payload: Record<string, unknown>;
    try {
      const verified = await jwtVerify(token, this.#keySet(), {
        issuer: `${prefix}${slug}`,
        audience: ADMIN_CLIENT_ID,
        typ: "at+jwt",
        algorithms: ["ES256"],
        clockTolerance: CLOCK_TOLERANCE_SECONDS,
        requiredClaims: ["exp", "iat", "sub"],
      });
      payload = verified.payload;
    } catch (error) {
      if (error instanceof ApiError) throw error;
      if (error instanceof joseErrors.JOSEError) throw new ApiError("invalid_token");
      throw error;
    }
    // A single audience only: a token for several applications is not an admin token.
    if (Array.isArray(payload.aud) && payload.aud.length !== 1) throw new ApiError("invalid_token");
    if ("rep" in payload) throw new ApiError("representation_not_allowed");
    if (payload.sub === ADMIN_CLIENT_ID || !("idp" in payload)) {
      throw new ApiError("service_token_not_allowed");
    }
    const claims = personTokenSchema.safeParse(payload);
    if (!claims.success) throw new ApiError("invalid_token");
    // The token's tenant claim must name the issuer's tenant.
    if (claims.data.tid !== slug) throw new ApiError("invalid_token");
    const { minAcr, acrRanking = [] } = this.#options;
    if (minAcr !== undefined) {
      const minimum = acrRanking.indexOf(minAcr);
      if (minimum < 0 || acrRanking.indexOf(claims.data.acr) < minimum) {
        throw new ApiError("acr_too_low");
      }
    }

    const { repos } = this.#options;
    const tenant = await repos.tenants.findActiveBySlug(slug);
    if (tenant === null) throw new ApiError("invalid_token");
    const [application, person] = await Promise.all([
      repos.applications.findEnabledByClientId(tenant.id, ADMIN_CLIENT_ID),
      repos.persons.findById(tenant.id, claims.data.sub),
    ]);
    if (application === null || person === null) throw new ApiError("invalid_token");

    // The token's roles count only while the person still holds them: a removed role (or rule)
    // takes effect on the next request, not when the token expires.
    const current = new Set(
      await repos.access.currentRoles(tenant.id, person.id, application.id, claims.data.idp),
    );
    const roles = claims.data.roles.filter((role) => current.has(role));
    const platform = tenant.slug === SYSTEM_TENANT_SLUG && roles.includes(PLATFORM_ADMIN_ROLE);
    if (!platform && !roles.includes(TENANT_ADMIN_ROLE)) throw new ApiError("forbidden");
    return { personId: person.id, tenant, platform, roles };
  }

  /** The published public keys, rebuilt whenever the key cache changes. */
  #keySet(): ReturnType<typeof createLocalJWKSet> {
    const current = this.#options.keyCache.current;
    if (current === undefined) throw new ApiError("unavailable");
    if (this.#jwks?.version !== current.version) {
      const keys = current.jwks.keys.map((key): JWK => {
        const { d: _d, ...publicKey } = key as Record<string, unknown>;
        void _d;
        return publicKey;
      });
      this.#jwks = { version: current.version, set: createLocalJWKSet({ keys }) };
    }
    return this.#jwks.set;
  }
}
