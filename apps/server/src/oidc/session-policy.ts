import type { TokenLifetimes } from "../config/index.js";
import type { LoginMethodKind } from "../domain/login-method.js";
import type { LoginMethodRepository } from "../repositories/login-methods.js";
import type { LoginContext } from "./login-context.js";

/**
 * Session policy semantics (docs/plan.md, "Session policy semantics"), from the login method
 * that authenticated the person:
 *
 * - the broker session lasts at most `maxAgeSeconds` (never beyond SESSION_TTL, the ceiling the
 *   login method repository also enforces at write time);
 * - without an authorization or refresh within `idleSeconds` the next authorization requires a
 *   login, and refresh tokens live at most `min(idleSeconds, remaining max age)` (and never
 *   beyond REFRESH_TOKEN_TTL);
 * - `allowSso = false` sends an authorization from another application to a fresh login.
 *
 * Applications tighten this with `max_age`, `prompt=login` and `acr_values` (the login prompt
 * checks in `provider.ts`). Times are epoch seconds.
 */
export interface EffectiveSessionPolicy {
  readonly loginMethodKind: LoginMethodKind;
  readonly maxAgeSeconds: number;
  readonly idleSeconds: number;
  readonly allowSso: boolean;
}

export class SessionPolicyService {
  readonly #tokens: TokenLifetimes;
  readonly #loginMethods: LoginMethodRepository;

  constructor(tokens: TokenLifetimes, loginMethods: LoginMethodRepository) {
    this.#tokens = tokens;
    this.#loginMethods = loginMethods;
  }

  /**
   * The policy of a login through `loginMethodId`, capped to SESSION_TTL (a method written before
   * SESSION_TTL was lowered still never outlives it). `null` when the method is gone.
   */
  async forLoginMethod(
    tenantId: string,
    loginMethodId: string,
  ): Promise<EffectiveSessionPolicy | null> {
    const method = await this.#loginMethods.findById(tenantId, loginMethodId);
    if (method === null) return null;
    const maxAgeSeconds = Math.min(method.sessionPolicy.maxAgeSeconds, this.#tokens.sessionSeconds);
    return {
      loginMethodKind: method.kind,
      maxAgeSeconds,
      idleSeconds: Math.min(method.sessionPolicy.idleSeconds, maxAgeSeconds),
      allowSso: method.sessionPolicy.allowSso,
    };
  }

  /**
   * Lifetime of a refresh token issued now for the grant's login. `login` is undefined only if
   * the grant's login could not be resolved (the token request then fails anyway).
   */
  refreshTokenTtl(login: LoginContext | undefined, now: number): number {
    if (login === undefined) return 1;
    return Math.max(
      1,
      Math.min(this.#tokens.refreshTokenSeconds, login.idleSeconds, login.sessionExpiresAt - now),
    );
  }
}
