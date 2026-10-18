import type { TokenLifetimes } from "../config/index.js";
import type { LoginContext } from "./login-context.js";

/**
 * Lifetimes that depend on the broker session. M2 uses the configured defaults; M3 replaces this
 * with the login method's session policy (`maxAgeSeconds`, `idleSeconds`). Everything is in
 * seconds; `now` is epoch seconds.
 */
export interface SessionPolicy {
  /** Absolute end (epoch seconds) of a broker session established by a login at `authTime`. */
  sessionExpiresAt(input: {
    readonly tenantId: string;
    readonly loginMethodId: string;
    readonly authTime: number;
  }): Promise<number>;
  /**
   * Lifetime of a refresh token issued now; must not outlive the session. `login` is undefined
   * only if the session context could not be resolved (the token request then fails anyway).
   */
  refreshTokenTtl(login: LoginContext | undefined, now: number): number;
}

export function defaultSessionPolicy(tokens: TokenLifetimes): SessionPolicy {
  return {
    sessionExpiresAt: ({ authTime }) => Promise.resolve(authTime + tokens.sessionSeconds),
    refreshTokenTtl: (login, now) =>
      Math.max(1, Math.min(tokens.refreshTokenSeconds, (login?.sessionExpiresAt ?? now + 1) - now)),
  };
}
