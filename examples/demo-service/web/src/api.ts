/** The demo server's JSON for the SPA: `/app/config`, `/auth/session`, `/app/api-call`. */

export interface AppConfig {
  readonly appName: string;
  readonly clientId: string;
  readonly stepUpAcr: string;
}

export interface SessionPrincipal {
  readonly sub: string;
  readonly tenant: string;
  readonly idpKind: "employee" | "citizen";
  readonly acr: string;
  readonly authTime: number;
  readonly roles: readonly string[];
  readonly name?: string;
  readonly protectedIdentity?: boolean;
  readonly rep?: {
    readonly sub: string;
    readonly type: "person" | "organisation";
    readonly name?: string;
  };
}

export type Session =
  | { readonly authenticated: false }
  | {
      readonly authenticated: true;
      readonly principal: SessionPrincipal;
      readonly expiresAt: string;
      readonly sessionEndsAt: string;
      readonly csrfToken: string;
    };

export interface ApiCallResult {
  readonly status: number;
  readonly body: unknown;
}

async function getJson<T>(path: string): Promise<T> {
  const response = await fetch(path, {
    headers: { accept: "application/json" },
    credentials: "same-origin",
  });
  if (!response.ok && response.status !== 401) throw new Error(`HTTP ${response.status}`);
  return (await response.json()) as T;
}

export const loadConfig = () => getJson<AppConfig>("/app/config");
export const loadSession = () => getJson<Session>("/auth/session");

/** Calls the demo's own API through the BFF; `null` when the session has ended. */
export async function callApi(): Promise<ApiCallResult | null> {
  const response = await fetch("/app/api-call", {
    headers: { accept: "application/json" },
    credentials: "same-origin",
  });
  if (response.status === 401) return null;
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return (await response.json()) as ApiCallResult;
}

export const loginUrl = (returnTo = "/") =>
  `/auth/login?${new URLSearchParams({ returnTo }).toString()}`;
export const stepUpUrl = (acr: string, returnTo = "/") =>
  `/auth/step-up?${new URLSearchParams({ acr, returnTo }).toString()}`;
export const selectRepresentationUrl = (returnTo = "/") =>
  `/auth/select-representation?${new URLSearchParams({ returnTo }).toString()}`;
