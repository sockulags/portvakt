import { createHash, randomBytes } from "node:crypto";
import type { Page } from "@playwright/test";
import { URLS } from "./env";

/**
 * The test as an OIDC relying party of a seeded application (it knows the client secret): an
 * authorization code flow through the real browser path (login UI, mock IdP), with the code read
 * from the redirect to the application's callback and redeemed by the test. For scenarios
 * that need the tokens themselves (claims of a new tenant, an access token to send to another
 * API, the kid of a fresh token), which the demo's BFF never shows.
 */

export interface Tokens {
  readonly accessToken: string;
  readonly idToken: string;
  readonly refreshToken?: string;
  readonly idClaims: Record<string, unknown>;
  readonly accessClaims: Record<string, unknown>;
  readonly accessHeader: Record<string, unknown>;
}

export function decodeJwt(token: string): {
  header: Record<string, unknown>;
  claims: Record<string, unknown>;
} {
  const [header, payload] = token.split(".");
  if (header === undefined || payload === undefined) throw new Error("not a JWT");
  const json = (part: string) =>
    JSON.parse(Buffer.from(part, "base64url").toString("utf8")) as Record<string, unknown>;
  return { header: json(header), claims: json(payload) };
}

const base64url = (bytes: Buffer): string => bytes.toString("base64url");

export interface Discovery {
  readonly issuer: string;
  readonly authorization_endpoint: string;
  readonly token_endpoint: string;
  readonly jwks_uri: string;
}

export async function discover(tenant: string): Promise<Discovery> {
  const response = await fetch(`${URLS.portvakt}/t/${tenant}/.well-known/openid-configuration`);
  if (!response.ok) throw new Error(`discovery of ${tenant} answered ${response.status}`);
  return (await response.json()) as Discovery;
}

export async function jwks(tenant: string): Promise<{ kid: string }[]> {
  const { jwks_uri } = await discover(tenant);
  const response = await fetch(jwks_uri);
  return ((await response.json()) as { keys: { kid: string }[] }).keys;
}

export interface Authorization {
  /** Waits for the browser to arrive at the callback, then redeems the code. */
  finish(): Promise<Tokens>;
}

/**
 * Navigates the page to the tenant's authorization endpoint for `clientId`; the caller drives
 * the login UI and calls `finish()`.
 */
export async function startAuthorization(
  page: Page,
  options: {
    readonly tenant: string;
    readonly clientId: string;
    readonly clientSecret: string;
    /** The application's registered callback, intercepted by the test. */
    readonly redirectUri: string;
    readonly scope?: string;
  },
): Promise<Authorization> {
  const discovery = await discover(options.tenant);
  const state = base64url(randomBytes(16));
  const nonce = base64url(randomBytes(16));
  const verifier = base64url(randomBytes(32));
  const challenge = base64url(createHash("sha256").update(verifier).digest());

  let resolveCode: (code: string) => void = () => undefined;
  let rejectCode: (error: Error) => void = () => undefined;
  const code = new Promise<string>((resolve, reject) => {
    resolveCode = resolve;
    rejectCode = reject;
  });
  // Portvakt redirects to the callback (a 303), and page.route never sees a redirect's target,
  // so the code is read from the request event. The application itself then gets the request
  // too and refuses it (it started no login: no transaction cookie), so the code stays unused.
  const onRequest = (request: import("@playwright/test").Request): void => {
    if (!request.url().startsWith(`${options.redirectUri}?`)) return;
    page.off("request", onRequest);
    const url = new URL(request.url());
    const error = url.searchParams.get("error");
    if (error !== null) rejectCode(new Error(`authorization failed: ${error}`));
    else if (url.searchParams.get("state") !== state) rejectCode(new Error("state mismatch"));
    else resolveCode(url.searchParams.get("code") ?? "");
  };
  page.on("request", onRequest);

  const authorize = new URL(discovery.authorization_endpoint);
  authorize.search = new URLSearchParams({
    client_id: options.clientId,
    redirect_uri: options.redirectUri,
    response_type: "code",
    scope: options.scope ?? "openid profile",
    state,
    nonce,
    code_challenge: challenge,
    code_challenge_method: "S256",
  }).toString();
  await page.goto(authorize.href);

  return {
    async finish(): Promise<Tokens> {
      const received = await code;
      const response = await fetch(discovery.token_endpoint, {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          accept: "application/json",
          authorization: `Basic ${Buffer.from(
            `${encodeURIComponent(options.clientId)}:${encodeURIComponent(options.clientSecret)}`,
          ).toString("base64")}`,
        },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code: received,
          redirect_uri: options.redirectUri,
          code_verifier: verifier,
        }).toString(),
      });
      const body = (await response.json()) as Record<string, string>;
      if (!response.ok)
        throw new Error(`token endpoint answered ${response.status}: ${body.error}`);
      const id = decodeJwt(body.id_token!);
      if (id.claims.nonce !== nonce) throw new Error("nonce mismatch");
      const access = decodeJwt(body.access_token!);
      return {
        accessToken: body.access_token!,
        idToken: body.id_token!,
        ...(body.refresh_token === undefined ? {} : { refreshToken: body.refresh_token }),
        idClaims: id.claims,
        accessClaims: access.claims,
        accessHeader: access.header,
      };
    },
  };
}
