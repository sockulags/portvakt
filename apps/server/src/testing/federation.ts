import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import {
  createMockIdp,
  MOCK_ENTRA_TENANT_ID,
  PERSONAL_IDENTITY_NUMBER_CLAIM,
  type IssuerKind,
  type MockClientInput,
  type MockIdp,
} from "@portvakt/mock-idp";
import * as client from "openid-client";
import { afterAll } from "vitest";
import { DEFAULT_ACR_RANKING } from "../config/index.js";
import { generateClientSecret } from "../crypto/secrets.js";
import type { CreateLoginMethodInput, OidcLoginMethod } from "../domain/login-method.js";
import type { Tenant } from "../domain/tenant.js";
import { federationCallbackPath, federationJwksPath } from "../federation/service.js";
import type { InteractionDetailsResponse } from "../login/routes.js";
import type { UiBootstrap } from "../login/ui-shell.js";
import { EMPLOYEE_ACR, uniqueSuffix } from "./fixtures.js";
import { TestBrowser, type TestServer } from "./test-server.js";

/** Upstream federation in tests: the mock IdP in-process, and a driver for the whole flow. */

export const LOA3 = DEFAULT_ACR_RANKING[1]!;
export const LOA2 = DEFAULT_ACR_RANKING[0]!;
export const LOA4 = DEFAULT_ACR_RANKING[2]!;

/** The login UI bootstrap block of a page served by Portvakt. */
export function bootstrapOf(html: string): UiBootstrap {
  const match = /<script type="application\/json" id="pv-bootstrap">([^<]*)<\/script>/.exec(html);
  if (match === null) throw new Error("page has no login UI bootstrap");
  return JSON.parse(match[1]!) as UiBootstrap;
}

export interface TestIdp {
  readonly idp: MockIdp;
  readonly baseUrl: string;
  issuer(kind: IssuerKind): string;
}

/** The mock IdP (`/entra`, `/bankid`) on an ephemeral port of 127.0.0.1, closed after the file. */
export async function startTestIdp(): Promise<TestIdp> {
  const server = createServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const idp = await createMockIdp({ publicUrl: baseUrl });
  server.on("request", idp.app);
  afterAll(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });
  return { idp, baseUrl, issuer: (kind) => idp.issuer(kind) };
}

type MethodDefaults = Omit<CreateLoginMethodInput, "issuer" | "clientId">;

const ENTRA_DEFAULTS: MethodDefaults = {
  kind: "employee",
  displayName: "Mock Entra",
  scopes: ["openid", "profile", "email"],
  claimMapping: { subject: "oid", name: "name", email: "email", groups: "groups" },
  assertedAcr: EMPLOYEE_ACR,
  // Entra ID work accounts carry verified addresses but no email_verified claim.
  trustUpstreamEmail: true,
  sessionPolicy: { maxAgeSeconds: 8 * 3600, idleSeconds: 3600, allowSso: true },
};

/** Login method defaults matching the mock issuers' claims. */
const METHOD_DEFAULTS: Record<IssuerKind, MethodDefaults> = {
  entra: ENTRA_DEFAULTS,
  "entra-mt": {
    ...ENTRA_DEFAULTS,
    displayName: "Mock Entra (multi-tenant)",
    allowedUpstreamTenants: [MOCK_ENTRA_TENANT_ID],
  },
  bankid: {
    kind: "citizen",
    displayName: "Mock BankID",
    scopes: ["openid", "profile"],
    claimMapping: {
      subject: "sub",
      name: "name",
      pin: PERSONAL_IDENTITY_NUMBER_CLAIM,
      acr: "acr",
      protectedIdentity: "protected_identity",
    },
    assertedAcr: LOA3,
    sessionPolicy: { maxAgeSeconds: 3600, idleSeconds: 900, allowSso: false },
  },
};

/**
 * A login method of `tenant` pointing at a mock issuer, registered there as a client with the
 * login method's redirect URI (and, for private_key_jwt, its published JWKS).
 */
export async function createFederatedLoginMethod(
  ts: TestServer,
  testIdp: TestIdp,
  tenant: Tenant,
  kind: IssuerKind,
  overrides: Partial<CreateLoginMethodInput> = {},
  client: Partial<Pick<MockClientInput, "omit_auth_time">> = {},
): Promise<OidcLoginMethod> {
  const clientId = `portvakt-${uniqueSuffix()}`;
  const secret = generateClientSecret();
  const method = await ts.db.repos.loginMethods.create(tenant.id, {
    ...METHOD_DEFAULTS[kind],
    issuer: testIdp.issuer(kind),
    clientId,
    clientSecret: secret,
    ...overrides,
  });
  const auth = method.clientAuthMethod;
  testIdp.idp.registerClient({
    ...client,
    issuer: kind,
    client_id: clientId,
    token_endpoint_auth_method: auth,
    redirect_uris: [`${ts.baseUrl}${federationCallbackPath(tenant.slug, method.id)}`],
    ...(auth === "private_key_jwt"
      ? { jwks_uri: `${ts.baseUrl}${federationJwksPath(tenant.slug, method.id)}` }
      : { client_secret: secret }),
  });
  return method;
}

/** Where a followed chain of redirects ended. */
export type Landing =
  /** The application's redirect URI (outside Portvakt and the mock IdP). */
  | { readonly kind: "app"; readonly url: URL }
  /** A login UI page served by Portvakt. */
  | {
      readonly kind: "login_ui";
      readonly url: string;
      readonly status: number;
      readonly bootstrap: UiBootstrap;
    }
  /** The mock IdP's persona page. */
  | { readonly kind: "idp_page"; readonly url: string; readonly html: string }
  /** A SAML response form to Portvakt, held back (`FlowDriver.holdSamlResponses`). */
  | { readonly kind: "auto_post"; readonly url: string; readonly form: AutoPost }
  | {
      readonly kind: "other";
      readonly url: string;
      readonly status: number;
      readonly body: string;
    };

const MAX_REDIRECTS = 20;

const decodeEntities = (value: string): string =>
  value
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&");

/** An auto-submitting SAML form (HTTP-POST binding) the driver posted. */
export interface AutoPost {
  readonly action: string;
  readonly fields: Readonly<Record<string, string>>;
}

const HIDDEN_INPUT = /<input type="hidden" name="([^"]+)" value="([^"]*)"\s*\/?>/g;

/** The auto-submitting SAML form of a page (Portvakt's POST binding page, the mock's response). */
function autoPostOf(body: string, base: string): AutoPost | undefined {
  if (!body.includes("data-pv-autosubmit") && !body.includes('data-testid="saml-post-form"')) {
    return undefined;
  }
  const action = /<form method="post" action="([^"]+)"/.exec(body)?.[1];
  if (action === undefined) return undefined;
  const fields: Record<string, string> = {};
  for (const match of body.matchAll(HIDDEN_INPUT)) fields[match[1]!] = decodeEntities(match[2]!);
  return { action: new URL(decodeEntities(action), base).href, fields };
}

/**
 * Drives the browser side of a federated login with a cookie jar, no JavaScript: follows
 * redirects across the application, Portvakt and the mock IdP, and does what the login UI and
 * the persona page would (choose a login method, choose a persona). Auto-submitting SAML forms
 * are posted like a browser would; a post to Portvakt (the ACS, SLO) carries no cookies, as a
 * cross-site POST carries no SameSite=Lax cookie.
 */
export class FlowDriver {
  readonly browser: TestBrowser;
  /** Every URL requested, in order (to replay a callback, for example). */
  readonly visited: string[] = [];
  /** The auto-submitting SAML forms posted, in order (to replay a SAML response). */
  readonly autoPosts: AutoPost[] = [];
  /** Stop at SAML response forms to Portvakt instead of posting them (an `auto_post` landing). */
  holdSamlResponses = false;
  readonly #ts: TestServer;
  readonly #idp: TestIdp;

  constructor(ts: TestServer, idp: TestIdp, browser = new TestBrowser()) {
    this.#ts = ts;
    this.#idp = idp;
    this.browser = browser;
  }

  /** Posts an auto-submitting SAML form (again) and follows the flow. */
  async post(form: AutoPost): Promise<Landing> {
    this.autoPosts.push(form);
    return this.follow(
      form.action,
      {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams(form.fields).toString(),
      },
      { sendCookies: new URL(form.action).origin !== this.#ts.baseUrl },
    );
  }

  /** Requests `url` and follows redirects until a page or the application is reached. */
  async follow(
    url: string,
    init?: RequestInit,
    options: { readonly sendCookies?: boolean } = {},
  ): Promise<Landing> {
    let current = url;
    this.visited.push(current);
    let response = await this.browser.request(current, init, options);
    for (let hops = 0; ; hops += 1) {
      if (response.status < 300 || response.status >= 400) break;
      if (hops >= MAX_REDIRECTS) throw new Error("too many redirects");
      current = TestBrowser.location(response, current);
      const target = new URL(current);
      if (target.origin !== this.#ts.baseUrl && target.origin !== this.#idp.baseUrl) {
        return { kind: "app", url: target };
      }
      this.visited.push(current);
      response = await this.browser.request(current);
    }
    const body = await response.text();
    const origin = new URL(current).origin;
    const autoPost = autoPostOf(body, current);
    if (autoPost !== undefined) {
      const toPortvakt = new URL(autoPost.action).origin === this.#ts.baseUrl;
      if (this.holdSamlResponses && toPortvakt && "SAMLResponse" in autoPost.fields) {
        return { kind: "auto_post", url: current, form: autoPost };
      }
      return this.post(autoPost);
    }
    // oidc-provider's auto-submitting form (a session switch to another person): a browser
    // with JavaScript posts it at once.
    if (body.includes("<title>Submitting Callback</title>")) {
      const action = /<form method="post" action="([^"]+)">/.exec(body)?.[1];
      if (action === undefined) throw new Error("auto-submit form without action");
      const fields = new URLSearchParams();
      for (const match of body.matchAll(
        /<input type="hidden" name="([^"]+)" value="([^"]*)"\/>/g,
      )) {
        fields.set(match[1]!, decodeEntities(match[2]!));
      }
      return this.follow(new URL(decodeEntities(action), current).href, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: fields.toString(),
      });
    }
    if (origin === this.#ts.baseUrl && body.includes('id="pv-bootstrap"')) {
      return {
        kind: "login_ui",
        url: current,
        status: response.status,
        bootstrap: bootstrapOf(body),
      };
    }
    if (origin === this.#idp.baseUrl && body.includes('name="persona"')) {
      return { kind: "idp_page", url: current, html: body };
    }
    return { kind: "other", url: current, status: response.status, body };
  }

  /** The login UI's details for the interaction of a `login` view. */
  async details(landing: Landing): Promise<InteractionDetailsResponse> {
    const response = await this.browser.request(`${this.#interactionUrl(landing)}/details`);
    if (response.status !== 200) throw new Error(`details failed: ${response.status}`);
    return (await response.json()) as InteractionDetailsResponse;
  }

  /** POSTs the login UI's choice (`{ loginMethodId }` or `{ email }`) with its CSRF token. */
  async choose(
    landing: Landing,
    choice: { readonly loginMethodId: string } | { readonly email: string },
  ): Promise<{ readonly status: number; readonly body: Record<string, unknown> }> {
    const { csrfToken } = await this.details(landing);
    const response = await this.browser.request(`${this.#interactionUrl(landing)}/login`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-csrf-token": csrfToken },
      body: JSON.stringify(choice),
    });
    return { status: response.status, body: (await response.json()) as Record<string, unknown> };
  }

  /** Chooses a login method and follows the flow from there. */
  async chooseAndFollow(
    landing: Landing,
    choice: { readonly loginMethodId: string } | { readonly email: string },
  ): Promise<Landing> {
    const { status, body } = await this.choose(landing, choice);
    if (status !== 200 || typeof body.redirectTo !== "string") {
      throw new Error(`login choice refused: ${status} ${JSON.stringify(body)}`);
    }
    return this.follow(body.redirectTo);
  }

  /**
   * Submits a persona (or `cancel`) on the mock IdP's page and follows the flow; `switch` picks
   * a test switch of the mock SAML IdPs.
   */
  async persona(
    landing: Landing,
    personaId: string,
    options: { readonly switch?: string } = {},
  ): Promise<Landing> {
    if (landing.kind !== "idp_page") throw new Error(`expected the IdP page, got ${landing.kind}`);
    return personaId === "cancel"
      ? this.follow(`${landing.url}/cancel`, { method: "POST" })
      : this.follow(`${landing.url}/login`, {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            persona: personaId,
            ...(options.switch === undefined ? {} : { switch: options.switch }),
          }).toString(),
        });
  }

  #interactionUrl(landing: Landing): string {
    if (landing.kind !== "login_ui" || landing.bootstrap.view !== "login") {
      throw new Error(`expected the login view, got ${landing.kind}`);
    }
    return `${this.#ts.baseUrl}/t/${landing.bootstrap.tenant}/interaction/${landing.bootstrap.uid}`;
  }
}

export interface AuthorizationRequest {
  readonly url: URL;
  readonly codeVerifier: string;
  readonly state: string;
  readonly nonce: string;
}

/** An authorization request of the application (openid-client, PKCE, state, nonce). */
export async function authorizationRequest(
  config: client.Configuration,
  redirectUri: string,
  params: Record<string, string> = {},
): Promise<AuthorizationRequest> {
  const codeVerifier = client.randomPKCECodeVerifier();
  const state = client.randomState();
  const nonce = client.randomNonce();
  const url = client.buildAuthorizationUrl(config, {
    redirect_uri: redirectUri,
    scope: "openid profile email",
    code_challenge: await client.calculatePKCECodeChallenge(codeVerifier),
    code_challenge_method: "S256",
    state,
    nonce,
    ...params,
  });
  return { url, codeVerifier, state, nonce };
}

/** Redeems the code of an `app` landing for tokens. */
export async function redeem(
  config: client.Configuration,
  request: AuthorizationRequest,
  landing: Landing,
) {
  if (landing.kind !== "app") {
    throw new Error(
      `expected the application callback, got ${landing.kind}: ${JSON.stringify(landing)}`,
    );
  }
  return client.authorizationCodeGrant(config, landing.url, {
    pkceCodeVerifier: request.codeVerifier,
    expectedState: request.state,
    expectedNonce: request.nonce,
  });
}
