import * as client from "openid-client";
import { generateClientSecret } from "../crypto/secrets.js";
import type { Application } from "../domain/application.js";
import type { LoginMethod } from "../domain/login-method.js";
import type { Tenant } from "../domain/tenant.js";
import type { Repositories } from "../repositories/index.js";
import { createApplication, createLoginMethod, createTenant, login } from "./fixtures.js";
import { TestBrowser, type TestServer } from "./test-server.js";

/** Relying-party side of the tests: openid-client against the running test server. */

export interface TestClient {
  readonly application: Application;
  readonly secret: string;
}

/** An application with a client secret, enabled for the tenant unless `enable` is false. */
export async function createTestClient(
  repos: Repositories,
  tenant: Tenant | null,
  overrides: Parameters<typeof createApplication>[1] = {},
): Promise<TestClient> {
  const secret = generateClientSecret();
  const application = await createApplication(repos, {
    clientAuth: { method: "client_secret_basic", clientSecret: secret },
    ...overrides,
  });
  if (tenant !== null) await repos.applications.enableForTenant(tenant.id, application.id);
  return { application, secret };
}

export async function discover(
  server: TestServer,
  slug: string,
  clientId: string,
  auth: client.ClientAuth,
): Promise<client.Configuration> {
  return client.discovery(
    new URL(server.issuerOf(slug)),
    clientId,
    { id_token_signed_response_alg: "ES256" },
    auth,
    { execute: [client.allowInsecureRequests] },
  );
}

export async function discoverWithSecret(
  server: TestServer,
  slug: string,
  testClient: TestClient,
): Promise<client.Configuration> {
  return discover(
    server,
    slug,
    testClient.application.clientId,
    client.ClientSecretBasic(testClient.secret),
  );
}

export interface LoginAs {
  readonly personId: string;
  readonly loginMethodId: string;
  readonly acr: string;
  readonly amr?: readonly string[];
}

export interface AuthorizationResult {
  readonly callbackUrl: URL;
  readonly codeVerifier: string;
  readonly state: string;
  readonly nonce: string;
}

/**
 * Drives the front channel: authorization request, the interaction, the test-only login route
 * (which calls `completeLogin`), and the resume, up to the redirect back to the application.
 */
export async function authorize(
  server: TestServer,
  config: client.Configuration,
  redirectUri: string,
  as: LoginAs,
  options: { readonly browser?: TestBrowser; readonly scope?: string } = {},
): Promise<AuthorizationResult> {
  const browser = options.browser ?? new TestBrowser();
  const codeVerifier = client.randomPKCECodeVerifier();
  const state = client.randomState();
  const nonce = client.randomNonce();
  const authorizationUrl = client.buildAuthorizationUrl(config, {
    redirect_uri: redirectUri,
    scope: options.scope ?? "openid profile email",
    code_challenge: await client.calculatePKCECodeChallenge(codeVerifier),
    code_challenge_method: "S256",
    state,
    nonce,
  });

  const start = await browser.request(authorizationUrl.href);
  let next = TestBrowser.location(start, authorizationUrl.href);
  if (new URL(next).pathname.includes("/interaction/")) {
    const loginResponse = await browser.request(`${next}/__test__/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        personId: as.personId,
        loginMethodId: as.loginMethodId,
        acr: as.acr,
        amr: as.amr ?? ["pwd"],
      }),
    });
    if (loginResponse.status !== 303) {
      throw new Error(`test login failed: ${loginResponse.status} ${await loginResponse.text()}`);
    }
    const resume = await browser.request(TestBrowser.location(loginResponse, next));
    next = TestBrowser.location(resume, next);
  }
  const callbackUrl = new URL(next);
  if (`${callbackUrl.origin}${callbackUrl.pathname}` !== redirectUri) {
    throw new Error(`unexpected redirect to ${callbackUrl.pathname}`);
  }
  return { callbackUrl, codeVerifier, state, nonce };
}

/** Full authorization code + PKCE flow, returning the token response. */
export async function codeFlow(
  server: TestServer,
  config: client.Configuration,
  redirectUri: string,
  as: LoginAs,
  options: { readonly browser?: TestBrowser; readonly scope?: string } = {},
) {
  const result = await authorize(server, config, redirectUri, as, options);
  return client.authorizationCodeGrant(config, result.callbackUrl, {
    pkceCodeVerifier: result.codeVerifier,
    expectedState: result.state,
    expectedNonce: result.nonce,
  });
}

export interface TenantWorld {
  readonly tenant: Tenant;
  readonly loginMethod: LoginMethod;
  readonly app: TestClient;
}

/** A tenant with one login method and one enabled application with a client secret. */
export async function createTenantWorld(
  repos: Repositories,
  prefix = "t",
  loginMethod: Parameters<typeof createLoginMethod>[2] = {},
): Promise<TenantWorld> {
  const tenant = await createTenant(repos, prefix);
  const method = await createLoginMethod(repos, tenant.id, loginMethod);
  const app = await createTestClient(repos, tenant);
  return { tenant, loginMethod: method, app };
}

/** JIT login of a person through the world's login method, with upstream groups. */
export async function createPerson(
  repos: Repositories,
  world: TenantWorld,
  subject: string,
  attributes: { groups?: string[]; name?: string; email?: string } = {},
) {
  return login(repos, world.tenant.id, world.loginMethod, subject, {
    attributes: { groups: attributes.groups ?? [], name: attributes.name, email: attributes.email },
  });
}
