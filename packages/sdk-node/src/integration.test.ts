import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import {
  createFederatedLoginMethod,
  createSamlLoginMethod,
  createTenant,
  createTestClient,
  FlowDriver,
  LOA3,
  LOA4,
  startTestIdp,
  startTestServer,
  TestBrowser,
  type Landing,
  type TestClient,
} from "@portvakt/server/testing";
import express from "express";
import { decodeJwt } from "jose";
import { afterAll, describe, expect, it } from "vitest";
import { createPortvaktClient } from "./client.js";
import { silentLogger } from "./logger.js";
import { MemoryStore } from "./stores/memory.js";

/**
 * The SDK against a real, in-process Portvakt and mock IdP: BFF logins (OIDC and SAML), SSO,
 * step-up, representation, API calls with the BFF's access token, logout, refresh after a
 * revoked representation, and Portvakt outages.
 */

const ts = await startTestServer();
const idp = ts === undefined ? undefined : await startTestIdp();

const ENCRYPTION_KEY = Buffer.alloc(32, 3).toString("base64");
const TEST_ORGNR = "556677-8899";
const SVEN_PIN = "191212121212";

interface App {
  readonly base: string;
  readonly client: TestClient;
  /** Makes every request of the SDK to Portvakt fail at the network level. */
  setDown(down: boolean): void;
}

const servers: Server[] = [];
afterAll(async () => {
  for (const server of servers) {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

/** An application with the SDK on an ephemeral port, registered and enabled in the tenant. */
async function startApp(
  tenant: Awaited<ReturnType<typeof createTenant>>,
  options: {
    readonly representationMode?: "none" | "optional" | "required";
    readonly grace?: number;
  } = {},
): Promise<App> {
  const server = createServer();
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const testClient = await createTestClient(ts!.db.repos, tenant, {
    redirectUris: [`${base}/auth/callback`],
    postLogoutRedirectUris: [`${base}/`],
    representationMode: options.representationMode ?? "none",
  });
  let down = false;
  const portvakt = createPortvaktClient({
    issuer: ts!.issuerOf(tenant.slug),
    clientId: testClient.application.clientId,
    clientAuth: { method: "client_secret_basic", clientSecret: testClient.secret },
    redirectUri: `${base}/auth/callback`,
    postLogoutRedirectUri: `${base}/`,
    allowInsecureRequests: true,
    outageGraceSeconds: options.grace ?? 0,
    logger: silentLogger,
    fetch: (input, init) =>
      down ? Promise.reject(new TypeError("fetch failed")) : fetch(input, init),
  });
  const bff = portvakt.bff({
    sessionStore: new MemoryStore(),
    encryptionKey: ENCRYPTION_KEY,
    cookie: {
      name: `app_${testClient.application.clientId.replace(/[^A-Za-z0-9]/g, "")}`,
      secrets: ["integration-cookie-secret-0123456789abcdef"],
      secure: false,
    },
  });
  const app = express();
  app.use(bff);
  app.get("/", (_req, res) => {
    res.send("home");
  });
  app.get("/private", bff.requireLogin(), (req, res) => {
    res.json(bff.principal(req));
  });
  app.get("/sensitive", bff.requireAcr(LOA4), (req, res) => {
    res.json(bff.principal(req));
  });
  app.get("/token", bff.requireLogin(), (req, res, next) => {
    const min = typeof req.query.min === "string" ? Number(req.query.min) : undefined;
    bff
      .getAccessToken(req, min === undefined ? {} : { minValiditySeconds: min })
      .then((token) => res.json({ token }))
      .catch(next);
  });
  // The BFF calls its own API with the session's access token.
  app.get("/call-api", bff.requireLogin(), (req, res, next) => {
    bff
      .getAccessToken(req)
      .then(async (token) => {
        const response = await fetch(`${base}/api/me`, {
          headers: { authorization: `Bearer ${token}` },
        });
        res.status(response.status).json(await response.json());
      })
      .catch(next);
  });
  app.get(
    "/api/me",
    portvakt.requireAccessToken({ audience: testClient.application.clientId }),
    (req, res) => {
      res.json(portvakt.principal(req));
    },
  );
  app.use(bff.errorHandler());
  server.on("request", app);
  return {
    base,
    client: testClient,
    setDown: (value) => {
      down = value;
    },
  };
}

const json = { accept: "application/json" };

/**
 * Starts a login at the application and drives Portvakt and the mock IdP (login method choice,
 * persona, representation choice) until the browser is back at the application.
 */
async function signIn(
  driver: FlowDriver,
  app: App,
  steps: {
    readonly path?: string;
    readonly methodId?: string;
    readonly persona?: string;
    readonly representation?: Readonly<Record<string, unknown>>;
  } = {},
): Promise<{ readonly upstreamLogin: boolean; readonly returnedTo: string }> {
  // A browser following a link of the application's own page sends Sec-Fetch-Site: same-origin
  // (step-up and representation switches refuse cross-site starts).
  const start = await driver.browser.request(
    `${app.base}${steps.path ?? "/auth/login?returnTo=%2Fprivate"}`,
    { headers: { "sec-fetch-site": "same-origin" } },
  );
  expect(start.status).toBe(302);
  let landing: Landing = await driver.follow(TestBrowser.location(start, app.base));
  if (landing.kind === "login_ui" && landing.bootstrap.view === "login" && steps.methodId) {
    landing = await driver.chooseAndFollow(landing, { loginMethodId: steps.methodId });
  }
  const upstreamLogin = landing.kind === "idp_page";
  if (landing.kind === "idp_page") {
    if (steps.persona === undefined) throw new Error("unexpected upstream login");
    landing = await driver.persona(landing, steps.persona);
  }
  if (landing.kind === "login_ui" && landing.bootstrap.view === "representation") {
    if (steps.representation === undefined) throw new Error("unexpected representation chooser");
    landing = await driver.chooseRepresentationAndFollow(landing, steps.representation);
  }
  if (landing.kind !== "app") throw new Error(`expected the app, got ${JSON.stringify(landing)}`);
  expect(landing.url.origin).toBe(app.base);
  const callback = await driver.browser.request(landing.url.href);
  expect(callback.status).toBe(303);
  return { upstreamLogin, returnedTo: callback.headers.get("location")! };
}

async function getJson(driver: FlowDriver, url: string) {
  const response = await driver.browser.request(url, { headers: json });
  return { status: response.status, body: (await response.json()) as Record<string, unknown> };
}

describe.skipIf(ts === undefined)("SDK against Portvakt", () => {
  // The describe body also runs when the suite is skipped (no Postgres): only the tests use it.
  const repos = ts?.db.repos as NonNullable<typeof ts>["db"]["repos"];

  it("signs an employee in over OIDC, calls the API with the BFF's token and logs out", async () => {
    const tenant = await createTenant(repos, "sdk-emp");
    const method = await createFederatedLoginMethod(ts!, idp!, tenant, "entra");
    const a = await startApp(tenant);
    await repos.access.createRule(tenant.id, {
      applicationId: a.client.application.id,
      loginMethodId: method.id,
      groupValue: "grp-handlaggare",
      role: "handlaggare",
    });
    const driver = new FlowDriver(ts!, idp!);
    const { upstreamLogin, returnedTo } = await signIn(driver, a, { persona: "anna-handlaggare" });
    expect(upstreamLogin).toBe(true);
    expect(returnedTo).toBe("/private");

    const principal = await getJson(driver, `${a.base}/private`);
    expect(principal.status).toBe(200);
    expect(principal.body).toMatchObject({
      isService: false,
      tenant: tenant.slug,
      idp: method.id,
      idpKind: "employee",
      acr: method.assertedAcr,
      roles: ["handlaggare"],
      name: "Anna Andersson",
      email: "anna.andersson@kommun.example",
      clientId: a.client.application.clientId,
    });

    // The API validates the BFF's access token: same person, minimal claims.
    const api = await getJson(driver, `${a.base}/call-api`);
    expect(api.status).toBe(200);
    expect(api.body).toMatchObject({
      isService: false,
      sub: principal.body.sub,
      roles: ["handlaggare"],
      clientId: a.client.application.clientId,
    });
    expect(api.body).not.toHaveProperty("name");
    const token = (await getJson(driver, `${a.base}/token`)).body.token as string;
    expect(decodeJwt(token)).not.toHaveProperty("email");

    // A token for this application is refused by another application's API.
    const b = await startApp(tenant);
    const other = await fetch(`${b.base}/api/me`, {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(other.status).toBe(401);

    // RP-initiated logout: CSRF token, Portvakt's confirmation, back to the application.
    const session = await getJson(driver, `${a.base}/auth/session`);
    const logout = await driver.browser.request(`${a.base}/auth/logout`, {
      method: "POST",
      headers: { "x-csrf-token": session.body.csrfToken as string },
    });
    expect(logout.status).toBe(303);
    const endSession = TestBrowser.location(logout, a.base);
    expect(endSession).toContain(`${ts!.issuerOf(tenant.slug)}/session/end`);
    expect(new URL(endSession).searchParams.get("id_token_hint")).toBeTruthy();
    const page = await (await driver.browser.request(endSession)).text();
    const action = /<form id="op\.logoutForm" method="post" action="([^"]+)">/.exec(page)![1]!;
    const xsrf = /name="xsrf" value="([^"]+)"/.exec(page)![1]!;
    const confirmed = await driver.browser.request(new URL(action, endSession).href, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ xsrf, logout: "yes" }).toString(),
    });
    expect(TestBrowser.location(confirmed, endSession)).toBe(`${a.base}/`);
    expect((await getJson(driver, `${a.base}/auth/session`)).body).toEqual({
      authenticated: false,
    });
    expect((await getJson(driver, `${a.base}/private`)).status).toBe(401);
    // The broker session ended as well: the next login goes upstream again (the mock IdP may
    // answer from its own session without its persona page).
    const visited = driver.visited.length;
    await signIn(driver, a, { persona: "anna-handlaggare" });
    expect(driver.visited.slice(visited).some((url) => url.startsWith(idp!.baseUrl))).toBe(true);
  });

  it("gives single sign-on from Service A to Service B", async () => {
    const tenant = await createTenant(repos, "sdk-sso");
    await createFederatedLoginMethod(ts!, idp!, tenant, "entra");
    const [a, b] = [await startApp(tenant), await startApp(tenant)];
    const driver = new FlowDriver(ts!, idp!);
    expect((await signIn(driver, a, { persona: "anna-handlaggare" })).upstreamLogin).toBe(true);
    const atB = await signIn(driver, b);
    expect(atB.upstreamLogin).toBe(false);
    const [principalA, principalB] = [
      (await getJson(driver, `${a.base}/private`)).body,
      (await getJson(driver, `${b.base}/private`)).body,
    ];
    expect(principalB.sub).toBe(principalA.sub);
    expect(principalB.clientId).toBe(b.client.application.clientId);
  });

  it("signs a citizen in over SAML and switches representation", async () => {
    const tenant = await createTenant(repos, "sdk-rep");
    await createSamlLoginMethod(ts!, idp!, tenant, "bankid", { trustPinForRepresentation: true });
    const a = await startApp(tenant, { representationMode: "optional" });
    const org = await repos.parties.create(tenant.id, {
      type: "organisation",
      identifier: TEST_ORGNR,
      displayName: "Bygg AB",
    });
    const grant = await repos.grants.create(tenant.id, {
      agent: { pin: SVEN_PIN },
      partyId: org.id,
      allApplications: true,
    });
    const driver = new FlowDriver(ts!, idp!);
    await signIn(driver, a, { persona: "saml-sven", representation: { partyId: org.id } });
    const acting = (await getJson(driver, `${a.base}/private`)).body;
    expect(acting).toMatchObject({
      idpKind: "citizen",
      acr: LOA3,
      name: "Sven Medborgare",
      rep: { sub: org.id, type: "organisation", name: "Bygg AB" },
    });
    // The API sees rep without its name.
    const api = (await getJson(driver, `${a.base}/call-api`)).body;
    expect(api.rep).toEqual({ sub: org.id, type: "organisation" });

    // "Byt företrädd": the chooser again, without a new upstream login.
    const self = await signIn(driver, a, {
      path: "/auth/select-representation?returnTo=%2Fprivate",
      representation: { self: true },
    });
    expect(self.upstreamLogin).toBe(false);
    expect((await getJson(driver, `${a.base}/private`)).body).not.toHaveProperty("rep");

    // Back to the organisation, then the grant is revoked: the next refresh ends the session.
    await signIn(driver, a, {
      path: "/auth/select-representation?returnTo=%2Fprivate",
      representation: { partyId: org.id },
    });
    expect((await getJson(driver, `${a.base}/private`)).body.rep).toMatchObject({ sub: org.id });
    await repos.grants.revoke(tenant.id, grant.id, null);
    const refresh = await getJson(driver, `${a.base}/token?min=3600`);
    expect(refresh.status).toBe(401);
    expect(refresh.body).toMatchObject({ error: "login_required" });
    expect((await getJson(driver, `${a.base}/auth/session`)).body).toEqual({
      authenticated: false,
    });
  });

  it("steps up through requireAcr to a login method that provides loa4", async () => {
    const tenant = await createTenant(repos, "sdk-stepup");
    const policy = { maxAgeSeconds: 3600, idleSeconds: 900, allowSso: true };
    const loa3 = await createFederatedLoginMethod(ts!, idp!, tenant, "bankid", {
      displayName: "BankID",
      linkByPin: true,
      sessionPolicy: policy,
    });
    await createFederatedLoginMethod(ts!, idp!, tenant, "bankid", {
      displayName: "BankID high",
      assertedAcr: LOA4,
      linkByPin: true,
      pinLoginHint: true,
      sessionPolicy: policy,
    });
    const a = await startApp(tenant);
    const driver = new FlowDriver(ts!, idp!);
    await signIn(driver, a, { methodId: loa3.id, persona: "maja-loa4" });
    const before = (await getJson(driver, `${a.base}/private`)).body;
    expect(before.acr).toBe(LOA3);

    const refused = await getJson(driver, `${a.base}/sensitive`);
    expect(refused.status).toBe(401);
    expect(refused.body).toMatchObject({ error: "step_up_required", acr: LOA4 });
    const visited = driver.visited.length;
    const stepUp = await signIn(driver, a, {
      path: refused.body.stepUpUrl as string,
      persona: "maja-loa4",
    });
    // Upstream again (the mock signs the person named by login_hint in without its page).
    expect(driver.visited.slice(visited).some((url) => url.startsWith(idp!.baseUrl))).toBe(true);
    expect(stepUp.returnedTo).toBe("/");
    const after = await getJson(driver, `${a.base}/sensitive`);
    expect(after.status).toBe(200);
    expect(after.body).toMatchObject({ sub: before.sub, acr: LOA4 });
    const token = (await getJson(driver, `${a.base}/token`)).body.token as string;
    expect(decodeJwt(token).acr).toBe(LOA4);
  });

  it("ends the session when Portvakt is down and the outage grace is 0", async () => {
    const tenant = await createTenant(repos, "sdk-down0");
    await createFederatedLoginMethod(ts!, idp!, tenant, "entra");
    const a = await startApp(tenant, { grace: 0 });
    const driver = new FlowDriver(ts!, idp!);
    await signIn(driver, a, { persona: "anna-handlaggare" });
    expect((await getJson(driver, `${a.base}/call-api`)).status).toBe(200);
    a.setDown(true);
    // Local token validation (cached keys) keeps working while the access token is valid.
    expect((await getJson(driver, `${a.base}/call-api`)).status).toBe(200);
    const refresh = await getJson(driver, `${a.base}/token?min=3600`);
    expect(refresh.status).toBe(401);
    expect((await getJson(driver, `${a.base}/private`)).status).toBe(401);
  });

  it("keeps the session within the outage grace and refreshes once Portvakt is back", async () => {
    const tenant = await createTenant(repos, "sdk-down60");
    await createFederatedLoginMethod(ts!, idp!, tenant, "entra");
    const a = await startApp(tenant, { grace: 60 });
    const driver = new FlowDriver(ts!, idp!);
    await signIn(driver, a, { persona: "anna-handlaggare" });
    const original = (await getJson(driver, `${a.base}/token`)).body.token;
    a.setDown(true);
    const during = await getJson(driver, `${a.base}/token?min=3600`);
    expect(during).toEqual({ status: 503, body: { error: "portvakt_unavailable" } });
    expect((await getJson(driver, `${a.base}/private`)).status).toBe(200);
    // A new sign-in (an application that never reached Portvakt) fails with a clear page.
    const cold = await startApp(tenant, { grace: 60 });
    cold.setDown(true);
    const page = await new TestBrowser().request(`${cold.base}/auth/login`);
    expect(page.status).toBe(503);
    expect(await page.text()).toContain("portvakt_unavailable");
    a.setDown(false);
    const refreshed = await getJson(driver, `${a.base}/token?min=3600`);
    expect(refreshed.status).toBe(200);
    expect(refreshed.body.token).not.toBe(original);
  });
});
