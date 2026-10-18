import { createRemoteJWKSet, jwtVerify } from "jose";
import * as client from "openid-client";
import { describe, expect, it } from "vitest";
import type { LoginMethod } from "../domain/login-method.js";
import type { Tenant } from "../domain/tenant.js";
import { METRICS } from "../metrics/registry.js";
import { createTenant, EMPLOYEE_ACR } from "../testing/fixtures.js";
import {
  authorizationRequest,
  createFederatedLoginMethod,
  FlowDriver,
  LOA2,
  LOA3,
  LOA4,
  redeem,
  startTestIdp,
  type Landing,
} from "../testing/federation.js";
import { createTestClient, discoverWithSecret, type TestClient } from "../testing/oidc-flow.js";
import { startTestServer } from "../testing/test-server.js";

const ts = await startTestServer();
const idp = ts === undefined ? undefined : await startTestIdp();

describe.skipIf(ts === undefined)("upstream federation and login", () => {
  const { repos } = ts!.db;
  const db = ts!.db.db;

  interface World {
    readonly tenant: Tenant;
    readonly app: TestClient;
    readonly config: client.Configuration;
    readonly redirectUri: string;
  }

  async function world(prefix: string, appOverrides: Parameters<typeof createTestClient>[2] = {}) {
    const tenant = await createTenant(repos, prefix);
    const app = await createTestClient(repos, tenant, appOverrides);
    const config = await discoverWithSecret(ts!, tenant.slug, app);
    return { tenant, app, config, redirectUri: app.application.redirectUris[0]! } satisfies World;
  }

  const issuer = (w: World): string => ts!.issuerOf(w.tenant.slug);
  const verifyAccessToken = async (w: World, token: string) =>
    (
      await jwtVerify(token, createRemoteJWKSet(new URL(`${issuer(w)}/jwks`)), {
        issuer: issuer(w),
        audience: w.app.application.clientId,
      })
    ).payload;

  const auditOf = async (tenant: Tenant, action: string) =>
    (await repos.audit.query({ tenantId: tenant.id }, { actions: [action] })).events;

  function expectLoginView(landing: Landing, error?: string): void {
    expect(landing.kind).toBe("login_ui");
    if (landing.kind !== "login_ui") return;
    expect(landing.bootstrap).toMatchObject({
      view: "login",
      ...(error === undefined ? {} : { error }),
    });
  }

  /** Authorization through the mock IdP's persona page (one login method: no choice). */
  async function signIn(
    w: World,
    persona: string,
    options: { params?: Record<string, string>; driver?: FlowDriver } = {},
  ) {
    const driver = options.driver ?? new FlowDriver(ts!, idp!);
    const request = await authorizationRequest(w.config, w.redirectUri, options.params);
    let landing = await driver.follow(request.url.href);
    if (landing.kind === "idp_page") landing = await driver.persona(landing, persona);
    return { driver, request, landing, tokens: await redeem(w.config, request, landing) };
  }

  it("signs an employee in just in time; a group rule gives a role in the access token", async () => {
    const w = await world("jit");
    const method = await createFederatedLoginMethod(ts!, idp!, w.tenant, "entra");
    await repos.access.createRule(w.tenant.id, {
      applicationId: w.app.application.id,
      loginMethodId: method.id,
      groupValue: "grp-handlaggare",
      role: "handlaggare",
    });
    const driver = new FlowDriver(ts!, idp!);
    const request = await authorizationRequest(w.config, w.redirectUri);
    // One login method: straight to the IdP's persona page, no login UI.
    const page = await driver.follow(request.url.href);
    expect(page.kind).toBe("idp_page");
    const tokens = await redeem(w.config, request, await driver.persona(page, "anna-handlaggare"));

    const access = await verifyAccessToken(w, tokens.access_token);
    expect(access).toMatchObject({
      sub: tokens.claims()!.sub,
      tid: w.tenant.slug,
      idp: method.id,
      idp_kind: "employee",
      acr: EMPLOYEE_ACR,
      roles: ["handlaggare"],
      attrs: {},
    });
    expect(typeof access.auth_time).toBe("number");
    for (const claim of ["name", "email", "pin", "amr", "session_exp"]) {
      expect(access).not.toHaveProperty(claim);
    }
    const idClaims = tokens.claims()!;
    expect(idClaims).toMatchObject({
      name: "Anna Andersson",
      email: "anna.andersson@kommun.example",
      idp: method.id,
      idp_kind: "employee",
      acr: EMPLOYEE_ACR,
      amr: ["pwd", "mfa"],
      roles: ["handlaggare"],
    });
    // maxAge counts from the login at Portvakt, a moment after the upstream auth_time.
    const sessionLength = (idClaims.session_exp as number) - (idClaims.auth_time as number);
    expect(sessionLength).toBeGreaterThanOrEqual(8 * 3600);
    expect(sessionLength).toBeLessThanOrEqual(8 * 3600 + 5);
    expect(idClaims).not.toHaveProperty("protected_identity");

    // The person exists now, with the upstream attributes on its identity.
    const identity = await repos.persons.findIdentity(
      w.tenant.id,
      method.id,
      "6f1c8a52-3b7e-4d2a-9c41-8e2f5b7a1d03",
    );
    expect(identity?.personId).toBe(idClaims.sub);
    expect(identity?.attributes.groups).toEqual(["grp-handlaggare", "grp-all-staff"]);
    expect(await auditOf(w.tenant, "person.created")).toHaveLength(1);
    const success = await auditOf(w.tenant, "login.success");
    expect(success[0]).toMatchObject({
      subject: { type: "person", id: idClaims.sub },
      details: { loginMethodId: method.id, clientId: w.app.application.clientId },
    });

    // A second login finds the same person.
    const again = await signIn(w, "anna-handlaggare");
    expect(again.tokens.claims()!.sub).toBe(idClaims.sub);
    expect(await auditOf(w.tenant, "person.created")).toHaveLength(1);
  });

  it("finds the home realm from the email (login_hint or the email field)", async () => {
    const w = await world("hrd");
    const entra = await createFederatedLoginMethod(ts!, idp!, w.tenant, "entra", {
      homeRealmDomains: ["kommun.example"],
    });
    const other = await createFederatedLoginMethod(ts!, idp!, w.tenant, "entra", {
      displayName: "Partner Entra",
      homeRealmDomains: ["partner.example"],
    });
    await createFederatedLoginMethod(ts!, idp!, w.tenant, "bankid");

    // Several methods and no hint: the chooser, with the email field.
    const driver = new FlowDriver(ts!, idp!);
    const request = await authorizationRequest(w.config, w.redirectUri);
    const chooser = await driver.follow(request.url.href);
    expectLoginView(chooser);
    const details = await driver.details(chooser);
    expect(details).toMatchObject({
      tenant: { name: w.tenant.name },
      application: { name: w.app.application.name },
      homeRealmDiscovery: true,
      loginHint: null,
    });
    expect(details.methods.map((m) => m.id).sort()).toHaveLength(3);
    expect(details.methods.find((m) => m.id === other.id)).toEqual({
      id: other.id,
      displayName: "Partner Entra",
      kind: "employee",
    });

    // An unknown domain is refused; a known one (in any case) goes to its method.
    expect((await driver.choose(chooser, { email: "someone@elsewhere.example" })).status).toBe(404);
    const page = await driver.chooseAndFollow(chooser, { email: "Anna.Andersson@KOMMUN.example" });
    expect(page.kind).toBe("idp_page");
    const tokens = await redeem(w.config, request, await driver.persona(page, "anna-handlaggare"));
    expect(tokens.claims()).toMatchObject({ idp: entra.id });

    // login_hint with an email: no chooser at all, and the hint reaches the IdP (which signs the
    // matching persona in).
    const hinted = await signIn(w, "unused", {
      params: { login_hint: "erik.eriksson@kommun.example" },
    });
    expect(
      hinted.driver.visited.some(
        (url) => url.includes("/interaction/") && url.includes("/details"),
      ),
    ).toBe(false);
    expect(hinted.tokens.claims()).toMatchObject({ idp: entra.id, name: "Erik Eriksson" });
  });

  it("issues the pin claim only with scope pin, only to an app allowed it, ID token only", async () => {
    const allowed = await world("pin", { allowedExtraScopes: ["pin"] });
    const method = await createFederatedLoginMethod(ts!, idp!, allowed.tenant, "bankid");
    const withPin = await signIn(allowed, "sven-medborgare", {
      params: { scope: "openid profile pin", login_hint: "sven-medborgare" },
    });
    expect(withPin.tokens.claims()).toMatchObject({
      pin: "191212121212",
      name: "Sven Medborgare",
      idp: method.id,
      idp_kind: "citizen",
      acr: LOA3,
      amr: ["mfa"],
    });
    expect(await verifyAccessToken(allowed, withPin.tokens.access_token)).not.toHaveProperty("pin");

    const withoutScope = await signIn(allowed, "sven-medborgare", {
      params: { login_hint: "sven-medborgare" },
    });
    expect(withoutScope.tokens.claims()).not.toHaveProperty("pin");

    // A samordningsnummer is a pin as well, in canonical form.
    const coordination = await signIn(allowed, "samuel-samordning", {
      params: { scope: "openid pin", login_hint: "samuel-samordning" },
    });
    expect(coordination.tokens.claims()?.pin).toBe("199001612382");

    // An application not allowed the scope cannot ask for it at all.
    const other = await createTestClient(repos, allowed.tenant);
    const otherConfig = await discoverWithSecret(ts!, allowed.tenant.slug, other);
    const refused = await new FlowDriver(ts!, idp!).follow(
      (
        await authorizationRequest(otherConfig, other.application.redirectUris[0]!, {
          scope: "openid profile pin",
        })
      ).url.href,
    );
    expect(refused.kind).toBe("app");
    if (refused.kind === "app") expect(refused.url.searchParams.get("error")).toBe("invalid_scope");
  });

  it("keeps no name or email of a protected identity and flags it in the ID token", async () => {
    const w = await world("protected", { allowedExtraScopes: ["pin"] });
    const method = await createFederatedLoginMethod(ts!, idp!, w.tenant, "bankid");
    const { tokens } = await signIn(w, "skyddad-person", {
      params: { scope: "openid profile pin", login_hint: "skyddad-person" },
    });
    const claims = tokens.claims()!;
    expect(claims).toMatchObject({ protected_identity: true, pin: "200001010008" });
    expect(claims).not.toHaveProperty("name");
    const identity = await repos.persons.findIdentity(
      w.tenant.id,
      method.id,
      "bankid-skyddad-person",
    );
    expect(identity?.attributes).toEqual({
      groups: [],
      protectedIdentity: true,
      upstreamAcr: LOA3,
    });
    expect(await verifyAccessToken(w, tokens.access_token)).not.toHaveProperty(
      "protected_identity",
    );
  });

  it("shows a retryable error when the upstream login is cancelled, and audits it", async () => {
    const w = await world("denied");
    const method = await createFederatedLoginMethod(ts!, idp!, w.tenant, "entra");
    const driver = new FlowDriver(ts!, idp!);
    const request = await authorizationRequest(w.config, w.redirectUri);
    const page = await driver.follow(request.url.href);
    const denied = await driver.persona(page, "cancel");
    expectLoginView(denied, "upstream_denied");
    const [failure] = await auditOf(w.tenant, "login.failure");
    expect(failure).toMatchObject({
      outcome: "failure",
      subject: { type: "login_method", id: method.id },
      details: { reason: "upstream_denied", upstreamError: "access_denied" },
    });

    // Retry from the error view: the same interaction, a working login.
    const again = await driver.chooseAndFollow(denied, { loginMethodId: method.id });
    const tokens = await redeem(w.config, request, await driver.persona(again, "erik-admin"));
    expect(tokens.claims()?.name).toBe("Erik Eriksson");
  });

  it("refuses a replayed or expired callback, and a state used at another tenant", async () => {
    const w = await world("replay");
    await createFederatedLoginMethod(ts!, idp!, w.tenant, "entra");
    const first = await signIn(w, "anna-handlaggare");
    const callback = first.driver.visited.find(
      (url) => url.includes("/federation/") && url.includes("/callback"),
    );
    expect(callback).toBeDefined();
    const replayed = await first.driver.follow(callback!);
    expect(replayed.kind).toBe("login_ui");
    if (replayed.kind === "login_ui") {
      // The interaction is finished, so the view says so; the replay itself is audited.
      expect(replayed.bootstrap).toMatchObject({ view: "error", code: "interaction_expired" });
    }
    expect((await auditOf(w.tenant, "login.failure"))[0]?.details).toMatchObject({
      reason: "state_replayed",
    });

    // Expired: the state outlived its lifetime before the IdP came back.
    const driver = new FlowDriver(ts!, idp!);
    const request = await authorizationRequest(w.config, w.redirectUri);
    const page = await driver.follow(request.url.href);
    await db.query(
      "UPDATE federation_states SET expires_at = now() - interval '1 second' WHERE tenant_id = $1 AND callback_at IS NULL",
      [w.tenant.id],
    );
    expectLoginView(await driver.persona(page, "anna-handlaggare"), "state_expired");

    // Tenant B's callback with tenant A's state: unknown there, and A's state stays unused.
    const b = await world("replay-b");
    const methodB = await createFederatedLoginMethod(ts!, idp!, b.tenant, "entra");
    const pendingA = new FlowDriver(ts!, idp!);
    const requestA = await authorizationRequest(w.config, w.redirectUri);
    const pageA = await pendingA.follow(requestA.url.href);
    const upstream = new URL(pendingA.visited.find((url) => url.startsWith(idp!.baseUrl))!);
    const state = upstream.searchParams.get("state")!;
    const rejected = ts!.portvakt.metrics.counter(METRICS.federationCallbackRejected, "");
    const rejectedBefore = rejected.get({ reason: "unknown_state" });
    const crossed = await new FlowDriver(ts!, idp!).follow(
      `${ts!.baseUrl}/t/${b.tenant.slug}/federation/${methodB.id}/callback?code=forged&state=${state}`,
    );
    expect(crossed).toMatchObject({
      kind: "login_ui",
      bootstrap: { view: "error", code: "state_invalid" },
    });
    // Unknown at B: anyone can send such a callback, so it is counted, never audited.
    expect(await auditOf(b.tenant, "login.failure")).toEqual([]);
    expect(rejected.get({ reason: "unknown_state" })).toBeGreaterThan(rejectedBefore);
    const tokens = await redeem(
      w.config,
      requestA,
      await pendingA.persona(pageA, "anna-handlaggare"),
    );
    expect(tokens.claims()?.tid).toBe(w.tenant.slug);
  });

  it("offers only login methods that meet the requested acr", async () => {
    const w = await world("acr");
    const loa2 = await createFederatedLoginMethod(ts!, idp!, w.tenant, "bankid", {
      displayName: "Citizen loa2",
      assertedAcr: LOA2,
    });
    const loa3 = await createFederatedLoginMethod(ts!, idp!, w.tenant, "bankid", {
      displayName: "Citizen loa3",
    });
    const employee = await createFederatedLoginMethod(ts!, idp!, w.tenant, "entra");

    const methodsFor = async (acrValues?: string) => {
      const driver = new FlowDriver(ts!, idp!);
      const request = await authorizationRequest(
        w.config,
        w.redirectUri,
        acrValues === undefined ? {} : { acr_values: acrValues },
      );
      const landing = await driver.follow(request.url.href);
      return { driver, request, landing };
    };

    const all = await methodsFor();
    expect((await all.driver.details(all.landing)).methods.map((m) => m.id).sort()).toEqual(
      [loa2.id, loa3.id, employee.id].sort(),
    );
    // Two levels requested: loa2 and up qualify, the unranked employee acr does not.
    const two = await methodsFor(`${LOA2} ${LOA4}`);
    expect((await two.driver.details(two.landing)).methods.map((m) => m.id).sort()).toEqual(
      [loa2.id, loa3.id].sort(),
    );
    // Exactly one acceptable method: no chooser. The IdP is asked for the method's level.
    const one = await methodsFor(LOA3);
    expect(one.landing.kind).toBe("idp_page");
    const upstream = new URL(one.driver.visited.find((url) => url.startsWith(idp!.baseUrl))!);
    expect(upstream.searchParams.get("acr_values")).toBe(LOA3);
    // A persona that cannot reach it: the IdP refuses, the login UI says so.
    expectLoginView(await one.driver.persona(one.landing, "lisa-loa2"), "upstream_error");
    // The unranked employee acr satisfies only itself.
    const exact = await methodsFor(EMPLOYEE_ACR);
    expect(exact.landing.kind).toBe("idp_page");
    // Nothing meets loa4.
    const none = await methodsFor(LOA4);
    expectLoginView(none.landing, "no_acceptable_method");
    expect((await none.driver.details(none.landing)).methods).toEqual([]);
  });

  it("asserts a method's acr only when the upstream acr reaches it", async () => {
    const w = await world("acr-upstream");
    // The method asserts loa4: the IdP is asked for loa4, a loa3 persona is refused there and a
    // loa4 persona signs in with it.
    await createFederatedLoginMethod(ts!, idp!, w.tenant, "bankid", { assertedAcr: LOA4 });
    const driver = new FlowDriver(ts!, idp!);
    const request = await authorizationRequest(w.config, w.redirectUri);
    const page = await driver.follow(request.url.href);
    const refused = await driver.persona(page, "sven-medborgare");
    expectLoginView(refused, "upstream_error");
    const method = (await repos.loginMethods.list(w.tenant.id))[0]!;
    const retry = await driver.chooseAndFollow(refused, { loginMethodId: method.id });
    const tokens = await redeem(w.config, request, await driver.persona(retry, "maja-loa4"));
    expect(tokens.claims()).toMatchObject({ acr: LOA4, idp: method.id });

    // An IdP that sends no (or a lower) acr than the mapping expects: insufficient assurance.
    const strict = await world("acr-missing");
    await createFederatedLoginMethod(ts!, idp!, strict.tenant, "entra", {
      claimMapping: { subject: "oid", acr: "acr" },
    });
    const strictDriver = new FlowDriver(ts!, idp!);
    const strictRequest = await authorizationRequest(strict.config, strict.redirectUri);
    const strictPage = await strictDriver.follow(strictRequest.url.href);
    expectLoginView(
      await strictDriver.persona(strictPage, "anna-handlaggare"),
      "insufficient_assurance",
    );
  });

  it("treats an Entra groups overage as no groups, and audits it", async () => {
    const w = await world("overage");
    const method = await createFederatedLoginMethod(ts!, idp!, w.tenant, "entra");
    await repos.access.createRule(w.tenant.id, {
      applicationId: w.app.application.id,
      loginMethodId: method.id,
      groupValue: "grp-handlaggare",
      role: "handlaggare",
    });
    const { tokens } = await signIn(w, "olle-overage");
    expect(tokens.claims()).toMatchObject({ name: "Olle Overage", roles: [] });
    const identity = await repos.persons.findIdentity(
      w.tenant.id,
      method.id,
      "c7b2e4a1-9f3d-4e6c-8a15-d4f7b2c9e061",
    );
    expect(identity?.attributes.groups).toEqual([]);
    expect(await auditOf(w.tenant, "login.groups_overage")).toHaveLength(1);
  });

  it("ends a login whose method was disabled mid-flow with an error", async () => {
    const w = await world("disabled");
    const method = await createFederatedLoginMethod(ts!, idp!, w.tenant, "entra");
    const driver = new FlowDriver(ts!, idp!);
    const request = await authorizationRequest(w.config, w.redirectUri);
    const page = await driver.follow(request.url.href);
    await repos.loginMethods.update(w.tenant.id, method.id, { enabled: false });
    const landing = await driver.persona(page, "anna-handlaggare");
    expectLoginView(landing, "login_method_unavailable");
    expect((await auditOf(w.tenant, "login.failure"))[0]?.details).toMatchObject({
      reason: "login_method_unavailable",
    });
    // No method left: retrying offers nothing.
    expect((await driver.details(landing)).methods).toEqual([]);
  });

  it("authenticates upstream with private_key_jwt and publishes the key for registration", async () => {
    const w = await world("pkjwt");
    const method = await createFederatedLoginMethod(ts!, idp!, w.tenant, "entra", {
      clientAuthMethod: "private_key_jwt",
    });
    const jwks = await fetch(`${ts!.baseUrl}/t/${w.tenant.slug}/federation/${method.id}/jwks`);
    expect(jwks.status).toBe(200);
    const body = (await jwks.json()) as { keys: Record<string, unknown>[] };
    expect(body.keys).toEqual([
      expect.objectContaining({ kty: "EC", alg: "ES256", kid: method.clientKeyKid }),
    ]);
    expect(body.keys[0]).not.toHaveProperty("d");
    const { tokens } = await signIn(w, "anna-handlaggare");
    expect(tokens.claims()?.idp).toBe(method.id);

    // Another tenant's path does not publish it.
    const other = await createTenant(repos, "pkjwt-other");
    expect(
      (await fetch(`${ts!.baseUrl}/t/${other.slug}/federation/${method.id}/jwks`)).status,
    ).toBe(404);
  });

  it("calls userinfo when the login method asks for it", async () => {
    const w = await world("userinfo");
    await createFederatedLoginMethod(ts!, idp!, w.tenant, "entra", { useUserinfo: true });
    const { tokens } = await signIn(w, "erik-admin");
    expect(tokens.claims()).toMatchObject({
      name: "Erik Eriksson",
      email: "erik.eriksson@kommun.example",
    });
  });

  it("shows upstream_unavailable when the IdP cannot be reached", async () => {
    const w = await world("down");
    const method = await ts!.db.repos.loginMethods.create(w.tenant.id, {
      kind: "employee",
      displayName: "Unreachable",
      issuer: "http://127.0.0.1:9/unreachable",
      clientId: "nobody",
      clientSecret: "secret-value",
      claimMapping: { subject: "sub" },
      assertedAcr: EMPLOYEE_ACR,
      sessionPolicy: { maxAgeSeconds: 3600, idleSeconds: 600, allowSso: true },
    });
    const driver = new FlowDriver(ts!, idp!);
    const request = await authorizationRequest(w.config, w.redirectUri);
    expectLoginView(await driver.follow(request.url.href), "upstream_unavailable");
    expect((await auditOf(w.tenant, "login.failure"))[0]).toMatchObject({
      subject: { id: method.id },
      details: { reason: "upstream_unavailable" },
    });
  });

  it("protects the interaction POSTs against CSRF and lets the user cancel", async () => {
    const w = await world("csrf");
    await createFederatedLoginMethod(ts!, idp!, w.tenant, "entra");
    const method = await createFederatedLoginMethod(ts!, idp!, w.tenant, "bankid");
    const driver = new FlowDriver(ts!, idp!);
    const request = await authorizationRequest(w.config, w.redirectUri);
    const chooser = await driver.follow(request.url.href);
    expectLoginView(chooser);
    const { csrfToken } = await driver.details(chooser);
    const loginUrl = `${(chooser as { url: string }).url}/login`;
    const post = (
      headers: Record<string, string>,
      body = JSON.stringify({ loginMethodId: method.id }),
    ) => driver.browser.request(loginUrl, { method: "POST", headers, body });

    expect((await post({ "content-type": "application/json" })).status).toBe(403);
    expect(
      (await post({ "content-type": "application/json", "x-csrf-token": "A".repeat(43) })).status,
    ).toBe(403);
    expect(
      (
        await post({
          "content-type": "application/json",
          "x-csrf-token": csrfToken,
          origin: "https://evil.example",
        })
      ).status,
    ).toBe(403);
    expect(
      (
        await post(
          { "content-type": "application/x-www-form-urlencoded", "x-csrf-token": csrfToken },
          `loginMethodId=${method.id}`,
        )
      ).status,
    ).toBe(403);
    // A token of another interaction does not fit this one.
    const secondDriver = new FlowDriver(ts!, idp!);
    const second = await secondDriver.follow(
      (await authorizationRequest(w.config, w.redirectUri)).url.href,
    );
    const foreignToken = (await secondDriver.details(second)).csrfToken;
    expect(foreignToken).not.toBe(csrfToken);
    expect(
      (await post({ "content-type": "application/json", "x-csrf-token": foreignToken })).status,
    ).toBe(403);
    expect(
      (
        await post({
          "content-type": "application/json",
          "x-csrf-token": csrfToken,
          origin: ts!.baseUrl,
        })
      ).status,
    ).toBe(200);

    // Cancel: back to the application with access_denied.
    const fresh = new FlowDriver(ts!, idp!);
    const cancelled = await fresh.follow(
      (await authorizationRequest(w.config, w.redirectUri)).url.href,
    );
    const token = (await fresh.details(cancelled)).csrfToken;
    const abort = await fresh.browser.request(`${(cancelled as { url: string }).url}/abort`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-csrf-token": token },
      body: "{}",
    });
    const { redirectTo } = (await abort.json()) as { redirectTo: string };
    const back = await fresh.follow(redirectTo);
    expect(back.kind).toBe("app");
    if (back.kind === "app") expect(back.url.searchParams.get("error")).toBe("access_denied");
  });

  it("rebuilds the tenant's provider when login methods change (acr values)", async () => {
    const w = await world("fingerprint");
    const discovery = async () =>
      (await (await fetch(`${issuer(w)}/.well-known/openid-configuration`)).json()) as {
        acr_values_supported?: string[];
      };
    expect((await discovery()).acr_values_supported).not.toContain("urn:portvakt:acr:custom");
    const cached = ts!.portvakt.registry.peek(w.tenant.slug);
    expect(cached).toBeDefined();
    const method: LoginMethod = await createFederatedLoginMethod(ts!, idp!, w.tenant, "entra", {
      assertedAcr: "urn:portvakt:acr:custom",
    });
    await expect.poll(() => ts!.portvakt.registry.peek(w.tenant.slug)).not.toBe(cached);
    expect((await discovery()).acr_values_supported).toContain("urn:portvakt:acr:custom");
    // And the reconcile fallback sees login method changes in the fingerprint.
    const before = (await repos.tenants.providerFingerprints([w.tenant.id])).get(w.tenant.id);
    await repos.loginMethods.update(w.tenant.id, method.id, { displayName: "Renamed" });
    const after = (await repos.tenants.providerFingerprints([w.tenant.id])).get(w.tenant.id);
    expect(after).not.toBe(before);
  });
});
