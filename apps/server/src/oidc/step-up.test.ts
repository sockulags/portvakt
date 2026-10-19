import { decodeJwt } from "jose";
import * as client from "openid-client";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { CreateLoginMethodInput } from "../domain/login-method.js";
import type { Tenant } from "../domain/tenant.js";
import { createTenant } from "../testing/fixtures.js";
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
import { createSamlLoginMethod } from "../testing/saml.js";
import { startTestServer } from "../testing/test-server.js";

const ts = await startTestServer();
const idp = ts === undefined ? undefined : await startTestIdp();

/** maja-loa4 (mock BankID over OIDC) can authenticate up to loa4. */
const MAJA_PIN = "197811234561";
/** freja-frida (mock Freja over SAML) can authenticate with loa3 and loa2. */
const FRIDA_PIN = "198507099805";

/** Date is faked (timers stay real), so auth_time moves forward between the two logins. */
function useClock(): (seconds: number) => void {
  vi.useFakeTimers({ toFake: ["Date"], shouldAdvanceTime: true });
  vi.setSystemTime(Math.ceil(Date.now() / 1000) * 1000 + 50);
  return (seconds) => {
    vi.setSystemTime(Date.now() + seconds * 1000);
  };
}

describe.skipIf(ts === undefined)("step-up (acr_values, max_age)", () => {
  const { repos } = ts!.db;

  afterEach(() => {
    vi.useRealTimers();
  });

  interface App {
    readonly client: TestClient;
    readonly config: client.Configuration;
    readonly redirectUri: string;
  }

  async function app(
    tenant: Tenant,
    representationMode: "none" | "optional" | "required" = "none",
  ): Promise<App> {
    const testClient = await createTestClient(repos, tenant, { representationMode });
    return {
      client: testClient,
      config: await discoverWithSecret(ts!, tenant.slug, testClient),
      redirectUri: testClient.application.redirectUris[0]!,
    };
  }

  const policy = { maxAgeSeconds: 3600, idleSeconds: 900, allowSso: true };

  /** BankID (loa3) and BankID high (loa4) over OIDC; both link identities by pin. */
  async function oidcWorld(prefix: string, high: Partial<CreateLoginMethodInput> = {}) {
    const tenant = await createTenant(repos, prefix);
    const loa3 = await createFederatedLoginMethod(ts!, idp!, tenant, "bankid", {
      displayName: "BankID",
      linkByPin: true,
      sessionPolicy: policy,
    });
    const loa4 = await createFederatedLoginMethod(ts!, idp!, tenant, "bankid", {
      displayName: "BankID high",
      assertedAcr: LOA4,
      linkByPin: true,
      sessionPolicy: policy,
      ...high,
    });
    return { tenant, loa3, loa4, a: await app(tenant), b: await app(tenant) };
  }

  const audits = async (tenant: Tenant, action: string) =>
    (await repos.audit.query({ tenantId: tenant.id }, { actions: [action] })).events;

  /** Authorization of `target`: picks `methodId` in the chooser, then `persona` at the IdP. */
  async function authorize(
    driver: FlowDriver,
    target: App,
    options: {
      readonly params?: Record<string, string>;
      readonly methodId?: string;
      readonly persona?: string;
      readonly switch?: string;
    } = {},
  ) {
    const request = await authorizationRequest(target.config, target.redirectUri, options.params);
    let landing: Landing = await driver.follow(request.url.href);
    if (
      landing.kind === "login_ui" &&
      landing.bootstrap.view === "login" &&
      landing.bootstrap.error === undefined &&
      options.methodId !== undefined
    ) {
      landing = await driver.chooseAndFollow(landing, { loginMethodId: options.methodId });
    }
    const upstreamLogin = landing.kind === "idp_page";
    if (landing.kind === "idp_page" && options.persona !== undefined) {
      landing = await driver.persona(
        landing,
        options.persona,
        options.switch === undefined ? {} : { switch: options.switch },
      );
    }
    return { request, landing, upstreamLogin };
  }

  it("steps up over OIDC: same person, the app's grant gets the higher acr, the other app keeps its own", async () => {
    // The loa4 method accepts the personal identity number as login_hint.
    const w = await oidcWorld("stepup-oidc", { pinLoginHint: true });
    const advance = useClock();
    const driver = new FlowDriver(ts!, idp!);
    const first = await authorize(driver, w.a, { methodId: w.loa3.id, persona: "maja-loa4" });
    const tokensA = await redeem(w.a.config, first.request, first.landing);
    expect(tokensA.claims()).toMatchObject({ acr: LOA3, idp: w.loa3.id });
    const sub = tokensA.claims()!.sub;

    // B gets SSO with the loa3 login.
    const atB = await authorize(driver, w.b);
    expect(atB.upstreamLogin).toBe(false);
    const tokensB = await redeem(w.b.config, atB.request, atB.landing);
    expect(tokensB.claims()).toMatchObject({ acr: LOA3, sub });

    advance(30);
    // A asks for loa4: only the loa4 method qualifies, so the browser goes straight upstream,
    // with prompt=login and the person's number as login_hint (the mock signs that person in).
    // The number travels in a pushed authorization request, never in the browser's URL.
    const pushedBefore = idp!.idp.oidc("bankid").pushedAuthorizationRequests().length;
    const stepUp = await authorize(driver, w.a, { params: { acr_values: LOA4 } });
    const upstream = new URL(driver.visited.findLast((url) => url.includes("/bankid/auth?"))!);
    expect(upstream.searchParams.get("login_hint")).toBeNull();
    expect(upstream.searchParams.get("request_uri")).toMatch(/^urn:ietf:params:oauth:request_uri:/);
    expect(driver.visited.some((url) => url.includes(MAJA_PIN))).toBe(false);
    const pushed = idp!.idp.oidc("bankid").pushedAuthorizationRequests().slice(pushedBefore);
    expect(pushed).toEqual([{ clientId: w.loa4.clientId, loginHint: MAJA_PIN }]);
    const stepped = await redeem(w.a.config, stepUp.request, stepUp.landing);
    const id = stepped.claims()!;
    expect(id).toMatchObject({ sub, acr: LOA4, idp: w.loa4.id });
    expect(id.auth_time).toBeGreaterThanOrEqual((tokensA.claims()!.auth_time as number) + 30);
    const access = decodeJwt(stepped.access_token);
    expect(access).toMatchObject({ sub, acr: LOA4, auth_time: id.auth_time, idp: w.loa4.id });

    expect((await audits(w.tenant, "step_up.success"))[0]).toMatchObject({
      actor: { type: "person", id: sub },
      details: {
        clientId: w.a.client.application.clientId,
        loginMethodId: w.loa4.id,
        acr: LOA4,
        previousAcr: LOA3,
      },
    });
    expect((await audits(w.tenant, "login.success"))[0]?.details).toMatchObject({
      stepUp: true,
      acr: LOA4,
    });

    // B's grant keeps B's own login: its refresh still says loa3.
    const refreshedB = await client.refreshTokenGrant(w.b.config, tokensB.refresh_token!);
    expect(refreshedB.claims()).toMatchObject({ acr: LOA3, idp: w.loa3.id, sub });
    expect(decodeJwt(refreshedB.access_token)).toMatchObject({ acr: LOA3, idp: w.loa3.id });
    // A's refresh carries the step-up.
    const refreshedA = await client.refreshTokenGrant(w.a.config, stepped.refresh_token!);
    expect(decodeJwt(refreshedA.access_token)).toMatchObject({ acr: LOA4 });
    // And A is satisfied now: no new login for the same request.
    expect((await authorize(driver, w.a, { params: { acr_values: LOA4 } })).upstreamLogin).toBe(
      false,
    );
  });

  it("refuses a step-up that signs in another person and keeps the session", async () => {
    const w = await oidcWorld("stepup-mismatch");
    const advance = useClock();
    const driver = new FlowDriver(ts!, idp!);
    const first = await authorize(driver, w.a, { methodId: w.loa3.id, persona: "maja-loa4" });
    const sub = (await redeem(w.a.config, first.request, first.landing)).claims()!.sub;

    advance(10);
    // A fresher authentication (max_age) is a step-up of the same person too; Sven answers.
    const other = await authorize(driver, w.a, {
      params: { max_age: "5" },
      methodId: w.loa3.id,
      persona: "sven-medborgare",
    });
    expect(other.landing).toMatchObject({
      kind: "login_ui",
      bootstrap: { view: "login", error: "step_up_person_mismatch" },
    });
    const [mismatch] = await audits(w.tenant, "step_up.person_mismatch");
    expect(mismatch).toMatchObject({
      outcome: "failure",
      subject: { type: "person", id: sub },
      details: { loginMethodId: w.loa3.id, clientId: w.a.client.application.clientId },
    });
    expect(mismatch!.actor.id).not.toBe(sub);
    expect((await audits(w.tenant, "login.failure"))[0]?.details).toMatchObject({
      reason: "step_up_person_mismatch",
    });

    // The session is untouched: Maja is still signed in, without a new login.
    const after = await authorize(driver, w.a);
    expect(after.upstreamLogin).toBe(false);
    expect((await redeem(w.a.config, after.request, after.landing)).claims()).toMatchObject({
      sub,
      acr: LOA3,
    });
  });

  it("shows an error when no login method can reach the requested acr", async () => {
    const tenant = await createTenant(repos, "stepup-none");
    const method = await createFederatedLoginMethod(ts!, idp!, tenant, "bankid", {
      sessionPolicy: policy,
    });
    const a = await app(tenant);
    const driver = new FlowDriver(ts!, idp!);
    const first = await authorize(driver, a, { persona: "maja-loa4" });
    const sub = (await redeem(a.config, first.request, first.landing)).claims()!.sub;

    const stepUp = await authorize(driver, a, { params: { acr_values: LOA4 } });
    expect(stepUp.landing).toMatchObject({
      kind: "login_ui",
      bootstrap: { view: "login", error: "no_acceptable_method" },
    });
    expect((await audits(tenant, "step_up.failure"))[0]).toMatchObject({
      outcome: "failure",
      subject: { type: "person", id: sub },
      details: {
        reason: "no_acceptable_method",
        clientId: a.client.application.clientId,
        requestedAcr: [LOA4],
      },
    });
    expect(method.assertedAcr).toBe(LOA3);
  });

  it("steps up over SAML with PrincipalSelection of the session's person", async () => {
    const tenant = await createTenant(repos, "stepup-saml");
    const freja = await createSamlLoginMethod(ts!, idp!, tenant, "freja", {
      sessionPolicy: policy,
    });
    const a = await app(tenant);
    const b = await app(tenant);
    const mock = idp!.idp.saml("freja");
    const advance = useClock();
    const driver = new FlowDriver(ts!, idp!);
    // The first login returns loa2 (the method asserts loa2 and requests loa3 or loa2).
    const first = await authorize(driver, a, { persona: "freja-frida", switch: "lower-loa" });
    const tokensA = await redeem(a.config, first.request, first.landing);
    expect(tokensA.claims()).toMatchObject({ acr: LOA2, idp: freja.id });
    expect(mock.requests().at(-1)!.principalPin).toBeUndefined();
    const sub = tokensA.claims()!.sub;
    const atB = await authorize(driver, b);
    const tokensB = await redeem(b.config, atB.request, atB.landing);

    advance(20);
    const stepUp = await authorize(driver, a, {
      params: { acr_values: LOA3 },
      persona: "freja-frida",
    });
    const sent = mock.requests().at(-1)!;
    expect(sent).toMatchObject({
      requestedLoa: [LOA3],
      forceAuthn: true,
      principalPin: FRIDA_PIN,
      binding: "post",
    });
    const stepped = await redeem(a.config, stepUp.request, stepUp.landing);
    expect(stepped.claims()).toMatchObject({ sub, acr: LOA3 });
    expect(stepped.claims()!.auth_time).toBeGreaterThan(tokensA.claims()!.auth_time as number);
    expect(decodeJwt(stepped.access_token)).toMatchObject({ acr: LOA3 });
    expect((await audits(tenant, "step_up.success"))[0]?.details).toMatchObject({
      acr: LOA3,
      previousAcr: LOA2,
    });
    // B keeps loa2.
    const refreshedB = await client.refreshTokenGrant(b.config, tokensB.refresh_token!);
    expect(refreshedB.claims()).toMatchObject({ acr: LOA2 });

    // Another person at the IdP is refused there (UnknownPrincipal): nothing changes.
    advance(20);
    const other = await authorize(driver, a, {
      params: { acr_values: LOA3, max_age: "1" },
      persona: "freja-fredrik-loa2",
    });
    expect(other.landing).toMatchObject({
      kind: "login_ui",
      bootstrap: { view: "login", error: "account_not_allowed" },
    });
  });

  /** ID token and access token of one response carry the same login. */
  function expectSameLogin(tokens: { claims(): unknown; access_token: string }) {
    const id = tokens.claims() as Record<string, unknown>;
    const access = decodeJwt(tokens.access_token);
    expect({ acr: access.acr, auth_time: access.auth_time, idp: access.idp }).toEqual({
      acr: id.acr,
      auth_time: id.auth_time,
      idp: id.idp,
    });
    return id;
  }

  async function orgFor(tenant: Tenant, personId: string) {
    const party = await repos.parties.create(tenant.id, {
      type: "organisation",
      identifier: "556677-8899",
      displayName: "Bygg AB",
    });
    await repos.grants.create(tenant.id, {
      agent: { personId },
      partyId: party.id,
      allApplications: true,
    });
    return party;
  }

  it("keeps ID and access token in step when a chooser after a fresh login is abandoned", async () => {
    const w = await oidcWorld("abandon-fresh");
    const chooserApp = await app(w.tenant, "optional");
    // A first login creates the person; then they get a party, so the next login shows a chooser.
    const seed = await authorize(new FlowDriver(ts!, idp!), w.b, {
      methodId: w.loa3.id,
      persona: "maja-loa4",
    });
    const sub = (await redeem(w.b.config, seed.request, seed.landing)).claims()!.sub;
    await orgFor(w.tenant, sub);

    const driver = new FlowDriver(ts!, idp!);
    const abandoned = await authorize(driver, chooserApp, {
      methodId: w.loa4.id,
      persona: "maja-loa4",
    });
    expect(abandoned.landing).toMatchObject({ bootstrap: { view: "representation" } });
    // The person walks away from the chooser and opens another application: SSO with the login
    // that just happened, the same in both tokens.
    const atB = await authorize(driver, w.b);
    expect(atB.upstreamLogin).toBe(false);
    const id = expectSameLogin(await redeem(w.b.config, atB.request, atB.landing));
    expect(id).toMatchObject({ sub, acr: LOA4, idp: w.loa4.id });
  });

  it("keeps ID and access token in step when the chooser after a step-up is abandoned", async () => {
    const w = await oidcWorld("abandon-stepup");
    const chooserApp = await app(w.tenant, "optional");
    const advance = useClock();
    const driver = new FlowDriver(ts!, idp!);
    const first = await authorize(driver, chooserApp, {
      methodId: w.loa3.id,
      persona: "maja-loa4",
    });
    const sub = (await redeem(chooserApp.config, first.request, first.landing)).claims()!.sub;
    await orgFor(w.tenant, sub);

    advance(10);
    const stepUp = await authorize(driver, chooserApp, {
      params: { acr_values: LOA4 },
      persona: "maja-loa4",
    });
    expect(stepUp.landing).toMatchObject({ bootstrap: { view: "representation" } });
    // Abandoned: no step_up.success (the application never got the higher acr) ...
    expect(await audits(w.tenant, "step_up.success")).toEqual([]);
    // ... but the session is the step-up login now, consistently in both tokens.
    const atB = await authorize(driver, w.b);
    expect(atB.upstreamLogin).toBe(false);
    const id = expectSameLogin(await redeem(w.b.config, atB.request, atB.landing));
    expect(id).toMatchObject({ sub, acr: LOA4, idp: w.loa4.id });
  });

  it("steps up into an application that then shows its chooser", async () => {
    const w = await oidcWorld("stepup-chooser");
    const chooserApp = await app(w.tenant, "optional");
    const advance = useClock();
    const driver = new FlowDriver(ts!, idp!);
    const first = await authorize(driver, chooserApp, {
      methodId: w.loa3.id,
      persona: "maja-loa4",
    });
    const sub = (await redeem(chooserApp.config, first.request, first.landing)).claims()!.sub;
    const party = await orgFor(w.tenant, sub);

    advance(10);
    const stepUp = await authorize(driver, chooserApp, {
      params: { acr_values: LOA4 },
      persona: "maja-loa4",
    });
    const tokens = await redeem(
      chooserApp.config,
      stepUp.request,
      await driver.chooseRepresentationAndFollow(stepUp.landing, { partyId: party.id }),
    );
    const id = expectSameLogin(tokens);
    expect(id).toMatchObject({ sub, acr: LOA4, rep: { sub: party.id } });
    expect(await audits(w.tenant, "step_up.success")).toHaveLength(1);
    expect(await audits(w.tenant, "representation.selected")).toHaveLength(1);
  });

  it("lets the step-up method's policy govern the session (allowSso both ways)", async () => {
    // loa3 allows SSO, the loa4 step-up method does not: after the step-up, B needs a login.
    const strict = await oidcWorld("stepup-sso-off", {
      sessionPolicy: { ...policy, allowSso: false },
    });
    const one = new FlowDriver(ts!, idp!);
    const base = await authorize(one, strict.a, { methodId: strict.loa3.id, persona: "maja-loa4" });
    await redeem(strict.a.config, base.request, base.landing);
    expect((await authorize(new FlowDriver(ts!, idp!), strict.b)).landing.kind).not.toBe("app");
    const ssoBefore = await authorize(one, strict.b);
    expect(ssoBefore.landing.kind).toBe("app");
    await redeem(strict.b.config, ssoBefore.request, ssoBefore.landing);
    const stepped = await authorize(one, strict.a, {
      params: { acr_values: LOA4 },
      persona: "maja-loa4",
    });
    await redeem(strict.a.config, stepped.request, stepped.landing);
    const toB = await authorize(one, strict.b);
    expect(toB.landing.kind).not.toBe("app");

    // The other way: a loa3 method without SSO, a loa4 step-up method with it.
    const tenant = await createTenant(repos, "stepup-sso-on");
    const loa3 = await createFederatedLoginMethod(ts!, idp!, tenant, "bankid", {
      linkByPin: true,
      sessionPolicy: { ...policy, allowSso: false },
    });
    const loa4 = await createFederatedLoginMethod(ts!, idp!, tenant, "bankid", {
      displayName: "BankID high",
      assertedAcr: LOA4,
      linkByPin: true,
      sessionPolicy: policy,
    });
    const a = await app(tenant);
    const b = await app(tenant);
    const two = new FlowDriver(ts!, idp!);
    const first = await authorize(two, a, { methodId: loa3.id, persona: "maja-loa4" });
    await redeem(a.config, first.request, first.landing);
    expect((await authorize(two, b)).landing.kind).not.toBe("app");
    const up = await authorize(two, a, { params: { acr_values: LOA4 }, persona: "maja-loa4" });
    await redeem(a.config, up.request, up.landing);
    const sso = await authorize(two, b);
    expect(sso.upstreamLogin).toBe(false);
    expect(sso.landing.kind).toBe("app");
    expect((await redeem(b.config, sso.request, sso.landing)).claims()).toMatchObject({
      idp: loa4.id,
      acr: LOA4,
    });
  });

  it("leaves the pin hint out when the upstream has no PAR, and still requires the same person", async () => {
    const bankid = idp!.idp.oidc("bankid");
    bankid.advertisePushedAuthorizationRequests(false);
    try {
      // The methods discover the upstream now, without pushed_authorization_request_endpoint.
      const w = await oidcWorld("stepup-no-par", { pinLoginHint: true });
      const driver = new FlowDriver(ts!, idp!);
      const first = await authorize(driver, w.a, { methodId: w.loa3.id, persona: "maja-loa4" });
      const sub = (await redeem(w.a.config, first.request, first.landing)).claims()!.sub;
      const pushedBefore = bankid.pushedAuthorizationRequests().length;
      // No hint: the mock shows its persona page instead of signing Maja in by the number.
      const stepUp = await authorize(driver, w.a, { params: { acr_values: LOA4 } });
      expect(stepUp.landing.kind).toBe("idp_page");
      const upstream = new URL(driver.visited.findLast((url) => url.includes("/bankid/auth?"))!);
      expect(upstream.searchParams.get("login_hint")).toBeNull();
      expect(driver.visited.some((url) => url.includes(MAJA_PIN))).toBe(false);
      expect(bankid.pushedAuthorizationRequests().length).toBe(pushedBefore);
      const landing = await driver.persona(stepUp.landing, "maja-loa4");
      expect((await redeem(w.a.config, stepUp.request, landing)).claims()).toMatchObject({
        sub,
        acr: LOA4,
      });
      // Someone else at the IdP is still refused as another person (a fresher login of the
      // loa3 method, which takes the hint too: without PAR it is left out there as well).
      await repos.loginMethods.update(w.tenant.id, w.loa3.id, { pinLoginHint: true });
      const advance = useClock();
      advance(10);
      const other = await authorize(driver, w.a, {
        params: { max_age: "5" },
        methodId: w.loa3.id,
        persona: "sven-medborgare",
      });
      expect(other.landing).toMatchObject({ bootstrap: { error: "step_up_person_mismatch" } });
      expect(driver.visited.some((url) => url.includes(MAJA_PIN))).toBe(false);
    } finally {
      bankid.advertisePushedAuthorizationRequests(true);
    }
  });

  it("records only known acr values of a failed step-up, once per interaction", async () => {
    const tenant = await createTenant(repos, "stepup-arbitrary");
    await createFederatedLoginMethod(ts!, idp!, tenant, "bankid", { sessionPolicy: policy });
    const a = await app(tenant);
    const driver = new FlowDriver(ts!, idp!);
    const first = await authorize(driver, a, { persona: "maja-loa4" });
    await redeem(a.config, first.request, first.landing);

    const request = await authorizationRequest(a.config, a.redirectUri, {
      acr_values: `urn:x:made-up ${LOA4} 191212121212`,
    });
    const landing = await driver.follow(request.url.href);
    expect(landing).toMatchObject({ bootstrap: { error: "no_acceptable_method" } });
    // A reload of the same page writes nothing new.
    if (landing.kind !== "login_ui") throw new Error("expected the login UI");
    expect(await driver.follow(landing.url)).toMatchObject({
      bootstrap: { error: "no_acceptable_method" },
    });
    const failures = await audits(tenant, "step_up.failure");
    expect(failures).toHaveLength(1);
    expect(failures[0]!.details).toEqual({
      reason: "no_acceptable_method",
      clientId: a.client.application.clientId,
      requestedAcr: [LOA4],
      unknownAcr: 2,
    });
    expect(JSON.stringify(failures)).not.toContain("191212121212");
    expect(
      (await audits(tenant, "login.failure")).filter(
        (event) => event.details.reason === "no_acceptable_method",
      ),
    ).toHaveLength(1);
  });
});
