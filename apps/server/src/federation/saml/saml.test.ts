import * as client from "openid-client";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { SamlLoginMethod } from "../../domain/login-method.js";
import type { Tenant } from "../../domain/tenant.js";
import { METRICS } from "../../metrics/registry.js";
import { createTenant } from "../../testing/fixtures.js";
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
} from "../../testing/federation.js";
import { createTestClient, discoverWithSecret, type TestClient } from "../../testing/oidc-flow.js";
import { createSamlLoginMethod, spEntityId } from "../../testing/saml.js";
import { startTestServer } from "../../testing/test-server.js";

const ts = await startTestServer();
const idp = ts === undefined ? undefined : await startTestIdp();

const POST_LOGOUT = "https://app.example.test/signed-out";

describe.skipIf(ts === undefined)("SAML upstream (Swedish eID Framework)", () => {
  const { repos } = ts!.db;
  const db = ts!.db.db;

  afterEach(() => {
    vi.useRealTimers();
  });

  interface World {
    readonly tenant: Tenant;
    readonly app: TestClient;
    readonly config: client.Configuration;
    readonly redirectUri: string;
  }

  async function app(tenant: Tenant): Promise<Omit<World, "tenant">> {
    const created = await createTestClient(repos, tenant, {
      allowedExtraScopes: ["pin"],
      postLogoutRedirectUris: [POST_LOGOUT],
    });
    const config = await discoverWithSecret(ts!, tenant.slug, created);
    return { app: created, config, redirectUri: created.application.redirectUris[0]! };
  }

  async function world(prefix: string): Promise<World> {
    const tenant = await createTenant(repos, prefix);
    return { tenant, ...(await app(tenant)) };
  }

  const audits = async (tenant: Tenant, action: string) =>
    (await repos.audit.query({ tenantId: tenant.id }, { actions: [action] })).events;

  /** Authorization through a single SAML method: straight to the mock's persona page. */
  async function signIn(
    w: World,
    persona: string | undefined,
    options: {
      readonly params?: Record<string, string>;
      readonly driver?: FlowDriver;
      readonly switch?: string;
    } = {},
  ) {
    const driver = options.driver ?? new FlowDriver(ts!, idp!);
    const request = await authorizationRequest(w.config, w.redirectUri, {
      scope: "openid profile pin",
      ...options.params,
    });
    let landing = await driver.follow(request.url.href);
    if (landing.kind === "idp_page" && persona !== undefined) {
      landing = await driver.persona(
        landing,
        persona,
        options.switch === undefined ? {} : { switch: options.switch },
      );
    }
    return { driver, request, landing };
  }

  async function signedIn(w: World, persona: string, options: Parameters<typeof signIn>[2] = {}) {
    const result = await signIn(w, persona, options);
    return { ...result, tokens: await redeem(w.config, result.request, result.landing) };
  }

  function expectError(landing: Landing, code: string): void {
    expect(landing.kind).toBe("login_ui");
    if (landing.kind !== "login_ui") return;
    expect(landing.bootstrap).toMatchObject({ view: "login", error: code });
  }

  /** No broker session: a silent authorization answers login_required. */
  async function expectNoSession(w: World, driver: FlowDriver): Promise<void> {
    const request = await authorizationRequest(w.config, w.redirectUri, { prompt: "none" });
    const landing = await driver.follow(request.url.href);
    expect(landing.kind).toBe("app");
    if (landing.kind === "app")
      expect(landing.url.searchParams.get("error")).toBe("login_required");
  }

  const lastFailure = async (tenant: Tenant) => (await audits(tenant, "login.failure")).at(0);
  const mock = (flavour: "bankid" | "freja" | "siths") => idp!.idp.saml(flavour);

  describe("logins and claims", () => {
    it("signs a BankID-style citizen in: encrypted assertion, LoA3, pin keyed by blind index", async () => {
      const w = await world("saml-bankid");
      const method = await createSamlLoginMethod(ts!, idp!, w.tenant, "bankid");
      const { tokens } = await signedIn(w, "saml-sven");
      const claims = tokens.claims()!;
      expect(claims).toMatchObject({
        idp: method.id,
        idp_kind: "citizen",
        acr: LOA3,
        amr: ["fed"],
        name: "Sven Medborgare",
        pin: "191212121212",
      });
      expect(claims).not.toHaveProperty("protected_identity");

      // The SP sent a signed AuthnRequest (HTTP-Redirect) with the framework's LoA, no ForceAuthn.
      const sent = mock("bankid").requests().at(-1)!;
      expect(sent).toMatchObject({
        spEntityId: spEntityId(ts!, w.tenant, method),
        binding: "redirect",
        forceAuthn: false,
        requestedLoa: [LOA3],
        comparison: "exact",
      });

      // The identity is keyed by the pin's blind index, never by the number itself.
      const identities = await repos.persons.listIdentities(w.tenant.id, claims.sub);
      expect(identities).toHaveLength(1);
      expect(identities[0]!.subject).toMatch(/^pin-index:[A-Za-z0-9_-]{43}$/);
      expect(JSON.stringify(identities)).not.toContain("191212121212");
      const [row] = await db.query<{ subject: string }>(
        "SELECT subject FROM identities WHERE tenant_id = $1",
        [w.tenant.id],
      );
      expect(row?.subject).not.toContain("1912");

      // A second login (new browser) finds the same person.
      const again = await signedIn(w, "saml-sven");
      expect(again.tokens.claims()!.sub).toBe(claims.sub);
    });

    it("signs Freja-style citizens in at LoA3 and LoA2 and asserts the returned level", async () => {
      const w = await world("saml-freja");
      await createSamlLoginMethod(ts!, idp!, w.tenant, "freja");
      const frida = await signedIn(w, "freja-frida");
      expect(frida.tokens.claims()).toMatchObject({
        acr: LOA3,
        name: "Frida Freja",
        pin: "198507099805",
      });
      expect(mock("freja").requests().at(-1)!.requestedLoa).toEqual([LOA3, LOA2]);
      const fredrik = await signedIn(w, "freja-fredrik-loa2");
      expect(fredrik.tokens.claims()).toMatchObject({ acr: LOA2, name: "Fredrik Basnivå" });
    });

    it("signs a SITHS-style employee in by HSA-id; a rule on the scoped orgAffiliation gives a role", async () => {
      const w = await world("saml-siths");
      const method = await createSamlLoginMethod(ts!, idp!, w.tenant, "siths");
      await repos.access.createRule(w.tenant.id, {
        applicationId: w.app.application.id,
        loginMethodId: method.id,
        groupValue: "sara@2321000016",
        role: "handlaggare",
      });
      const { tokens } = await signedIn(w, "siths-sara");
      expect(tokens.claims()).toMatchObject({
        idp_kind: "employee",
        acr: LOA3,
        name: "Sara Sjuksköterska",
        roles: ["handlaggare"],
      });
      const identity = await repos.persons.findIdentity(
        w.tenant.id,
        method.id,
        "SE2321000016-1003",
      );
      expect(identity?.attributes.groups).toEqual(["sara@2321000016"]);

      // orgAffiliation values outside the IdP's shibmd:Scope are not accepted.
      await signedIn(w, "siths-lars");
      const lars = await repos.persons.findIdentity(w.tenant.id, method.id, "SE2321000016-2044");
      expect(lars?.attributes.groups).toEqual(["lars@2321000016"]);
      expect(lars?.pinIndex).toBeNull();
    });

    it("identifies a person by prid (subject source prid, no personal identity number)", async () => {
      const w = await world("saml-prid");
      const method = await createSamlLoginMethod(ts!, idp!, w.tenant, "freja", {
        assertedAcr: "http://id.swedenconnect.se/loa/1.0/loa3-nonresident",
        saml: {
          requestedLoa: ["http://id.swedenconnect.se/loa/1.0/loa3-nonresident"],
          subjectSource: "prid",
        },
      });
      const { tokens } = await signedIn(w, "freja-ingrid-foreign");
      expect(tokens.claims()).toMatchObject({ name: "Ingrid Nordmann" });
      expect(tokens.claims()).not.toHaveProperty("pin");
      expect(
        await repos.persons.findIdentity(w.tenant.id, method.id, "NO:5068907693"),
      ).not.toBeNull();
    });

    it("accepts unencrypted assertions only when the login method allows them", async () => {
      const w = await world("saml-plain");
      const strict = await createSamlLoginMethod(ts!, idp!, w.tenant, "bankid");
      await mock("bankid").registerSp(spEntityId(ts!, w.tenant, strict), { encrypt: false });
      const refused = await signIn(w, "saml-sven");
      expectError(refused.landing, "upstream_response_invalid");
      expect((await lastFailure(w.tenant))?.details).toMatchObject({
        detail: "assertion_not_encrypted",
      });
      await expectNoSession(w, refused.driver);

      await repos.loginMethods.updateSaml(w.tenant.id, strict.id, {
        saml: { requireEncryptedAssertions: false },
      });
      const { tokens } = await signedIn(w, "saml-sven");
      expect(tokens.claims()).toMatchObject({ pin: "191212121212" });
    });

    it("sends the AuthnRequest with the HTTP-POST binding when configured", async () => {
      const w = await world("saml-post");
      await createSamlLoginMethod(ts!, idp!, w.tenant, "bankid", {
        saml: { authnRequestBinding: "post" },
      });
      const { driver, tokens } = await signedIn(w, "saml-sven");
      expect(tokens.claims()).toMatchObject({ pin: "191212121212" });
      expect(mock("bankid").requests().at(-1)!.binding).toBe("post");
      const page = driver.autoPosts.find((form) => "SAMLRequest" in form.fields);
      expect(page?.action).toBe(`${mock("bankid").entityId}/sso`);
    });
  });

  describe("mock IdP aids", () => {
    it("signs a prepared persona in without the persona page (auto-login hint)", async () => {
      const w = await world("saml-auto");
      const method = await createSamlLoginMethod(ts!, idp!, w.tenant, "siths");
      mock("siths").prepare(spEntityId(ts!, w.tenant, method), { persona: "siths-sara" });
      const { landing, request } = await signIn(w, undefined);
      expect(landing.kind).toBe("app");
      const tokens = await redeem(w.config, request, landing);
      expect(tokens.claims()).toMatchObject({ name: "Sara Sjuksköterska", idp_kind: "employee" });
    });
  });

  describe("refused responses", () => {
    const cases: readonly {
      readonly switch: string;
      readonly code: string;
      readonly detail?: string;
    }[] = [
      { switch: "cancel", code: "upstream_cancelled" },
      { switch: "authn-failed", code: "authentication_failed" },
      { switch: "wrong-audience", code: "upstream_response_invalid", detail: "audience_mismatch" },
      { switch: "expired", code: "upstream_response_invalid", detail: "assertion_expired" },
      { switch: "unsigned", code: "upstream_response_invalid", detail: "response_not_signed" },
      {
        switch: "tampered-signature",
        code: "upstream_response_invalid",
        detail: "signature_invalid",
      },
      { switch: "wrong-in-response-to", code: "state_invalid", detail: "in_response_to_mismatch" },
      { switch: "lower-loa", code: "insufficient_assurance", detail: "loa_not_met" },
      {
        switch: "multiple-assertions",
        code: "upstream_response_invalid",
        detail: "assertion_count",
      },
    ];

    for (const testCase of cases) {
      it(`refuses the "${testCase.switch}" response with ${testCase.code} and no session`, async () => {
        const w = await world(`saml-${testCase.switch.slice(0, 10)}`);
        await createSamlLoginMethod(ts!, idp!, w.tenant, "bankid", {
          saml: { requireEncryptedAssertions: testCase.switch !== "multiple-assertions" },
        });
        const { landing, driver } = await signIn(w, "saml-sven", { switch: testCase.switch });
        expectError(landing, testCase.code);
        const failure = await lastFailure(w.tenant);
        expect(failure?.details).toMatchObject({
          reason: testCase.code,
          ...(testCase.detail === undefined ? {} : { detail: testCase.detail }),
        });
        expect(JSON.stringify(failure)).not.toContain("191212121212");
        expect(await audits(w.tenant, "login.success")).toHaveLength(0);
        expect(await audits(w.tenant, "person.created")).toHaveLength(0);
        await expectNoSession(w, driver);
      });
    }

    it("refuses unsigned assertions and signature wrapping even without a signed response", async () => {
      const w = await world("saml-xsw");
      await createSamlLoginMethod(ts!, idp!, w.tenant, "bankid", {
        saml: { requireSignedResponse: false, requireEncryptedAssertions: false },
      });
      for (const name of ["unsigned", "wrapped"]) {
        const { landing } = await signIn(w, "saml-sven", { switch: name });
        expectError(landing, "upstream_response_invalid");
        expect((await lastFailure(w.tenant))?.details).toMatchObject({
          detail: "signature_invalid",
        });
      }
      expect(await audits(w.tenant, "person.created")).toHaveLength(0);
    });

    it("refuses a response posted twice (single-use RelayState)", async () => {
      const w = await world("saml-replay");
      await createSamlLoginMethod(ts!, idp!, w.tenant, "bankid");
      const first = await signedIn(w, "saml-sven");
      const response = first.driver.autoPosts.find((form) => "SAMLResponse" in form.fields)!;
      const again = await first.driver.post(response);
      // The interaction has finished, so its page is gone; the replay is audited.
      expect(again.kind).toBe("login_ui");
      if (again.kind === "login_ui") {
        expect(again.bootstrap).toMatchObject({ view: "error", code: "interaction_expired" });
      }
      expect((await lastFailure(w.tenant))?.details).toMatchObject({ reason: "state_replayed" });
      expect(await audits(w.tenant, "login.success")).toHaveLength(1);
    });

    it("refuses a replayed response and a reused assertion ID", async () => {
      const w = await world("saml-reuse");
      await createSamlLoginMethod(ts!, idp!, w.tenant, "bankid");
      await signedIn(w, "saml-sven");
      // The IdP sends its previous response again for a new request: InResponseTo is stale.
      const replay = await signIn(w, "saml-sven", { switch: "replay" });
      expectError(replay.landing, "state_invalid");
      // A fresh response that reuses the previous assertion's ID: the replay cache refuses it.
      const reuse = await signIn(w, "saml-sven", { switch: "reuse-assertion-id" });
      expectError(reuse.landing, "state_replayed");
      expect((await lastFailure(w.tenant))?.details).toMatchObject({
        detail: "assertion_replayed",
      });
    });

    it("binds a response to its own request: other login methods and tenants refuse it", async () => {
      const a = await world("saml-bind-a");
      const b = await world("saml-bind-b");
      const methodA = await createSamlLoginMethod(ts!, idp!, a.tenant, "bankid");
      const methodB = await createSamlLoginMethod(ts!, idp!, b.tenant, "bankid");
      const sameTenantB = await createSamlLoginMethod(ts!, idp!, b.tenant, "freja", {
        displayName: "Second SAML method",
      });
      expect(sameTenantB.id).not.toBe(methodB.id);

      const driverA = new FlowDriver(ts!, idp!);
      driverA.holdSamlResponses = true;
      const heldA = await signIn(a, "saml-sven", { driver: driverA });
      expect(heldA.landing.kind).toBe("auto_post");
      if (heldA.landing.kind !== "auto_post") return;
      const responseA = heldA.landing.form;

      // B's own pending request, answered with A's response: InResponseTo does not match.
      const driverB = new FlowDriver(ts!, idp!);
      driverB.holdSamlResponses = true;
      const choice = await signIn(b, undefined, { driver: driverB });
      expect(choice.landing.kind).toBe("login_ui");
      const page = await driverB.chooseAndFollow(choice.landing, { loginMethodId: methodB.id });
      const heldB = page.kind === "idp_page" ? await driverB.persona(page, "saml-sven") : page;
      expect(heldB.kind).toBe("auto_post");
      if (heldB.kind !== "auto_post") return;
      const crossed = await driverB.post({
        action: heldB.form.action,
        fields: {
          SAMLResponse: responseA.fields.SAMLResponse!,
          RelayState: heldB.form.fields.RelayState!,
        },
      });
      expectError(crossed, "state_invalid");
      expect((await lastFailure(b.tenant))?.details).toMatchObject({
        detail: "in_response_to_mismatch",
      });

      // A's response and RelayState at another tenant's (or login method's) ACS: unknown state,
      // counted, never audited.
      const counter = ts!.portvakt.metrics
        .counters()
        .find((metric) => metric.name === METRICS.federationCallbackRejected);
      const before = counter?.get({ reason: "unknown_state" }) ?? 0;
      const failuresBefore = (await audits(b.tenant, "login.failure")).length;
      for (const target of [
        `${ts!.baseUrl}/t/${b.tenant.slug}/saml/${methodA.id}/acs`,
        `${ts!.baseUrl}/t/${b.tenant.slug}/saml/${sameTenantB.id}/acs`,
        `${ts!.baseUrl}/t/${a.tenant.slug}/saml/${methodB.id}/acs`,
      ]) {
        const landing = await new FlowDriver(ts!, idp!).post({
          action: target,
          fields: responseA.fields,
        });
        expect(landing.kind).toBe("login_ui");
        if (landing.kind === "login_ui") {
          expect(landing.bootstrap).toMatchObject({ view: "error", code: "state_invalid" });
        }
      }
      expect(
        ts!.portvakt.metrics
          .counters()
          .find((m) => m.name === METRICS.federationCallbackRejected)!
          .get({ reason: "unknown_state" }),
      ).toBe(before + 3);
      expect(await audits(b.tenant, "login.failure")).toHaveLength(failuresBefore);

      // The held response still completes A's own login.
      const done = await driverA.post(responseA);
      expect((await redeem(a.config, heldA.request, done)).claims()).toMatchObject({
        pin: "191212121212",
      });
    });
  });

  describe("fresh authentication and assurance", () => {
    it("sends ForceAuthn for prompt=login and reuses the IdP session otherwise", async () => {
      const w = await world("saml-force");
      await createSamlLoginMethod(ts!, idp!, w.tenant, "freja");
      const first = await signedIn(w, "freja-frida");
      expect(mock("freja").requests().at(-1)!.forceAuthn).toBe(false);

      // A second application in the same browser (allowSso: true): broker SSO, no IdP request.
      const count = mock("freja").requests().length;
      const other = { tenant: w.tenant, ...(await app(w.tenant)) };
      const sso = await signedIn(other, "freja-frida", { driver: first.driver });
      expect(sso.tokens.claims()!.sub).toBe(first.tokens.claims()!.sub);
      expect(mock("freja").requests()).toHaveLength(count);

      // prompt=login: ForceAuthn, and the IdP asks again (its persona page) despite its session.
      const forced = await signIn(w, "freja-frida", {
        driver: first.driver,
        params: { prompt: "login" },
      });
      expect(mock("freja").requests().at(-1)!.forceAuthn).toBe(true);
      expect(forced.landing.kind).toBe("app");
    });

    it("sends ForceAuthn when allowSso=false asks another application for a fresh login", async () => {
      const w = await world("saml-nosso");
      await createSamlLoginMethod(ts!, idp!, w.tenant, "bankid");
      const first = await signedIn(w, "saml-sven");
      expect(mock("bankid").requests().at(-1)!.forceAuthn).toBe(false);
      const other = { tenant: w.tenant, ...(await app(w.tenant)) };
      const second = await signedIn(other, "saml-sven", { driver: first.driver });
      expect(mock("bankid").requests().at(-1)!.forceAuthn).toBe(true);
      expect(second.tokens.claims()!.sub).toBe(first.tokens.claims()!.sub);
    });

    it("takes auth_time from AuthnInstant and enforces max_age and ForceAuthn against it", async () => {
      vi.useFakeTimers({ toFake: ["Date"], shouldAdvanceTime: true });
      vi.setSystemTime(Math.ceil(Date.now() / 1000) * 1000 + 50);
      const w = await world("saml-maxage");
      await createSamlLoginMethod(ts!, idp!, w.tenant, "freja");
      const first = await signedIn(w, "freja-frida");
      const authnInstant = first.tokens.claims()!.auth_time as number;

      // 10 minutes later another application signs in through the IdP's SSO session: auth_time
      // is the IdP's AuthnInstant, not the time of this login.
      vi.setSystemTime(Date.now() + 600_000);
      first.driver.browser.forgetHost(new URL(ts!.baseUrl).host);
      const other = { tenant: w.tenant, ...(await app(w.tenant)) };
      const sso = await signedIn(other, "freja-frida", { driver: first.driver });
      expect(sso.tokens.claims()!.auth_time).toBe(authnInstant);

      // max_age=60: ForceAuthn, a fresh AuthnInstant, a recent auth_time.
      const fresh = await signedIn(w, "freja-frida", {
        driver: first.driver,
        params: { max_age: "60" },
      });
      expect(mock("freja").requests().at(-1)!.forceAuthn).toBe(true);
      expect(fresh.tokens.claims()!.auth_time).toBeGreaterThanOrEqual(authnInstant + 600);

      // An IdP that ignores ForceAuthn (old AuthnInstant) is refused.
      const stale = await signIn(w, "freja-frida", {
        driver: new FlowDriver(ts!, idp!),
        params: { max_age: "60" },
        switch: "stale-authn",
      });
      expectError(stale.landing, "upstream_error");
      expect((await lastFailure(w.tenant))?.details).toMatchObject({ detail: "authn_not_fresh" });
    });

    it("narrows RequestedAuthnContext to acr_values (step-up) and maps NoAuthnContext", async () => {
      const w = await world("saml-loa");
      await createSamlLoginMethod(ts!, idp!, w.tenant, "freja");
      // acr_values loa3: only loa3 is requested; a LoA2-only persona gets NoAuthnContext.
      const refused = await signIn(w, "freja-fredrik-loa2", { params: { acr_values: LOA3 } });
      expect(mock("freja").requests().at(-1)!.requestedLoa).toEqual([LOA3]);
      expectError(refused.landing, "insufficient_assurance");
      expect((await lastFailure(w.tenant))?.details).toMatchObject({
        upstreamError: "NoAuthnContext",
      });
      const stepped = await signedIn(w, "freja-frida", { params: { acr_values: LOA3 } });
      expect(stepped.tokens.claims()).toMatchObject({ acr: LOA3 });
      // A level no request can reach: the method is not offered.
      const none = await signIn(w, undefined, { params: { acr_values: LOA4 } });
      expect(none.landing.kind).toBe("login_ui");
      if (none.landing.kind === "login_ui") {
        expect(none.landing.bootstrap).toMatchObject({ error: "no_acceptable_method" });
      }
    });

    it("sends PrincipalSelection for a known person and refuses another person", async () => {
      const w = await world("saml-principal");
      const method = await createSamlLoginMethod(ts!, idp!, w.tenant, "bankid");
      const driver = new FlowDriver(ts!, idp!);
      const request = await authorizationRequest(w.config, w.redirectUri);
      const landing = await driver.follow(request.url.href);
      expect(landing.kind).toBe("idp_page");
      // The step-up hook (M4): begin with a principal for the same interaction.
      const tp = await ts!.portvakt.registry.get(w.tenant.slug);
      const uid = new URL(
        driver.visited.find((url) => url.includes("/interaction/"))!,
      ).pathname.split("/")[4]!;
      const interaction = {
        uid,
        prompt: "login",
        reasons: [],
        clientId: w.app.application.clientId,
        sessionAccountId: undefined,
        sessionUid: undefined,
        sessionAcr: undefined,
        stepUp: false,
        params: {
          acrValues: undefined,
          loginHint: undefined,
          uiLocales: undefined,
          maxAge: undefined,
        },
      };
      const url = await ts!.portvakt.federation.begin(tp!, interaction, method, {
        principalPin: "191212121212",
      });
      const page = await driver.follow(url);
      expect(mock("bankid").requests().at(-1)!).toMatchObject({
        principalPin: "191212121212",
        // A request naming a personal identity number never goes in a URL.
        binding: "post",
      });
      const other = await driver.persona(page, "saml-samuel");
      expectError(other, "account_not_allowed");
    });
  });

  describe("identity linking and protected identity", () => {
    it("links an OIDC citizen method and a SAML citizen method by personal identity number", async () => {
      const w = await world("saml-link");
      const oidc = await createFederatedLoginMethod(ts!, idp!, w.tenant, "bankid", {
        linkByPin: true,
      });
      const saml = await createSamlLoginMethod(ts!, idp!, w.tenant, "bankid", { linkByPin: true });
      const viaOidc = await (async () => {
        const driver = new FlowDriver(ts!, idp!);
        const request = await authorizationRequest(w.config, w.redirectUri, {
          scope: "openid pin",
        });
        const choice = await driver.follow(request.url.href);
        const page = await driver.chooseAndFollow(choice, { loginMethodId: oidc.id });
        return redeem(w.config, request, await driver.persona(page, "sven-medborgare"));
      })();
      const viaSaml = await (async () => {
        const driver = new FlowDriver(ts!, idp!);
        const request = await authorizationRequest(w.config, w.redirectUri, {
          scope: "openid pin",
        });
        const choice = await driver.follow(request.url.href);
        // The login UI lists SAML methods like OIDC ones (a card per method, grouped by kind).
        expect((await driver.details(choice)).methods).toEqual(
          expect.arrayContaining([
            { id: saml.id, displayName: "Mock BankID (SAML)", kind: "citizen" },
            { id: oidc.id, displayName: "Mock BankID", kind: "citizen" },
          ]),
        );
        const page = await driver.chooseAndFollow(choice, { loginMethodId: saml.id });
        return redeem(w.config, request, await driver.persona(page, "saml-sven"));
      })();
      expect(viaSaml.claims()!.sub).toBe(viaOidc.claims()!.sub);
      expect(viaSaml.claims()).toMatchObject({ idp: saml.id, pin: "191212121212" });
      expect(await audits(w.tenant, "person.identity_linked")).toHaveLength(1);
    });

    it("keeps a protected identity sticky across login methods", async () => {
      const w = await world("saml-protected");
      const saml = await createSamlLoginMethod(ts!, idp!, w.tenant, "bankid", { linkByPin: true });
      // The OIDC method maps no protected identity claim at all.
      const oidc = await createFederatedLoginMethod(ts!, idp!, w.tenant, "bankid", {
        linkByPin: true,
        claimMapping: {
          subject: "sub",
          name: "name",
          pin: "https://id.oidc.se/claim/personalIdentityNumber",
          acr: "acr",
        },
      });
      const driver = new FlowDriver(ts!, idp!);
      const request = await authorizationRequest(w.config, w.redirectUri, {
        scope: "openid profile pin",
      });
      const page = await driver.chooseAndFollow(await driver.follow(request.url.href), {
        loginMethodId: saml.id,
      });
      const viaSaml = await redeem(w.config, request, await driver.persona(page, "saml-skyddad"));
      expect(viaSaml.claims()).toMatchObject({ protected_identity: true, pin: "200001010008" });
      expect(viaSaml.claims()).not.toHaveProperty("name");

      const second = new FlowDriver(ts!, idp!);
      const request2 = await authorizationRequest(w.config, w.redirectUri, {
        scope: "openid profile pin",
      });
      const page2 = await second.chooseAndFollow(await second.follow(request2.url.href), {
        loginMethodId: oidc.id,
      });
      const viaOidc = await redeem(
        w.config,
        request2,
        await second.persona(page2, "skyddad-person"),
      );
      expect(viaOidc.claims()!.sub).toBe(viaSaml.claims()!.sub);
      expect(viaOidc.claims()).toMatchObject({ protected_identity: true });
      expect(viaOidc.claims()).not.toHaveProperty("name");
    });
  });

  describe("single logout", () => {
    async function rpLogout(w: World, driver: FlowDriver, idToken: string): Promise<Landing> {
      const url = client.buildEndSessionUrl(w.config, {
        id_token_hint: idToken,
        post_logout_redirect_uri: POST_LOGOUT,
        state: "after-logout",
      });
      const page = await driver.browser.request(url.href);
      const html = await page.text();
      const action = /<form id="op\.logoutForm" method="post" action="([^"]+)">/.exec(html)?.[1];
      const xsrf = /name="xsrf" value="([^"]+)"/.exec(html)?.[1];
      expect(action).toBeDefined();
      return driver.follow(new URL(action!, url).href, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ xsrf: xsrf!, logout: "yes" }).toString(),
      });
    }

    it("sends a LogoutRequest to the IdP on RP-initiated logout and returns to the application", async () => {
      const w = await world("saml-slo-sp");
      await createSamlLoginMethod(ts!, idp!, w.tenant, "bankid");
      const { driver, tokens } = await signedIn(w, "saml-sven");
      const landing = await rpLogout(w, driver, tokens.id_token!);
      expect(landing.kind).toBe("app");
      if (landing.kind === "app") {
        expect(`${landing.url.origin}${landing.url.pathname}`).toBe(POST_LOGOUT);
        expect(landing.url.searchParams.get("state")).toBe("after-logout");
      }
      const logout = mock("bankid").logoutRequests().at(-1)!;
      expect(logout).toMatchObject({ nameId: "bankid-nameid-7f3a9c2e51d84b06" });
      expect(logout.sessionIndex).toMatch(/^_/);
      await expectNoSession(w, driver);
      const counter = ts!.portvakt.metrics.counters().find((m) => m.name === METRICS.samlLogout)!;
      expect(counter.get({ direction: "sp_initiated", outcome: "success" })).toBeGreaterThanOrEqual(
        1,
      );
    });

    it("finishes the local logout when the IdP's LogoutResponse is not valid", async () => {
      const w = await world("saml-slo-bad");
      await createSamlLoginMethod(ts!, idp!, w.tenant, "bankid");
      const { driver, tokens } = await signedIn(w, "saml-sven");
      // Step manually: Portvakt -> IdP SLO -> (tampered) Portvakt SLO.
      const url = client.buildEndSessionUrl(w.config, {
        id_token_hint: tokens.id_token!,
        post_logout_redirect_uri: POST_LOGOUT,
      });
      const html = await (await driver.browser.request(url.href)).text();
      const action = /<form id="op\.logoutForm" method="post" action="([^"]+)">/.exec(html)![1]!;
      const xsrf = /name="xsrf" value="([^"]+)"/.exec(html)![1]!;
      const confirm = await driver.browser.request(new URL(action, url).href, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ xsrf, logout: "yes" }).toString(),
      });
      const toIdp = confirm.headers.get("location")!;
      expect(toIdp.startsWith(`${mock("bankid").entityId}/slo?SAMLRequest=`)).toBe(true);
      const back = (await driver.browser.request(toIdp)).headers.get("location")!;
      const tampered = back.replace(/Signature=[^&]+/, "Signature=AAAA");
      const final = await driver.browser.request(tampered);
      expect(final.status).toBe(303);
      expect(final.headers.get("location")).toBe(POST_LOGOUT);
      await expectNoSession(w, driver);
    });

    it("ends the broker session on an IdP-initiated LogoutRequest and answers it", async () => {
      const w = await world("saml-slo-idp");
      const method = await createSamlLoginMethod(ts!, idp!, w.tenant, "freja");
      const { driver, tokens } = await signedIn(w, "freja-frida");
      expect(tokens.refresh_token).toBeDefined();
      const url = await mock("freja").initiateLogout(spEntityId(ts!, w.tenant, method), {
        nameId: "freja-nameid-2a7c9e4b6d1f3058",
      });
      const landing = await driver.follow(url);
      expect(landing.kind).toBe("other");
      if (landing.kind === "other") expect(landing.body).toContain('data-testid="idp-logged-out"');
      expect(mock("freja").logoutResponses().at(-1)?.status).toBe(
        "urn:oasis:names:tc:SAML:2.0:status:Success",
      );
      await expect(client.refreshTokenGrant(w.config, tokens.refresh_token!)).rejects.toThrow();
      await expectNoSession(w, driver);
      expect((await audits(w.tenant, "session.logout"))[0]?.details).toMatchObject({
        initiator: "idp",
        loginMethodId: method.id,
        sessions: 1,
      });
    });

    /**
     * One browser session with two upstream SAML logins of the same person: two BankID-style
     * methods (two SPs at the same IdP) that link by personal identity number, the second login
     * forced with prompt=login.
     */
    async function twoUpstreamLogins(prefix: string) {
      const w = await world(prefix);
      const first = await createSamlLoginMethod(ts!, idp!, w.tenant, "bankid", {
        displayName: "BankID A",
        linkByPin: true,
      });
      const second = await createSamlLoginMethod(ts!, idp!, w.tenant, "bankid", {
        displayName: "BankID B",
        linkByPin: true,
      });
      const driver = new FlowDriver(ts!, idp!);
      const loginWith = async (methodId: string, params: Record<string, string> = {}) => {
        const request = await authorizationRequest(w.config, w.redirectUri, {
          scope: "openid profile pin",
          ...params,
        });
        const chooser = await driver.follow(request.url.href);
        const page = await driver.chooseAndFollow(chooser, { loginMethodId: methodId });
        return redeem(w.config, request, await driver.persona(page, "saml-sven"));
      };
      const viaFirst = await loginWith(first.id);
      const viaSecond = await loginWith(second.id, { prompt: "login" });
      expect(viaSecond.claims()).toMatchObject({ idp: second.id, sub: viaFirst.claims()!.sub });
      return { w, first, second, driver, viaFirst, viaSecond };
    }

    it("sends single logout to every upstream session of the broker session", async () => {
      const { w, first, second, driver, viaSecond } = await twoUpstreamLogins("saml-slo-two");
      const before = mock("bankid").logoutRequests().length;
      const landing = await rpLogout(w, driver, viaSecond.id_token!);
      expect(landing.kind).toBe("app");
      if (landing.kind === "app") {
        expect(`${landing.url.origin}${landing.url.pathname}`).toBe(POST_LOGOUT);
      }
      // Newest login first, then the earlier one; both name the person's upstream session.
      const sent = mock("bankid").logoutRequests().slice(before);
      expect(sent.map((request) => request.spEntityId)).toEqual([
        spEntityId(ts!, w.tenant, second),
        spEntityId(ts!, w.tenant, first),
      ]);
      expect(sent.every((request) => request.nameId === "bankid-nameid-7f3a9c2e51d84b06")).toBe(
        true,
      );
      await expectNoSession(w, driver);
    });

    it("ends the local logout and the remaining upstream logouts when one IdP fails", async () => {
      const { w, first, driver, viaSecond } = await twoUpstreamLogins("saml-slo-two-bad");
      const url = client.buildEndSessionUrl(w.config, {
        id_token_hint: viaSecond.id_token!,
        post_logout_redirect_uri: POST_LOGOUT,
      });
      const html = await (await driver.browser.request(url.href)).text();
      const action = /<form id="op\.logoutForm" method="post" action="([^"]+)">/.exec(html)![1]!;
      const xsrf = /name="xsrf" value="([^"]+)"/.exec(html)![1]!;
      const confirm = await driver.browser.request(new URL(action, url).href, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ xsrf, logout: "yes" }).toString(),
      });
      // The first IdP's answer is tampered with: Portvakt still goes on to the next upstream.
      const back = (await driver.browser.request(confirm.headers.get("location")!)).headers.get(
        "location",
      )!;
      const next = await driver.browser.request(back.replace(/Signature=[^&]+/, "Signature=AAAA"));
      expect(next.status).toBe(303);
      const toSecondIdp = next.headers.get("location")!;
      expect(toSecondIdp.startsWith(`${mock("bankid").entityId}/slo?SAMLRequest=`)).toBe(true);
      const landing = await driver.follow(toSecondIdp);
      expect(landing.kind).toBe("app");
      expect(mock("bankid").logoutRequests().at(-1)?.spEntityId).toBe(
        spEntityId(ts!, w.tenant, first),
      );
      await expectNoSession(w, driver);
    });

    it("ends the broker session on an IdP-initiated logout from an earlier upstream login", async () => {
      const { w, first, driver, viaFirst, viaSecond } = await twoUpstreamLogins("saml-slo-two-idp");
      // The latest login came through the second method; the first IdP's logout still counts.
      const url = await mock("bankid").initiateLogout(spEntityId(ts!, w.tenant, first), {
        nameId: "bankid-nameid-7f3a9c2e51d84b06",
      });
      const landing = await driver.follow(url);
      expect(landing.kind).toBe("other");
      for (const tokens of [viaFirst, viaSecond]) {
        await expect(client.refreshTokenGrant(w.config, tokens.refresh_token!)).rejects.toThrow();
      }
      await expectNoSession(w, driver);
      expect((await audits(w.tenant, "session.logout"))[0]?.details).toMatchObject({
        initiator: "idp",
        loginMethodId: first.id,
        sessions: 1,
      });
    });

    it("refuses an unsigned IdP-initiated LogoutRequest", async () => {
      const w = await world("saml-slo-unsigned");
      const method = await createSamlLoginMethod(ts!, idp!, w.tenant, "freja");
      const { driver } = await signedIn(w, "freja-frida");
      const url = await mock("freja").initiateLogout(spEntityId(ts!, w.tenant, method), {
        nameId: "freja-nameid-2a7c9e4b6d1f3058",
      });
      const unsigned = url.replace(/&Signature=[^&]+/, "").replace(/&SigAlg=[^&]+/, "");
      const response = await driver.browser.request(unsigned);
      expect(response.status).toBe(400);
      // The session is still there: a silent authorization succeeds.
      const silent = await authorizationRequest(w.config, w.redirectUri, { prompt: "none" });
      const landing = await driver.follow(silent.url.href);
      expect(landing.kind).toBe("app");
      if (landing.kind === "app") expect(landing.url.searchParams.get("code")).not.toBeNull();
    });
  });

  describe("SP metadata", () => {
    it("publishes signing and encryption certificates, ACS, SLO and entity categories", async () => {
      const w = await world("saml-meta");
      const method: SamlLoginMethod = await createSamlLoginMethod(ts!, idp!, w.tenant, "bankid", {
        saml: { requestedAttributes: [{ name: "urn:oid:1.3.6.1.5.5.7.9.1", required: false }] },
      });
      const entity = spEntityId(ts!, w.tenant, method);
      const response = await fetch(`${entity}/metadata`);
      expect(response.headers.get("content-type")).toContain("application/samlmetadata+xml");
      const xml = await response.text();
      expect(xml).toContain(`entityID="${entity}"`);
      expect(xml).toContain(`Location="${entity}/acs"`);
      expect(xml).toContain(`Location="${entity}/slo"`);
      expect(xml).toContain('AuthnRequestsSigned="true"');
      expect(xml).toContain('WantAssertionsSigned="true"');
      expect(xml).toContain("http://macedir.org/entity-category");
      expect(xml).toContain("http://id.elegnamnden.se/ec/1.0/loa3-pnr");
      expect(xml).toContain('Name="urn:oid:1.3.6.1.5.5.7.9.1"');
      expect(xml.match(/<md:KeyDescriptor use="signing">/g)).toHaveLength(1);
      expect(xml.match(/<md:KeyDescriptor use="encryption">/g)).toHaveLength(1);
      expect(xml).not.toContain("PRIVATE KEY");

      expect(
        (await fetch(`${ts!.baseUrl}/t/${w.tenant.slug}/saml/${crypto.randomUUID()}/metadata`))
          .status,
      ).toBe(404);
    });

    it("serves the signed SP metadata from a cache, built again after a key or setting change", async () => {
      const w = await world("saml-meta-cache");
      const method = await createSamlLoginMethod(ts!, idp!, w.tenant, "bankid");
      const url = `${spEntityId(ts!, w.tenant, method)}/metadata`;
      const first = await (await fetch(url)).text();
      // Every build has a fresh ID: the same bytes again means nothing was built or signed.
      expect(first).toMatch(/ID="_[^"]+"/);
      expect(await (await fetch(url)).text()).toBe(first);
      await ts!.portvakt.samlAdmin.prepareSpKeyRotation(w.tenant.id, method.id);
      const rotated = await (await fetch(url)).text();
      expect(rotated).not.toBe(first);
      expect(rotated.match(/<md:KeyDescriptor use="signing">/g)).toHaveLength(2);
      expect(await (await fetch(url)).text()).toBe(rotated);
      await ts!.portvakt.samlAdmin.update(
        w.tenant.id,
        method.id,
        { displayName: "Mock BankID (renamed)" },
        { type: "system", id: null },
      );
      expect(await (await fetch(url)).text()).not.toBe(rotated);
    });

    it("refuses an ACS post without a known RelayState without auditing it", async () => {
      const w = await world("saml-junk");
      const method = await createSamlLoginMethod(ts!, idp!, w.tenant, "bankid");
      const response = await fetch(`${spEntityId(ts!, w.tenant, method)}/acs`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ SAMLResponse: "PHg+", RelayState: "nope" }).toString(),
        redirect: "manual",
      });
      expect(response.status).toBe(303);
      expect(response.headers.get("location")).toContain("/login/error?code=state_invalid");
      expect(await audits(w.tenant, "login.failure")).toHaveLength(0);
    });
  });
});
