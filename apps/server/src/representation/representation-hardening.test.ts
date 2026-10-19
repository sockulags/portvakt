import { decodeJwt } from "jose";
import * as client from "openid-client";
import { describe, expect, it } from "vitest";
import type { RepresentationMode } from "../domain/application.js";
import type { CreateLoginMethodInput } from "../domain/login-method.js";
import type { Tenant } from "../domain/tenant.js";
import { ValidationError } from "../repositories/errors.js";
import { createTenant, TEST_ORGNR } from "../testing/fixtures.js";
import {
  authorizationRequest,
  createFederatedLoginMethod,
  FlowDriver,
  LOA2,
  redeem,
  startTestIdp,
  type Landing,
} from "../testing/federation.js";
import { createTestClient, discoverWithSecret, type TestClient } from "../testing/oidc-flow.js";
import { createSamlLoginMethod } from "../testing/saml.js";
import { startTestServer } from "../testing/test-server.js";

const ts = await startTestServer();
const idp = ts === undefined ? undefined : await startTestIdp();

const SVEN_PIN = "191212121212";
const policy = { maxAgeSeconds: 3600, idleSeconds: 900, allowSso: true };

async function oauthError(promise: Promise<unknown>): Promise<string> {
  try {
    await promise;
  } catch (error) {
    if (error instanceof client.ResponseBodyError) return error.error;
    throw error;
  }
  throw new Error("expected the request to fail");
}

describe.skipIf(ts === undefined)("representation: trust, sources and edge cases", () => {
  const { repos } = ts!.db;

  interface App {
    readonly client: TestClient;
    readonly config: client.Configuration;
    readonly redirectUri: string;
  }

  async function app(tenant: Tenant, representationMode: RepresentationMode): Promise<App> {
    const testClient = await createTestClient(repos, tenant, { representationMode });
    return {
      client: testClient,
      config: await discoverWithSecret(ts!, tenant.slug, testClient),
      redirectUri: testClient.application.redirectUris[0]!,
    };
  }

  const audits = async (tenant: Tenant, action: string) =>
    (await repos.audit.query({ tenantId: tenant.id }, { actions: [action] })).events;

  async function org(tenant: Tenant) {
    return repos.parties.create(tenant.id, {
      type: "organisation",
      identifier: TEST_ORGNR,
      displayName: "Bygg AB",
    });
  }

  /** Authorizes through the method chooser (if shown) and the persona page; stops at the chooser. */
  async function start(
    driver: FlowDriver,
    target: App,
    options: { persona?: string; methodId?: string; params?: Record<string, string> } = {},
  ) {
    const request = await authorizationRequest(target.config, target.redirectUri, options.params);
    let landing: Landing = await driver.follow(request.url.href);
    if (
      landing.kind === "login_ui" &&
      landing.bootstrap.view === "login" &&
      options.methodId !== undefined
    ) {
      landing = await driver.chooseAndFollow(landing, { loginMethodId: options.methodId });
    }
    const upstreamLogin = landing.kind === "idp_page";
    if (landing.kind === "idp_page" && options.persona !== undefined) {
      landing = await driver.persona(landing, options.persona);
    }
    return { request, landing, upstreamLogin };
  }

  const isChooser = (landing: Landing): boolean =>
    landing.kind === "login_ui" && landing.bootstrap.view === "representation";

  it("allows trusting pins for representation only on loa3+ methods that map a pin", async () => {
    const tenant = await createTenant(repos, "trust-rules");
    const { loginMethods } = ts!.portvakt.repos;
    const base: Partial<CreateLoginMethodInput> = { sessionPolicy: policy };
    // loa2 is below loa3.
    await expect(
      createFederatedLoginMethod(ts!, idp!, tenant, "bankid", {
        ...base,
        assertedAcr: LOA2,
        trustPinForRepresentation: true,
      }),
    ).rejects.toBeInstanceOf(ValidationError);
    // An employee method without a pin mapping (and an unranked acr).
    await expect(
      createFederatedLoginMethod(ts!, idp!, tenant, "entra", { trustPinForRepresentation: true }),
    ).rejects.toThrow(/map a personal identity number/);
    const trusted = await createFederatedLoginMethod(ts!, idp!, tenant, "bankid", {
      ...base,
      trustPinForRepresentation: true,
    });
    expect(trusted.trustPinForRepresentation).toBe(true);
    await expect(
      loginMethods.update(tenant.id, trusted.id, { assertedAcr: LOA2 }),
    ).rejects.toBeInstanceOf(ValidationError);
    // SAML methods always map the personal identity number; Freja asserts loa2 by default.
    await expect(
      createSamlLoginMethod(ts!, idp!, tenant, "freja", { trustPinForRepresentation: true }),
    ).rejects.toBeInstanceOf(ValidationError);
    const saml = await createSamlLoginMethod(ts!, idp!, tenant, "bankid", {
      trustPinForRepresentation: true,
    });
    expect(saml.trustPinForRepresentation).toBe(true);
  });

  it("counts a pin-addressed grant only for the pin of the current login through a trusted method", async () => {
    const tenant = await createTenant(repos, "trust-pin");
    // Both methods link by pin, so both logins are one person; only "trusted" may use pins.
    const trusted = await createFederatedLoginMethod(ts!, idp!, tenant, "bankid", {
      displayName: "Trusted BankID",
      linkByPin: true,
      trustPinForRepresentation: true,
      sessionPolicy: { ...policy, allowSso: false },
    });
    const untrusted = await createFederatedLoginMethod(ts!, idp!, tenant, "bankid", {
      displayName: "Other eID",
      linkByPin: true,
      sessionPolicy: { ...policy, allowSso: false },
    });
    const a = await app(tenant, "optional");
    const party = await org(tenant);
    await repos.grants.create(tenant.id, {
      agent: { pin: SVEN_PIN },
      partyId: party.id,
      allApplications: true,
    });

    // Not trusted: the pin grant does not count, so there is nothing to choose.
    const viaUntrusted = await start(new FlowDriver(ts!, idp!), a, {
      methodId: untrusted.id,
      persona: "sven-medborgare",
    });
    expect(viaUntrusted.landing.kind).toBe("app");
    const tokens = await redeem(a.config, viaUntrusted.request, viaUntrusted.landing);
    expect(tokens.claims()).not.toHaveProperty("rep");
    const personId = tokens.claims()!.sub;

    // Trusted: the same person now gets the party.
    const driver = new FlowDriver(ts!, idp!);
    const viaTrusted = await start(driver, a, { methodId: trusted.id, persona: "sven-medborgare" });
    expect(isChooser(viaTrusted.landing)).toBe(true);
    const chosen = await redeem(
      a.config,
      viaTrusted.request,
      await driver.chooseRepresentationAndFollow(viaTrusted.landing, { partyId: party.id }),
    );
    expect(chosen.claims()).toMatchObject({ sub: personId, rep: { sub: party.id } });

    // A later login of the same person through the untrusted method does not inherit it: the
    // linked identity's (trusted) pin is not this login's, so a new authorization offers nothing.
    const b = await app(tenant, "optional");
    const other = await start(driver, b, { methodId: untrusted.id, persona: "sven-medborgare" });
    expect(other.landing.kind).toBe("app");
    expect((await redeem(b.config, other.request, other.landing)).claims()).toMatchObject({
      sub: personId,
    });
  });

  it("re-checks pin trust at refresh: un-trusting the method ends the representation", async () => {
    const tenant = await createTenant(repos, "trust-refresh");
    const method = await createFederatedLoginMethod(ts!, idp!, tenant, "bankid", {
      sessionPolicy: policy,
      trustPinForRepresentation: true,
    });
    const a = await app(tenant, "optional");
    const party = await org(tenant);
    await repos.grants.create(tenant.id, {
      agent: { pin: SVEN_PIN },
      partyId: party.id,
      allApplications: true,
    });
    const driver = new FlowDriver(ts!, idp!);
    const first = await start(driver, a, { persona: "sven-medborgare" });
    const tokens = await redeem(
      a.config,
      first.request,
      await driver.chooseRepresentationAndFollow(first.landing, { partyId: party.id }),
    );
    await ts!.portvakt.repos.loginMethods.update(tenant.id, method.id, {
      trustPinForRepresentation: false,
    });
    expect(await oauthError(client.refreshTokenGrant(a.config, tokens.refresh_token!))).toBe(
      "invalid_grant",
    );
  });

  it("offers nothing from a tenant with no representation sources", async () => {
    const tenant = await createTenant(repos, "no-sources");
    await ts!.portvakt.repos.tenants.update(tenant.id, { representationSources: [] });
    await createFederatedLoginMethod(ts!, idp!, tenant, "bankid", {
      sessionPolicy: policy,
      trustPinForRepresentation: true,
    });
    const optional = await app(tenant, "optional");
    const required = await app(tenant, "required");
    const party = await org(tenant);
    await repos.grants.create(tenant.id, {
      agent: { pin: SVEN_PIN },
      partyId: party.id,
      allApplications: true,
    });
    const driver = new FlowDriver(ts!, idp!);
    const atOptional = await start(driver, optional, { persona: "sven-medborgare" });
    expect(atOptional.landing.kind).toBe("app");
    const atRequired = await start(driver, required);
    expect(atRequired.landing).toMatchObject({
      kind: "login_ui",
      bootstrap: { view: "representation", error: "no_representation_available" },
    });
  });

  it("ignores prompt=select_account for an application without representation", async () => {
    const tenant = await createTenant(repos, "select-none");
    await createFederatedLoginMethod(ts!, idp!, tenant, "bankid", {
      sessionPolicy: policy,
      trustPinForRepresentation: true,
    });
    const none = await app(tenant, "none");
    const party = await org(tenant);
    await repos.grants.create(tenant.id, {
      agent: { pin: SVEN_PIN },
      partyId: party.id,
      allApplications: true,
    });
    const driver = new FlowDriver(ts!, idp!);
    const first = await start(driver, none, { persona: "sven-medborgare" });
    await redeem(none.config, first.request, first.landing);
    const again = await start(driver, none, { params: { prompt: "select_account" } });
    expect(again.upstreamLogin).toBe(false);
    expect(again.landing.kind).toBe("app");
    expect((await redeem(none.config, again.request, again.landing)).claims()).not.toHaveProperty(
      "rep",
    );
  });

  it("denies a code exchange and a refresh when the right ends in between", async () => {
    const tenant = await createTenant(repos, "code-revoke");
    await createFederatedLoginMethod(ts!, idp!, tenant, "bankid", {
      sessionPolicy: policy,
      trustPinForRepresentation: true,
    });
    const a = await app(tenant, "required");
    const party = await org(tenant);
    const grant = await repos.grants.create(tenant.id, {
      agent: { pin: SVEN_PIN },
      partyId: party.id,
      allApplications: true,
    });
    const driver = new FlowDriver(ts!, idp!);
    const first = await start(driver, a, { persona: "sven-medborgare" });
    const back = await driver.chooseRepresentationAndFollow(first.landing, { partyId: party.id });
    // Revoked after the authorization, before the code is redeemed.
    await repos.grants.revoke(tenant.id, grant.id, null);
    expect(await oauthError(redeem(a.config, first.request, back))).toBe("invalid_grant");
    const [denied] = await audits(tenant, "token.exchange_denied");
    expect(denied).toMatchObject({
      outcome: "failure",
      details: { clientId: a.client.application.clientId, reason: "representation_invalid" },
    });
    expect((await audits(tenant, "grant.revoked"))[0]?.details).toMatchObject({
      reason: "representation_invalid",
    });
    expect(await audits(tenant, "token.issued")).toEqual([]);
  });

  it("ends the representation when its party is deleted", async () => {
    const tenant = await createTenant(repos, "party-delete");
    await createFederatedLoginMethod(ts!, idp!, tenant, "bankid", {
      sessionPolicy: policy,
      trustPinForRepresentation: true,
    });
    const a = await app(tenant, "optional");
    const party = await org(tenant);
    await repos.grants.create(tenant.id, {
      agent: { pin: SVEN_PIN },
      partyId: party.id,
      allApplications: true,
    });
    const driver = new FlowDriver(ts!, idp!);
    const first = await start(driver, a, { persona: "sven-medborgare" });
    const tokens = await redeem(
      a.config,
      first.request,
      await driver.chooseRepresentationAndFollow(first.landing, { partyId: party.id }),
    );
    expect(decodeJwt(tokens.access_token).rep).toMatchObject({ sub: party.id });
    expect(await repos.parties.delete(tenant.id, party.id)).toBe(true);
    expect(await oauthError(client.refreshTokenGrant(a.config, tokens.refresh_token!))).toBe(
      "invalid_grant",
    );
    // The next authorization acts as self (nothing left), without rep.
    const next = await start(driver, a);
    expect(next.landing.kind).toBe("app");
    expect((await redeem(a.config, next.request, next.landing)).claims()).not.toHaveProperty("rep");
  });

  it("audits token issuance per grant type, without token values", async () => {
    const tenant = await createTenant(repos, "token-issued");
    await createFederatedLoginMethod(ts!, idp!, tenant, "bankid", { sessionPolicy: policy });
    const a = await app(tenant, "none");
    const driver = new FlowDriver(ts!, idp!);
    const first = await start(driver, a, { persona: "sven-medborgare" });
    const tokens = await redeem(a.config, first.request, first.landing);
    const refreshed = await client.refreshTokenGrant(a.config, tokens.refresh_token!);
    await client.clientCredentialsGrant(a.config);
    const issued = await audits(tenant, "token.issued");
    expect(issued.map((event) => event.details.grantType)).toEqual([
      "client_credentials",
      "refresh_token",
      "authorization_code",
    ]);
    expect(issued[0]!.subject).toBeNull();
    expect(issued[1]!.subject).toEqual({ type: "person", id: tokens.claims()!.sub });
    const serialized = JSON.stringify(issued);
    for (const token of [tokens.access_token, tokens.refresh_token!, refreshed.access_token]) {
      expect(serialized).not.toContain(token.slice(0, 20));
    }
  });
});
