import { decodeJwt } from "jose";
import * as client from "openid-client";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { RepresentationMode } from "../domain/application.js";
import type { RepresentationSourceId } from "../domain/representation.js";
import type { Tenant } from "../domain/tenant.js";
import { createLogger } from "../logging/logger.js";
import { createLoginMethod, createTenant, login, TEST_ORGNR } from "../testing/fixtures.js";
import {
  authorizationRequest,
  createFederatedLoginMethod,
  FlowDriver,
  redeem,
  startTestIdp,
  type Landing,
} from "../testing/federation.js";
import { createTestClient, discoverWithSecret, type TestClient } from "../testing/oidc-flow.js";
import { startTestServer } from "../testing/test-server.js";
import { choiceFor, partyOptionView, RepresentationRegistry } from "./registry.js";
import { InternalRepresentationSource, type RepresentationSource } from "./source.js";

const ts = await startTestServer();
const idp = ts === undefined ? undefined : await startTestIdp();

/** Personas of the mock BankID issuer (apps/mock-idp/personas.json). */
const SVEN_PIN = "191212121212";
const SAMUEL_PIN = "199001612382";
const PROTECTED_PIN = "200001010008";

async function oauthError(promise: Promise<unknown>): Promise<string> {
  try {
    await promise;
  } catch (error) {
    if (error instanceof client.ResponseBodyError) return error.error;
    throw error;
  }
  throw new Error("expected the request to fail");
}

describe.skipIf(ts === undefined)("representation (ombud)", () => {
  const { repos } = ts!.db;

  afterEach(() => {
    vi.useRealTimers();
  });

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

  /** A tenant with one citizen method (SSO allowed) and two applications. */
  async function world(prefix: string, modes: [RepresentationMode, RepresentationMode]) {
    const tenant = await createTenant(repos, prefix);
    const method = await createFederatedLoginMethod(ts!, idp!, tenant, "bankid", {
      sessionPolicy: { maxAgeSeconds: 3600, idleSeconds: 900, allowSso: true },
      trustPinForRepresentation: true,
    });
    const [a, b] = [await app(tenant, modes[0]), await app(tenant, modes[1])];
    const org = await repos.parties.create(tenant.id, {
      type: "organisation",
      identifier: TEST_ORGNR,
      displayName: "Bygg AB",
    });
    const person = await repos.parties.create(tenant.id, {
      type: "person",
      identifier: SAMUEL_PIN,
      displayName: "Samuel Samordning",
    });
    return { tenant, method, a, b, org, person };
  }

  /** Grant for Sven (by personal identity number: he need not have signed in yet). */
  async function grantForSven(
    tenantId: string,
    partyId: string,
    extra: { applicationIds?: string[]; validTo?: Date } = {},
  ) {
    return repos.grants.create(tenantId, {
      agent: { pin: SVEN_PIN },
      partyId,
      allApplications: extra.applicationIds === undefined,
      applicationIds: extra.applicationIds ?? [],
      ...(extra.validTo === undefined ? {} : { validTo: extra.validTo }),
    });
  }

  /** Authorizes `target`; signs `persona` in if the IdP asks; stops at the chooser or the app. */
  async function start(
    driver: FlowDriver,
    target: App,
    persona: string | undefined,
    params: Record<string, string> = {},
  ) {
    const request = await authorizationRequest(target.config, target.redirectUri, params);
    let landing: Landing = await driver.follow(request.url.href);
    const upstreamLogin = landing.kind === "idp_page";
    if (landing.kind === "idp_page") {
      if (persona === undefined) throw new Error("an upstream login was not expected");
      landing = await driver.persona(landing, persona);
    }
    return { request, landing, upstreamLogin };
  }

  const isChooser = (landing: Landing): boolean =>
    landing.kind === "login_ui" && landing.bootstrap.view === "representation";

  const accessClaims = (tokens: { access_token: string }) => decodeJwt(tokens.access_token);

  const audits = async (tenant: Tenant, action: string) =>
    (await repos.audit.query({ tenantId: tenant.id }, { actions: [action] })).events;

  it("offers myself and the parties of a grant made out to a pin before the first login", async () => {
    const w = await world("rep-opt", ["optional", "none"]);
    await grantForSven(w.tenant.id, w.org.id);
    await grantForSven(w.tenant.id, w.person.id);
    // A second grant for the same party: still one choice.
    await grantForSven(w.tenant.id, w.org.id);
    const driver = new FlowDriver(ts!, idp!);
    const { request, landing } = await start(driver, w.a, "sven-medborgare");
    expect(isChooser(landing)).toBe(true);
    const details = await driver.representation(landing);
    expect(details).toMatchObject({
      tenant: { name: w.tenant.name },
      application: { name: w.a.client.application.name },
      allowSelf: true,
    });
    expect(details.parties).toEqual([
      {
        id: w.org.id,
        type: "organisation",
        name: "Bygg AB",
        identifier: { kind: "organisation_number", value: "5566778899" },
      },
      {
        id: w.person.id,
        type: "person",
        name: "Samuel Samordning",
        identifier: { kind: "birth_date", value: "19900161" },
      },
    ]);
    // The full personal identity number never reaches the browser.
    expect(JSON.stringify(details)).not.toContain(SAMUEL_PIN);

    const back = await driver.chooseRepresentationAndFollow(landing, { partyId: w.org.id });
    const tokens = await redeem(w.a.config, request, back);
    const id = tokens.claims()!;
    expect(id.rep).toEqual({ sub: w.org.id, type: "organisation", name: "Bygg AB" });
    const person = await repos.persons.findIdentity(
      w.tenant.id,
      (await repos.loginMethods.listEnabled(w.tenant.id))[0]!.id,
      "bankid-sven-medborgare",
    );
    expect(id.sub).toBe(person?.personId);
    expect(id).not.toHaveProperty("act");
    const access = accessClaims(tokens);
    expect(access.sub).toBe(id.sub);
    expect(access.rep).toEqual({ sub: w.org.id, type: "organisation" });

    const [selected] = await audits(w.tenant, "representation.selected");
    expect(selected).toMatchObject({
      actor: { type: "person", id: id.sub },
      subject: { type: "party", id: w.org.id },
      details: {
        clientId: w.a.client.application.clientId,
        choice: "party",
        partyId: w.org.id,
        partyType: "organisation",
        sources: ["internal"],
      },
    });

    // The refresh keeps the representation (still valid).
    const refreshed = await client.refreshTokenGrant(w.a.config, tokens.refresh_token!);
    expect(refreshed.claims()?.rep).toEqual(id.rep);
    expect(accessClaims(refreshed).rep).toEqual({ sub: w.org.id, type: "organisation" });
  });

  it("issues no rep when the person chooses themselves, and none for a mode none app", async () => {
    const w = await world("rep-self", ["optional", "none"]);
    await grantForSven(w.tenant.id, w.org.id);
    const driver = new FlowDriver(ts!, idp!);
    const { request, landing } = await start(driver, w.a, "sven-medborgare");
    const back = await driver.chooseRepresentationAndFollow(landing, { self: true });
    const tokens = await redeem(w.a.config, request, back);
    expect(tokens.claims()).not.toHaveProperty("rep");
    expect(accessClaims(tokens)).not.toHaveProperty("rep");
    expect((await audits(w.tenant, "representation.selected"))[0]?.details).toEqual({
      clientId: w.a.client.application.clientId,
      choice: "self",
    });

    // B does not offer representation: SSO straight to the app, no chooser, no rep.
    const atB = await start(driver, w.b, undefined);
    expect(atB.upstreamLogin).toBe(false);
    expect(atB.landing.kind).toBe("app");
    const tokensB = await redeem(w.b.config, atB.request, atB.landing);
    expect(tokensB.claims()).not.toHaveProperty("rep");
  });

  it("acts as oneself without a chooser when an optional app has nobody to choose", async () => {
    const w = await world("rep-nobody", ["optional", "none"]);
    const driver = new FlowDriver(ts!, idp!);
    const { request, landing } = await start(driver, w.a, "sven-medborgare");
    expect(landing.kind).toBe("app");
    expect((await redeem(w.a.config, request, landing)).claims()).not.toHaveProperty("rep");
  });

  it("requires a party in required mode: no self choice, and an error page without grants", async () => {
    const w = await world("rep-req", ["required", "required"]);
    const driver = new FlowDriver(ts!, idp!);
    const none = await start(driver, w.a, "sven-medborgare");
    expect(none.landing).toMatchObject({
      kind: "login_ui",
      status: 403,
      bootstrap: { view: "representation", error: "no_representation_available" },
    });
    expect((await audits(w.tenant, "representation.denied"))[0]).toMatchObject({
      outcome: "failure",
      details: {
        clientId: w.a.client.application.clientId,
        reason: "no_representation_available",
      },
    });

    // With a grant the chooser offers only the party; "myself" is refused at the server too.
    await grantForSven(w.tenant.id, w.org.id);
    const { request, landing } = await start(driver, w.b, undefined);
    expect(isChooser(landing)).toBe(true);
    const details = await driver.representation(landing);
    expect(details.allowSelf).toBe(false);
    expect(details.parties.map((party) => party.id)).toEqual([w.org.id]);
    expect(await driver.chooseRepresentation(landing, { self: true })).toEqual({
      status: 403,
      body: { error: "representation_not_allowed" },
    });
    const back = await driver.chooseRepresentationAndFollow(landing, { partyId: w.org.id });
    expect((await redeem(w.b.config, request, back)).claims()?.rep).toMatchObject({
      sub: w.org.id,
    });
  });

  it("refuses a tampered party id and re-checks the right at selection time", async () => {
    const w = await world("rep-tamper", ["optional", "optional"]);
    await grantForSven(w.tenant.id, w.org.id);
    // A right for B only: not a choice for A.
    await grantForSven(w.tenant.id, w.person.id, { applicationIds: [w.b.client.application.id] });
    const driver = new FlowDriver(ts!, idp!);
    const { request, landing } = await start(driver, w.a, "sven-medborgare");
    const details = await driver.representation(landing);
    expect(details.parties.map((party) => party.id)).toEqual([w.org.id]);

    const refused = { status: 403, body: { error: "representation_not_allowed" } };
    expect(await driver.chooseRepresentation(landing, { partyId: w.person.id })).toEqual(refused);
    expect(
      await driver.chooseRepresentation(landing, {
        partyId: "00000000-0000-4000-8000-000000000000",
      }),
    ).toEqual(refused);
    expect((await driver.chooseRepresentation(landing, { partyId: "x" })).status).toBe(400);
    expect(
      (await driver.chooseRepresentation(landing, { partyId: w.org.id, self: true })).status,
    ).toBe(400);
    const denied = await audits(w.tenant, "representation.denied");
    expect(denied.map((event) => event.details)).toEqual([
      {
        clientId: w.a.client.application.clientId,
        reason: "not_allowed",
        partyId: "00000000-0000-4000-8000-000000000000",
      },
      { clientId: w.a.client.application.clientId, reason: "not_allowed", partyId: w.person.id },
    ]);

    // Without the CSRF token the choice is refused before anything else.
    const url = `${ts!.baseUrl}/t/${w.tenant.slug}/interaction/${
      landing.kind === "login_ui" && landing.bootstrap.view === "representation"
        ? landing.bootstrap.uid
        : ""
    }/representation`;
    const noToken = await driver.browser.request(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ partyId: w.org.id }),
    });
    expect(noToken.status).toBe(403);

    // Revoked between showing the chooser and choosing: refused.
    const grant = (await repos.grants.listForParty(w.tenant.id, w.org.id))[0]!;
    await repos.grants.revoke(w.tenant.id, grant.id, null);
    expect(await driver.chooseRepresentation(landing, { partyId: w.org.id })).toEqual(refused);
    const back = await driver.chooseRepresentationAndFollow(landing, { self: true });
    expect((await redeem(w.a.config, request, back)).claims()).not.toHaveProperty("rep");
  });

  it("keeps each application's choice apart under SSO; select_account switches it", async () => {
    const w = await world("rep-sso", ["optional", "optional"]);
    await grantForSven(w.tenant.id, w.org.id);
    await grantForSven(w.tenant.id, w.person.id);
    const driver = new FlowDriver(ts!, idp!);

    const atA = await start(driver, w.a, "sven-medborgare");
    const tokensA = await redeem(
      w.a.config,
      atA.request,
      await driver.chooseRepresentationAndFollow(atA.landing, { partyId: w.org.id }),
    );
    expect(tokensA.claims()?.rep).toMatchObject({ sub: w.org.id });

    // B in the same browser: SSO (no upstream login), but B's own chooser; A's choice is not
    // carried over.
    const atB = await start(driver, w.b, undefined);
    expect(atB.upstreamLogin).toBe(false);
    expect(isChooser(atB.landing)).toBe(true);
    const tokensB = await redeem(
      w.b.config,
      atB.request,
      await driver.chooseRepresentationAndFollow(atB.landing, { partyId: w.person.id }),
    );
    expect(tokensB.claims()?.rep).toEqual({
      sub: w.person.id,
      type: "person",
      name: "Samuel Samordning",
    });

    // A again: the grant's choice is reused (no chooser), B's choice changed nothing for A.
    const again = await start(driver, w.a, undefined);
    expect(again.landing.kind).toBe("app");
    expect((await redeem(w.a.config, again.request, again.landing)).claims()?.rep).toMatchObject({
      sub: w.org.id,
    });
    expect(
      (await client.refreshTokenGrant(w.a.config, tokensA.refresh_token!)).claims()?.rep,
    ).toMatchObject({ sub: w.org.id });

    // prompt=select_account re-opens A's chooser without an upstream login.
    const switching = await start(driver, w.a, undefined, { prompt: "select_account" });
    expect(switching.upstreamLogin).toBe(false);
    expect(isChooser(switching.landing)).toBe(true);
    const switched = await redeem(
      w.a.config,
      switching.request,
      await driver.chooseRepresentationAndFollow(switching.landing, { partyId: w.person.id }),
    );
    expect(switched.claims()?.rep).toMatchObject({ sub: w.person.id });
    // Another representation is another grant: A's earlier refresh tokens are revoked.
    expect(await oauthError(client.refreshTokenGrant(w.a.config, tokensA.refresh_token!))).toBe(
      "invalid_grant",
    );
    expect((await audits(w.tenant, "grant.revoked"))[0]?.details).toEqual({
      clientId: w.a.client.application.clientId,
      reason: "representation_changed",
    });
    // B is untouched.
    expect(
      (await client.refreshTokenGrant(w.b.config, tokensB.refresh_token!)).claims()?.rep,
    ).toMatchObject({ sub: w.person.id });

    // prompt=none cannot show a chooser: a third application gets account_selection_required.
    const c = await app(w.tenant, "optional");
    const silent = await authorizationRequest(c.config, c.redirectUri, { prompt: "none" });
    const silentLanding = await driver.follow(silent.url.href);
    expect(silentLanding.kind).toBe("app");
    if (silentLanding.kind === "app") {
      expect(silentLanding.url.searchParams.get("error")).toBe("account_selection_required");
    }
  });

  it("revokes the grant at refresh after the representation was revoked", async () => {
    const w = await world("rep-revoke", ["required", "none"]);
    const grant = await grantForSven(w.tenant.id, w.org.id);
    const driver = new FlowDriver(ts!, idp!);
    const { request, landing } = await start(driver, w.a, "sven-medborgare");
    const tokens = await redeem(
      w.a.config,
      request,
      await driver.chooseRepresentationAndFollow(landing, { partyId: w.org.id }),
    );
    await repos.grants.revoke(w.tenant.id, grant.id, null);
    expect(await oauthError(client.refreshTokenGrant(w.a.config, tokens.refresh_token!))).toBe(
      "invalid_grant",
    );
    const personId = tokens.claims()!.sub;
    expect((await audits(w.tenant, "token.refresh_denied"))[0]).toMatchObject({
      outcome: "failure",
      subject: { type: "person", id: personId },
      details: {
        clientId: w.a.client.application.clientId,
        reason: "representation_invalid",
      },
    });
    expect((await audits(w.tenant, "grant.revoked"))[0]?.details).toEqual({
      clientId: w.a.client.application.clientId,
      reason: "representation_invalid",
    });
    // The grant's tokens are gone with it.
    const left = await ts!.db.db.query(
      "SELECT kind FROM oidc_payloads WHERE tenant_id = $1 AND kind IN ('Grant', 'RefreshToken')",
      [w.tenant.id],
    );
    expect(left).toEqual([]);

    // The next authorization asks again: nothing left to choose in required mode.
    const next = await start(driver, w.a, undefined);
    expect(next.upstreamLogin).toBe(false);
    expect(next.landing).toMatchObject({
      kind: "login_ui",
      bootstrap: { view: "representation", error: "no_representation_available" },
    });
  });

  it("ends a representation at its validity end (refresh and re-authorization)", async () => {
    const w = await world("rep-expiry", ["optional", "none"]);
    vi.useFakeTimers({ toFake: ["Date"], shouldAdvanceTime: true });
    vi.setSystemTime(Math.ceil(Date.now() / 1000) * 1000 + 50);
    await grantForSven(w.tenant.id, w.org.id, { validTo: new Date(Date.now() + 120_000) });
    const driver = new FlowDriver(ts!, idp!);
    const { request, landing } = await start(driver, w.a, "sven-medborgare");
    const tokens = await redeem(
      w.a.config,
      request,
      await driver.chooseRepresentationAndFollow(landing, { partyId: w.org.id }),
    );
    // Within the window: the refresh works, and a re-authorization reuses the choice.
    vi.setSystemTime(Date.now() + 60_000);
    const refreshed = await client.refreshTokenGrant(w.a.config, tokens.refresh_token!);
    expect(refreshed.claims()?.rep).toMatchObject({ sub: w.org.id });
    expect((await start(driver, w.a, undefined)).landing.kind).toBe("app");

    vi.setSystemTime(Date.now() + 61_000);
    // A new authorization does not reuse it: the grant ends with its representation, and with
    // nobody left to choose (optional mode) the person acts for themselves.
    const next = await start(driver, w.a, undefined);
    expect(next.upstreamLogin).toBe(false);
    expect(next.landing.kind).toBe("app");
    expect((await redeem(w.a.config, next.request, next.landing)).claims()).not.toHaveProperty(
      "rep",
    );
    expect((await audits(w.tenant, "representation.denied"))[0]?.details).toEqual({
      clientId: w.a.client.application.clientId,
      reason: "no_longer_valid",
      partyId: w.org.id,
    });
    expect((await audits(w.tenant, "grant.revoked"))[0]?.details).toEqual({
      clientId: w.a.client.application.clientId,
      reason: "representation_invalid",
    });
    // The earlier refresh token died with that grant.
    expect(await oauthError(client.refreshTokenGrant(w.a.config, refreshed.refresh_token!))).toBe(
      "invalid_grant",
    );
  });

  it("refuses the refresh at the validity end", async () => {
    const w = await world("rep-expiry2", ["optional", "none"]);
    vi.useFakeTimers({ toFake: ["Date"], shouldAdvanceTime: true });
    vi.setSystemTime(Math.ceil(Date.now() / 1000) * 1000 + 50);
    await grantForSven(w.tenant.id, w.org.id, { validTo: new Date(Date.now() + 120_000) });
    const driver = new FlowDriver(ts!, idp!);
    const { request, landing } = await start(driver, w.a, "sven-medborgare");
    const tokens = await redeem(
      w.a.config,
      request,
      await driver.chooseRepresentationAndFollow(landing, { partyId: w.org.id }),
    );
    vi.setSystemTime(Date.now() + 121_000);
    expect(await oauthError(client.refreshTokenGrant(w.a.config, tokens.refresh_token!))).toBe(
      "invalid_grant",
    );
    expect((await audits(w.tenant, "token.refresh_denied"))[0]?.details).toEqual({
      clientId: w.a.client.application.clientId,
      reason: "representation_invalid",
    });
  });

  it("ends a representation when its application is removed from the grant", async () => {
    const w = await world("rep-app", ["optional", "optional"]);
    await grantForSven(w.tenant.id, w.org.id, { applicationIds: [w.a.client.application.id] });
    const grant2 = await grantForSven(w.tenant.id, w.person.id);
    const driver = new FlowDriver(ts!, idp!);
    const { request, landing } = await start(driver, w.a, "sven-medborgare");
    const tokens = await redeem(
      w.a.config,
      request,
      await driver.chooseRepresentationAndFollow(landing, { partyId: w.org.id }),
    );
    const [grant] = await repos.grants.listForParty(w.tenant.id, w.org.id);
    await repos.grants.setApplications(w.tenant.id, grant!.id, {
      allApplications: false,
      applicationIds: [w.b.client.application.id],
    });
    expect(await oauthError(client.refreshTokenGrant(w.a.config, tokens.refresh_token!))).toBe(
      "invalid_grant",
    );
    // Re-authorization: the chooser again, without the party (still a choice for B only).
    const next = await start(driver, w.a, undefined);
    expect(isChooser(next.landing)).toBe(true);
    expect((await driver.representation(next.landing)).parties.map((p) => p.id)).toEqual([
      grant2.party.id,
    ]);
  });

  it("omits the name of a represented person with a protected identity", async () => {
    const w = await world("rep-protected", ["optional", "none"]);
    // The protected person signs in once: the flag is sticky on their person.
    const protectedDriver = new FlowDriver(ts!, idp!);
    const own = await start(protectedDriver, w.b, "skyddad-person");
    await redeem(w.b.config, own.request, own.landing);
    const party = await repos.parties.create(w.tenant.id, {
      type: "person",
      identifier: PROTECTED_PIN,
      displayName: "Skyddad Person",
    });
    const marked = await repos.parties.create(w.tenant.id, {
      type: "person",
      identifier: "19121212-1212",
      displayName: "Marked Protected",
      protectedIdentity: true,
    });
    await grantForSven(w.tenant.id, party.id);
    await grantForSven(w.tenant.id, marked.id);

    const driver = new FlowDriver(ts!, idp!);
    const { request, landing } = await start(driver, w.a, "sven-medborgare");
    const details = await driver.representation(landing);
    for (const id of [party.id, marked.id]) {
      expect(details.parties.find((option) => option.id === id)?.identifier).toBeNull();
    }
    const tokens = await redeem(
      w.a.config,
      request,
      await driver.chooseRepresentationAndFollow(landing, { partyId: party.id }),
    );
    expect(tokens.claims()?.rep).toEqual({ sub: party.id, type: "person" });
    expect(accessClaims(tokens).rep).toEqual({ sub: party.id, type: "person" });
  });
});

describe.skipIf(ts === undefined)("RepresentationRegistry", () => {
  const { repos } = ts!.db;
  const logger = createLogger({ level: "silent" });

  it("merges sources by party, keeps every provenance, and fails closed per source", async () => {
    const tenant = await createTenant(repos, "registry");
    const application = await createTestClient(repos, tenant);
    const person = (
      await login(repos, tenant.id, await createLoginMethod(repos, tenant.id), "agent-1")
    ).person;
    const org = await repos.parties.create(tenant.id, {
      type: "organisation",
      identifier: TEST_ORGNR,
      displayName: "Örebro Bygg AB",
    });
    const other = await repos.parties.create(tenant.id, {
      type: "organisation",
      identifier: "2120000142",
      displayName: "Alingsås kommun",
    });
    const grant = await repos.grants.create(tenant.id, {
      agent: { personId: person.id },
      partyId: org.id,
      allApplications: true,
    });
    const external = "external" as RepresentationSourceId;
    const externalSource: RepresentationSource = {
      id: external,
      candidates: (query) =>
        Promise.resolve(
          query.personId === person.id
            ? [
                { party: org, source: external, reference: "ext-1", validTo: null },
                { party: other, source: external, reference: "ext-2", validTo: null },
              ]
            : [],
        ),
    };
    const failing: RepresentationSource = {
      id: "failing" as RepresentationSourceId,
      candidates: () => Promise.reject(new Error("source down")),
    };
    const registry = new RepresentationRegistry({
      sources: [new InternalRepresentationSource(repos.grants), externalSource, failing],
      persons: repos.persons,
      loginMethods: repos.loginMethods,
      logger,
    });
    const agent = { personId: person.id, loginMethodId: undefined };
    const everything: Tenant = {
      ...tenant,
      representationSources: ["internal", external, "failing" as RepresentationSourceId],
    };
    const options = await registry.options(everything, agent, application.application.id);
    // Ordered by name (Swedish collation), one entry per party.
    expect(options.map((option) => option.party.displayName)).toEqual([
      "Alingsås kommun",
      "Örebro Bygg AB",
    ]);
    expect(options[1]!.provenance).toEqual([
      { source: "internal", reference: grant.id, validTo: null },
      { source: external, reference: "ext-1", validTo: null },
    ]);
    expect(choiceFor(options[1]!)).toEqual({
      type: "party",
      partyId: org.id,
      partyType: "organisation",
      sources: ["internal", external],
    });
    // Only the tenant's enabled sources are asked.
    const internalOnly = await registry.options(tenant, agent, application.application.id);
    expect(internalOnly.map((option) => option.party.id)).toEqual([org.id]);
    expect(await registry.find(tenant, agent, application.application.id, other.id)).toBeNull();
  });

  it("masks identifiers for the chooser", () => {
    const base = {
      tenantId: "t",
      createdAt: new Date(),
      updatedAt: new Date(),
      protectedIdentity: false,
    };
    const view = (type: "person" | "organisation", identifier: string, hidden = false) =>
      partyOptionView({
        party: { ...base, id: "p", type, identifier, displayName: "N" },
        protectedIdentity: hidden,
        provenance: [],
      }).identifier;
    expect(view("organisation", "5566778899")).toEqual({
      kind: "organisation_number",
      value: "5566778899",
    });
    expect(view("person", "191212121212")).toEqual({ kind: "birth_date", value: "19121212" });
    expect(view("person", "191212121212", true)).toBeNull();
  });
});
