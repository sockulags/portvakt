import { MOCK_ENTRA_TENANT_ID, PERSONAL_IDENTITY_NUMBER_CLAIM } from "@portvakt/mock-idp";
import * as client from "openid-client";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Tenant } from "../domain/tenant.js";
import { ValidationError } from "../repositories/errors.js";
import { createTenant, EMPLOYEE_ACR } from "../testing/fixtures.js";
import {
  authorizationRequest,
  createFederatedLoginMethod,
  FlowDriver,
  LOA3,
  redeem,
  startTestIdp,
  type Landing,
} from "../testing/federation.js";
import { createTestClient, discoverWithSecret, type TestClient } from "../testing/oidc-flow.js";
import { startTestServer } from "../testing/test-server.js";

const ts = await startTestServer();
const idp = ts === undefined ? undefined : await startTestIdp();

/** The OAuth error code of a failed openid-client call. */
async function oauthError(promise: Promise<unknown>): Promise<string> {
  try {
    await promise;
  } catch (error) {
    if (error instanceof client.ResponseBodyError) return error.error;
    throw error;
  }
  throw new Error("expected the request to fail");
}

describe.skipIf(ts === undefined)("federation hardening", () => {
  const { repos } = ts!.db;
  const db = ts!.db.db;

  afterEach(() => {
    vi.useRealTimers();
  });

  interface App {
    readonly tenant: Tenant;
    readonly client: TestClient;
    readonly config: client.Configuration;
    readonly redirectUri: string;
  }

  async function app(tenant: Tenant, overrides: Parameters<typeof createTestClient>[2] = {}) {
    const testClient = await createTestClient(repos, tenant, overrides);
    return {
      tenant,
      client: testClient,
      config: await discoverWithSecret(ts!, tenant.slug, testClient),
      redirectUri: testClient.application.redirectUris[0]!,
    } satisfies App;
  }

  const auditOf = async (tenant: Tenant, action: string) =>
    (await repos.audit.query({ tenantId: tenant.id }, { actions: [action] })).events;

  function expectLoginError(landing: Landing, error: string): void {
    expect(landing).toMatchObject({ kind: "login_ui", bootstrap: { view: "login", error } });
  }

  /**
   * Authorizes `target` in the driver's browser. With several login methods, `method` is chosen
   * in the login UI; the IdP's persona page (if shown) gets `persona`.
   */
  async function signIn(
    driver: FlowDriver,
    target: App,
    persona: string,
    options: { params?: Record<string, string>; method?: string } = {},
  ) {
    const request = await authorizationRequest(target.config, target.redirectUri, options.params);
    let landing = await driver.follow(request.url.href);
    if (landing.kind === "login_ui" && options.method !== undefined) {
      landing = await driver.chooseAndFollow(landing, { loginMethodId: options.method });
    }
    if (landing.kind === "idp_page") landing = await driver.persona(landing, persona);
    return { request, landing };
  }

  async function signedIn(
    driver: FlowDriver,
    target: App,
    persona: string,
    options: { params?: Record<string, string>; method?: string } = {},
  ) {
    const { request, landing } = await signIn(driver, target, persona, options);
    return redeem(target.config, request, landing);
  }

  describe("multi-tenant upstream issuers", () => {
    it("lets only the allowed upstream tenants sign in", async () => {
      const tenant = await createTenant(repos, "mt");
      const a = await app(tenant);
      const method = await createFederatedLoginMethod(ts!, idp!, tenant, "entra-mt");
      expect(method.issuer).toMatch(/\/entra-mt\/organizations\/v2\.0$/);
      const tokens = await signedIn(new FlowDriver(ts!, idp!), a, "anna-handlaggare");
      expect(tokens.claims()).toMatchObject({ idp: method.id, name: "Anna Andersson" });

      // Another tenant's login method listing a different upstream tenant refuses the account.
      const other = await createTenant(repos, "mt-other");
      const b = await app(other);
      await createFederatedLoginMethod(ts!, idp!, other, "entra-mt", {
        allowedUpstreamTenants: ["0b1d2c3e-4f50-4a6b-8c7d-9e0f1a2b3c4d"],
      });
      const { landing } = await signIn(new FlowDriver(ts!, idp!), b, "anna-handlaggare");
      expectLoginError(landing, "account_not_allowed");
      expect((await auditOf(other, "login.failure"))[0]?.details).toMatchObject({
        reason: "account_not_allowed",
      });
      expect(await auditOf(other, "person.created")).toEqual([]);
    });

    it("refuses to save a multi-tenant issuer without allowed tenants", async () => {
      const tenant = await createTenant(repos, "mt-save");
      const input = {
        kind: "employee",
        displayName: "Entra (any tenant)",
        issuer: "https://login.microsoftonline.com/organizations/v2.0",
        clientId: "portvakt",
        clientSecret: "secret-value",
        claimMapping: { subject: "oid" },
        assertedAcr: EMPLOYEE_ACR,
        sessionPolicy: { maxAgeSeconds: 3600, idleSeconds: 600, allowSso: true },
      } as const;
      for (const issuer of [
        input.issuer,
        "https://login.microsoftonline.com/common/v2.0",
        "https://login.microsoftonline.com/consumers/v2.0",
      ]) {
        await expect(
          repos.loginMethods.create(tenant.id, { ...input, issuer }),
        ).rejects.toBeInstanceOf(ValidationError);
      }
      const method = await repos.loginMethods.create(tenant.id, {
        ...input,
        allowedUpstreamTenants: [MOCK_ENTRA_TENANT_ID],
      });
      await expect(
        repos.loginMethods.update(tenant.id, method.id, { allowedUpstreamTenants: [] }),
      ).rejects.toBeInstanceOf(ValidationError);
      const single = await repos.loginMethods.create(tenant.id, {
        ...input,
        issuer: `https://login.microsoftonline.com/${MOCK_ENTRA_TENANT_ID}/v2.0`,
      });
      await expect(
        repos.loginMethods.update(tenant.id, single.id, { issuer: input.issuer }),
      ).rejects.toBeInstanceOf(ValidationError);
    });

    it("refuses a login when discovery reveals a {tenantid} issuer the method does not restrict", async () => {
      const tenant = await createTenant(repos, "mt-hidden");
      const a = await app(tenant);
      // The configured URL looks single-tenant; its discovery says otherwise.
      await createFederatedLoginMethod(ts!, idp!, tenant, "entra-mt", {
        issuer: `${idp!.baseUrl}/entra-mt/${MOCK_ENTRA_TENANT_ID}/v2.0`,
        allowedUpstreamTenants: [],
      });
      const landing = await new FlowDriver(ts!, idp!).follow(
        (await authorizationRequest(a.config, a.redirectUri)).url.href,
      );
      expectLoginError(landing, "upstream_error");
    });
  });

  describe("protected identity", () => {
    it("is sticky on the person across login methods until an administrator clears it", async () => {
      const tenant = await createTenant(repos, "sticky");
      const a = await app(tenant, { allowedExtraScopes: ["pin"] });
      // Both methods link by pin; only the second one maps the upstream protected flag.
      const plain = await createFederatedLoginMethod(ts!, idp!, tenant, "bankid", {
        displayName: "Plain eID",
        linkByPin: true,
        claimMapping: {
          subject: "sub",
          name: "name",
          pin: PERSONAL_IDENTITY_NUMBER_CLAIM,
          acr: "acr",
        },
      });
      const flagged = await createFederatedLoginMethod(ts!, idp!, tenant, "bankid", {
        displayName: "Flagging eID",
        linkByPin: true,
      });
      const params = { scope: "openid profile pin", login_hint: "skyddad-person" };
      const viaPlain = () =>
        signedIn(new FlowDriver(ts!, idp!), a, "", { params, method: plain.id });

      const before = await viaPlain();
      expect(before.claims()).toMatchObject({ name: "Skyddad Person" });
      expect(before.claims()).not.toHaveProperty("protected_identity");

      const protectedLogin = await signedIn(new FlowDriver(ts!, idp!), a, "", {
        params,
        method: flagged.id,
      });
      const personId = protectedLogin.claims()!.sub;
      expect(protectedLogin.claims()).toMatchObject({
        sub: before.claims()!.sub,
        protected_identity: true,
      });

      // The other method's identity lost its name, and its logins carry none.
      const plainIdentity = await repos.persons.findIdentity(
        tenant.id,
        plain.id,
        "bankid-skyddad-person",
      );
      expect(plainIdentity?.attributes).not.toHaveProperty("name");
      const after = await viaPlain();
      expect(after.claims()).toMatchObject({ protected_identity: true, pin: "200001010008" });
      expect(after.claims()).not.toHaveProperty("name");
      expect((await repos.persons.findById(tenant.id, personId))?.protectedIdentity).toBe(true);

      expect(await repos.persons.clearProtectedIdentity(tenant.id, personId)).toBe(true);
      const cleared = await viaPlain();
      expect(cleared.claims()).toMatchObject({ name: "Skyddad Person" });
      expect(cleared.claims()).not.toHaveProperty("protected_identity");
    });
  });

  describe("upstream requests", () => {
    it("reuses one pending state per interaction and login method", async () => {
      const tenant = await createTenant(repos, "reuse");
      const a = await app(tenant);
      await createFederatedLoginMethod(ts!, idp!, tenant, "entra");
      const driver = new FlowDriver(ts!, idp!);
      await driver.follow((await authorizationRequest(a.config, a.redirectUri)).url.href);
      const interaction = driver.visited.find((url) => /\/interaction\/[^/]+$/.test(url))!;
      await driver.follow(interaction);
      await driver.follow(interaction);
      const upstream = driver.visited
        .filter((url) => url.startsWith(`${idp!.issuer("entra")}/auth?`))
        .map((url) => new URL(url).searchParams.get("state"));
      expect(upstream).toHaveLength(3);
      expect(new Set(upstream).size).toBe(1);
      const [{ count } = { count: -1 }] = await db.query<{ count: number }>(
        "SELECT count(*)::int AS count FROM federation_states WHERE tenant_id = $1",
        [tenant.id],
      );
      expect(count).toBe(1);
    });

    it("requires auth_time when max_age was sent upstream, and passes auth_time on", async () => {
      const tenant = await createTenant(repos, "maxage");
      const a = await app(tenant);
      await createFederatedLoginMethod(ts!, idp!, tenant, "entra", {}, { omit_auth_time: true });
      const strict = await signIn(new FlowDriver(ts!, idp!), a, "anna-handlaggare", {
        params: { max_age: "600" },
      });
      expectLoginError(strict.landing, "upstream_error");
      // Without max_age, a missing auth_time is fine: the login time is now.
      const lax = await signedIn(new FlowDriver(ts!, idp!), a, "anna-handlaggare");
      expect(Math.abs((lax.claims()!.auth_time as number) - Date.now() / 1000)).toBeLessThan(5);

      // The upstream's auth_time (from its own session) becomes the downstream auth_time.
      vi.useFakeTimers({ toFake: ["Date"], shouldAdvanceTime: true });
      const other = await createTenant(repos, "maxage-sso");
      const b = await app(other);
      await createFederatedLoginMethod(ts!, idp!, other, "entra");
      const driver = new FlowDriver(ts!, idp!);
      const first = await signedIn(driver, b, "erik-admin");
      vi.setSystemTime(Date.now() + 120_000);
      driver.browser.forgetHost(new URL(ts!.baseUrl).host); // a new broker session
      const second = await signedIn(driver, b, "erik-admin");
      expect(second.claims()!.auth_time).toBe(first.claims()!.auth_time);
      expect(second.claims()!.iat - (first.claims()!.auth_time as number)).toBeGreaterThanOrEqual(
        120,
      );
    });

    it("signs private_key_jwt assertions for the token endpoint by default, or the issuer", async () => {
      const tenant = await createTenant(repos, "aud");
      const a = await app(tenant);
      const byEndpoint = await createFederatedLoginMethod(ts!, idp!, tenant, "entra", {
        clientAuthMethod: "private_key_jwt",
      });
      await signedIn(new FlowDriver(ts!, idp!), a, "anna-handlaggare");
      expect(idp!.idp.lastClientAssertionAudience("entra", byEndpoint.clientId)).toBe(
        `${idp!.issuer("entra")}/token`,
      );
      await repos.loginMethods.update(tenant.id, byEndpoint.id, {
        clientAssertionAudience: "issuer",
      });
      await signedIn(new FlowDriver(ts!, idp!), a, "anna-handlaggare");
      expect(idp!.idp.lastClientAssertionAudience("entra", byEndpoint.clientId)).toBe(
        idp!.issuer("entra"),
      );
    });

    it("does not redeem the code when the interaction is gone", async () => {
      const tenant = await createTenant(repos, "gone");
      const a = await app(tenant);
      await createFederatedLoginMethod(ts!, idp!, tenant, "entra");
      const driver = new FlowDriver(ts!, idp!);
      const page = await driver.follow(
        (await authorizationRequest(a.config, a.redirectUri)).url.href,
      );
      await db.query("DELETE FROM oidc_payloads WHERE tenant_id = $1 AND kind = 'Interaction'", [
        tenant.id,
      ]);
      const landing = await driver.persona(page, "anna-handlaggare");
      expect(landing).toMatchObject({
        kind: "login_ui",
        bootstrap: { view: "error", code: "interaction_expired" },
      });
      expect((await auditOf(tenant, "login.failure"))[0]?.details).toMatchObject({
        reason: "interaction_expired",
      });
      expect(await auditOf(tenant, "person.created")).toEqual([]);
    });

    it("maps email only from an upstream trusted for it (or with email_verified)", async () => {
      const tenant = await createTenant(repos, "email");
      const a = await app(tenant);
      await createFederatedLoginMethod(ts!, idp!, tenant, "entra", { trustUpstreamEmail: false });
      const tokens = await signedIn(new FlowDriver(ts!, idp!), a, "anna-handlaggare");
      expect(tokens.claims()).toMatchObject({ name: "Anna Andersson" });
      expect(tokens.claims()).not.toHaveProperty("email");
    });

    it("requires an upstream acr mapping for a ranked asserted acr", async () => {
      const tenant = await createTenant(repos, "ranked");
      const { loginMethods } = ts!.portvakt.repos;
      const input = {
        kind: "citizen",
        displayName: "eID",
        issuer: idp!.issuer("bankid"),
        clientId: "c",
        clientSecret: "secret-value",
        assertedAcr: LOA3,
        sessionPolicy: { maxAgeSeconds: 3600, idleSeconds: 600, allowSso: false },
      } as const;
      await expect(
        loginMethods.create(tenant.id, { ...input, claimMapping: { subject: "sub" } }),
      ).rejects.toBeInstanceOf(ValidationError);
      const method = await loginMethods.create(tenant.id, {
        ...input,
        claimMapping: { subject: "sub", acr: "acr" },
      });
      await expect(
        loginMethods.update(tenant.id, method.id, { claimMapping: { subject: "sub" } }),
      ).rejects.toBeInstanceOf(ValidationError);
      // An unranked acr needs no upstream evidence.
      await expect(
        loginMethods.update(tenant.id, method.id, {
          assertedAcr: EMPLOYEE_ACR,
          claimMapping: { subject: "sub" },
        }),
      ).resolves.toMatchObject({ assertedAcr: EMPLOYEE_ACR });
    });
  });

  describe("another person in the same browser", () => {
    it("ends the first person's session; nothing of them reaches the second", async () => {
      const tenant = await createTenant(repos, "switch");
      const citizen = await createFederatedLoginMethod(ts!, idp!, tenant, "bankid", {
        sessionPolicy: { maxAgeSeconds: 3600, idleSeconds: 600, allowSso: true },
      });
      const employee = await createFederatedLoginMethod(ts!, idp!, tenant, "entra");
      const a = await app(tenant);
      const b = await app(tenant);
      const driver = new FlowDriver(ts!, idp!);
      const sven = await signedIn(driver, a, "sven-medborgare", { method: citizen.id });
      const anna = await signedIn(driver, b, "anna-handlaggare", {
        method: employee.id,
        params: { prompt: "login" },
      });
      expect(anna.claims()).toMatchObject({ name: "Anna Andersson", idp: employee.id });
      expect(anna.claims()!.sub).not.toBe(sven.claims()!.sub);
      expect(JSON.stringify(anna.claims())).not.toContain("Sven");
      expect(await oauthError(client.refreshTokenGrant(a.config, sven.refresh_token!))).toBe(
        "invalid_grant",
      );
      const sessions = await db.query<{ account: string }>(
        "SELECT payload->>'accountId' AS account FROM oidc_payloads WHERE tenant_id = $1 AND kind = 'Session'",
        [tenant.id],
      );
      expect(sessions.map((row) => row.account)).toEqual([anna.claims()!.sub]);
      // A's next authorization belongs to Anna's session now, not Sven's.
      const again = await signedIn(driver, a, "unused");
      expect(again.claims()).toMatchObject({ sub: anna.claims()!.sub });
    });

    it("works when the upstream IdP switches persons as well", async () => {
      const tenant = await createTenant(repos, "switch-upstream");
      await createFederatedLoginMethod(ts!, idp!, tenant, "bankid", {
        sessionPolicy: { maxAgeSeconds: 3600, idleSeconds: 600, allowSso: true },
      });
      const a = await app(tenant);
      const b = await app(tenant);
      const driver = new FlowDriver(ts!, idp!);
      await signedIn(driver, a, "sven-medborgare");
      // prompt=login: the mock IdP shows its page over Sven's session; Samuel signs in there.
      const samuel = await signedIn(driver, b, "samuel-samordning", {
        params: { prompt: "login" },
      });
      expect(samuel.claims()).toMatchObject({ name: "Samuel Samordning" });
    });
  });
});
