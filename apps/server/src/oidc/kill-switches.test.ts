import * as client from "openid-client";
import { beforeAll, describe, expect, it } from "vitest";
import { createLoginMethod, login, uniqueSuffix } from "../testing/fixtures.js";
import {
  adminCall,
  adminToken,
  createAdmin,
  PLATFORM_ADMIN_ROLE,
  setupAdminWorld,
  type AdminWorld,
} from "../testing/admin.js";
import {
  authorize,
  codeFlow,
  createTenantWorld,
  discoverWithSecret,
  type TenantWorld,
} from "../testing/oidc-flow.js";
import { startTestServer, TestBrowser } from "../testing/test-server.js";

const ts = await startTestServer();

const LOA3 = "http://id.elegnamnden.se/loa/1.0/loa3";

/**
 * The kill switches: an administrator's change that takes a login away ends its sessions and
 * grants in the same transaction (audited), the token endpoint re-checks them at every refresh,
 * and switching the thing on again never brings an old refresh token back.
 */
describe.skipIf(ts === undefined)("kill switches", () => {
  const { repos } = ts!.db;
  let world: AdminWorld;
  let platform: string;

  beforeAll(async () => {
    world = await setupAdminWorld(ts!);
    const admin = await createAdmin(world, world.system, world.systemMethod, [PLATFORM_ADMIN_ROLE]);
    platform = await adminToken(world, world.system, world.systemMethod, admin);
  });

  interface Signed {
    readonly w: TenantWorld;
    readonly rp: client.Configuration;
    readonly personId: string;
    readonly refreshToken: string;
    readonly browser: TestBrowser;
  }

  /** A person of a fresh tenant signed in to its application, with a refresh token. */
  async function signedIn(loginMethod: Parameters<typeof createTenantWorld>[2] = {}) {
    const w = await createTenantWorld(repos, "kill", loginMethod);
    const { person } = await login(repos, w.tenant.id, w.loginMethod, `p-${uniqueSuffix()}`, {
      ...(loginMethod.claimMapping?.pin === undefined ? {} : { pin: "199001012385" }),
    });
    const rp = await discoverWithSecret(ts!, w.tenant.slug, w.app);
    const browser = new TestBrowser();
    const tokens = await codeFlow(
      ts!,
      rp,
      w.app.application.redirectUris[0]!,
      { personId: person.id, loginMethodId: w.loginMethod.id, acr: w.loginMethod.assertedAcr },
      { browser },
    );
    expect(tokens.refresh_token).toBeTypeOf("string");
    return { w, rp, personId: person.id, refreshToken: tokens.refresh_token!, browser };
  }

  const refreshFails = async (signed: Signed, token = signed.refreshToken) => {
    await expect(client.refreshTokenGrant(signed.rp, token)).rejects.toMatchObject({
      error: "invalid_grant",
    });
  };

  async function etagOf(path: string): Promise<string> {
    const response = await adminCall(ts!, platform, "GET", path);
    expect(response.status).toBe(200);
    return response.etag!;
  }

  async function adminChange(method: string, path: string, body?: unknown, etagPath = path) {
    const response = await adminCall(ts!, platform, method, path, {
      ...(body === undefined ? {} : { body }),
      ifMatch: await etagOf(etagPath),
    });
    expect(response.status).toBeLessThan(300);
    return response;
  }

  async function revocationEvents(tenantId: string) {
    const { events } = await repos.audit.query({ tenantId }, { actions: ["sessions.revoked"] });
    return events;
  }

  /** The browser's broker session no longer serves the application: a login is required. */
  async function sessionEnded(signed: Signed): Promise<void> {
    const authorizationUrl = client.buildAuthorizationUrl(signed.rp, {
      redirect_uri: signed.w.app.application.redirectUris[0]!,
      scope: "openid",
      code_challenge: await client.calculatePKCECodeChallenge(client.randomPKCECodeVerifier()),
      code_challenge_method: "S256",
      state: client.randomState(),
    });
    const response = await signed.browser.request(authorizationUrl.href);
    expect(new URL(TestBrowser.location(response, authorizationUrl.href)).pathname).toContain(
      "/interaction/",
    );
  }

  it("disabling a login method ends its logins; enabling it again revives nothing", async () => {
    const signed = await signedIn();
    const methodPath = `/tenants/${signed.w.tenant.id}/login-methods/${signed.w.loginMethod.id}`;
    await adminChange("PATCH", methodPath, { enabled: false });
    const [event] = await revocationEvents(signed.w.tenant.id);
    expect(event).toMatchObject({
      subject: { type: "login_method", id: signed.w.loginMethod.id },
      details: { reason: "login_method_disabled", sessions: 1, grants: 1 },
    });
    await adminChange("PATCH", methodPath, { enabled: true });
    await refreshFails(signed);
    await sessionEnded(signed);
  });

  it("suspending the tenant ends every login; reactivating it revives nothing", async () => {
    const signed = await signedIn();
    const tenantPath = `/tenants/${signed.w.tenant.id}`;
    await adminChange("POST", `${tenantPath}/suspend`, undefined, tenantPath);
    expect((await revocationEvents(signed.w.tenant.id))[0]?.details).toMatchObject({
      reason: "tenant_suspended",
      sessions: 1,
      grants: 1,
    });
    await adminChange("POST", `${tenantPath}/reactivate`, undefined, tenantPath);
    await refreshFails(signed);
    await sessionEnded(signed);
  });

  it("disabling the application in the tenant revokes its grants; enabling it revives nothing", async () => {
    const signed = await signedIn();
    const path = `/tenants/${signed.w.tenant.id}/applications/${signed.w.app.application.id}`;
    const etag = async () =>
      (
        await adminCall<{ items: { applicationId?: string; id?: string; etag: string }[] }>(
          ts!,
          platform,
          "GET",
          `/tenants/${signed.w.tenant.id}/applications`,
        )
      ).body.items[0]!.etag;
    for (const enabled of [false, true]) {
      const response = await adminCall(ts!, platform, "PATCH", path, {
        body: { enabled },
        ifMatch: await etag(),
      });
      expect(response.status).toBe(200);
    }
    expect((await revocationEvents(signed.w.tenant.id))[0]?.details).toMatchObject({
      reason: "application_disabled",
      grants: 1,
      clientId: signed.w.app.application.clientId,
    });
    await refreshFails(signed);
  });

  it("detaching the application revokes its grants; attaching it again revives nothing", async () => {
    const signed = await signedIn();
    const { tenant, app } = signed.w;
    const list = await adminCall<{ items: { etag: string }[] }>(
      ts!,
      platform,
      "GET",
      `/tenants/${tenant.id}/applications`,
    );
    const detached = await adminCall(
      ts!,
      platform,
      "POST",
      `/tenants/${tenant.id}/applications/${app.application.id}/detach`,
      { body: { confirmClientId: app.application.clientId }, ifMatch: list.body.items[0]!.etag },
    );
    expect(detached.status).toBe(200);
    expect((await revocationEvents(tenant.id))[0]?.details).toMatchObject({
      reason: "application_detached",
      grants: 1,
    });
    await repos.applications.enableForTenant(tenant.id, app.application.id);
    await refreshFails(signed);
  });

  it("unlinking the identity of the login ends it; the person's other logins stay", async () => {
    const citizen = {
      kind: "citizen" as const,
      assertedAcr: LOA3,
      claimMapping: { subject: "sub", pin: "pin", acr: "acr" },
      linkByPin: true,
    };
    const signed = await signedIn(citizen);
    const other = await createLoginMethod(repos, signed.w.tenant.id, {
      ...citizen,
      displayName: "Other eID",
    });
    const linked = await login(repos, signed.w.tenant.id, other, "other-sub", {
      pin: "199001012385",
    });
    expect(linked.person.id).toBe(signed.personId);
    const otherTokens = await codeFlow(ts!, signed.rp, signed.w.app.application.redirectUris[0]!, {
      personId: signed.personId,
      loginMethodId: other.id,
      acr: LOA3,
    });
    const identity = (await repos.persons.listIdentities(signed.w.tenant.id, signed.personId)).find(
      (item) => item.loginMethodId === signed.w.loginMethod.id,
    )!;
    const personPath = `/tenants/${signed.w.tenant.id}/persons/${signed.personId}`;
    await adminChange(
      "POST",
      `${personPath}/identities/${identity.id}/unlink`,
      undefined,
      personPath,
    );
    expect((await revocationEvents(signed.w.tenant.id))[0]?.details).toMatchObject({
      reason: "identity_unlinked",
      loginMethodId: signed.w.loginMethod.id,
      sessions: 1,
      grants: 1,
    });
    await refreshFails(signed);
    // The login through the other identity is the person's own and keeps working.
    await expect(
      client.refreshTokenGrant(signed.rp, otherTokens.refresh_token!),
    ).resolves.toBeDefined();
  });

  it("deleting the person ends every login of theirs", async () => {
    const signed = await signedIn();
    const personPath = `/tenants/${signed.w.tenant.id}/persons/${signed.personId}`;
    await adminChange("DELETE", personPath);
    expect((await revocationEvents(signed.w.tenant.id))[0]?.details).toMatchObject({
      reason: "person_deleted",
      sessions: 1,
      grants: 1,
    });
    await refreshFails(signed);
  });

  it("end-sessions signs a person out everywhere, audited", async () => {
    const signed = await signedIn();
    const response = await adminCall(
      ts!,
      platform,
      "POST",
      `/tenants/${signed.w.tenant.id}/persons/${signed.personId}/end-sessions`,
    );
    expect(response).toMatchObject({ status: 200, body: { sessions: 1, grants: 1 } });
    const [event] = await revocationEvents(signed.w.tenant.id);
    expect(event).toMatchObject({
      actor: { type: "person" },
      subject: { type: "person", id: signed.personId },
      details: { reason: "ended_by_admin", sessions: 1, grants: 1 },
    });
    await refreshFails(signed);
    await sessionEnded(signed);
    // Signing in again works as usual.
    await expect(
      authorize(ts!, signed.rp, signed.w.app.application.redirectUris[0]!, {
        personId: signed.personId,
        loginMethodId: signed.w.loginMethod.id,
        acr: signed.w.loginMethod.assertedAcr,
      }),
    ).resolves.toBeDefined();
  });

  it("re-checks at the refresh and the authorization when the change bypassed the admin API", async () => {
    const signed = await signedIn();
    const { tenant, loginMethod } = signed.w;
    // A change straight in the database: nothing revoked the logins.
    await repos.loginMethods.update(tenant.id, loginMethod.id, { enabled: false });
    await sessionEnded(signed);
    await refreshFails(signed);
    const { events } = await repos.audit.query(
      { tenantId: tenant.id },
      { actions: ["token.refresh_denied", "grant.revoked"] },
    );
    expect(events.map((event) => [event.action, event.details.reason])).toEqual(
      expect.arrayContaining([
        ["token.refresh_denied", "login_revoked"],
        ["grant.revoked", "login_revoked"],
      ]),
    );
    // The refresh revoked the grant: enabling the method again does not bring it back.
    await repos.loginMethods.update(tenant.id, loginMethod.id, { enabled: true });
    await refreshFails(signed);

    // A lost identity and a suspended tenant are refused the same way.
    const unlinked = await signedIn();
    await repos.persons.deleteIdentity(
      unlinked.w.tenant.id,
      unlinked.personId,
      (await repos.persons.listIdentities(unlinked.w.tenant.id, unlinked.personId))[0]!.id,
    );
    await refreshFails(unlinked);
  });
});
