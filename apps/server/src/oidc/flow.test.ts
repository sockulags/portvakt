import {
  createRemoteJWKSet,
  decodeProtectedHeader,
  exportJWK,
  generateKeyPair,
  jwtVerify,
} from "jose";
import * as client from "openid-client";
import { describe, expect, it } from "vitest";
import { uniqueSuffix } from "../testing/fixtures.js";
import {
  authorize,
  codeFlow,
  createPerson,
  createTenantWorld,
  createTestClient,
  discover,
  discoverWithSecret,
  type TenantWorld,
} from "../testing/oidc-flow.js";
import { bootstrapOf } from "../testing/federation.js";
import { TestBrowser, startTestServer } from "../testing/test-server.js";
import { resourceIndicatorFor } from "./clients.js";

const ts = await startTestServer();

const redirectUriOf = (world: TenantWorld): string => world.app.application.redirectUris[0]!;

/** The OAuth error code of a failed openid-client call. */
async function oauthError(promise: Promise<unknown>): Promise<string> {
  try {
    await promise;
  } catch (error) {
    if (error instanceof client.ResponseBodyError) return error.error;
    if (error instanceof client.AuthorizationResponseError) return error.error;
    if (error instanceof client.WWWAuthenticateChallengeError) {
      return String(error.cause[0]?.parameters.error);
    }
    throw error;
  }
  throw new Error("expected the request to fail");
}

describe.skipIf(ts === undefined)("authorization code flow", () => {
  const { db, portvakt } = ts!;
  const { repos } = db;

  async function worldWithPerson() {
    const world = await createTenantWorld(repos, "flow");
    const { application } = world.app;
    await repos.access.createRule(world.tenant.id, {
      applicationId: application.id,
      loginMethodId: world.loginMethod.id,
      groupValue: "grp-handlaggare",
      role: "handlaggare",
    });
    const { person } = await createPerson(repos, world, `emp-${uniqueSuffix()}`, {
      groups: ["grp-handlaggare", "grp-other"],
      name: "Test Person",
      email: "test.person@example.org",
    });
    await repos.access.assignRole(world.tenant.id, {
      personId: person.id,
      applicationId: application.id,
      role: "reader",
    });
    await repos.access.setAttribute(world.tenant.id, {
      personId: person.id,
      applicationId: application.id,
      key: "unit",
      value: "north",
    });
    const as = {
      personId: person.id,
      loginMethodId: world.loginMethod.id,
      acr: world.loginMethod.assertedAcr,
      amr: ["pwd", "mfa"],
    };
    return { world, person, as };
  }

  it("issues an ID token, a JWT access token for the app and rotating refresh tokens", async () => {
    const { world, person, as } = await worldWithPerson();
    const issuer = ts!.issuerOf(world.tenant.slug);
    const clientId = world.app.application.clientId;
    const config = await discoverWithSecret(ts!, world.tenant.slug, world.app);
    const tokens = await codeFlow(ts!, config, redirectUriOf(world), as);

    // ID token: claims contract for this app only.
    const idClaims = tokens.claims()!;
    expect(idClaims).toMatchObject({
      iss: issuer,
      aud: clientId,
      sub: person.id,
      tid: world.tenant.slug,
      roles: ["handlaggare", "reader"],
      attrs: { unit: "north" },
      name: "Test Person",
      email: "test.person@example.org",
    });
    expect(typeof idClaims.auth_time).toBe("number");
    expect(decodeProtectedHeader(tokens.id_token!)).toMatchObject({
      alg: "ES256",
      kid: portvakt.keyCache.current!.activeKid,
    });

    // Access token: a JWT whose aud is exactly the client_id, verifiable against JWKS.
    const jwks = createRemoteJWKSet(new URL(`${issuer}/jwks`));
    const verified = await jwtVerify(tokens.access_token, jwks, {
      issuer,
      audience: clientId,
      typ: "at+jwt",
      algorithms: ["ES256"],
    });
    expect(verified.protectedHeader.kid).toBe(portvakt.keyCache.current!.activeKid);
    expect(verified.payload).toMatchObject({
      aud: clientId,
      sub: person.id,
      client_id: clientId,
      tid: world.tenant.slug,
      roles: ["handlaggare", "reader"],
      attrs: { unit: "north" },
    });
    expect(verified.payload).not.toHaveProperty("name");
    expect(verified.payload).not.toHaveProperty("email");
    expect(tokens.expires_in).toBe(300);

    // Refresh: rotates, and replaying a used refresh token revokes the whole grant.
    const firstRefresh = tokens.refresh_token!;
    const refreshed = await client.refreshTokenGrant(config, firstRefresh);
    expect(refreshed.refresh_token).toBeDefined();
    expect(refreshed.refresh_token).not.toBe(firstRefresh);
    const again = await jwtVerify(refreshed.access_token, jwks, { issuer, audience: clientId });
    expect(again.payload).toMatchObject({ sub: person.id, roles: ["handlaggare", "reader"] });
    expect(refreshed.claims()).toMatchObject({ sub: person.id, tid: world.tenant.slug });

    expect(await oauthError(client.refreshTokenGrant(config, firstRefresh))).toBe("invalid_grant");
    expect(await oauthError(client.refreshTokenGrant(config, refreshed.refresh_token!))).toBe(
      "invalid_grant",
    );
  });

  it("ends the broker session on RP-initiated logout; its refresh tokens end with it", async () => {
    const { world, as } = await worldWithPerson();
    const postLogout = `https://${world.app.application.clientId}.example.test/signed-out`;
    await repos.applications.update(world.app.application.id, {
      postLogoutRedirectUris: [postLogout],
    });
    const config = await discoverWithSecret(ts!, world.tenant.slug, world.app);
    const browser = new TestBrowser();
    const tokens = await codeFlow(ts!, config, redirectUriOf(world), as, { browser });

    const endSession = client.buildEndSessionUrl(config, {
      id_token_hint: tokens.id_token!,
      post_logout_redirect_uri: postLogout,
      state: "bye",
    });
    const confirm = await browser.request(endSession.href);
    expect(confirm.status).toBe(200);
    const form = await confirm.text();
    const action = /action="([^"]+)"/.exec(form)?.[1];
    const xsrf = /name="xsrf" value="([^"]+)"/.exec(form)?.[1];
    expect(action).toBeDefined();
    const done = await browser.request(new URL(action!, endSession).href, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ xsrf: xsrf!, logout: "yes" }).toString(),
    });
    const back = new URL(TestBrowser.location(done, endSession.href));
    expect(`${back.origin}${back.pathname}`).toBe(postLogout);
    expect(back.searchParams.get("state")).toBe("bye");

    expect(await oauthError(client.refreshTokenGrant(config, tokens.refresh_token!))).toBe(
      "invalid_grant",
    );
  });

  it("reflects role changes on refresh: roles are evaluated for every token", async () => {
    const { world, person, as } = await worldWithPerson();
    const config = await discoverWithSecret(ts!, world.tenant.slug, world.app);
    const tokens = await codeFlow(ts!, config, redirectUriOf(world), as);
    await repos.access.unassignRole(world.tenant.id, {
      personId: person.id,
      applicationId: world.app.application.id,
      role: "reader",
    });
    const refreshed = await client.refreshTokenGrant(config, tokens.refresh_token!);
    expect(refreshed.claims()?.roles).toEqual(["handlaggare"]);
  });

  it("gives roles and attributes of the audience app only (SSO to a second app)", async () => {
    const { world, person, as } = await worldWithPerson();
    const second = await createTestClient(repos, world.tenant);
    await repos.access.assignRole(world.tenant.id, {
      personId: person.id,
      applicationId: second.application.id,
      role: "admin",
    });
    const browser = new TestBrowser();
    const first = await discoverWithSecret(ts!, world.tenant.slug, world.app);
    await codeFlow(ts!, first, redirectUriOf(world), as, { browser });

    // Same browser: the broker session is reused, no second login.
    const config = await discoverWithSecret(ts!, world.tenant.slug, second);
    const result = await authorize(
      ts!,
      config,
      second.application.redirectUris[0]!,
      { ...as, personId: "00000000-0000-4000-8000-000000000000" },
      { browser },
    );
    const tokens = await client.authorizationCodeGrant(config, result.callbackUrl, {
      pkceCodeVerifier: result.codeVerifier,
      expectedState: result.state,
      expectedNonce: result.nonce,
    });
    expect(tokens.claims()).toMatchObject({
      sub: person.id,
      aud: second.application.clientId,
      roles: ["admin"],
      attrs: {},
    });
  });

  it("asks for a new login when the session's login state is gone", async () => {
    const { world, as } = await worldWithPerson();
    const config = await discoverWithSecret(ts!, world.tenant.slug, world.app);
    const browser = new TestBrowser();
    const tokens = await codeFlow(ts!, config, redirectUriOf(world), as, { browser });
    await db.db.query(
      `DELETE FROM oidc_payloads
        WHERE tenant_id = $1 AND kind IN ('PortvaktSession', 'PortvaktGrantLogin')`,
      [world.tenant.id],
    );
    expect(await oauthError(client.refreshTokenGrant(config, tokens.refresh_token!))).toBe(
      "invalid_grant",
    );
    const url = client.buildAuthorizationUrl(config, {
      redirect_uri: redirectUriOf(world),
      scope: "openid",
      code_challenge: await client.calculatePKCECodeChallenge(client.randomPKCECodeVerifier()),
      code_challenge_method: "S256",
    });
    const next = TestBrowser.location(await browser.request(url.href), url.href);
    expect(new URL(next).pathname).toContain("/interaction/");
    // Logging in again restores a working session.
    expect(
      (await codeFlow(ts!, config, redirectUriOf(world), as, { browser })).id_token,
    ).toBeDefined();
  });

  it("requires PKCE with S256 and refuses implicit and hybrid flows", async () => {
    const { world } = await worldWithPerson();
    const config = await discoverWithSecret(ts!, world.tenant.slug, world.app);
    const browser = new TestBrowser();
    const redirectUri = redirectUriOf(world);
    const errorOf = async (params: Record<string, string>): Promise<string | null> => {
      const url = client.buildAuthorizationUrl(config, { redirect_uri: redirectUri, ...params });
      const response = await browser.request(url.href);
      const location = new URL(TestBrowser.location(response, url.href));
      return (
        location.searchParams.get("error") ??
        new URLSearchParams(location.hash.slice(1)).get("error")
      );
    };
    expect(await errorOf({ scope: "openid" })).toBe("invalid_request");
    expect(
      await errorOf({
        scope: "openid",
        code_challenge: "x".repeat(43),
        code_challenge_method: "plain",
      }),
    ).toBe("invalid_request");
    expect(await errorOf({ scope: "openid", response_type: "id_token", nonce: "n" })).toBe(
      "unsupported_response_type",
    );
    expect(await errorOf({ scope: "openid", response_type: "code id_token", nonce: "n" })).toBe(
      "unsupported_response_type",
    );
  });

  it("refuses a login for a person of another tenant", async () => {
    const { world, as } = await worldWithPerson();
    const other = await worldWithPerson();
    const config = await discoverWithSecret(ts!, world.tenant.slug, world.app);
    await expect(
      authorize(ts!, config, redirectUriOf(world), { ...as, personId: other.person.id }),
    ).rejects.toThrow(/test login failed: 403/);
  });

  it("serves the login UI on the interaction route, bound to the interaction cookie", async () => {
    const { world } = await worldWithPerson();
    const config = await discoverWithSecret(ts!, world.tenant.slug, world.app);
    const browser = new TestBrowser();
    const url = client.buildAuthorizationUrl(config, {
      redirect_uri: redirectUriOf(world),
      scope: "openid",
      code_challenge: await client.calculatePKCECodeChallenge(client.randomPKCECodeVerifier()),
      code_challenge_method: "S256",
    });
    const interaction = TestBrowser.location(await browser.request(url.href), url.href);
    expect(new URL(interaction).pathname).toMatch(
      new RegExp(`^/t/${world.tenant.slug}/interaction/[A-Za-z0-9_-]+$`),
    );
    // The fixture login method is unreachable upstream (no choice to make, so it is tried
    // directly): the login view opens with the error and a retry.
    const response = await browser.request(interaction);
    expect(response.status).toBe(200);
    expect(response.headers.get("content-security-policy")).toContain("script-src 'self'");
    expect(bootstrapOf(await response.text())).toMatchObject({
      view: "login",
      uid: interaction.split("/").at(-1),
      error: "upstream_unavailable",
    });
    // The shell itself is never served raw, only with its bootstrap block.
    expect((await fetch(`${ts!.baseUrl}/ui/login/index.html`)).status).toBe(404);
    // Without the interaction cookie the interaction is not found.
    const expired = await fetch(interaction);
    expect(expired.status).toBe(404);
    expect(bootstrapOf(await expired.text())).toMatchObject({
      view: "error",
      code: "interaction_expired",
    });
  });
});

describe.skipIf(ts === undefined)("clients and tenants", () => {
  const { db, portvakt } = ts!;
  const { repos } = db;

  it("rejects a client whose app is not enabled for the tenant, and accepts it once enabled", async () => {
    const world = await createTenantWorld(repos, "enable");
    const later = await createTestClient(repos, null);
    const config = await discoverWithSecret(ts!, world.tenant.slug, later);
    expect(await oauthError(client.clientCredentialsGrant(config))).toBe("invalid_client");

    // Change notifications are per test schema, so only this file's changes drop the provider.
    const cached = portvakt.registry.peek(world.tenant.slug);
    expect(cached).toBeDefined();
    await repos.applications.enableForTenant(world.tenant.id, later.application.id);
    // The change notification drops the cached provider on every replica.
    await expect.poll(() => portvakt.registry.peek(world.tenant.slug)).not.toBe(cached);
    const tokens = await client.clientCredentialsGrant(config);
    expect(tokens.token_type).toBe("bearer");

    await repos.applications.disableForTenant(world.tenant.id, later.application.id);
    expect(await oauthError(client.clientCredentialsGrant(config))).toBe("invalid_client");
  });

  it("does not let an app enabled in tenant X authenticate at tenant Y", async () => {
    const x = await createTenantWorld(repos, "x");
    const y = await createTenantWorld(repos, "y");
    const atX = await discoverWithSecret(ts!, x.tenant.slug, x.app);
    expect((await client.clientCredentialsGrant(atX)).access_token).toBeTypeOf("string");
    const atY = await discoverWithSecret(ts!, y.tenant.slug, x.app);
    expect(await oauthError(client.clientCredentialsGrant(atY))).toBe("invalid_client");
  });

  it("issues client_credentials tokens for another app enabled in the tenant, nothing else", async () => {
    const world = await createTenantWorld(repos, "s2s");
    const api = await createTestClient(repos, world.tenant);
    const foreign = await createTestClient(repos, null);
    const issuer = ts!.issuerOf(world.tenant.slug);
    const config = await discoverWithSecret(ts!, world.tenant.slug, world.app);
    const jwks = createRemoteJWKSet(new URL(`${issuer}/jwks`));

    const own = await client.clientCredentialsGrant(config);
    const ownToken = await jwtVerify(own.access_token, jwks, { issuer, typ: "at+jwt" });
    expect(ownToken.payload).toMatchObject({
      aud: world.app.application.clientId,
      sub: world.app.application.clientId,
      client_id: world.app.application.clientId,
      tid: world.tenant.slug,
    });

    const forApi = await client.clientCredentialsGrant(config, {
      resource: resourceIndicatorFor(api.application.clientId),
    });
    const apiToken = await jwtVerify(forApi.access_token, jwks, {
      issuer,
      audience: api.application.clientId,
    });
    expect(apiToken.payload.aud).toBe(api.application.clientId);
    expect(apiToken.payload).not.toHaveProperty("roles");

    expect(
      await oauthError(
        client.clientCredentialsGrant(config, {
          resource: resourceIndicatorFor(foreign.application.clientId),
        }),
      ),
    ).toBe("invalid_target");
    expect(
      await oauthError(
        client.clientCredentialsGrant(config, { resource: "https://elsewhere.example" }),
      ),
    ).toBe("invalid_target");
  });

  it("authenticates a private_key_jwt client and rejects an assertion signed by another key", async () => {
    const world = await createTenantWorld(repos, "pkjwt");
    const { privateKey, publicKey } = await generateKeyPair("ES256", { extractable: true });
    const publicJwk = {
      ...(await exportJWK(publicKey)),
      kty: "EC",
      kid: "client-key-1",
      alg: "ES256",
      use: "sig",
    };
    const keyClient = await createTestClient(repos, world.tenant, {
      clientAuth: { method: "private_key_jwt", jwks: { keys: [publicJwk] } },
    });
    const config = await discover(
      ts!,
      world.tenant.slug,
      keyClient.application.clientId,
      client.PrivateKeyJwt({ key: privateKey, kid: "client-key-1" }),
    );
    const tokens = await client.clientCredentialsGrant(config);
    expect(tokens.access_token).toBeTypeOf("string");

    const other = await generateKeyPair("ES256");
    const impostor = await discover(
      ts!,
      world.tenant.slug,
      keyClient.application.clientId,
      client.PrivateKeyJwt({ key: other.privateKey, kid: "client-key-1" }),
    );
    expect(await oauthError(client.clientCredentialsGrant(impostor))).toBe("invalid_client");
  });

  it("introspects and revokes refresh tokens of the tenant's own clients", async () => {
    const world = await createTenantWorld(repos, "intro");
    const { person } = await createPerson(repos, world, `p-${uniqueSuffix()}`);
    const config = await discoverWithSecret(ts!, world.tenant.slug, world.app);
    const tokens = await codeFlow(ts!, config, world.app.application.redirectUris[0]!, {
      personId: person.id,
      loginMethodId: world.loginMethod.id,
      acr: world.loginMethod.assertedAcr,
    });
    const active = await client.tokenIntrospection(config, tokens.refresh_token!);
    expect(active).toMatchObject({
      active: true,
      sub: person.id,
      client_id: world.app.application.clientId,
    });

    // Another tenant's client sees nothing: the token is not in its tenant's storage.
    const elsewhere = await createTenantWorld(repos, "intro-other");
    const otherConfig = await discoverWithSecret(ts!, elsewhere.tenant.slug, elsewhere.app);
    expect((await client.tokenIntrospection(otherConfig, tokens.refresh_token!)).active).toBe(
      false,
    );

    await client.tokenRevocation(config, tokens.refresh_token!);
    expect((await client.tokenIntrospection(config, tokens.refresh_token!)).active).toBe(false);
    expect(await oauthError(client.refreshTokenGrant(config, tokens.refresh_token!))).toBe(
      "invalid_grant",
    );
  });
});
