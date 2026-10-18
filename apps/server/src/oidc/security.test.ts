import { createServer, request as httpRequest, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import * as client from "openid-client";
import { describe, expect, it } from "vitest";
import { createLogger } from "../logging/logger.js";
import { createPortvakt } from "../server.js";
import { uniqueSuffix } from "../testing/fixtures.js";
import {
  authorize,
  codeFlow,
  createPerson,
  createTenantWorld,
  createTestClient,
  discoverWithSecret,
  type TenantWorld,
} from "../testing/oidc-flow.js";
import { startTestServer, TestBrowser } from "../testing/test-server.js";

/** Sessions here end one hour after login, well before SESSION_TTL (8h). */
const SESSION_SECONDS = 3600;

const ts = await startTestServer({
  sessionPolicy: {
    sessionExpiresAt: ({ authTime }) => Promise.resolve(authTime + SESSION_SECONDS),
    refreshTokenTtl: (login, now) => Math.max(1, (login?.sessionExpiresAt ?? now + 1) - now),
  },
});

async function oauthError(promise: Promise<unknown>): Promise<string> {
  try {
    await promise;
  } catch (error) {
    if (error instanceof client.ResponseBodyError) return error.error;
    if (error instanceof client.WWWAuthenticateChallengeError) {
      return String(error.cause[0]?.parameters.error);
    }
    throw error;
  }
  throw new Error("expected the request to fail");
}

/** GET with full control over the Host and forwarding headers (fetch cannot set Host). */
function rawGet(
  url: string,
  headers: Record<string, string>,
): Promise<{ status: number; headers: Record<string, unknown>; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(url, { headers, agent: false }, (res) => {
      let body = "";
      res.setEncoding("utf8");
      res.on("data", (chunk: string) => (body += chunk));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body }));
    });
    req.on("error", reject);
    req.end();
  });
}

async function listen(server: Server): Promise<string> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

describe.skipIf(ts === undefined)("security properties", () => {
  const { db, baseUrl, config } = ts!;
  const { repos } = db;

  async function worldWithPerson(prefix = "sec") {
    const world = await createTenantWorld(repos, prefix);
    const { person } = await createPerson(repos, world, `p-${uniqueSuffix()}`);
    const as = {
      personId: person.id,
      loginMethodId: world.loginMethod.id,
      acr: world.loginMethod.assertedAcr,
    };
    return { world, person, as };
  }
  const redirectUriOf = (world: TenantWorld): string => world.app.application.redirectUris[0]!;

  it("redeems an authorization code once, even under parallel requests", async () => {
    const { world, as } = await worldWithPerson();
    const config = await discoverWithSecret(ts!, world.tenant.slug, world.app);
    const result = await authorize(ts!, config, redirectUriOf(world), as);
    const attempts = await Promise.allSettled(
      Array.from({ length: 8 }, () =>
        client.authorizationCodeGrant(config, result.callbackUrl, {
          pkceCodeVerifier: result.codeVerifier,
          expectedState: result.state,
          expectedNonce: result.nonce,
        }),
      ),
    );
    const won = attempts.filter((attempt) => attempt.status === "fulfilled");
    expect(won).toHaveLength(1);
    for (const lost of attempts.filter((attempt) => attempt.status === "rejected")) {
      expect((lost.reason as client.ResponseBodyError).error).toBe("invalid_grant");
    }
    // The replay revoked the grant, so even the winner's refresh token is dead.
    const tokens = won[0]!.value;
    expect(await oauthError(client.refreshTokenGrant(config, tokens.refresh_token!))).toBe(
      "invalid_grant",
    );
  });

  it("rotates a refresh token once, even under parallel requests, and revokes on replay", async () => {
    const { world, as } = await worldWithPerson();
    const config = await discoverWithSecret(ts!, world.tenant.slug, world.app);
    const tokens = await codeFlow(ts!, config, redirectUriOf(world), as);
    const attempts = await Promise.allSettled(
      Array.from({ length: 8 }, () => client.refreshTokenGrant(config, tokens.refresh_token!)),
    );
    const won = attempts.filter((attempt) => attempt.status === "fulfilled");
    expect(won).toHaveLength(1);
    for (const lost of attempts.filter((attempt) => attempt.status === "rejected")) {
      expect((lost.reason as client.ResponseBodyError).error).toBe("invalid_grant");
    }
    expect(await oauthError(client.refreshTokenGrant(config, won[0]!.value.refresh_token!))).toBe(
      "invalid_grant",
    );
  });

  it("accepts a private_key_jwt client assertion once, even under parallel requests", async () => {
    const world = await createTenantWorld(repos, "assert");
    const { privateKey, publicKey } = await generateKeyPair("ES256", { extractable: true });
    const jwk = { ...(await exportJWK(publicKey)), kty: "EC", kid: "k1", alg: "ES256", use: "sig" };
    const keyClient = await createTestClient(repos, world.tenant, {
      clientAuth: { method: "private_key_jwt", jwks: { keys: [jwk] } },
    });
    const issuer = ts!.issuerOf(world.tenant.slug);
    const clientId = keyClient.application.clientId;
    const assertion = await new SignJWT({})
      .setProtectedHeader({ alg: "ES256", kid: "k1" })
      .setIssuer(clientId)
      .setSubject(clientId)
      .setAudience(issuer)
      .setJti(`jti-${uniqueSuffix()}`)
      .setIssuedAt()
      .setExpirationTime("1m")
      .sign(privateKey);
    const body = new URLSearchParams({
      grant_type: "client_credentials",
      client_id: clientId,
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      client_assertion: assertion,
    }).toString();
    const responses = await Promise.all(
      Array.from({ length: 8 }, () =>
        fetch(`${issuer}/token`, {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body,
        }),
      ),
    );
    const statuses = responses.map((response) => response.status).sort();
    expect(statuses.filter((status) => status === 200)).toHaveLength(1);
    expect(statuses.filter((status) => status === 401)).toHaveLength(7);
    for (const response of responses.filter((r) => r.status === 401)) {
      expect(await response.json()).toMatchObject({ error: "invalid_client" });
    }
  });

  it("builds endpoint URLs from PUBLIC_URL, never from Host or X-Forwarded-Host", async () => {
    const world = await createTenantWorld(repos, "host");
    const url = `${baseUrl}/t/${world.tenant.slug}/.well-known/openid-configuration`;
    const forged = await rawGet(url, {
      host: "attacker.example",
      "x-forwarded-host": "attacker.example",
      "x-forwarded-proto": "https",
      forwarded: "host=attacker.example;proto=https",
    });
    expect(forged.status).toBe(200);
    expect(forged.body).not.toContain("attacker.example");
    const discovery = JSON.parse(forged.body) as Record<string, unknown>;
    expect(discovery.token_endpoint).toBe(`${baseUrl}/t/${world.tenant.slug}/token`);
    expect(discovery.issuer).toBe(`${baseUrl}/t/${world.tenant.slug}`);
    expect(forged.headers["cache-control"]).toBe("public, max-age=300");
    const jwks = await rawGet(`${baseUrl}/t/${world.tenant.slug}/jwks`, { host: "x.example" });
    expect(jwks.headers["cache-control"]).toBe("public, max-age=60");
  });

  it("lets only the token's own client introspect it", async () => {
    const { world, as } = await worldWithPerson();
    const other = await createTestClient(repos, world.tenant);
    const own = await discoverWithSecret(ts!, world.tenant.slug, world.app);
    const tokens = await codeFlow(ts!, own, redirectUriOf(world), as);
    expect((await client.tokenIntrospection(own, tokens.refresh_token!)).active).toBe(true);
    const sameTenant = await discoverWithSecret(ts!, world.tenant.slug, other);
    expect((await client.tokenIntrospection(sameTenant, tokens.refresh_token!)).active).toBe(false);
  });

  it("refuses an id_token_hint of tenant A at tenant B's logout", async () => {
    const a = await worldWithPerson("logout-a");
    const b = await createTenantWorld(repos, "logout-b");
    const postLogout = `https://${a.world.app.application.clientId}.example.test/signed-out`;
    await repos.applications.update(a.world.app.application.id, {
      postLogoutRedirectUris: [postLogout],
    });
    // The same application is enabled in both tenants.
    await repos.applications.enableForTenant(b.tenant.id, a.world.app.application.id);
    const atA = await discoverWithSecret(ts!, a.world.tenant.slug, a.world.app);
    const tokens = await codeFlow(ts!, atA, redirectUriOf(a.world), a.as);
    const atB = await discoverWithSecret(ts!, b.tenant.slug, a.world.app);
    const endSession = client.buildEndSessionUrl(atB, {
      id_token_hint: tokens.id_token!,
      post_logout_redirect_uri: postLogout,
    });
    const response = await new TestBrowser().request(endSession.href);
    expect(response.status).toBe(400);
    expect(response.headers.get("location")).toBeNull();
    expect(await response.text()).toContain("invalid_request");
  });

  it("lets a grant expire with the session's real end, also on SSO", async () => {
    const { world, as } = await worldWithPerson("grant-ttl");
    const second = await createTestClient(repos, world.tenant);
    const browser = new TestBrowser();
    const first = await discoverWithSecret(ts!, world.tenant.slug, world.app);
    await codeFlow(ts!, first, redirectUriOf(world), as, { browser });
    const config = await discoverWithSecret(ts!, world.tenant.slug, second);
    await codeFlow(ts!, config, second.application.redirectUris[0]!, as, { browser });
    const grants = await db.db.query<{ seconds: number }>(
      `SELECT extract(epoch FROM expires_at - now())::int AS seconds
         FROM oidc_payloads WHERE tenant_id = $1 AND kind = 'Grant'`,
      [world.tenant.id],
    );
    expect(grants).toHaveLength(2);
    for (const grant of grants) {
      expect(grant.seconds).toBeLessThanOrEqual(SESSION_SECONDS);
      expect(grant.seconds).toBeGreaterThan(SESSION_SECONDS - 60);
    }
  });

  it("sets Secure, HttpOnly, SameSite=Lax cookies scoped to the tenant in production", async () => {
    const world = await createTenantWorld(repos, "cookies");
    const { person } = await createPerson(repos, world, `p-${uniqueSuffix()}`);
    const publicUrl = "https://login.example.org";
    const production = createPortvakt({
      config: { ...config, isProduction: true, publicUrl },
      pool: db.pool,
      logger: createLogger({ level: "silent" }),
      keys: db.keys,
    });
    await production.start();
    const server = createServer();
    production.serve(server);
    const local = await listen(server);
    const toLocal = (url: string): string => url.replace(publicUrl, local);
    try {
      const basePath = `/t/${world.tenant.slug}`;
      const params = new URLSearchParams({
        client_id: world.app.application.clientId,
        response_type: "code",
        scope: "openid",
        redirect_uri: redirectUriOf(world),
        code_challenge: await client.calculatePKCECodeChallenge(client.randomPKCECodeVerifier()),
        code_challenge_method: "S256",
      });
      const browser = new TestBrowser();
      const start = await browser.request(`${local}${basePath}/auth?${params.toString()}`);
      const interaction = TestBrowser.location(start, publicUrl);
      expect(interaction.startsWith(`${publicUrl}${basePath}/interaction/`)).toBe(true);
      const uid = interaction.split("/").at(-1)!;
      const startCookies = start.headers.getSetCookie().join("\n");
      expect(startCookies).toMatch(
        new RegExp(`_pv_interaction=[^;]+; path=${basePath}/interaction/${uid};[^\n]*secure`, "i"),
      );
      expect(startCookies).toMatch(
        new RegExp(`_pv_resume=[^;]+; path=${basePath}/auth/${uid}`, "i"),
      );

      const loggedIn = await browser.request(`${toLocal(interaction)}/__test__/login`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          personId: person.id,
          loginMethodId: world.loginMethod.id,
          acr: world.loginMethod.assertedAcr,
          amr: ["pwd"],
        }),
      });
      const resume = await browser.request(toLocal(TestBrowser.location(loggedIn, publicUrl)));
      expect(resume.status).toBe(303);
      const session = resume.headers
        .getSetCookie()
        .find((cookie) => cookie.startsWith("_pv_session="));
      expect(session).toBeDefined();
      const attributes = session!.toLowerCase();
      expect(attributes).toContain(`path=${basePath.toLowerCase()};`);
      expect(attributes).toContain("secure");
      expect(attributes).toContain("httponly");
      expect(attributes).toContain("samesite=lax");
    } finally {
      await production.shutdown();
    }
  });
});
