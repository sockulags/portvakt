import * as client from "openid-client";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { CreateLoginMethodInput } from "../domain/login-method.js";
import type { Tenant } from "../domain/tenant.js";
import { ValidationError } from "../repositories/errors.js";
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
import { startTestServer } from "../testing/test-server.js";

const ts = await startTestServer();
const idp = ts === undefined ? undefined : await startTestIdp();

/**
 * A controlled clock: Date is faked (timers stay real, and the fake clock keeps running), starting
 * just after a whole second, so the whole-second times of tokens and sessions are deterministic.
 * Expiry decisions are made on this clock (oidc-provider's and Portvakt's checks); rows the
 * database expires by its own clock are still found, and then refused by those checks.
 */
function useClock(): (seconds: number) => void {
  vi.useFakeTimers({ toFake: ["Date"], shouldAdvanceTime: true });
  vi.setSystemTime(Math.ceil(Date.now() / 1000) * 1000 + 50);
  return (seconds) => {
    vi.setSystemTime(Date.now() + seconds * 1000);
  };
}

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

describe.skipIf(ts === undefined)("session policies", () => {
  const { repos } = ts!.db;
  const db = ts!.db.db;

  afterEach(() => {
    vi.useRealTimers();
  });

  interface App {
    readonly client: TestClient;
    readonly config: client.Configuration;
    readonly redirectUri: string;
  }

  async function app(tenant: Tenant): Promise<App> {
    const testClient = await createTestClient(repos, tenant);
    return {
      client: testClient,
      config: await discoverWithSecret(ts!, tenant.slug, testClient),
      redirectUri: testClient.application.redirectUris[0]!,
    };
  }

  /** A tenant with one citizen login method of the given policy and two applications. */
  async function setup(prefix: string, overrides: Partial<CreateLoginMethodInput> = {}) {
    const tenant = await createTenant(repos, prefix);
    const method = await createFederatedLoginMethod(ts!, idp!, tenant, "bankid", overrides);
    return { tenant, method, a: await app(tenant), b: await app(tenant) };
  }

  /** Authorizes `target` in `driver`'s browser; signs `persona` in if the IdP asks. */
  async function authorize(
    driver: FlowDriver,
    target: App,
    persona: string | undefined,
    params: Record<string, string> = {},
  ) {
    const request = await authorizationRequest(target.config, target.redirectUri, params);
    let landing: Landing = await driver.follow(request.url.href);
    const upstreamLogin = landing.kind === "idp_page";
    const upstreamUrl = driver.visited.findLast((url) =>
      url.startsWith(`${idp!.baseUrl}/bankid/auth?`),
    );
    if (landing.kind === "idp_page") {
      if (persona === undefined) throw new Error("an upstream login was not expected");
      landing = await driver.persona(landing, persona);
    }
    return {
      request,
      landing,
      upstreamLogin,
      upstreamUrl,
      tokens: await redeem(target.config, request, landing),
    };
  }

  it("gives SSO to another app with allowSso, and a fresh upstream login without it", async () => {
    const sso = await setup("sso", {
      sessionPolicy: { maxAgeSeconds: 3600, idleSeconds: 600, allowSso: true },
    });
    const driver = new FlowDriver(ts!, idp!);
    const first = await authorize(driver, sso.a, "sven-medborgare");
    expect(first.upstreamLogin).toBe(true);
    const second = await authorize(driver, sso.b, undefined);
    expect(second.upstreamLogin).toBe(false);
    expect(second.tokens.claims()?.sub).toBe(first.tokens.claims()?.sub);

    const strict = await setup("nosso", {
      sessionPolicy: { maxAgeSeconds: 3600, idleSeconds: 600, allowSso: false },
    });
    const browser = new FlowDriver(ts!, idp!);
    const atA = await authorize(browser, strict.a, "sven-medborgare");
    // The same application may reuse the session.
    expect((await authorize(browser, strict.a, undefined)).upstreamLogin).toBe(false);
    // Another one needs a fresh upstream login, even though the IdP still has a session.
    const atB = await authorize(browser, strict.b, "sven-medborgare");
    expect(atB.upstreamLogin).toBe(true);
    expect(new URL(atB.upstreamUrl!).searchParams.get("prompt")).toBe("login");
    expect(atB.tokens.claims()?.sub).toBe(atA.tokens.claims()?.sub);
    // The session is now established for B: A needs a fresh login again.
    expect((await authorize(browser, strict.a, "sven-medborgare")).upstreamLogin).toBe(true);
  });

  it("lets an app tighten the policy with prompt=login, max_age and acr_values", async () => {
    const { a, b } = await setup("tighten", {
      sessionPolicy: { maxAgeSeconds: 3600, idleSeconds: 600, allowSso: true },
      assertedAcr: LOA2,
    });
    const advance = useClock();
    const driver = new FlowDriver(ts!, idp!);
    await authorize(driver, a, "sven-medborgare");
    const forced = await authorize(driver, b, "sven-medborgare", { prompt: "login" });
    expect(forced.upstreamLogin).toBe(true);
    expect(new URL(forced.upstreamUrl!).searchParams.get("prompt")).toBe("login");

    advance(5);
    const aged = await authorize(driver, b, "sven-medborgare", { max_age: "1" });
    expect(aged.upstreamLogin).toBe(true);
    expect(new URL(aged.upstreamUrl!).searchParams.get("max_age")).toBe("1");

    // The session's loa2 does not satisfy loa3 and no login method offers loa3.
    const request = await authorizationRequest(b.config, b.redirectUri, { acr_values: LOA3 });
    const stepUp = await driver.follow(request.url.href);
    expect(stepUp).toMatchObject({
      kind: "login_ui",
      bootstrap: { error: "no_acceptable_method" },
    });
  });

  it("ends the session after the login method's maxAge", async () => {
    const { a } = await setup("maxage", {
      sessionPolicy: { maxAgeSeconds: 120, idleSeconds: 120, allowSso: true },
    });
    const advance = useClock();
    const driver = new FlowDriver(ts!, idp!);
    const { tokens } = await authorize(driver, a, "sven-medborgare");
    const claims = tokens.claims()!;
    const sessionLength = (claims.session_exp as number) - (claims.auth_time as number);
    expect(sessionLength).toBeGreaterThanOrEqual(120);
    expect(sessionLength).toBeLessThanOrEqual(125);
    advance(60);
    expect((await authorize(driver, a, undefined)).upstreamLogin).toBe(false);
    advance(61);
    expect(await oauthError(client.refreshTokenGrant(a.config, tokens.refresh_token!))).toBe(
      "invalid_grant",
    );
    expect((await authorize(driver, a, "sven-medborgare")).upstreamLogin).toBe(true);
  });

  it("requires a login after idleSeconds without activity; a refresh is activity", async () => {
    const { a, b } = await setup("idle", {
      sessionPolicy: { maxAgeSeconds: 600, idleSeconds: 60, allowSso: true },
    });
    const advance = useClock();
    const driver = new FlowDriver(ts!, idp!);
    const { tokens } = await authorize(driver, a, "sven-medborgare");
    advance(40);
    const refreshed = await client.refreshTokenGrant(a.config, tokens.refresh_token!);
    advance(50);
    // 90s after the login (idle, had the refresh not counted), 50s after the refresh: still
    // active, SSO to B works (and is activity itself).
    expect((await authorize(driver, b, undefined)).upstreamLogin).toBe(false);
    advance(61);
    // Idle now: the refresh token lived at most idleSeconds, and B's next authorization logs in.
    expect(await oauthError(client.refreshTokenGrant(a.config, refreshed.refresh_token!))).toBe(
      "invalid_grant",
    );
    const fresh = await authorize(driver, b, "sven-medborgare");
    expect(fresh.upstreamLogin).toBe(true);
    expect(new URL(fresh.upstreamUrl!).searchParams.get("prompt")).toBe("login");
  });

  it("bounds refresh tokens by min(idleSeconds, remaining maxAge)", async () => {
    const { tenant, a } = await setup("rt-ttl", {
      sessionPolicy: { maxAgeSeconds: 900, idleSeconds: 600, allowSso: true },
    });
    const driver = new FlowDriver(ts!, idp!);
    const { tokens } = await authorize(driver, a, "sven-medborgare");
    const ttlOf = async () =>
      (
        await db.query<{ seconds: number }>(
          `SELECT extract(epoch FROM expires_at - now())::int AS seconds FROM oidc_payloads
            WHERE tenant_id = $1 AND kind = 'RefreshToken' AND consumed_at IS NULL`,
          [tenant.id],
        )
      ).map((row) => row.seconds);
    const [initial] = await ttlOf();
    expect(initial).toBeLessThanOrEqual(600);
    expect(initial).toBeGreaterThan(590);
    await client.refreshTokenGrant(a.config, tokens.refresh_token!);
    expect(await ttlOf()).toHaveLength(1);

    const short = await setup("rt-short", {
      sessionPolicy: { maxAgeSeconds: 30, idleSeconds: 30, allowSso: true },
    });
    await authorize(new FlowDriver(ts!, idp!), short.a, "sven-medborgare");
    const [remaining] = (
      await db.query<{ seconds: number }>(
        `SELECT extract(epoch FROM expires_at - now())::int AS seconds FROM oidc_payloads
          WHERE tenant_id = $1 AND kind = 'RefreshToken'`,
        [short.tenant.id],
      )
    ).map((row) => row.seconds);
    expect(remaining).toBeLessThanOrEqual(30);
  });

  it("keeps app A's claims when app B's fresh login uses another login method", async () => {
    const tenant = await createTenant(repos, "snapshot");
    const policy = { maxAgeSeconds: 3600, idleSeconds: 600, allowSso: false };
    // Both citizen methods link by pin, so both logins are the same person.
    const strong = await createFederatedLoginMethod(ts!, idp!, tenant, "bankid", {
      displayName: "BankID",
      assertedAcr: LOA4,
      linkByPin: true,
      sessionPolicy: policy,
    });
    const weak = await createFederatedLoginMethod(ts!, idp!, tenant, "bankid", {
      displayName: "Other eID",
      assertedAcr: LOA3,
      linkByPin: true,
      sessionPolicy: policy,
    });
    const a = await app(tenant);
    const b = await app(tenant);
    const driver = new FlowDriver(ts!, idp!);

    const loginWith = async (target: App, methodId: string) => {
      const request = await authorizationRequest(target.config, target.redirectUri);
      const chooser = await driver.follow(request.url.href);
      const page = await driver.chooseAndFollow(chooser, { loginMethodId: methodId });
      return redeem(target.config, request, await driver.persona(page, "maja-loa4"));
    };
    const atA = await loginWith(a, strong.id);
    expect(atA.claims()).toMatchObject({ idp: strong.id, acr: LOA4 });
    const atB = await loginWith(b, weak.id);
    expect(atB.claims()).toMatchObject({ idp: weak.id, acr: LOA3, sub: atA.claims()?.sub });

    // A's next refresh still reflects A's own login.
    const refreshed = await client.refreshTokenGrant(a.config, atA.refresh_token!);
    expect(refreshed.claims()).toMatchObject({ idp: strong.id, acr: LOA4 });
    const access = JSON.parse(
      Buffer.from(refreshed.access_token.split(".")[1]!, "base64url").toString("utf8"),
    ) as Record<string, unknown>;
    expect(access).toMatchObject({ idp: strong.id, acr: LOA4 });
    // And B's refresh reflects B's.
    const refreshedB = await client.refreshTokenGrant(b.config, atB.refresh_token!);
    expect(refreshedB.claims()).toMatchObject({ idp: weak.id, acr: LOA3 });
  });

  it("refuses a login method maxAge beyond SESSION_TTL at write time", async () => {
    const tenant = await createTenant(repos, "ceiling");
    const ceiling = ts!.config.tokens.sessionSeconds;
    // The server's repositories carry the ceiling (the test database's plain ones do not).
    const { loginMethods } = ts!.portvakt.repos;
    const input = {
      kind: "employee",
      displayName: "Long",
      issuer: idp!.issuer("entra"),
      clientId: "long",
      clientSecret: "secret-value",
      claimMapping: { subject: "oid" },
      assertedAcr: "urn:portvakt:acr:employee",
    } as const;
    await expect(
      loginMethods.create(tenant.id, {
        ...input,
        sessionPolicy: { maxAgeSeconds: ceiling + 1, idleSeconds: 60, allowSso: true },
      }),
    ).rejects.toBeInstanceOf(ValidationError);
    const method = await loginMethods.create(tenant.id, {
      ...input,
      sessionPolicy: { maxAgeSeconds: ceiling, idleSeconds: 60, allowSso: true },
    });
    await expect(
      loginMethods.update(tenant.id, method.id, {
        sessionPolicy: { maxAgeSeconds: ceiling * 2, idleSeconds: 60, allowSso: true },
      }),
    ).rejects.toBeInstanceOf(ValidationError);
  });
});
