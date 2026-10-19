import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type RequestListener } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { JSON_CSP, PERMISSIONS_POLICY } from "@portvakt/http-kit";
import type { AddressInfo } from "node:net";
import { MemoryStore, silentLogger } from "@portvakt/sdk-node";
import {
  createAdmin,
  createAdminTenant,
  setupAdminWorld,
  startTestServer,
  TestBrowser,
  TENANT_ADMIN_ROLE,
  type AdminTenant,
  type AdminWorld,
} from "@portvakt/server/testing";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ADMIN_PAGE_CSP, createAdminApp } from "./app.js";
import { AdminConfigError, loadAdminConfig } from "./config.js";
import { apiTarget } from "./proxy.js";
import { TenantClients } from "./tenants.js";

/** The admin BFF in-process against an in-process Portvakt (test login route). */

const ts = await startTestServer();

describe("apiTarget", () => {
  const api = "https://login.example.org";
  it("builds URLs below the admin API only", () => {
    expect(apiTarget(api, ["tenants", "abc"], "?x=1")?.href).toBe(
      "https://login.example.org/admin/api/v1/tenants/abc?x=1",
    );
    for (const segments of [
      ["..", "healthz"],
      ["."],
      ["%2e%2e"],
      ["a/b"],
      ["@evil.example"],
      [],
      ["x y"],
    ]) {
      expect(apiTarget(api, segments, ""), JSON.stringify(segments)).toBeUndefined();
    }
    expect(apiTarget(api, ["me"], "?a=1#frag")).toBeUndefined();
  });
});

describe.skipIf(ts === undefined)("admin BFF", () => {
  const server = createServer();
  let base: string;
  let world: AdminWorld;
  let x: AdminTenant;
  let y: AdminTenant;
  let adminX: string;

  beforeAll(async () => {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    world = await setupAdminWorld(ts!, base);
    x = await createAdminTenant(world, "bffx");
    y = await createAdminTenant(world, "bffy");
    adminX = await createAdmin(world, x.tenant, x.method, [TENANT_ADMIN_ROLE]);
    const config = loadAdminConfig({
      NODE_ENV: "development",
      ADMIN_PUBLIC_URL: base,
      PORTVAKT_PUBLIC_URL: ts!.baseUrl,
      ADMIN_CLIENT_SECRET: world.secret,
      ADMIN_WEB_DIR: "does-not-exist",
    });
    server.on("request", createAdminApp(config, { logger: silentLogger }));
  });
  afterAll(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  /** Signs the person in to the portal of `slug` through the test login route. */
  async function signIn(
    browser: TestBrowser,
    admin: AdminTenant,
    personId: string,
  ): Promise<string> {
    const slug = admin.tenant.slug;
    let response = await browser.request(`${base}/t/${slug}/auth/login?returnTo=%2Ft%2F${slug}%2F`);
    let next = TestBrowser.location(response, base);
    response = await browser.request(next);
    next = TestBrowser.location(response, next);
    expect(new URL(next).pathname).toContain("/interaction/");
    response = await browser.request(`${next}/__test__/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        personId,
        loginMethodId: admin.method.id,
        acr: admin.method.assertedAcr,
        amr: ["pwd"],
      }),
    });
    next = TestBrowser.location(response, next);
    for (let hops = 0; hops < 5 && !next.startsWith(`${base}/t/${slug}/auth/callback`); hops += 1) {
      response = await browser.request(next);
      next = TestBrowser.location(response, next);
    }
    response = await browser.request(next);
    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe(`/t/${slug}/`);
    const cookie = response.headers.getSetCookie().find((value) => value.startsWith("pv_admin="));
    expect(cookie).toContain(`Path=/t/${slug}`);
    return cookie!.split(";")[0]!;
  }

  async function csrf(browser: TestBrowser, slug: string): Promise<string> {
    const session = (await (await browser.request(`${base}/t/${slug}/auth/session`)).json()) as {
      csrfToken: string;
    };
    return session.csrfToken;
  }

  it("proxies to the admin API with the session's token and scopes cookies to the tenant", async () => {
    const browser = new TestBrowser();
    expect((await browser.request(`${base}/t/${x.tenant.slug}/api/me`)).status).toBe(401);
    const cookie = await signIn(browser, x, adminX);
    expect(browser.cookieNames()).toContain(`pv_admin@/t/${x.tenant.slug}`);
    const me = await browser.request(`${base}/t/${x.tenant.slug}/api/me`);
    expect(me.status).toBe(200);
    expect(await me.json()).toMatchObject({ personId: adminX, tenant: { id: x.tenant.id } });
    // The SPA never receives a token.
    const session = await (await browser.request(`${base}/t/${x.tenant.slug}/auth/session`)).text();
    expect(session).not.toMatch(/eyJ[A-Za-z0-9_-]+\.eyJ/);

    // Tenant X's cookie presented below tenant Y's path finds no session there.
    expect((await fetch(`${base}/t/${x.tenant.slug}/api/me`, { headers: { cookie } })).status).toBe(
      200,
    );
    expect((await fetch(`${base}/t/${y.tenant.slug}/api/me`, { headers: { cookie } })).status).toBe(
      401,
    );
  });

  it("serves the SPA shell at the tenant root and redirects the bare tenant path", async () => {
    const root = await fetch(`${base}/t/${x.tenant.slug}/`, { redirect: "manual" });
    expect(root.status).toBe(200);
    const bare = await fetch(`${base}/t/${x.tenant.slug}`, { redirect: "manual" });
    expect(bare.status).toBe(302);
    expect(bare.headers.get("location")).toBe(`/t/${x.tenant.slug}/`);
    expect((await fetch(`${base}/t/Not_A_Slug/`, { redirect: "manual" })).status).toBe(404);
  });

  it("requires the CSRF token, a same-origin request and JSON for mutations", async () => {
    const browser = new TestBrowser();
    await signIn(browser, x, adminX);
    const slug = x.tenant.slug;
    const url = `${base}/t/${slug}/api/tenants/${x.tenant.id}/persons/search`;
    const body = JSON.stringify({ query: "test" });
    const json = { "content-type": "application/json" };
    expect((await browser.request(url, { method: "POST", headers: json, body })).status).toBe(403);
    const token = await csrf(browser, slug);
    const crossSite = await browser.request(url, {
      method: "POST",
      headers: { ...json, "x-csrf-token": token, "sec-fetch-site": "cross-site" },
      body,
    });
    expect(crossSite.status).toBe(403);
    const otherOrigin = await browser.request(url, {
      method: "POST",
      headers: { ...json, "x-csrf-token": token, origin: "https://evil.example" },
      body,
    });
    expect(otherOrigin.status).toBe(403);
    const form = await browser.request(url, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", "x-csrf-token": token },
      body: "query=test",
    });
    expect(form.status).toBe(415);
    const ok = await browser.request(url, {
      method: "POST",
      headers: { ...json, "x-csrf-token": token, "sec-fetch-site": "same-origin" },
      body,
    });
    expect(ok.status).toBe(200);
    expect(await ok.json()).toMatchObject({
      items: [expect.objectContaining({ displayName: "Test Admin" })],
    });
  });

  it("forwards only below the admin API and passes problems and ETags through", async () => {
    const browser = new TestBrowser();
    await signIn(browser, x, adminX);
    const slug = x.tenant.slug;
    for (const path of [
      "..%2F..%2Fhealthz",
      "%2e%2e%2f%2e%2e%2fhealthz",
      "me%2F..%2F..%2Freadyz",
    ]) {
      const response = await browser.request(`${base}/t/${slug}/api/${path}`);
      expect(response.status, path).toBe(404);
    }
    const other = await browser.request(`${base}/t/${slug}/api/tenants/${y.tenant.id}`);
    expect(other.status).toBe(404);
    expect(other.headers.get("content-type")).toContain("application/problem+json");
    const own = await browser.request(`${base}/t/${slug}/api/tenants/${x.tenant.id}`);
    expect(own.headers.get("etag")).toMatch(/^"/);
  });
  it("answers unknown tenants with 404 without creating clients, and caches the answer", async () => {
    const config = loadAdminConfig({
      NODE_ENV: "development",
      ADMIN_PUBLIC_URL: base,
      PORTVAKT_PUBLIC_URL: ts!.baseUrl,
      ADMIN_CLIENT_SECRET: world.secret,
      ADMIN_WEB_DIR: "does-not-exist",
    });
    const asked: string[] = [];
    const counting: typeof fetch = (input, init) => {
      asked.push(new URL(input instanceof Request ? input.url : input).pathname);
      return fetch(input, init);
    };
    const clients = new TenantClients(config, new MemoryStore(), silentLogger, counting);
    const known = await clients.get(x.tenant.slug);
    expect(known).toBeDefined();
    for (let index = 0; index < 250; index += 1) {
      expect(await clients.get(`no-such-tenant-${index}`)).toBeUndefined();
    }
    // Remembered: no second lookup for the same unknown slug, and the known client survived.
    expect(await clients.get("no-such-tenant-0")).toBeUndefined();
    expect(asked.filter((path) => path.startsWith("/t/no-such-tenant-0/"))).toHaveLength(1);
    expect(await clients.get(x.tenant.slug)).toBe(known);
    expect(asked.filter((path) => path.startsWith(`/t/${x.tenant.slug}/`))).toHaveLength(1);

    for (const path of [
      "/t/no-such-tenant/",
      "/t/no-such-tenant/auth/login",
      "/t/no-such-tenant/api/me",
    ]) {
      const response = await fetch(`${base}${path}`, { redirect: "manual" });
      expect(response.status, path).toBe(404);
    }
  });

  /** Runs `handler` on an ephemeral port for `fn`. */
  async function serving(
    handler: RequestListener,
    fn: (origin: string) => Promise<void>,
  ): Promise<void> {
    const other = createServer(handler);
    await new Promise<void>((resolve) => other.listen(0, "127.0.0.1", resolve));
    try {
      await fn(`http://127.0.0.1:${(other.address() as AddressInfo).port}`);
    } finally {
      other.closeAllConnections();
      await new Promise<void>((resolve) => other.close(() => resolve()));
    }
  }

  it("sends the baseline security headers, and the SPA its page CSP", async () => {
    const health = await fetch(`${base}/healthz`);
    expect(health.headers.get("content-security-policy")).toBe(JSON_CSP);
    expect(health.headers.get("x-frame-options")).toBe("DENY");
    expect(health.headers.get("cross-origin-opener-policy")).toBe("same-origin");
    expect(health.headers.get("permissions-policy")).toBe(PERMISSIONS_POLICY);
    expect(health.headers.get("referrer-policy")).toBe("no-referrer");
    expect(health.headers.get("x-content-type-options")).toBe("nosniff");
    expect(ADMIN_PAGE_CSP).not.toMatch(/unsafe-(inline|eval)/);

    const web = mkdtempSync(join(tmpdir(), "portvakt-admin-web-"));
    writeFileSync(join(web, "index.html"), "<!doctype html><title>Admin</title>");
    try {
      const config = loadAdminConfig({
        NODE_ENV: "development",
        ADMIN_PUBLIC_URL: base,
        PORTVAKT_PUBLIC_URL: ts!.baseUrl,
        ADMIN_CLIENT_SECRET: world.secret,
        ADMIN_WEB_DIR: web,
      });
      await serving(createAdminApp(config, { logger: silentLogger }), async (origin) => {
        const page = await fetch(`${origin}/t/${x.tenant.slug}/`);
        expect(page.status).toBe(200);
        expect(page.headers.get("content-security-policy")).toBe(ADMIN_PAGE_CSP);
        expect(page.headers.get("cache-control")).toBe("no-store");
      });
    } finally {
      rmSync(web, { recursive: true, force: true });
    }
  });

  it("limits sign-in starts per client IP with a page and Retry-After", async () => {
    const config = loadAdminConfig({
      NODE_ENV: "development",
      ADMIN_PUBLIC_URL: base,
      PORTVAKT_PUBLIC_URL: ts!.baseUrl,
      ADMIN_CLIENT_SECRET: world.secret,
      ADMIN_WEB_DIR: "does-not-exist",
      ADMIN_RATE_LIMIT_LOGIN: "2/1m",
      ADMIN_TRUST_PROXY: "1",
    });
    await serving(createAdminApp(config, { logger: silentLogger }), async (origin) => {
      const login = (ip: string) =>
        fetch(`${origin}/t/${x.tenant.slug}/auth/login`, {
          headers: { "x-forwarded-for": ip },
          redirect: "manual",
        });
      expect((await login("203.0.113.7")).status).toBe(302);
      expect((await login("203.0.113.7")).status).toBe(302);
      const refused = await login("203.0.113.7");
      expect(refused.status).toBe(429);
      expect(refused.headers.get("retry-after")).not.toBeNull();
      expect(await refused.text()).toContain("För många inloggningsförsök");
      // Another client IP (as TRUST_PROXY resolves it) is not affected.
      expect((await login("203.0.113.8")).status).toBe(302);
      const metrics = await (await fetch(`${origin}/metrics`)).text();
      expect(metrics).toContain('portvakt_admin_rate_limited_total{limit="login"} 1');
      expect(metrics).toContain(
        'portvakt_admin_http_requests_total{method="GET",route="/t/{slug}/auth/login",status="429"} 1',
      );
      expect(metrics).not.toContain(x.tenant.slug);
    });
  });

  it("continues the trace into the admin API and names it in problem responses", async () => {
    const browser = new TestBrowser();
    await signIn(browser, x, adminX);
    const traceId = "5bf92f3577b34da6a3ce929d0e0e4736";
    const other = await browser.request(`${base}/t/${x.tenant.slug}/api/tenants/${y.tenant.id}`, {
      headers: { traceparent: `00-${traceId}-00f067aa0ba902b7-01`, "x-request-id": "portal-req-1" },
    });
    expect(other.status).toBe(404);
    expect(other.headers.get("x-request-id")).toBe("portal-req-1");
    // The admin API's problem: the same trace and request id (forwarded by the proxy).
    expect(await other.json()).toMatchObject({
      code: "not_found",
      traceId,
      requestId: "portal-req-1",
    });
    // The portal's own problems carry them too.
    const unauthenticated = await fetch(`${base}/t/${x.tenant.slug}/api/me`, {
      headers: { traceparent: `00-${traceId}-00f067aa0ba902b7-01` },
    });
    expect(await unauthenticated.json()).toMatchObject({ code: "login_required", traceId });
  });

  it("protects /metrics with ADMIN_METRICS_TOKEN and validates production secrets", async () => {
    const config = loadAdminConfig({
      NODE_ENV: "development",
      ADMIN_PUBLIC_URL: base,
      PORTVAKT_PUBLIC_URL: ts!.baseUrl,
      ADMIN_CLIENT_SECRET: world.secret,
      ADMIN_WEB_DIR: "does-not-exist",
      ADMIN_METRICS_TOKEN: "admin-metrics-token-0123456789abcdef",
    });
    await serving(createAdminApp(config, { logger: silentLogger }), async (origin) => {
      expect((await fetch(`${origin}/metrics`)).status).toBe(401);
      const scrape = await fetch(`${origin}/metrics`, {
        headers: { authorization: "Bearer admin-metrics-token-0123456789abcdef" },
      });
      expect(scrape.status).toBe(200);
    });

    const production = {
      NODE_ENV: "production",
      ADMIN_PUBLIC_URL: "https://admin.example.org",
      PORTVAKT_PUBLIC_URL: "https://login.example.org",
      ADMIN_CLIENT_SECRET: "a-production-admin-client-secret-0123456789",
      ADMIN_COOKIE_SECRET: "a-production-cookie-secret-0123456789abcdef",
      ADMIN_SESSION_ENCRYPTION_KEY: Buffer.alloc(32, 9).toString("base64"),
      ADMIN_DATABASE_URL: "postgres://admin:pw@db.example.org/portvakt",
      ADMIN_METRICS_TOKEN: "a-production-metrics-token-0123456789abcdef",
    };
    expect(() => loadAdminConfig(production)).not.toThrow();
    const issuesOf = (env: Record<string, string | undefined>): readonly string[] => {
      try {
        loadAdminConfig(env);
        return [];
      } catch (error) {
        if (error instanceof AdminConfigError) return error.issues;
        throw error;
      }
    };
    expect(issuesOf({ ...production, ADMIN_METRICS_TOKEN: undefined })).toContain(
      "ADMIN_METRICS_TOKEN: required in production (or ADMIN_METRICS_ENABLED=false)",
    );
    expect(
      issuesOf({ ...production, ADMIN_METRICS_TOKEN: undefined, ADMIN_METRICS_ENABLED: "false" }),
    ).toEqual([]);
    const reused = issuesOf({
      ...production,
      ADMIN_COOKIE_SECRET: production.ADMIN_CLIENT_SECRET,
    });
    expect(reused).toContain(
      "ADMIN_COOKIE_SECRET: reuses the value of ADMIN_CLIENT_SECRET; every secret must be generated separately",
    );
    expect(reused.join("\n")).not.toContain(production.ADMIN_CLIENT_SECRET);
  });

  it("sends HSTS only when the portal is served over https", async () => {
    expect((await fetch(`${base}/healthz`)).headers.get("strict-transport-security")).toBeNull();
    const config = loadAdminConfig({
      NODE_ENV: "development",
      ADMIN_PUBLIC_URL: "https://admin.example.test",
      PORTVAKT_PUBLIC_URL: ts!.baseUrl,
      ADMIN_CLIENT_SECRET: world.secret,
      ADMIN_WEB_DIR: "does-not-exist",
    });
    const secure = createServer(createAdminApp(config, { logger: silentLogger }));
    await new Promise<void>((resolve) => secure.listen(0, "127.0.0.1", resolve));
    try {
      const port = (secure.address() as AddressInfo).port;
      const response = await fetch(`http://127.0.0.1:${port}/healthz`);
      expect(response.headers.get("strict-transport-security")).toBe(
        "max-age=31536000; includeSubDomains",
      );
    } finally {
      secure.closeAllConnections();
      await new Promise<void>((resolve) => secure.close(() => resolve()));
    }
  });
});
