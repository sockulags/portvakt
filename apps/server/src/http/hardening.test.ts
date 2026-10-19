import { randomUUID } from "node:crypto";
import { request as httpRequest } from "node:http";
import type { AddressInfo } from "node:net";
import { JSON_CSP, PERMISSIONS_POLICY } from "@portvakt/http-kit";
import { describe, expect, it } from "vitest";
import { createPool } from "../db/database.js";
import { LOGIN_UI_CSP } from "../login/ui-shell.js";
import { PROVIDER_CSP } from "../oidc/routes.js";
import { createAdmin, createAdminTenant, adminToken, setupAdminWorld } from "../testing/admin.js";
import { bootstrapOf } from "../testing/federation.js";
import { createTestClient, createTenantWorld, discoverWithSecret } from "../testing/oidc-flow.js";
import { startTestServer, TestBrowser } from "../testing/test-server.js";
import * as client from "openid-client";

const METRICS_TOKEN = "metrics-token-for-tests-0123456789abcdef";
const logs: Record<string, unknown>[] = [];

/**
 * M8: rate limits (per IP through TRUST_PROXY, per client, per admin caller), security headers
 * and caching, request bounds, metrics and trace context, against the real app. Each test sends
 * its own X-Forwarded-For (TRUST_PROXY=1), so the per-IP buckets do not interfere.
 */
const ts = await startTestServer({
  env: {
    TRUST_PROXY: "1",
    RATE_LIMIT_AUTHORIZE_IP: "3/1m",
    RATE_LIMIT_INTERACTION_IP: "2/1m",
    RATE_LIMIT_FEDERATION_IP: "2/1m",
    RATE_LIMIT_TOKEN_IP: "3/1m",
    RATE_LIMIT_TOKEN_CLIENT: "4/1m",
    RATE_LIMIT_ADMIN_API: "3/1m",
    METRICS_TOKEN,
  },
  logDestination: {
    write: (line: string) => {
      logs.push(JSON.parse(line) as Record<string, unknown>);
    },
  },
});

let ipCounter = 0;
/** A client IP of its own for one test (documentation range 198.51.100.0/24). */
const freshIp = (): string => `198.51.100.${(ipCounter += 1)}`;

const basic = (id: string, secret: string): string =>
  `Basic ${Buffer.from(`${encodeURIComponent(id)}:${encodeURIComponent(secret)}`).toString("base64")}`;

describe.skipIf(ts === undefined)("production hardening (M8)", () => {
  const { db, baseUrl } = ts!;
  const { repos } = db;

  const tokenRequest = (
    slug: string,
    ip: string,
    auth: { readonly header?: string; readonly body?: Record<string, string> },
  ) =>
    fetch(`${baseUrl}/t/${slug}/token`, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        "x-forwarded-for": ip,
        ...(auth.header === undefined ? {} : { authorization: auth.header }),
      },
      body: new URLSearchParams({ grant_type: "client_credentials", ...auth.body }).toString(),
    });

  describe("security headers and caching", () => {
    it("sends the baseline headers on JSON responses, and no HSTS over http", async () => {
      const res = await fetch(`${baseUrl}/healthz`);
      expect(res.headers.get("content-security-policy")).toBe(JSON_CSP);
      expect(res.headers.get("x-frame-options")).toBe("DENY");
      expect(res.headers.get("x-content-type-options")).toBe("nosniff");
      expect(res.headers.get("referrer-policy")).toBe("no-referrer");
      expect(res.headers.get("cross-origin-opener-policy")).toBe("same-origin");
      expect(res.headers.get("permissions-policy")).toBe(PERMISSIONS_POLICY);
      expect(res.headers.get("cache-control")).toBe("no-store");
      expect(res.headers.get("strict-transport-security")).toBeNull();
    });

    it("gives provider responses their CSP, login pages theirs, and the admin API no-store", async () => {
      const { tenant } = await createTenantWorld(repos, "hdr");
      const discovery = await fetch(`${baseUrl}/t/${tenant.slug}/.well-known/openid-configuration`);
      expect(discovery.headers.get("content-security-policy")).toBe(PROVIDER_CSP);
      expect(discovery.headers.get("x-frame-options")).toBe("DENY");
      expect(discovery.headers.get("cache-control")).toBe("public, max-age=300");

      const page = await fetch(`${baseUrl}/t/${tenant.slug}/login/error?code=request_failed`);
      expect(page.headers.get("content-security-policy")).toBe(LOGIN_UI_CSP);
      expect(LOGIN_UI_CSP).toContain("frame-ancestors 'none'");
      expect(LOGIN_UI_CSP).not.toMatch(/unsafe-(inline|eval)/);
      expect(page.headers.get("cache-control")).toBe("no-store");
      expect(page.headers.get("x-frame-options")).toBe("DENY");

      const api = await fetch(`${baseUrl}/admin/api/v1/me`, {
        headers: { "x-forwarded-for": freshIp() },
      });
      expect(api.status).toBe(401);
      expect(api.headers.get("cache-control")).toBe("no-store");
      expect(api.headers.get("content-security-policy")).toBe(JSON_CSP);
    });

    it("answers token requests with no-store", async () => {
      const world = await createTenantWorld(repos, "nostore");
      const res = await tokenRequest(world.tenant.slug, freshIp(), {
        header: basic(world.app.application.clientId, world.app.secret),
      });
      expect(res.status).toBe(200);
      expect(res.headers.get("cache-control")).toBe("no-store");
    });
  });

  describe("request bounds", () => {
    it("refuses long URLs with 414 and oversized headers with 431", async () => {
      const long = await fetch(`${baseUrl}/healthz?x=${"a".repeat(9000)}`);
      expect(long.status).toBe(414);
      const status = await new Promise<number>((resolve, reject) => {
        const req = httpRequest(`${baseUrl}/healthz`, {
          headers: { "x-padding": "b".repeat(20_000) },
        });
        req.on("response", (res) => {
          res.resume();
          resolve(res.statusCode ?? 0);
        });
        req.on("error", reject);
        req.end();
      });
      expect(status).toBe(431);
    });

    it("refuses a token request body above the provider's limit", async () => {
      const world = await createTenantWorld(repos, "bigbody");
      const res = await tokenRequest(world.tenant.slug, freshIp(), {
        body: { client_id: world.app.application.clientId, padding: "c".repeat(60 * 1024) },
      });
      expect(res.status).toBe(413);
    });

    it("configures the server timeouts and the database session timeouts", async () => {
      expect(ts!.server.requestTimeout).toBe(30_000);
      expect(ts!.server.headersTimeout).toBe(20_000);
      expect(ts!.server.keepAliveTimeout).toBe(65_000);
      const pool = createPool({
        url: db.url,
        statementTimeoutSeconds: ts!.config.database.statementTimeoutSeconds,
        idleInTransactionTimeoutSeconds: ts!.config.database.idleInTransactionTimeoutSeconds,
      });
      try {
        const settings = await pool.query<{ statement: string; idle: string }>(
          `SELECT current_setting('statement_timeout') AS statement,
                  current_setting('idle_in_transaction_session_timeout') AS idle`,
        );
        expect(settings.rows[0]).toEqual({ statement: "15s", idle: "1min" });
      } finally {
        await pool.end();
      }
    });
  });

  describe("rate limits", () => {
    it("limits the token endpoint per IP with an OAuth error and Retry-After", async () => {
      const world = await createTenantWorld(repos, "rl-ip");
      const ip = freshIp();
      const auth = { header: basic(world.app.application.clientId, world.app.secret) };
      for (let i = 0; i < 3; i += 1) {
        expect((await tokenRequest(world.tenant.slug, ip, auth)).status).toBe(200);
      }
      const refused = await tokenRequest(world.tenant.slug, ip, auth);
      expect(refused.status).toBe(429);
      expect(Number(refused.headers.get("retry-after"))).toBeGreaterThanOrEqual(1);
      expect(refused.headers.get("cache-control")).toBe("no-store");
      expect(await refused.json()).toEqual({
        error: "temporarily_unavailable",
        error_description: "Too many requests; retry later",
      });
      // Another client IP is not affected.
      expect((await tokenRequest(world.tenant.slug, freshIp(), auth)).status).toBe(200);
    });

    it("limits the token endpoint per client_id from Basic auth and from the form body", async () => {
      const world = await createTenantWorld(repos, "rl-client");
      const basicAuth = { header: basic(world.app.application.clientId, world.app.secret) };
      for (let i = 0; i < 4; i += 1) {
        expect((await tokenRequest(world.tenant.slug, freshIp(), basicAuth)).status).toBe(200);
      }
      expect((await tokenRequest(world.tenant.slug, freshIp(), basicAuth)).status).toBe(429);

      // client_secret_post: the client_id is read from the body, which the provider still
      // parses as sent (the tokens are issued).
      const post = await createTestClient(repos, world.tenant, {
        clientAuth: {
          method: "client_secret_post",
          clientSecret: "post-secret-0123456789abcdef-0123456789",
        },
      });
      const body = {
        body: {
          client_id: post.application.clientId,
          client_secret: "post-secret-0123456789abcdef-0123456789",
        },
      };
      for (let i = 0; i < 4; i += 1) {
        const ok = await tokenRequest(world.tenant.slug, freshIp(), body);
        expect(ok.status).toBe(200);
        expect(((await ok.json()) as { access_token?: string }).access_token).toBeTypeOf("string");
      }
      expect((await tokenRequest(world.tenant.slug, freshIp(), body)).status).toBe(429);
      // The same client_id in another tenant has a bucket of its own.
      const other = await createTenantWorld(repos, "rl-client-2");
      await repos.applications.enableForTenant(other.tenant.id, post.application.id);
      expect((await tokenRequest(other.tenant.slug, freshIp(), body)).status).toBe(200);
    });

    it("limits authorization requests per IP with the login UI's page", async () => {
      const world = await createTenantWorld(repos, "rl-auth");
      const config = await discoverWithSecret(ts!, world.tenant.slug, world.app);
      const url = client.buildAuthorizationUrl(config, {
        redirect_uri: world.app.application.redirectUris[0]!,
        scope: "openid",
        code_challenge: await client.calculatePKCECodeChallenge(client.randomPKCECodeVerifier()),
        code_challenge_method: "S256",
      });
      const ip = freshIp();
      for (let i = 0; i < 3; i += 1) {
        const ok = await fetch(url, { headers: { "x-forwarded-for": ip }, redirect: "manual" });
        expect(ok.status).toBe(303);
      }
      const refused = await fetch(url, {
        headers: { "x-forwarded-for": ip, "accept-language": "sv" },
        redirect: "manual",
      });
      expect(refused.status).toBe(429);
      expect(refused.headers.get("retry-after")).not.toBeNull();
      expect(refused.headers.get("content-security-policy")).toBe(LOGIN_UI_CSP);
      expect(bootstrapOf(await refused.text())).toMatchObject({
        view: "error",
        code: "rate_limited",
      });
    });

    it("limits the interaction API per IP (method choice, home realm lookup)", async () => {
      const world = await createTenantWorld(repos, "rl-ia");
      const config = await discoverWithSecret(ts!, world.tenant.slug, world.app);
      const ip = freshIp();
      const browser = new TestBrowser();
      const headers = { "x-forwarded-for": ip };
      const url = client.buildAuthorizationUrl(config, {
        redirect_uri: world.app.application.redirectUris[0]!,
        scope: "openid",
        code_challenge: await client.calculatePKCECodeChallenge(client.randomPKCECodeVerifier()),
        code_challenge_method: "S256",
      });
      const start = await browser.request(url.href, { headers });
      const interaction = TestBrowser.location(start, url.href);
      const details = (await (
        await browser.request(`${interaction}/details`, { headers })
      ).json()) as { csrfToken: string };
      const post = () =>
        browser.request(`${interaction}/login`, {
          method: "POST",
          headers: {
            ...headers,
            "content-type": "application/json",
            "x-csrf-token": details.csrfToken,
          },
          body: JSON.stringify({ email: "someone@nowhere.example" }),
        });
      expect((await post()).status).toBe(404);
      expect((await post()).status).toBe(404);
      const refused = await post();
      expect(refused.status).toBe(429);
      expect(refused.headers.get("retry-after")).not.toBeNull();
      expect(await refused.json()).toMatchObject({ error: "rate_limited" });
    });

    it("limits upstream callbacks per IP with the login UI's page", async () => {
      const world = await createTenantWorld(repos, "rl-fed");
      const ip = freshIp();
      const callback = `${baseUrl}/t/${world.tenant.slug}/federation/${world.loginMethod.id}/callback?state=x&code=y`;
      for (let i = 0; i < 2; i += 1) {
        const res = await fetch(callback, {
          headers: { "x-forwarded-for": ip },
          redirect: "manual",
        });
        expect(res.status).not.toBe(429);
      }
      const acs = await fetch(`${baseUrl}/t/${world.tenant.slug}/saml/${randomUUID()}/acs`, {
        method: "POST",
        headers: { "x-forwarded-for": ip, "content-type": "application/x-www-form-urlencoded" },
        body: "SAMLResponse=x&RelayState=y",
        redirect: "manual",
      });
      expect(acs.status).toBe(429);
      expect(bootstrapOf(await acs.text())).toMatchObject({ view: "error", code: "rate_limited" });
    });

    it("limits the admin API per caller, and failed authentications per IP", async () => {
      const ip = freshIp();
      for (let i = 0; i < 3; i += 1) {
        const res = await fetch(`${baseUrl}/admin/api/v1/me`, {
          headers: { "x-forwarded-for": ip },
        });
        expect(res.status).toBe(401);
      }
      const refused = await fetch(`${baseUrl}/admin/api/v1/me`, {
        headers: {
          "x-forwarded-for": ip,
          traceparent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        },
      });
      expect(refused.status).toBe(429);
      expect(refused.headers.get("retry-after")).not.toBeNull();
      expect(refused.headers.get("content-type")).toContain("application/problem+json");
      expect(await refused.json()).toMatchObject({
        code: "rate_limited",
        status: 429,
        traceId: "4bf92f3577b34da6a3ce929d0e0e4736",
        requestId: "4bf92f3577b34da6a3ce929d0e0e4736",
      });

      const world = await setupAdminWorld(ts!);
      const { tenant, method } = await createAdminTenant(world, "rl-admin");
      const person = await createAdmin(world, tenant, method, ["tenant-admin"]);
      const token = await adminToken(world, tenant, method, person);
      const call = () =>
        fetch(`${baseUrl}/admin/api/v1/me`, {
          headers: { authorization: `Bearer ${token}`, "x-forwarded-for": freshIp() },
        });
      for (let i = 0; i < 3; i += 1) expect((await call()).status).toBe(200);
      // Another IP does not help the same caller.
      expect((await call()).status).toBe(429);
    });
  });

  describe("observability", () => {
    it("serves Prometheus metrics behind the token, by route template and without raw paths", async () => {
      const world = await createTenantWorld(repos, "metrics");
      const issued = await tokenRequest(world.tenant.slug, freshIp(), {
        header: basic(world.app.application.clientId, world.app.secret),
      });
      expect(issued.status).toBe(200);

      expect((await fetch(`${baseUrl}/metrics`)).status).toBe(401);
      const scrape = await fetch(`${baseUrl}/metrics`, {
        headers: { authorization: `Bearer ${METRICS_TOKEN}` },
      });
      expect(scrape.status).toBe(200);
      expect(scrape.headers.get("content-type")).toContain("text/plain; version=0.0.4");
      const text = await scrape.text();
      expect(text).toContain(
        'portvakt_http_requests_total{method="POST",route="/t/{slug}/token",status="200"}',
      );
      expect(text).toMatch(/portvakt_http_request_duration_seconds_bucket\{.*route="\/healthz"/);
      expect(text).toContain(
        `portvakt_tokens_issued_total{grant_type="client_credentials",tenant="${world.tenant.slug}"}`,
      );
      expect(text).toMatch(/portvakt_rate_limited_total\{limit="tokenIp"\} \d+/);
      expect(text).toMatch(/portvakt_signing_key_age_seconds\{kid="[^"]+",state="active"\} \d+/);
      expect(text).toMatch(/portvakt_signing_keys_loaded\{state="active"\} 1/);
      expect(text).toMatch(/portvakt_db_pool_connections\{state="total"\} \d+/);
      expect(text).toMatch(/process_resident_memory_bytes \d+/);
      expect(text).toContain("# TYPE portvakt_logins_total counter");
      // Route templates only: no tenant slug, client id or interaction uid in a path label.
      expect(text).not.toContain(`/t/${world.tenant.slug}`);
      expect(text).not.toContain(world.app.application.clientId);
    });

    it("serves metrics alone on a port of their own (METRICS_PORT)", async () => {
      const server = await ts!.portvakt.listenMetrics(0, "127.0.0.1");
      try {
        const { port } = server.address() as AddressInfo;
        const scrape = await fetch(`http://127.0.0.1:${port}/metrics`, {
          headers: { authorization: `Bearer ${METRICS_TOKEN}` },
        });
        expect(scrape.status).toBe(200);
        expect(await scrape.text()).toContain("# TYPE portvakt_http_requests_total counter");
        expect((await fetch(`http://127.0.0.1:${port}/healthz`)).status).toBe(404);
      } finally {
        await new Promise((resolve) => server.close(resolve));
      }
    });

    it("continues an incoming trace, echoes the ids and puts them on every log line", async () => {
      const traceId = "0af7651916cd43dd8448eb211c80319c";
      const res = await fetch(`${baseUrl}/healthz`, {
        headers: { traceparent: `00-${traceId}-b7ad6b7169203331-01`, "x-request-id": "req-m8-1" },
      });
      expect(res.headers.get("x-request-id")).toBe("req-m8-1");
      expect(res.headers.get("traceparent")).toMatch(new RegExp(`^00-${traceId}-[0-9a-f]{16}-01$`));
      await expect
        .poll(() => logs.find((line) => line.traceId === traceId && line.msg === "request"))
        .toMatchObject({ requestId: "req-m8-1", req: { method: "GET", path: "/healthz" } });

      // Lines written while handling a request carry them too (here: the refused token request).
      const world = await createTenantWorld(repos, "trace");
      const traced = "1af7651916cd43dd8448eb211c80319d";
      await fetch(`${baseUrl}/t/${world.tenant.slug}/token`, {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          "x-forwarded-for": freshIp(),
          traceparent: `00-${traced}-b7ad6b7169203331-01`,
        },
        body: "grant_type=client_credentials&client_id=nobody",
      });
      await expect
        .poll(() => logs.filter((line) => line.traceId === traced).map((line) => line.msg))
        .toEqual(expect.arrayContaining(["oidc request refused", "request"]));
    });
  });
});
