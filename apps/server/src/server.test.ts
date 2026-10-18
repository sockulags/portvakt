import { createServer, request as httpRequest, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { describe, expect, it } from "vitest";
import { loadConfig } from "./config/index.js";
import { createPool } from "./db/database.js";
import { createLogger } from "./logging/logger.js";
import { createPortvakt } from "./server.js";
import { createTenant, uniqueSuffix } from "./testing/fixtures.js";
import {
  codeFlow,
  createPerson,
  createTenantWorld,
  discoverWithSecret,
} from "./testing/oidc-flow.js";
import { startTestServer } from "./testing/test-server.js";

const logLines: string[] = [];
const ts = await startTestServer({
  logDestination: { write: (line: string) => void logLines.push(line) },
});

async function listen(server: Server): Promise<string> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

describe.skipIf(ts === undefined)("server lifecycle", () => {
  const { db, portvakt, baseUrl, config } = ts!;
  const silent = createLogger({ level: "silent" });

  it("is ready once the database answers and signing keys are loaded", async () => {
    const response = await fetch(`${baseUrl}/readyz`);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      status: "ready",
      checks: { database: true, signingKeys: true, accepting: true },
    });
    expect((await fetch(`${baseUrl}/healthz`)).status).toBe(200);
  });

  it("is not ready before keys are loaded, nor without a reachable database", async () => {
    const notStarted = createPortvakt({ config, pool: db.pool, logger: silent, keys: db.keys });
    expect(await notStarted.readiness()).toEqual({
      ready: false,
      checks: { database: true, signingKeys: false, accepting: true },
    });
    // Requests to a tenant are refused with 503 until then, without building anything.
    const tenant = await createTenant(db.repos, "early");
    const server = createServer();
    notStarted.serve(server);
    const url = await listen(server);
    const early = await fetch(`${url}/t/${tenant.slug}/jwks`);
    expect(early.status).toBe(503);
    await notStarted.shutdown();

    const unreachable = createPool({
      url: "postgres://portvakt_app:portvakt_app@127.0.0.1:1/portvakt_test",
      connectionTimeoutMillis: 500,
    });
    try {
      const offline = createPortvakt({ config, pool: unreachable, logger: silent, keys: db.keys });
      expect((await offline.readiness()).checks.database).toBe(false);
      expect((await offline.readiness()).ready).toBe(false);
    } finally {
      await unreachable.end();
    }
  });

  it("shuts down gracefully: in-flight requests finish, new connections are refused", async () => {
    const replica = createPortvakt({ config, pool: db.pool, logger: silent, keys: db.keys });
    await replica.start();
    const slowStarted = Promise.withResolvers<void>();
    let releaseSlow: () => void = () => undefined;
    const server = createServer();
    replica.serve(server, (req, res) => {
      if (req.url !== "/slow") {
        replica.app(req, res);
        return;
      }
      slowStarted.resolve();
      releaseSlow = () => res.end("done");
    });
    const replicaUrl = await listen(server);
    const slowResult = fetch(`${replicaUrl}/slow`).then(async (response) => ({
      status: response.status,
      body: await response.text(),
    }));
    await slowStarted.promise;
    expect((await replica.readiness()).ready).toBe(true);

    const stopped = replica.shutdown();
    expect((await replica.readiness()).checks.accepting).toBe(false);
    // The listening socket is closed at once: new connections are refused.
    await expect(
      new Promise((resolve, reject) => {
        const req = httpRequest(`${replicaUrl}/healthz`, { agent: false }, resolve);
        req.on("error", reject);
        req.end();
      }),
    ).rejects.toMatchObject({ code: "ECONNREFUSED" });
    // The in-flight request still completes; only then does shutdown finish.
    let finished = false;
    void stopped.then(() => {
      finished = true;
    });
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(finished).toBe(false);
    releaseSlow();
    expect(await slowResult).toEqual({ status: 200, body: "done" });
    await stopped;
    expect(finished).toBe(true);
  });

  it("runs the expired payload cleanup job", async () => {
    const tenant = await createTenant(db.repos, "cleanup");
    await db.repos.oidcPayloads.upsert(tenant.id, "AccessToken", "expired", {}, 60);
    await db.repos.oidcPayloads.upsert(tenant.id, "AccessToken", "live", {}, 60);
    await db.db.query(
      `UPDATE oidc_payloads SET expires_at = now() - interval '1 minute'
        WHERE tenant_id = $1 AND id = 'expired'`,
      [tenant.id],
    );
    expect(await portvakt.jobs.cleanupExpired()).toBeGreaterThanOrEqual(1);
    const left = await db.db.query<{ id: string }>(
      "SELECT id FROM oidc_payloads WHERE tenant_id = $1",
      [tenant.id],
    );
    expect(left.map((row) => row.id)).toEqual(["live"]);
  });

  it("mounts the test-only login route only when NODE_ENV=test", async () => {
    const tenant = await createTenant(db.repos, "routes");
    const path = `/t/${tenant.slug}/interaction/some-uid/__test__/login`;
    const asTest = await fetch(`${baseUrl}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    expect(asTest.status).toBe(400);

    const development = loadConfig({
      NODE_ENV: "development",
      PUBLIC_URL: baseUrl,
      DATABASE_URL: db.url,
      MASTER_KEY: config.masterKeys.current.toString("base64"),
      COOKIE_KEYS: config.cookieKeys.join(","),
      SHUTDOWN_DRAIN_DELAY: "0",
    });
    const dev = createPortvakt({
      config: development,
      pool: db.pool,
      logger: silent,
      keys: db.keys,
    });
    await dev.start();
    const server = createServer();
    dev.serve(server);
    try {
      const url = await listen(server);
      const response = await fetch(`${url}${path}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      });
      expect(response.status).toBe(404);
    } finally {
      await dev.shutdown();
    }
  });

  it("warns in the log that the test-only login route is mounted", () => {
    const warnings = logLines
      .map((line) => JSON.parse(line) as { level: string; msg: string })
      .filter((line) => line.level === "warn");
    expect(warnings.map((line) => line.msg)).toContainEqual(
      expect.stringContaining("unauthenticated test login route is mounted"),
    );
  });

  it("keeps serving during the drain delay while readiness already reports 503", async () => {
    const replica = createPortvakt({
      config: { ...config, shutdownDrainDelaySeconds: 1 },
      pool: db.pool,
      logger: silent,
      keys: db.keys,
    });
    await replica.start();
    const server = createServer();
    replica.serve(server);
    const url = await listen(server);
    const stopped = replica.shutdown();
    const draining = await fetch(`${url}/readyz`);
    expect(draining.status).toBe(503);
    expect(await draining.json()).toMatchObject({ checks: { accepting: false } });
    expect((await fetch(`${url}/healthz`)).status).toBe(200);
    await stopped;
    await expect(fetch(`${url}/healthz`)).rejects.toThrow();
  });

  it("writes JSON logs without personal data, tokens or secrets", async () => {
    const world = await createTenantWorld(db.repos, "logs");
    const email = `logged.person.${uniqueSuffix()}@example.org`;
    const name = `Logged Person ${uniqueSuffix()}`;
    const { person } = await createPerson(db.repos, world, `sub-${uniqueSuffix()}`, {
      email,
      name,
    });
    const rp = await discoverWithSecret(ts!, world.tenant.slug, world.app);
    const tokens = await codeFlow(ts!, rp, world.app.application.redirectUris[0]!, {
      personId: person.id,
      loginMethodId: world.loginMethod.id,
      acr: world.loginMethod.assertedAcr,
    });
    // A refused request is logged too.
    await fetch(`${ts!.issuerOf(world.tenant.slug)}/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: `grant_type=refresh_token&refresh_token=${tokens.refresh_token}&client_id=nope`,
    });

    const output = logLines.join("");
    expect(output).toContain('"path":"/t/');
    for (const line of logLines) expect(() => JSON.parse(line) as unknown).not.toThrow();
    for (const secret of [
      email,
      name,
      tokens.access_token,
      tokens.id_token!,
      tokens.refresh_token!,
      world.app.secret,
      "code=",
      "_pv_session=",
    ]) {
      expect(output).not.toContain(secret);
    }
  });
});
