import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import {
  createFederatedLoginMethod,
  createTenant,
  createTestClient,
  FlowDriver,
  startTestIdp,
  startTestServer,
  TestBrowser,
} from "@portvakt/server/testing";
import { silentLogger } from "@portvakt/sdk-node";
import { afterAll, describe, expect, it } from "vitest";
import { createDemoApp } from "./app.js";
import { loadDemoConfig } from "./config.js";

/** Smoke test: the demo service in-process against an in-process Portvakt and mock IdP. */

const ts = await startTestServer();
const idp = ts === undefined ? undefined : await startTestIdp();

describe.skipIf(ts === undefined)("demo service smoke test", () => {
  const server = createServer();
  afterAll(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it("signs an employee in, shows the session and calls its own API", async () => {
    const repos = ts!.db.repos;
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const port = (server.address() as AddressInfo).port;
    const base = `http://127.0.0.1:${port}`;
    const tenant = await createTenant(repos, "demo-smoke");
    const method = await createFederatedLoginMethod(ts!, idp!, tenant, "entra");
    const service = await createTestClient(repos, tenant, {
      redirectUris: [`${base}/auth/callback`],
      postLogoutRedirectUris: [`${base}/`],
    });
    await repos.access.createRule(tenant.id, {
      applicationId: service.application.id,
      loginMethodId: method.id,
      groupValue: "grp-handlaggare",
      role: "handlaggare",
    });
    const config = loadDemoConfig({
      APP_NAME: "Tjänst A",
      PORT: String(port),
      PUBLIC_URL: base,
      ISSUER: ts!.issuerOf(tenant.slug),
      CLIENT_ID: service.application.clientId,
      CLIENT_SECRET: service.secret,
      WEB_DIR: "does-not-exist",
    });
    server.on("request", createDemoApp(config, { logger: silentLogger }));

    const driver = new FlowDriver(ts!, idp!);
    const start = await driver.browser.request(`${base}/auth/login?returnTo=%2F`);
    let landing = await driver.follow(TestBrowser.location(start, base));
    landing = await driver.persona(landing, "anna-handlaggare");
    if (landing.kind !== "app") throw new Error(`expected the demo, got ${landing.kind}`);
    const callback = await driver.browser.request(landing.url.href);
    expect(callback.status).toBe(303);
    expect(callback.headers.get("location")).toBe("/");

    const json = { headers: { accept: "application/json" } };
    const session = (await (await driver.browser.request(`${base}/auth/session`, json)).json()) as {
      authenticated: boolean;
      principal: { sub: string; roles: string[]; name: string; idpKind: string };
    };
    expect(session).toMatchObject({
      authenticated: true,
      principal: { roles: ["handlaggare"], name: "Anna Andersson", idpKind: "employee" },
    });

    const call = (await (await driver.browser.request(`${base}/app/api-call`, json)).json()) as {
      status: number;
      body: { app: string; principal: Record<string, unknown> };
    };
    expect(call).toEqual({
      status: 200,
      body: {
        app: "Tjänst A",
        principal: {
          isService: false,
          sub: session.principal.sub,
          tenant: tenant.slug,
          idpKind: "employee",
          acr: method.assertedAcr,
          roles: ["handlaggare"],
          rep: null,
          clientId: service.application.clientId,
        },
      },
    });
  });
});
