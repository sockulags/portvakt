import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { silentLogger } from "@portvakt/sdk-node";
import request from "supertest";
import { afterAll, describe, expect, it } from "vitest";
import { createDemoApp } from "./app.js";
import { DemoConfigError, loadDemoConfig } from "./config.js";

const webDir = mkdtempSync(join(tmpdir(), "demo-web-"));
writeFileSync(join(webDir, "index.html"), '<!doctype html><div id="root"></div>');
afterAll(() => {
  rmSync(webDir, { recursive: true, force: true });
});

const env = {
  APP_NAME: "Tjänst A",
  PORT: "3100",
  ISSUER: "http://localhost:3000/t/demo",
  CLIENT_ID: "service-a",
  CLIENT_SECRET: "service-a-secret-0123456789abcdef0123",
  WEB_DIR: webDir,
};

describe("demo configuration", () => {
  it("derives defaults per instance", () => {
    const config = loadDemoConfig(env);
    expect(config).toMatchObject({
      appName: "Tjänst A",
      port: 3100,
      publicUrl: "http://localhost:3100",
      apiUrl: "http://127.0.0.1:3100",
      cookieName: "service-a_session",
      cookieSecure: false,
      stepUpAcr: "http://id.elegnamnden.se/loa/1.0/loa4",
      scopes: ["openid", "profile", "email"],
    });
    expect(loadDemoConfig({ ...env, COOKIE_NAME: "demo_b" }).cookieName).toBe("demo_b");
  });

  it("defaults to Secure cookies except for http on localhost", () => {
    expect(loadDemoConfig(env).cookieSecure).toBe(false);
    expect(loadDemoConfig({ ...env, PUBLIC_URL: "http://127.0.0.1:3100" }).cookieSecure).toBe(
      false,
    );
    expect(loadDemoConfig({ ...env, PUBLIC_URL: "http://demo.example:3100" }).cookieSecure).toBe(
      true,
    );
    expect(loadDemoConfig({ ...env, PUBLIC_URL: "https://demo.example" }).cookieSecure).toBe(true);
    expect(
      loadDemoConfig({ ...env, PUBLIC_URL: "https://demo.example", COOKIE_SECURE: "false" })
        .cookieSecure,
    ).toBe(false);
  });

  it("never allows an http issuer in production", () => {
    const production = loadDemoConfig({
      ...env,
      NODE_ENV: "production",
      PUBLIC_URL: "https://demo.example",
      COOKIE_SECRET: "a-production-cookie-secret-0123456789abcdef",
      SESSION_ENCRYPTION_KEY: Buffer.alloc(32, 1).toString("base64"),
    });
    expect(() => createDemoApp(production, { logger: silentLogger })).toThrow(
      /issuer: must be https/,
    );
  });

  it("refuses missing settings and development secrets in production", () => {
    expect(() => loadDemoConfig({ APP_NAME: "x" })).toThrow(DemoConfigError);
    expect(() => loadDemoConfig({ ...env, NODE_ENV: "production" })).toThrow(
      /COOKIE_SECRET: the development secret/,
    );
  });
});

describe("demo app", () => {
  const app = createDemoApp(loadDemoConfig(env), { logger: silentLogger });

  it("answers health checks and its SPA configuration", async () => {
    const health = await request(app).get("/healthz");
    expect(health.status).toBe(200);
    expect(health.body).toEqual({ status: "ok", app: "Tjänst A" });
    expect(health.headers["content-security-policy"]).toContain("default-src 'self'");
    expect(health.headers["content-security-policy"]).toContain(
      "form-action 'self' http://localhost:3000",
    );
    expect(health.headers["content-security-policy"]).toContain("frame-ancestors 'none'");
    expect(health.headers["content-security-policy"]).not.toMatch(/unsafe-(inline|eval)/);
    expect(health.headers["x-frame-options"]).toBe("DENY");
    expect(health.headers["x-content-type-options"]).toBe("nosniff");
    expect(health.headers["cross-origin-opener-policy"]).toBe("same-origin");
    expect(health.headers["permissions-policy"]).toContain("camera=()");
    // Over http (local development) no HSTS.
    expect(health.headers["strict-transport-security"]).toBeUndefined();
    const config = await request(app).get("/app/config");
    expect(config.body).toEqual({
      appName: "Tjänst A",
      clientId: "service-a",
      stepUpAcr: "http://id.elegnamnden.se/loa/1.0/loa4",
    });
  });

  it("reports signed out, protects its routes and serves the SPA", async () => {
    expect((await request(app).get("/auth/session")).body).toEqual({ authenticated: false });
    const call = await request(app).post("/app/api-call").set("accept", "application/json");
    expect(call.status).toBe(401);
    expect(call.body).toEqual({ error: "login_required", loginUrl: "/auth/login?returnTo=%2F" });
    const api = await request(app).get("/api/whoami");
    expect(api.status).toBe(401);
    expect(api.headers["www-authenticate"]).toBe('Bearer realm="portvakt"');
    expect((await request(app).get("/api/nothing")).status).toBe(404);
    const page = await request(app).get("/some/page");
    expect(page.status).toBe(200);
    expect(page.text).toContain('<div id="root">');
  });
});
