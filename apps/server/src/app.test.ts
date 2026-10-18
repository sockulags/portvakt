import { Router } from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { createApp, type ReadinessReport } from "./app.js";
import { createLogger } from "./logging/logger.js";

const logger = createLogger({ level: "silent" });

function appWith(report: ReadinessReport, draining = false) {
  return createApp({
    logger,
    trustProxy: false,
    readiness: () => Promise.resolve(report),
    isDraining: () => draining,
  });
}

describe("health probes", () => {
  it("reports the process as up on /healthz", async () => {
    const res = await request(appWith({ ready: false, checks: {} })).get("/healthz");
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ status: "ok" });
    expect(res.headers["cache-control"]).toBe("no-store");
  });

  it("reports readiness and each check on /readyz", async () => {
    const ready = await request(
      appWith({ ready: true, checks: { database: true, signingKeys: true } }),
    ).get("/readyz");
    expect(ready.status).toBe(200);
    expect(ready.body).toEqual({
      status: "ready",
      checks: { database: true, signingKeys: true },
    });
    const notReady = await request(
      appWith({ ready: false, checks: { database: false, signingKeys: true } }),
    ).get("/readyz");
    expect(notReady.status).toBe(503);
    expect(notReady.body).toMatchObject({ status: "not_ready" });
  });

  it("asks clients to close connections while draining", async () => {
    const res = await request(appWith({ ready: false, checks: {} }, true)).get("/healthz");
    expect(res.headers.connection).toBe("close");
  });

  it("answers unknown paths with a JSON 404 and does not advertise Express", async () => {
    const res = await request(appWith({ ready: true, checks: {} })).get("/nothing-here");
    expect(res.status).toBe(404);
    expect(res.body).toEqual({ error: "not_found" });
    expect(res.headers["x-powered-by"]).toBeUndefined();
    expect(res.headers["x-request-id"]).toMatch(/^[0-9a-f-]{36}$/);
  });
});

describe("error handler", () => {
  it("answers client errors with invalid_request and server errors with server_error", async () => {
    const router = Router();
    router.get("/client-error", (_req, _res, next) => {
      next(Object.assign(new Error("request entity too large: secret body"), { status: 413 }));
    });
    router.get("/server-error", () => {
      throw new Error("database exploded");
    });
    const app = createApp({
      logger,
      trustProxy: false,
      readiness: () => Promise.resolve({ ready: true, checks: {} }),
      routes: [router],
    });
    const clientError = await request(app).get("/client-error");
    expect(clientError.status).toBe(413);
    expect(clientError.body).toEqual({ error: "invalid_request" });
    const serverError = await request(app).get("/server-error");
    expect(serverError.status).toBe(500);
    expect(serverError.body).toEqual({ error: "server_error" });
    expect(JSON.stringify(serverError.body)).not.toContain("exploded");
  });
});
