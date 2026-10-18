import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, describe, expect, it } from "vitest";
import type { LoginMethod } from "../domain/login-method.js";
import { createLogger } from "../logging/logger.js";
import type { LoginMethodRepository } from "../repositories/login-methods.js";
import { classifyUpstreamError, UpstreamClients, UpstreamRecentlyFailedError } from "./upstream.js";

// A local upstream that is down: every request answers 503.
let hits = 0;
const stub = createServer((_req, res) => {
  hits += 1;
  res.writeHead(503, { "content-type": "text/plain" }).end("unavailable");
});
await new Promise<void>((resolve) => stub.listen(0, "127.0.0.1", resolve));
const issuer = `http://127.0.0.1:${(stub.address() as AddressInfo).port}/idp`;
afterAll(() => new Promise<void>((resolve) => stub.close(() => resolve())));

const loginMethods = {
  getClientSecret: () => Promise.resolve("upstream-secret"),
} as unknown as LoginMethodRepository;

const method = (id: string): LoginMethod =>
  ({
    id,
    tenantId: "7d0b5a52-6a43-4f4e-9b8a-0f1d2c3b4a59",
    issuer,
    clientId: "portvakt",
    clientAuthMethod: "client_secret_basic",
    allowedUpstreamTenants: [],
    clientAssertionAudience: "token_endpoint",
    updatedAt: new Date("2026-10-18T00:00:00Z"),
  }) as unknown as LoginMethod;

const clients = (failureCacheSeconds: number) =>
  new UpstreamClients({
    loginMethods,
    logger: createLogger({ level: "silent" }),
    production: false,
    timeoutSeconds: 2,
    metadataTtlSeconds: 3600,
    failureCacheSeconds,
  });

describe("UpstreamClients discovery failures", () => {
  it("does not ask a failing upstream again while the failure is cached", async () => {
    const upstream = clients(5);
    hits = 0;
    const first = await upstream.setupFor(method("a1")).catch((error: unknown) => error);
    expect(classifyUpstreamError(first)).toBe("upstream_unavailable");
    expect(hits).toBe(1);
    const second = await upstream.setupFor(method("a1")).catch((error: unknown) => error);
    expect(second).toBeInstanceOf(UpstreamRecentlyFailedError);
    expect(classifyUpstreamError(second)).toBe("upstream_unavailable");
    expect(hits).toBe(1);
    // Another login method is not affected.
    await upstream.setupFor(method("b2")).catch(() => undefined);
    expect(hits).toBe(2);
  });

  it("asks again every time with the failure cache disabled", async () => {
    const upstream = clients(0);
    hits = 0;
    await upstream.setupFor(method("c3")).catch(() => undefined);
    await upstream.setupFor(method("c3")).catch(() => undefined);
    expect(hits).toBe(2);
  });
});
