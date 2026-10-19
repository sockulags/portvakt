import { decodeJwt } from "jose";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { createPortvaktClient } from "./client.js";
import { PortvaktUnavailableError } from "./errors.js";
import { silentLogger } from "./logger.js";
import { startFakeOp, type FakeOp } from "./testing/fake-op.js";

let op: FakeOp;
beforeAll(async () => {
  op = await startFakeOp();
});
afterAll(async () => {
  await op.close();
});
afterEach(() => {
  op.down = false;
  op.serverError = undefined;
  op.accessTokenTtl = 300;
  vi.useRealTimers();
});

const client = () =>
  createPortvaktClient({
    issuer: op.issuer,
    clientId: op.clientId,
    clientAuth: { method: "client_secret_post", clientSecret: op.clientSecret },
    allowInsecureRequests: true,
    logger: silentLogger,
  });

describe("clientCredentials", () => {
  it("requests a token for the target application and caches it until shortly before expiry", async () => {
    vi.useFakeTimers({ toFake: ["Date"], shouldAdvanceTime: true });
    const source = client().clientCredentials({ audience: "service-b" });
    const before = op.counters.token;
    const [first, second] = await Promise.all([source.getToken(), source.getToken()]);
    expect(first).toBe(second);
    expect(op.counters.token - before).toBe(1);
    expect(decodeJwt(first)).toMatchObject({ aud: "service-b", sub: op.clientId });

    vi.setSystemTime(Date.now() + 200_000);
    expect(await source.getToken()).toBe(first);
    // 300 s tokens are fetched again 30 s before they expire.
    vi.setSystemTime(Date.now() + 75_000);
    const renewed = await source.getToken();
    expect(renewed).not.toBe(first);
    expect(op.counters.token - before).toBe(2);
    source.clear();
    await source.getToken();
    expect(op.counters.token - before).toBe(3);
  });

  it("reports Portvakt unavailable", async () => {
    const source = client().clientCredentials();
    op.down = true;
    await expect(source.getToken()).rejects.toBeInstanceOf(PortvaktUnavailableError);
  });

  it("reports a 5xx token endpoint as unavailable, not as a refusal", async () => {
    const source = client().clientCredentials({ audience: "service-c" });
    await source.getToken();
    source.clear();
    op.serverError = 502;
    await expect(source.getToken()).rejects.toBeInstanceOf(PortvaktUnavailableError);
  });
});
