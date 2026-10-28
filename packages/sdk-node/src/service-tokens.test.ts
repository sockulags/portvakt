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
  op.clientCredentialsError = undefined;
  op.rejectClient = false;
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

  it("reports 429 and temporarily_unavailable as unavailable with Portvakt's Retry-After", async () => {
    const source = client().clientCredentials({ audience: "service-d" });
    for (const refusal of [
      { status: 429, body: { error: "invalid_request" }, retryAfter: "7" },
      { status: 429, body: "<html>Too many requests</html>", retryAfter: "3" },
      { status: 400, body: { error: "temporarily_unavailable" }, retryAfter: "11" },
    ]) {
      op.clientCredentialsError = refusal;
      const error = await source.getToken().catch((caught: unknown) => caught);
      expect(error).toBeInstanceOf(PortvaktUnavailableError);
      expect((error as PortvaktUnavailableError).retryAfterSeconds).toBe(
        Number(refusal.retryAfter),
      );
    }
    op.clientCredentialsError = undefined;
    expect(typeof (await source.getToken())).toBe("string");
  });

  it("reports a refusal with Portvakt's OAuth error, also from a Basic challenge", async () => {
    op.clientCredentialsError = { status: 400, body: { error: "invalid_target" } };
    const post = client().clientCredentials({ audience: "service-e" });
    await expect(post.getToken()).rejects.toMatchObject({ code: "invalid_target", status: 502 });
    op.clientCredentialsError = undefined;
    // client_secret_basic: oidc-provider puts invalid_client into a WWW-Authenticate challenge.
    op.rejectClient = true;
    const basic = createPortvaktClient({
      issuer: op.issuer,
      clientId: op.clientId,
      clientAuth: { method: "client_secret_basic", clientSecret: op.clientSecret },
      allowInsecureRequests: true,
      logger: silentLogger,
    }).clientCredentials({ audience: "service-e" });
    await expect(basic.getToken()).rejects.toMatchObject({ code: "invalid_client", status: 502 });
    await expect(post.getToken()).rejects.toMatchObject({ code: "invalid_client", status: 502 });
  });
});
