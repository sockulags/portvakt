import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import express from "express";
import { SignJWT, base64url } from "jose";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { createPortvaktClient, type PortvaktClient } from "./client.js";
import { silentLogger } from "./logger.js";
import { startFakeOp, type FakeOp } from "./testing/fake-op.js";

const PERSON = "3f2b8c4e-91d7-4a3e-8b6f-2d4c9e1a7b55";
const LOA3 = "http://id.elegnamnden.se/loa/1.0/loa3";
const LOA4 = "http://id.elegnamnden.se/loa/1.0/loa4";

let op: FakeOp;
const now = (): number => Math.floor(Date.now() / 1000);

beforeAll(async () => {
  op = await startFakeOp();
});
afterAll(async () => {
  await op.close();
});
afterEach(() => {
  op.down = false;
  op.serverError = undefined;
  vi.useRealTimers();
});

function client(overrides: { cooldownSeconds?: number; cacheMaxAgeSeconds?: number } = {}) {
  return createPortvaktClient({
    issuer: op.issuer,
    clientId: op.clientId,
    clientAuth: { method: "client_secret_basic", clientSecret: op.clientSecret },
    allowInsecureRequests: true,
    logger: silentLogger,
    jwks: {
      cooldownSeconds: overrides.cooldownSeconds ?? 30,
      cacheMaxAgeSeconds: overrides.cacheMaxAgeSeconds ?? 600,
    },
  });
}

/** Person access token claims as Portvakt issues them. */
const person = (extra: Record<string, unknown> = {}) => ({
  iss: op.issuer,
  aud: op.clientId,
  client_id: op.clientId,
  sub: PERSON,
  tid: "fake",
  idp: "0f1976f6-7f6c-4baf-a88c-2bc6f2e68ce7",
  idp_kind: "employee",
  acr: LOA3,
  auth_time: now() - 10,
  roles: ["handlaggare"],
  attrs: { unit: "north" },
  jti: "jti-1",
  iat: now(),
  exp: now() + 300,
  ...extra,
});

const service = (extra: Record<string, unknown> = {}) => ({
  iss: op.issuer,
  aud: op.clientId,
  client_id: "other-app",
  sub: "other-app",
  tid: "fake",
  jti: "jti-2",
  iat: now(),
  exp: now() + 300,
  ...extra,
});

async function refusal(portvakt: PortvaktClient, token: string, audience = op.clientId) {
  try {
    await portvakt.verifyAccessToken(token, audience);
  } catch (error) {
    return error as { code: string; status: number; description?: string };
  }
  throw new Error("expected the token to be refused");
}

describe("access token validation", () => {
  it("accepts a person token and maps the principal", async () => {
    const portvakt = client();
    const token = await op.signAccessToken(
      person({ rep: { sub: "party-1", type: "organisation" } }),
    );
    const principal = await portvakt.verifyAccessToken(token, op.clientId);
    expect(principal).toEqual({
      isService: false,
      sub: PERSON,
      tenant: "fake",
      idp: "0f1976f6-7f6c-4baf-a88c-2bc6f2e68ce7",
      idpKind: "employee",
      acr: LOA3,
      authTime: expect.any(Number) as number,
      roles: ["handlaggare"],
      attrs: { unit: "north" },
      rep: { sub: "party-1", type: "organisation" },
      clientId: op.clientId,
    });
  });

  it("tells service tokens from person tokens by the claims Portvakt issues", async () => {
    const portvakt = client();
    const principal = await portvakt.verifyAccessToken(
      await op.signAccessToken(service()),
      op.clientId,
    );
    expect(principal).toEqual({
      isService: true,
      sub: "other-app",
      tenant: "fake",
      clientId: "other-app",
      roles: [],
      attrs: {},
    });
    // A token with login claims but sub = client_id, or a service token whose sub is not its
    // client, is neither.
    expect(
      (await refusal(portvakt, await op.signAccessToken(person({ sub: op.clientId })))).code,
    ).toBe("invalid_token");
    expect((await refusal(portvakt, await op.signAccessToken(service({ sub: PERSON })))).code).toBe(
      "invalid_token",
    );
    // A person token missing a login claim is refused.
    const { auth_time: _a, ...partial } = person();
    void _a;
    expect((await refusal(portvakt, await op.signAccessToken(partial))).code).toBe("invalid_token");
  });

  it("pins iss exactly: a token of another tenant signed with the shared keys is refused", async () => {
    const portvakt = client();
    const otherTenant = await op.signAccessToken(person({ iss: `${op.baseUrl}/t/other` }));
    expect(await refusal(portvakt, otherTenant)).toMatchObject({
      code: "invalid_token",
      status: 401,
    });
    const prefix = await op.signAccessToken(person({ iss: `${op.issuer}/` }));
    expect((await refusal(portvakt, prefix)).code).toBe("invalid_token");
  });

  it("refuses a wrong audience, a wrong typ, an expired, a not-yet-valid or a future token", async () => {
    const portvakt = client();
    const token = await op.signAccessToken(person());
    expect((await refusal(portvakt, token, "service-b")).code).toBe("invalid_token");
    expect((await refusal(portvakt, await op.signAccessToken(person(), { typ: "JWT" }))).code).toBe(
      "invalid_token",
    );
    // An ID token presented as an access token has no at+jwt typ.
    const expired = await refusal(
      portvakt,
      await op.signAccessToken(person({ exp: now() - 120, iat: now() - 400 })),
    );
    expect(expired).toMatchObject({
      code: "invalid_token",
      description: "The access token has expired",
    });
    expect(
      (await refusal(portvakt, await op.signAccessToken(person({ nbf: now() + 600 })))).code,
    ).toBe("invalid_token");
    expect(
      (await refusal(portvakt, await op.signAccessToken(person({ iat: now() + 600 })))).code,
    ).toBe("invalid_token");
    // Within the clock skew (30 s) a just-expired token still passes.
    await expect(
      portvakt.verifyAccessToken(await op.signAccessToken(person({ exp: now() - 5 })), op.clientId),
    ).resolves.toMatchObject({ sub: PERSON });
  });

  it("refuses alg none and HS256 (key confusion) and a signature by an unpublished key", async () => {
    const portvakt = client();
    const payload = base64url.encode(JSON.stringify(person()));
    const noneHeader = base64url.encode(
      JSON.stringify({ alg: "none", typ: "at+jwt", kid: "key-1" }),
    );
    expect((await refusal(portvakt, `${noneHeader}.${payload}.`)).code).toBe("invalid_token");

    const hmac = await new SignJWT(person())
      .setProtectedHeader({ alg: "HS256", typ: "at+jwt", kid: "key-1" })
      .sign(new TextEncoder().encode("a-shared-secret-that-is-long-enough-for-hs256"));
    expect((await refusal(portvakt, hmac)).code).toBe("invalid_token");

    const foreign = await op.foreignKey();
    const forged = await op.signAccessToken(person(), { kid: "key-1", key: foreign.key });
    expect((await refusal(portvakt, forged)).code).toBe("invalid_token");
  });

  it("refetches the JWKS for an unknown kid, rate limited, and keeps stale keys on error", async () => {
    const portvakt = client({ cooldownSeconds: 30 });
    await portvakt.verifyAccessToken(await op.signAccessToken(person()), op.clientId);
    const baseline = op.counters.jwks;
    vi.useFakeTimers({ toFake: ["Date"], shouldAdvanceTime: true });
    vi.setSystemTime(Date.now() + 31_000);

    // A rotated-in key: one refetch finds it.
    const kid = await op.addKey();
    await expect(
      portvakt.verifyAccessToken(await op.signAccessToken(person(), { kid }), op.clientId),
    ).resolves.toMatchObject({ sub: PERSON });
    expect(op.counters.jwks).toBe(baseline + 1);

    // Unknown kids within the cooldown do not refetch.
    const foreign = await op.foreignKey();
    for (let attempt = 0; attempt < 5; attempt += 1) {
      const token = await op.signAccessToken(person(), { kid: foreign.kid, key: foreign.key });
      expect((await refusal(portvakt, token)).code).toBe("invalid_token");
    }
    expect(op.counters.jwks).toBe(baseline + 1);

    // After the cooldown one more refetch is allowed.
    vi.setSystemTime(Date.now() + 31_000);
    const late = await op.signAccessToken(person(), { kid: foreign.kid, key: foreign.key });
    expect((await refusal(portvakt, late)).code).toBe("invalid_token");
    expect(op.counters.jwks).toBe(baseline + 2);

    // Portvakt down: known keys keep working (stale-if-error), even past the cache age.
    op.down = true;
    vi.setSystemTime(Date.now() + 700_000);
    await expect(
      portvakt.verifyAccessToken(await op.signAccessToken(person()), op.clientId),
    ).resolves.toMatchObject({ sub: PERSON });
  });

  it("answers unavailable when the keys were never fetched and Portvakt is down", async () => {
    const portvakt = client();
    op.down = true;
    const error = await refusal(portvakt, await op.signAccessToken(person()));
    expect(error).toMatchObject({ code: "portvakt_unavailable", status: 503 });
  });

  it("stops trusting cached keys past cacheMaxAge + staleMaxAge, also within the cooldown", async () => {
    const portvakt = client({ cooldownSeconds: 30 });
    await portvakt.verifyAccessToken(await op.signAccessToken(person()), op.clientId);
    vi.useFakeTimers({ toFake: ["Date"], shouldAdvanceTime: true });
    // A day (cache age plus stale limit) is fine while Portvakt answers nothing...
    op.down = true;
    vi.setSystemTime(Date.now() + 80_000_000);
    await expect(
      portvakt.verifyAccessToken(await op.signAccessToken(person()), op.clientId),
    ).resolves.toMatchObject({ sub: PERSON });
    // ...a month is not: the refetch fails, and the next request (within the cooldown, so no
    // refetch) must not fall back to the month-old keys either.
    vi.setSystemTime(Date.now() + 30 * 86_400_000);
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const token = await op.signAccessToken(person());
      expect(await refusal(portvakt, token)).toMatchObject({ code: "portvakt_unavailable" });
    }
  });

  it("treats a 5xx JWKS or discovery answer as unavailable", async () => {
    const portvakt = client();
    op.serverError = 503;
    expect(await refusal(portvakt, await op.signAccessToken(person()))).toMatchObject({
      code: "portvakt_unavailable",
      status: 503,
    });
  });

  it("does not hit Portvakt for every request while nothing is cached (negative cache)", async () => {
    for (const mode of ["down", "5xx"] as const) {
      const portvakt = client();
      if (mode === "down") op.down = true;
      else op.serverError = 502;
      const before = op.counters.failed;
      const token = await op.signAccessToken(person());
      for (let attempt = 0; attempt < 20; attempt += 1) {
        expect((await refusal(portvakt, token)).code).toBe("portvakt_unavailable");
      }
      // One discovery attempt; the rest are answered from the failure cache.
      expect(op.counters.failed - before).toBeLessThanOrEqual(2);
      op.down = false;
      op.serverError = undefined;
    }
  });
});

describe("requireAccessToken middleware", () => {
  let server: Server;
  let base: string;
  let portvakt: PortvaktClient;

  beforeAll(async () => {
    portvakt = client();
    const app = express();
    const handler: express.RequestHandler = (req, res) => {
      res.json(portvakt.principal(req));
    };
    app.get("/plain", portvakt.requireAccessToken({ audience: op.clientId }), handler);
    app.get(
      "/roles",
      portvakt.requireAccessToken({ audience: op.clientId, roles: ["handlaggare", "admin"] }),
      handler,
    );
    app.get(
      "/any-role",
      portvakt.requireAccessToken({ audience: op.clientId, anyRole: ["admin", "handlaggare"] }),
      handler,
    );
    app.get("/loa4", portvakt.requireAccessToken({ audience: op.clientId, acr: LOA4 }), handler);
    app.get(
      "/service",
      portvakt.requireAccessToken({ audience: op.clientId, allowService: ["other-app"] }),
      handler,
    );
    app.get(
      "/self-only",
      portvakt.requireAccessToken({ audience: op.clientId, allowRepresentation: false }),
      handler,
    );
    server = createServer(app);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });
  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  const call = (path: string, authorization?: string) =>
    fetch(`${base}${path}`, authorization === undefined ? {} : { headers: { authorization } });

  it("answers 401 with WWW-Authenticate per RFC 6750 without and with a bad token", async () => {
    const missing = await call("/plain");
    expect(missing.status).toBe(401);
    expect(missing.headers.get("www-authenticate")).toBe('Bearer realm="portvakt"');
    const bad = await call("/plain", "Bearer abc.def.ghi");
    expect(bad.status).toBe(401);
    expect(bad.headers.get("www-authenticate")).toBe(
      'Bearer realm="portvakt", error="invalid_token", error_description="The access token is invalid"',
    );
    expect(await bad.json()).toEqual({
      error: "invalid_token",
      error_description: "The access token is invalid",
    });
    const malformed = await call("/plain", "Basic dXNlcjpwYXNz");
    expect(malformed.status).toBe(400);
    expect(malformed.headers.get("www-authenticate")).toContain('error="invalid_request"');
  });

  it("attaches the principal and checks roles, anyRole and acr", async () => {
    const token = await op.signAccessToken(person());
    const ok = await call("/plain", `Bearer ${token}`);
    expect(ok.status).toBe(200);
    expect(await ok.json()).toMatchObject({ sub: PERSON, isService: false });

    const roles = await call("/roles", `Bearer ${token}`);
    expect(roles.status).toBe(403);
    expect(roles.headers.get("www-authenticate")).toContain('error="insufficient_scope"');
    expect(await roles.json()).toMatchObject({
      error: "insufficient_scope",
      reason: "missing_role",
    });
    expect((await call("/any-role", `Bearer ${token}`)).status).toBe(200);

    const loa4 = await call("/loa4", `Bearer ${token}`);
    expect(loa4.status).toBe(401);
    expect(loa4.headers.get("www-authenticate")).toContain(
      `error="insufficient_user_authentication"`,
    );
    expect(loa4.headers.get("www-authenticate")).toContain(`acr_values="${LOA4}"`);
    const strong = await op.signAccessToken(person({ acr: LOA4 }));
    expect((await call("/loa4", `Bearer ${strong}`)).status).toBe(200);
  });

  it("refuses service tokens unless allowed, and representation when refused", async () => {
    const serviceToken = await op.signAccessToken(service());
    const refused = await call("/plain", `Bearer ${serviceToken}`);
    expect(refused.status).toBe(403);
    expect(await refused.json()).toMatchObject({ reason: "service_not_allowed" });
    const allowed = await call("/service", `Bearer ${serviceToken}`);
    expect(allowed.status).toBe(200);
    expect(await allowed.json()).toMatchObject({ isService: true, clientId: "other-app" });
    const stranger = await op.signAccessToken(
      service({ sub: "third-app", client_id: "third-app" }),
    );
    expect((await call("/service", `Bearer ${stranger}`)).status).toBe(403);

    const acting = await op.signAccessToken(person({ rep: { sub: "party-1", type: "person" } }));
    expect((await call("/plain", `Bearer ${acting}`)).status).toBe(200);
    const self = await call("/self-only", `Bearer ${acting}`);
    expect(self.status).toBe(403);
    expect(await self.json()).toMatchObject({ reason: "representation_not_allowed" });
  });

  it("answers 503 when the keys cannot be fetched at all", async () => {
    const cold = client();
    const app = express();
    app.get("/x", cold.requireAccessToken({ audience: op.clientId }), (_req, res) => {
      res.end();
    });
    const coldServer = createServer(app);
    await new Promise<void>((resolve) => coldServer.listen(0, "127.0.0.1", resolve));
    op.down = true;
    try {
      const response = await fetch(
        `http://127.0.0.1:${(coldServer.address() as AddressInfo).port}/x`,
        { headers: { authorization: `Bearer ${await op.signAccessToken(person())}` } },
      );
      expect(response.status).toBe(503);
      expect(await response.json()).toMatchObject({ error: "temporarily_unavailable" });
    } finally {
      await new Promise<void>((resolve) => coldServer.close(() => resolve()));
    }
  });
});
