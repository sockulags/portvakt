import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import express, { type Express } from "express";
import express4 from "express4";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { createPortvaktClient } from "../client.js";
import { LoginRequiredError, PortvaktUnavailableError } from "../errors.js";
import { silentLogger } from "../logger.js";
import { MemoryStore } from "../stores/memory.js";
import { MiniBrowser } from "../testing/browser.js";
import { startFakeOp, type FakeOp } from "../testing/fake-op.js";
import type { BffOptions, PortvaktBff } from "./bff.js";

const LOA3 = "http://id.elegnamnden.se/loa/1.0/loa3";
const LOA4 = "http://id.elegnamnden.se/loa/1.0/loa4";
const ENCRYPTION_KEY = Buffer.alloc(32, 9).toString("base64");
const COOKIE = "demo_session";

/** A store that records what reaches it. */
class RecordingStore extends MemoryStore {
  readonly writes: { key: string; value: string }[] = [];
  override async set(key: string, value: string, expiresAt: Date): Promise<void> {
    this.writes.push({ key, value });
    await super.set(key, value, expiresAt);
  }
}

interface Harness {
  readonly base: string;
  readonly bff: PortvaktBff;
  readonly store: RecordingStore;
  close(): Promise<void>;
}

let op: FakeOp;

beforeAll(async () => {
  op = await startFakeOp();
});
afterAll(async () => {
  await op.close();
});
beforeEach(() => {
  op.claims = {};
  op.accessTokenTtl = 300;
  op.refreshDelayMs = 0;
  op.refuseRefresh = false;
  op.down = false;
  op.serverError = undefined;
});
afterEach(() => {
  vi.useRealTimers();
});

async function harness(
  options: {
    readonly grace?: number;
    readonly bff?: Partial<BffOptions>;
    readonly express?: () => Express;
  } = {},
): Promise<Harness> {
  const server: Server = createServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const portvakt = createPortvaktClient({
    issuer: op.issuer,
    clientId: op.clientId,
    clientAuth: { method: "client_secret_basic", clientSecret: op.clientSecret },
    redirectUri: `${base}/auth/callback`,
    postLogoutRedirectUri: `${base}/`,
    allowInsecureRequests: true,
    outageGraceSeconds: options.grace ?? 0,
    logger: silentLogger,
  });
  const store = new RecordingStore();
  const bff = portvakt.bff({
    sessionStore: store,
    encryptionKey: ENCRYPTION_KEY,
    cookie: { name: COOKIE, secrets: ["cookie-secret-cookie-secret-cookie-secret"], secure: false },
    ...options.bff,
  });
  const app = (options.express ?? express)();
  app.use(bff);
  app.get("/", (_req, res) => {
    res.send("home");
  });
  app.get("/private", bff.requireLogin(), (req, res) => {
    res.json(bff.principal(req));
  });
  app.get("/sensitive", bff.requireAcr(LOA4), (_req, res) => {
    res.send("sensitive");
  });
  app.get("/token", bff.requireLogin(), (req, res, next) => {
    const min = typeof req.query.min === "string" ? Number(req.query.min) : undefined;
    bff
      .getAccessToken(req, min === undefined ? {} : { minValiditySeconds: min })
      .then((token) => res.json({ token }))
      .catch(next);
  });
  app.use(bff.errorHandler());
  server.on("request", app);
  return {
    base,
    bff,
    store,
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}

/** A full login through the fake OP, started from the application's own page. */
async function login(h: Harness, browser: MiniBrowser, query = "returnTo=%2Fprivate") {
  const start = await browser.request(`${h.base}/auth/login?${query}`, {
    headers: { "sec-fetch-site": "same-origin" },
  });
  expect(start.status).toBe(302);
  const authorization = new URL(start.headers.get("location")!);
  expect(authorization.origin + authorization.pathname).toBe(`${op.issuer}/auth`);
  const toCallback = await browser.request(authorization.href);
  const callback = new URL(toCallback.headers.get("location")!);
  const done = await browser.request(callback.href);
  return { authorization, callback, done };
}

const sessionOf = async (h: Harness, browser: MiniBrowser) =>
  (await (await browser.request(`${h.base}/auth/session`)).json()) as Record<string, unknown>;

describe("BFF login", () => {
  let h: Harness;
  beforeAll(async () => {
    h = await harness();
  });
  afterAll(async () => {
    await h.close();
  });

  it("logs in with PKCE S256, state and nonce, and returns to the same-origin returnTo", async () => {
    const browser = new MiniBrowser();
    const { authorization, done } = await login(h, browser);
    expect(authorization.searchParams.get("code_challenge_method")).toBe("S256");
    expect(authorization.searchParams.get("code_challenge")).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(authorization.searchParams.get("state")).toBeTruthy();
    expect(authorization.searchParams.get("nonce")).toBeTruthy();
    expect(authorization.searchParams.get("scope")).toBe("openid profile email");
    expect(authorization.searchParams.get("redirect_uri")).toBe(`${h.base}/auth/callback`);
    expect(done.status).toBe(303);
    expect(done.headers.get("location")).toBe("/private");
    const cookie = done.headers.getSetCookie().find((value) => value.startsWith(`${COOKIE}=`));
    expect(cookie).toMatch(/HttpOnly/);
    expect(cookie).toMatch(/SameSite=Lax/);
    expect(cookie).toMatch(/Path=\//);

    const session = await sessionOf(h, browser);
    expect(session).toMatchObject({
      authenticated: true,
      principal: {
        isService: false,
        sub: "3f2b8c4e-91d7-4a3e-8b6f-2d4c9e1a7b55",
        tenant: "fake",
        idpKind: "employee",
        acr: LOA3,
        roles: ["handlaggare"],
        name: "Anna Andersson",
      },
      csrfToken: expect.any(String) as string,
    });
    const text = JSON.stringify(session);
    // No JWT (header and payload start with "eyJ"); random base64 may contain "eyJ" by chance.
    expect(text).not.toMatch(/eyJ[\w-]*\.eyJ/);
    expect(text).not.toContain("refresh");
    const privateRoute = await browser.request(`${h.base}/private`);
    expect(privateRoute.status).toBe(200);
  });

  it("refuses unsafe returnTo values (falls back to /)", async () => {
    for (const unsafe of [
      "//evil.example",
      "/\\evil.example",
      "https://evil.example/x",
      "/.//evil.example",
      "/a/..//evil.example",
      "/%2e//evil.example",
      "/%2e%2e//evil.example",
    ]) {
      const browser = new MiniBrowser();
      const { done } = await login(h, browser, `returnTo=${encodeURIComponent(unsafe)}`);
      expect(done.headers.get("location")).toBe("/");
    }
  });

  it("passes acr, prompt, loginHint and uiLocales on, and refuses invalid ones", async () => {
    const browser = new MiniBrowser();
    const start = await browser.request(
      `${h.base}/auth/login?prompt=login&loginHint=anna%40kommun.example&uiLocales=sv%20en&acr=${encodeURIComponent(LOA3)}`,
      { headers: { "sec-fetch-site": "same-origin" } },
    );
    const url = new URL(start.headers.get("location")!);
    expect(url.searchParams.get("prompt")).toBe("login");
    expect(url.searchParams.get("login_hint")).toBe("anna@kommun.example");
    expect(url.searchParams.get("ui_locales")).toBe("sv en");
    expect(url.searchParams.get("acr_values")).toBe(LOA3);
    expect((await browser.request(`${h.base}/auth/login?prompt=consent`)).status).toBe(400);
    expect((await browser.request(`${h.base}/auth/login?prompt=login&prompt=none`)).status).toBe(
      400,
    );
    const representation = await browser.request(`${h.base}/auth/select-representation`, {
      headers: { "sec-fetch-site": "same-origin" },
    });
    expect(new URL(representation.headers.get("location")!).searchParams.get("prompt")).toBe(
      "select_account",
    );
    expect((await browser.request(`${h.base}/auth/step-up`)).status).toBe(400);
  });

  it("verifies the pending login: no cookie, wrong state and replays are refused", async () => {
    const browser = new MiniBrowser();
    const start = await browser.request(`${h.base}/auth/login`);
    const toCallback = await browser.request(start.headers.get("location")!);
    const callback = new URL(toCallback.headers.get("location")!);

    const stranger = new MiniBrowser();
    const noCookie = await stranger.request(callback.href, {
      headers: { accept: "application/json" },
    });
    expect(noCookie.status).toBe(400);
    expect(await noCookie.json()).toEqual({ error: "login_expired" });

    const tampered = new URL(callback);
    tampered.searchParams.set("state", "forged");
    const wrongState = await browser.request(tampered.href, {
      headers: { accept: "application/json" },
    });
    expect(await wrongState.json()).toEqual({ error: "state_mismatch" });
    // The pending login was consumed by the failed attempt: the real callback is refused too.
    const replay = await browser.request(callback.href, {
      headers: { accept: "application/json" },
    });
    expect(await replay.json()).toEqual({ error: "login_expired" });
    expect((await sessionOf(h, browser)).authenticated).toBe(false);
  });

  it("shows Portvakt's error (access_denied) as a page", async () => {
    const browser = new MiniBrowser();
    const start = await browser.request(`${h.base}/auth/login`);
    const state = new URL(start.headers.get("location")!).searchParams.get("state")!;
    const page = await browser.request(
      `${h.base}/auth/callback?error=access_denied&state=${state}`,
    );
    expect(page.status).toBe(400);
    expect(page.headers.get("content-security-policy")).toContain("default-src 'none'");
    expect(await page.text()).toContain('data-testid="portvakt-error-code">access_denied<');
  });

  it("regenerates the session id at every login", async () => {
    const browser = new MiniBrowser();
    await login(h, browser);
    const first = browser.cookie(COOKIE);
    await login(h, browser);
    const second = browser.cookie(COOKIE);
    expect(second).toBeDefined();
    expect(second).not.toBe(first);
    // The old session is gone: its cookie no longer works.
    const old = new MiniBrowser();
    old.setCookie(new URL(h.base).host, COOKIE, first!);
    expect((await sessionOf(h, old)).authenticated).toBe(false);
  });

  it("stores sessions encrypted under hashed keys", async () => {
    const browser = new MiniBrowser();
    h.store.writes.length = 0;
    await login(h, browser);
    const token = ((await (await browser.request(`${h.base}/token`)).json()) as { token: string })
      .token;
    const cookieId = decodeURIComponent(browser.cookie(COOKIE)!).split(".")[0]!;
    expect(h.store.writes.length).toBeGreaterThan(0);
    for (const write of h.store.writes) {
      expect(write.key).not.toContain(cookieId);
      expect(write.value.startsWith("v1.")).toBe(true);
      expect(write.value).not.toContain(token);
      expect(write.value).not.toMatch(/eyJ[\w-]*\.eyJ/);
      expect(write.value).not.toContain("Anna");
    }
  });
});

describe("BFF logout", () => {
  let h: Harness;
  beforeAll(async () => {
    h = await harness();
  });
  afterAll(async () => {
    await h.close();
  });

  it("requires the CSRF token, then ends the session and logs out at Portvakt", async () => {
    const browser = new MiniBrowser();
    await login(h, browser);
    const { csrfToken } = (await sessionOf(h, browser)) as { csrfToken: string };
    const post = (body: string) =>
      browser.request(`${h.base}/auth/logout`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body,
      });
    expect((await post("")).status).toBe(403);
    expect((await post("_csrf=wrong")).status).toBe(403);
    expect((await sessionOf(h, browser)).authenticated).toBe(true);

    const done = await post(`_csrf=${encodeURIComponent(csrfToken)}`);
    expect(done.status).toBe(303);
    const target = new URL(done.headers.get("location")!);
    expect(target.origin + target.pathname).toBe(`${op.issuer}/session/end`);
    expect(target.searchParams.get("id_token_hint")).toMatch(/^eyJ/);
    expect(target.searchParams.get("post_logout_redirect_uri")).toBe(`${h.base}/`);
    expect(target.searchParams.get("client_id")).toBe(op.clientId);
    expect((await sessionOf(h, browser)).authenticated).toBe(false);
  });

  it("accepts the token as a header from fetch and answers JSON", async () => {
    const browser = new MiniBrowser();
    await login(h, browser);
    const { csrfToken } = (await sessionOf(h, browser)) as { csrfToken: string };
    const done = await browser.request(`${h.base}/auth/logout`, {
      method: "POST",
      headers: { "x-csrf-token": csrfToken, accept: "application/json" },
    });
    expect(done.status).toBe(200);
    expect(((await done.json()) as { redirectTo: string }).redirectTo).toContain("/session/end");
  });
});

describe("BFF session lifetime", () => {
  let h: Harness;
  beforeAll(async () => {
    h = await harness({ bff: { idleTimeoutSeconds: 600, maxAgeSeconds: 7200 } });
  });
  afterAll(async () => {
    await h.close();
  });

  const clock = () => {
    vi.useFakeTimers({ toFake: ["Date"], shouldAdvanceTime: true });
    return (seconds: number) => vi.setSystemTime(Date.now() + seconds * 1000);
  };

  it("ends no later than the ID token's session_exp", async () => {
    const advance = clock();
    op.claims = { session_exp: Math.floor(Date.now() / 1000) + 300 };
    const browser = new MiniBrowser();
    await login(h, browser);
    const session = (await sessionOf(h, browser)) as { sessionEndsAt: string };
    expect(Math.abs(Date.parse(session.sessionEndsAt) - (Date.now() + 300_000))).toBeLessThan(2000);
    advance(250);
    expect((await browser.request(`${h.base}/private`)).status).toBe(200);
    advance(60);
    const after = await browser.request(`${h.base}/private`, {
      headers: { accept: "application/json" },
    });
    expect(after.status).toBe(401);
    expect(await after.json()).toEqual({
      error: "login_required",
      loginUrl: "/auth/login?returnTo=%2F",
    });
    // The cookie is cleared too.
    expect(browser.cookie(COOKIE)).toBeUndefined();
  });

  it("caps the session at the BFF's maxAge and ends it after the idle timeout", async () => {
    const advance = clock();
    op.claims = { session_exp: Math.floor(Date.now() / 1000) + 86_400 };
    const browser = new MiniBrowser();
    await login(h, browser);
    const session = (await sessionOf(h, browser)) as { sessionEndsAt: string };
    expect(Math.abs(Date.parse(session.sessionEndsAt) - (Date.now() + 7_200_000))).toBeLessThan(
      2000,
    );
    advance(500);
    expect((await browser.request(`${h.base}/private`)).status).toBe(200);
    advance(500);
    // Activity at 500 s moved the idle end; /session reads do not count as activity.
    expect((await sessionOf(h, browser)).authenticated).toBe(true);
    advance(200);
    expect((await sessionOf(h, browser)).authenticated).toBe(false);
  });

  it("redirects browser navigations to the login", async () => {
    const browser = new MiniBrowser();
    const response = await browser.navigate(`${h.base}/private?x=1`);
    expect(response.status).toBe(302);
    expect(response.location).toBe("/auth/login?returnTo=%2Fprivate%3Fx%3D1");
  });
});

describe("BFF step-up", () => {
  let h: Harness;
  beforeAll(async () => {
    h = await harness();
  });
  afterAll(async () => {
    await h.close();
  });

  it("sends navigations to the step-up and answers XHR with a structured 401", async () => {
    const browser = new MiniBrowser();
    await login(h, browser);
    const xhr = await browser.request(`${h.base}/sensitive`, {
      headers: { accept: "application/json" },
    });
    expect(xhr.status).toBe(401);
    expect(await xhr.json()).toEqual({
      error: "step_up_required",
      acr: LOA4,
      stepUpUrl: `/auth/step-up?acr=${encodeURIComponent(LOA4)}&returnTo=%2F`,
    });
    const navigation = await browser.navigate(`${h.base}/sensitive`);
    expect(navigation.status).toBe(302);
    const stepUp = await browser.request(new URL(navigation.location!, h.base).href, {
      headers: { "sec-fetch-site": "same-origin" },
    });
    const authorization = new URL(stepUp.headers.get("location")!);
    expect(authorization.searchParams.get("acr_values")).toBe(LOA4);
    const callback = await browser.request(authorization.href);
    const done = await browser.request(callback.headers.get("location")!);
    expect(done.headers.get("location")).toBe("/sensitive");
    expect((await browser.request(`${h.base}/sensitive`)).status).toBe(200);
  });
});

describe("BFF access tokens and refresh", () => {
  it("refreshes once for concurrent requests (per-session lock) and rotates", async () => {
    const h = await harness();
    try {
      const browser = new MiniBrowser();
      await login(h, browser);
      const first = await browser.request(`${h.base}/token`);
      const original = ((await first.json()) as { token: string }).token;
      op.refreshDelayMs = 100;
      const before = op.counters.refresh;
      const results = await Promise.all(
        Array.from({ length: 8 }, () => browser.request(`${h.base}/token?min=3600`)),
      );
      const tokens = await Promise.all(
        results.map(async (response) => ((await response.json()) as { token: string }).token),
      );
      // Each request needed a token valid for an hour, so each refreshed; one at a time, every
      // refresh with the token the previous one returned (no replays).
      expect(op.counters.refresh - before).toBe(8);
      expect(new Set(op.presentedRefreshTokens).size).toBe(op.presentedRefreshTokens.length);
      expect(tokens.every((token) => token !== original)).toBe(true);

      // Tokens that are fresh enough are shared: concurrent requests trigger one refresh.
      op.accessTokenTtl = 20;
      await browser.request(`${h.base}/token?min=3600`);
      op.accessTokenTtl = 300;
      const mid = op.counters.refresh;
      const shared = await Promise.all(
        Array.from({ length: 8 }, () => browser.request(`${h.base}/token`)),
      );
      expect(op.counters.refresh - mid).toBe(1);
      const values = new Set(
        await Promise.all(
          shared.map(async (response) => ((await response.json()) as { token: string }).token),
        ),
      );
      expect(values.size).toBe(1);
    } finally {
      await h.close();
    }
  });

  it("ends the session when the refresh is refused (invalid_grant)", async () => {
    const h = await harness();
    try {
      const browser = new MiniBrowser();
      await login(h, browser);
      op.refuseRefresh = true;
      const response = await browser.request(`${h.base}/token?min=3600`, {
        headers: { accept: "application/json" },
      });
      expect(response.status).toBe(401);
      expect(await response.json()).toMatchObject({ error: "login_required" });
      expect((await sessionOf(h, browser)).authenticated).toBe(false);
    } finally {
      await h.close();
    }
  });

  it("with outage grace 0, Portvakt down ends the session at the refresh", async () => {
    const h = await harness({ grace: 0 });
    try {
      const browser = new MiniBrowser();
      await login(h, browser);
      op.down = true;
      // A token that is still valid needs no Portvakt.
      expect((await browser.request(`${h.base}/token`)).status).toBe(200);
      const response = await browser.request(`${h.base}/token?min=3600`, {
        headers: { accept: "application/json" },
      });
      expect(response.status).toBe(401);
      expect((await sessionOf(h, browser)).authenticated).toBe(false);
    } finally {
      await h.close();
    }
  });

  it("with outage grace, the session survives an outage within the grace", async () => {
    const h = await harness({ grace: 120 });
    vi.useFakeTimers({ toFake: ["Date"], shouldAdvanceTime: true });
    try {
      const browser = new MiniBrowser();
      await login(h, browser);
      op.down = true;
      const during = await browser.request(`${h.base}/token?min=3600`);
      expect(during.status).toBe(503);
      expect((await browser.request(`${h.base}/private`)).status).toBe(200);
      vi.setSystemTime(Date.now() + 60_000);
      expect((await browser.request(`${h.base}/token?min=3600`)).status).toBe(503);
      // Portvakt is back within the grace: the refresh works and the outage is over.
      op.down = false;
      expect((await browser.request(`${h.base}/token?min=3600`)).status).toBe(200);
      op.down = true;
      expect((await browser.request(`${h.base}/token?min=3600`)).status).toBe(503);
      vi.setSystemTime(Date.now() + 121_000);
      // Pages that need no token keep working; the first refresh that fails after the grace
      // ends the session.
      expect((await browser.request(`${h.base}/private`)).status).toBe(200);
      const late = await browser.request(`${h.base}/token?min=3600`, {
        headers: { accept: "application/json" },
      });
      expect(late.status).toBe(401);
      expect((await sessionOf(h, browser)).authenticated).toBe(false);
    } finally {
      await h.close();
    }
  });

  it("throws typed errors from getAccessToken", async () => {
    const h = await harness({ grace: 60 });
    try {
      const req = {
        headers: {},
        method: "GET",
        get: () => undefined,
      } as unknown as express.Request;
      await expect(h.bff.getAccessToken(req)).rejects.toBeInstanceOf(LoginRequiredError);
      expect(new PortvaktUnavailableError().status).toBe(503);
    } finally {
      await h.close();
    }
  });
});

describe("review regressions", () => {
  const json = { headers: { accept: "application/json" } };

  it("treats a 5xx from Portvakt as an outage (refresh with grace, callback, grace 0)", async () => {
    const h = await harness({ grace: 120 });
    try {
      const browser = new MiniBrowser();
      await login(h, browser);
      op.serverError = 502;
      const during = await browser.request(`${h.base}/token?min=3600`, json);
      expect(during.status).toBe(503);
      expect(await during.json()).toEqual({ error: "portvakt_unavailable" });
      expect((await sessionOf(h, browser)).authenticated).toBe(true);
      op.serverError = undefined;
      expect((await browser.request(`${h.base}/token?min=3600`)).status).toBe(200);

      // The token endpoint answers 503 during a callback: the clear "unavailable" page.
      const fresh = new MiniBrowser();
      const start = await fresh.request(`${h.base}/auth/login`);
      const toCallback = await fresh.request(start.headers.get("location")!);
      op.serverError = 503;
      const page = await fresh.request(toCallback.headers.get("location")!);
      expect(page.status).toBe(503);
      expect(await page.text()).toContain(">portvakt_unavailable<");
    } finally {
      await h.close();
    }
    op.serverError = undefined;
    const strict = await harness({ grace: 0 });
    try {
      const browser = new MiniBrowser();
      await login(strict, browser);
      op.serverError = 504;
      expect((await browser.request(`${strict.base}/token?min=3600`, json)).status).toBe(401);
      expect((await sessionOf(strict, browser)).authenticated).toBe(false);
    } finally {
      await strict.close();
    }
  });

  it("does not end a session for an old outage marker (blip, then idle)", async () => {
    const h = await harness({ grace: 60 });
    vi.useFakeTimers({ toFake: ["Date"], shouldAdvanceTime: true });
    try {
      const browser = new MiniBrowser();
      await login(h, browser);
      op.down = true;
      expect((await browser.request(`${h.base}/token?min=3600`)).status).toBe(503);
      op.down = false;
      // Idle for longer than the grace (not the idle timeout): still signed in.
      vi.setSystemTime(Date.now() + 120_000);
      expect((await browser.request(`${h.base}/private`)).status).toBe(200);
      expect((await browser.request(`${h.base}/token?min=3600`)).status).toBe(200);
      // The successful refresh cleared the marker: a new blip starts a new grace.
      op.down = true;
      expect((await browser.request(`${h.base}/token?min=3600`)).status).toBe(503);
    } finally {
      await h.close();
    }
  });

  it("consumes the pending login once: of concurrent callbacks one wins", async () => {
    const h = await harness();
    try {
      const browser = new MiniBrowser();
      const start = await browser.request(`${h.base}/auth/login`);
      const toCallback = await browser.request(start.headers.get("location")!);
      const callback = toCallback.headers.get("location")!;
      const results = await Promise.all([
        browser.request(callback, json),
        browser.request(callback, json),
        browser.request(callback, json),
      ]);
      expect(results.map((response) => response.status).sort()).toEqual([303, 400, 400]);
    } finally {
      await h.close();
    }
  });

  it("refuses step-up and representation switches started from another site", async () => {
    const h = await harness();
    try {
      const browser = new MiniBrowser();
      await login(h, browser);
      const { csrfToken } = (await sessionOf(h, browser)) as { csrfToken: string };
      const stepUp = `${h.base}/auth/step-up?acr=${encodeURIComponent(LOA4)}`;
      const select = `${h.base}/auth/select-representation?returnTo=%2F`;
      for (const url of [stepUp, select]) {
        const status = async (target: string, headers: Record<string, string>) =>
          (await browser.navigate(target, headers)).status;
        expect(await status(url, { "sec-fetch-site": "cross-site" })).toBe(403);
        expect(await status(url, { "sec-fetch-site": "same-site" })).toBe(403);
        expect(await status(url, { "sec-fetch-site": "same-origin" })).toBe(302);
        expect(await status(url, { "sec-fetch-site": "none" })).toBe(302);
        // Without Sec-Fetch-Site: a same-origin Referer or the session's CSRF token.
        expect(await status(url, {})).toBe(403);
        expect(await status(url, { referer: "https://evil.example/" })).toBe(403);
        expect(await status(url, { referer: `${h.base}/page` })).toBe(302);
        expect(await status(`${url}&csrf=wrong`, {})).toBe(403);
        expect(await status(`${url}&csrf=${encodeURIComponent(csrfToken)}`, {})).toBe(302);
      }
      // A plain login without a session may be linked from anywhere; with one it may not.
      expect((await new MiniBrowser().navigate(`${h.base}/auth/login`, {})).status).toBe(302);
      expect(
        (await browser.navigate(`${h.base}/auth/login`, { "sec-fetch-site": "cross-site" })).status,
      ).toBe(403);
    } finally {
      await h.close();
    }
  });

  it("refuses logins with prompt or acr, or over a session, started from another site", async () => {
    const h = await harness();
    try {
      const stranger = new MiniBrowser();
      const crossSite = { "sec-fetch-site": "cross-site" };
      const status = async (browser: MiniBrowser, path: string, headers: Record<string, string>) =>
        (await browser.navigate(`${h.base}${path}`, headers)).status;
      // Without a session a plain login is fine from anywhere ...
      expect(await status(stranger, "/auth/login", crossSite)).toBe(302);
      // ... but not one that asks for the chooser, a prompt or an acr.
      expect(await status(stranger, "/auth/login?prompt=select_account", crossSite)).toBe(403);
      expect(await status(stranger, "/auth/login?prompt=login", crossSite)).toBe(403);
      expect(await status(stranger, `/auth/login?acr=${encodeURIComponent(LOA4)}`, crossSite)).toBe(
        403,
      );
      expect(await status(stranger, "/auth/login?prompt=select_account", {})).toBe(403);
      expect(
        await status(stranger, "/auth/login?prompt=select_account", {
          "sec-fetch-site": "same-origin",
        }),
      ).toBe(302);
      // With a session even a plain login must come from the application itself.
      const signedIn = new MiniBrowser();
      await login(h, signedIn);
      expect(await status(signedIn, "/auth/login", crossSite)).toBe(403);
      expect(await status(signedIn, "/auth/login", { referer: `${h.base}/page` })).toBe(302);
    } finally {
      await h.close();
    }
  });

  it("keeps the existing session when a step-up does not reach its level", async () => {
    const h = await harness();
    try {
      const browser = new MiniBrowser();
      await login(h, browser);
      const before = browser.cookie(COOKIE);
      const session = await sessionOf(h, browser);
      // The provider answers the step-up with loa3 anyway.
      op.claims = { acr: LOA3 };
      const start = await browser.navigate(
        `${h.base}/auth/step-up?acr=${encodeURIComponent(LOA4)}`,
        { "sec-fetch-site": "same-origin" },
      );
      const toCallback = await browser.request(start.location!);
      const refused = await browser.request(toCallback.headers.get("location")!, json);
      expect(refused.status).toBe(403);
      expect(await refused.json()).toEqual({ error: "acr_not_met" });
      expect(browser.cookie(COOKIE)).toBe(before);
      expect(await sessionOf(h, browser)).toEqual(session);
    } finally {
      await h.close();
    }
  });

  it("counts getAccessToken as activity", async () => {
    const h = await harness({ bff: { idleTimeoutSeconds: 600 } });
    vi.useFakeTimers({ toFake: ["Date"], shouldAdvanceTime: true });
    try {
      const browser = new MiniBrowser();
      await login(h, browser);
      vi.setSystemTime(Date.now() + 500_000);
      expect((await browser.request(`${h.base}/token`)).status).toBe(200);
      vi.setSystemTime(Date.now() + 500_000);
      // 1000 s after the login, 500 s after the token call: within the idle timeout.
      expect((await sessionOf(h, browser)).authenticated).toBe(true);
    } finally {
      await h.close();
    }
  });
});

describe("Express 4", () => {
  it("serves the BFF routes and middleware", async () => {
    const h = await harness({ express: () => express4() });
    try {
      const browser = new MiniBrowser();
      const { done } = await login(h, browser);
      expect(done.status).toBe(303);
      expect((await browser.request(`${h.base}/private`)).status).toBe(200);
      const { csrfToken } = (await sessionOf(h, browser)) as { csrfToken: string };
      expect((await browser.request(`${h.base}/token`)).status).toBe(200);
      const logout = await browser.request(`${h.base}/auth/logout`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: `_csrf=${encodeURIComponent(csrfToken)}`,
      });
      expect(logout.status).toBe(303);
      expect((await sessionOf(h, browser)).authenticated).toBe(false);
    } finally {
      await h.close();
    }
  });
});
