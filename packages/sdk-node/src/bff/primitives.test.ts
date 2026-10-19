import type { Request } from "express";
import { describe, expect, it, vi } from "vitest";
import { acrAtLeast, DEFAULT_ACR_RANKING, hasRole, type PersonPrincipal } from "../principal.js";
import { MemoryStore } from "../stores/memory.js";
import { CookieSigner, Sealer, storeKey } from "./crypto.js";
import { isBrowserNavigation, readCookie, safeReturnTo } from "./http.js";
import { KeyedMutex } from "./lock.js";

const key = (fill: number) => Buffer.alloc(32, fill).toString("base64");

describe("returnTo validation", () => {
  it.each([
    ["/", "/"],
    ["/cases/42?tab=docs#top", "/cases/42?tab=docs#top"],
    ["/a/../b", "/b"],
  ])("accepts the same-origin path %s", (input, output) => {
    expect(safeReturnTo(input)).toBe(output);
  });

  it.each([
    "//evil.example",
    "/\\evil.example",
    "\\\\evil.example",
    "/%2F%2Fevil.example",
    "/%5Cevil.example",
    "https://evil.example/",
    "http:/evil.example",
    "javascript:alert(1)",
    "evil.example",
    "",
    "/\tevil",
    "/a\nb",
    " /a",
    "/%E0%A4%A",
    `/${"a".repeat(3000)}`,
    "/.//evil.com",
    "/a/..//evil.com",
    "/%2e//evil.com",
    "/%2e%2e//evil.com",
    "/%2E//evil.com",
    "/a/b/../..//evil.com",
    "/./%2F/evil.com",
    "/%2e/%5Cevil.com",
  ])("refuses %j", (input) => {
    expect(safeReturnTo(input)).toBeUndefined();
  });

  it("refuses non-strings", () => {
    expect(safeReturnTo(["/a", "/b"])).toBeUndefined();
    expect(safeReturnTo(undefined)).toBeUndefined();
  });
});

describe("cookies and navigation", () => {
  const request = (headers: Record<string, string>, method = "GET") =>
    ({
      method,
      headers,
      get: (name: string) => headers[name.toLowerCase()],
    }) as unknown as Request;

  it("reads the first cookie of a name", () => {
    const req = request({ cookie: "a=1; app_session=abc.def; app_session=other" });
    expect(readCookie(req, "app_session")).toBe("abc.def");
    expect(readCookie(req, "missing")).toBeUndefined();
  });

  it("signs cookie values and verifies with every secret", () => {
    const old = new CookieSigner(["old-secret-old-secret-old-secret-0"]);
    const rotated = new CookieSigner([
      "new-secret-new-secret-new-secret-1",
      "old-secret-old-secret-old-secret-0",
    ]);
    const signed = old.sign("session-id");
    expect(rotated.verify(signed)).toBe("session-id");
    expect(rotated.verify(`${signed}x`)).toBeUndefined();
    expect(rotated.verify("session-id")).toBeUndefined();
    expect(new CookieSigner(["another-secret-another-secret-xx"]).verify(signed)).toBeUndefined();
  });

  it("tells browser navigations from XHR", () => {
    expect(isBrowserNavigation(request({ "sec-fetch-mode": "navigate" }))).toBe(true);
    expect(isBrowserNavigation(request({ "sec-fetch-mode": "cors", accept: "text/html" }))).toBe(
      false,
    );
    expect(isBrowserNavigation(request({ accept: "text/html,application/xhtml+xml" }))).toBe(true);
    expect(isBrowserNavigation(request({ accept: "application/json" }))).toBe(false);
    expect(
      isBrowserNavigation(request({ accept: "text/html", "x-requested-with": "XMLHttpRequest" })),
    ).toBe(false);
    expect(isBrowserNavigation(request({ accept: "text/html" }, "POST"))).toBe(false);
  });
});

describe("session encryption", () => {
  it("round-trips, binds to the store key and rotates keys", () => {
    const sealer = new Sealer([key(1)]);
    const sealed = sealer.seal('{"accessToken":"secret-token"}', "s:abc");
    expect(sealed).not.toContain("secret-token");
    expect(sealed.startsWith("v1.")).toBe(true);
    expect(sealer.open(sealed, "s:abc")).toBe('{"accessToken":"secret-token"}');
    expect(sealer.open(sealed, "s:other")).toBeUndefined();
    const parts = sealed.split(".");
    const tampered = [...parts.slice(0, 3), `A${parts[3]!.slice(1)}`].join(".");
    expect(sealer.open(tampered, "s:abc")).toBeUndefined();

    const rotated = new Sealer([key(2), key(1)]);
    expect(rotated.open(sealed, "s:abc")).toBe('{"accessToken":"secret-token"}');
    expect(new Sealer([key(2)]).open(sealed, "s:abc")).toBeUndefined();
    expect(rotated.seal("x", "k").split(".")[1]).not.toBe(parts[1]);
  });

  it("stores hashed keys, never the cookie id", () => {
    const hashed = storeKey("s", "the-cookie-id");
    expect(hashed).toMatch(/^s:[A-Za-z0-9_-]{43}$/);
    expect(hashed).not.toContain("the-cookie-id");
  });
});

describe("KeyedMutex", () => {
  it("runs holders of one key one at a time, other keys in parallel", async () => {
    const mutex = new KeyedMutex();
    const events: string[] = [];
    const task = (key: string, name: string, ms: number) =>
      mutex.run(key, async () => {
        events.push(`${name}:start`);
        await new Promise((resolve) => setTimeout(resolve, ms));
        events.push(`${name}:end`);
        return name;
      });
    const results = await Promise.all([
      task("a", "a1", 30),
      task("a", "a2", 1),
      task("b", "b1", 1),
    ]);
    expect(results).toEqual(["a1", "a2", "b1"]);
    expect(events.indexOf("a1:end")).toBeLessThan(events.indexOf("a2:start"));
    expect(events.indexOf("b1:end")).toBeLessThan(events.indexOf("a1:end"));
    expect(mutex.size).toBe(0);
    await expect(mutex.run("a", () => Promise.reject(new Error("boom")))).rejects.toThrow("boom");
    await expect(mutex.run("a", () => Promise.resolve("after"))).resolves.toBe("after");
  });
});

describe("MemoryStore", () => {
  it("expires entries and bounds its size", async () => {
    const store = new MemoryStore({ maxEntries: 3 });
    await store.set("a", "1", new Date(Date.now() + 60_000));
    await store.set("gone", "x", new Date(Date.now() - 1));
    expect(await store.get("a")).toBe("1");
    expect(await store.get("gone")).toBeUndefined();
    for (const name of ["b", "c", "d", "e"]) {
      await store.set(name, name, new Date(Date.now() + 120_000));
    }
    expect(store.size).toBeLessThanOrEqual(3);
    expect(await store.get("a")).toBeUndefined();
    await store.destroy("e");
    expect(await store.get("e")).toBeUndefined();
  });

  it("warns in production", () => {
    const warn = vi.fn();
    const previous = process.env.NODE_ENV;
    process.env.NODE_ENV = "production";
    try {
      new MemoryStore({
        logger: { warn, info: vi.fn(), debug: vi.fn(), error: vi.fn() },
      });
    } finally {
      process.env.NODE_ENV = previous;
    }
    expect(warn).toHaveBeenCalledOnce();
  });
});

describe("principal helpers", () => {
  const principal: PersonPrincipal = {
    isService: false,
    sub: "p",
    tenant: "t",
    idp: "i",
    idpKind: "citizen",
    acr: DEFAULT_ACR_RANKING[1]!,
    authTime: 0,
    roles: ["handlaggare"],
    attrs: {},
  };

  it("checks roles and acr with Portvakt's ranking semantics", () => {
    expect(hasRole(principal, "handlaggare")).toBe(true);
    expect(hasRole(principal, "admin")).toBe(false);
    expect(hasRole(undefined, "admin")).toBe(false);
    expect(acrAtLeast(principal, DEFAULT_ACR_RANKING[0]!)).toBe(true);
    expect(acrAtLeast(principal, DEFAULT_ACR_RANKING[1]!)).toBe(true);
    expect(acrAtLeast(principal, DEFAULT_ACR_RANKING[2]!)).toBe(false);
    expect(acrAtLeast("urn:portvakt:acr:employee", "urn:portvakt:acr:employee")).toBe(true);
    expect(acrAtLeast("urn:portvakt:acr:employee", DEFAULT_ACR_RANKING[0]!)).toBe(false);
    expect(acrAtLeast(DEFAULT_ACR_RANKING[2], "urn:custom")).toBe(false);
    expect(acrAtLeast("b", "a", ["a", "b"])).toBe(true);
    expect(
      acrAtLeast(
        { isService: true, sub: "s", tenant: "t", clientId: "s", roles: [], attrs: {} },
        DEFAULT_ACR_RANKING[0]!,
      ),
    ).toBe(false);
  });
});
