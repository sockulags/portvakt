import { describe, expect, it } from "vitest";
import { createPortvaktClient } from "./client.js";
import { resolveConfig, type PortvaktClientConfig } from "./config.js";
import { PortvaktConfigError } from "./errors.js";
import { silentLogger } from "./logger.js";
import { MemoryStore } from "./stores/memory.js";

const SECRET = "app-secret-0123456789abcdef-do-not-log";

const valid: PortvaktClientConfig = {
  issuer: "https://login.example.org/t/kommunen",
  clientId: "case-service",
  clientAuth: { method: "client_secret_basic", clientSecret: SECRET },
  redirectUri: "https://case.example.org/auth/callback",
  logger: silentLogger,
};

function issuesOf(fn: () => unknown): string[] {
  try {
    fn();
  } catch (error) {
    if (error instanceof PortvaktConfigError) return [...error.issues];
    throw error;
  }
  throw new Error("expected a configuration error");
}

describe("client configuration", () => {
  it("applies the defaults", () => {
    const config = resolveConfig(valid);
    expect(config).toMatchObject({
      scopes: ["openid", "profile", "email"],
      clockSkewSeconds: 30,
      httpTimeoutSeconds: 10,
      discoveryCacheSeconds: 3600,
      jwks: { cacheMaxAgeSeconds: 600, cooldownSeconds: 30, staleMaxAgeSeconds: 86_400 },
      outageGraceSeconds: 0,
      acrRanking: [
        "http://id.elegnamnden.se/loa/1.0/loa2",
        "http://id.elegnamnden.se/loa/1.0/loa3",
        "http://id.elegnamnden.se/loa/1.0/loa4",
      ],
      allowInsecureRequests: false,
    });
  });

  it("refuses invalid values with readable issues that never echo secrets", () => {
    const issues = issuesOf(() =>
      resolveConfig({
        ...valid,
        issuer: "http://login.example.org/t/kommunen/",
        clientAuth: { method: "client_secret_basic", clientSecret: "short" },
        scopes: ["profile"],
        clockSkewSeconds: -1,
      }),
    );
    expect(issues.some((issue) => issue.startsWith("issuer:"))).toBe(true);
    expect(issues.some((issue) => issue.startsWith("clientAuth.clientSecret:"))).toBe(true);
    expect(issues).toContain("scopes: must include openid");
    expect(issues.some((issue) => issue.startsWith("clockSkewSeconds:"))).toBe(true);
    expect(issues.join("\n")).not.toContain("short");
  });

  it("allows http issuers only with allowInsecureRequests", () => {
    const http = { ...valid, issuer: "http://localhost:3000/t/demo" };
    expect(issuesOf(() => resolveConfig(http))[0]).toMatch(/^issuer: must be https/);
    expect(resolveConfig({ ...http, allowInsecureRequests: true }).issuer).toBe(http.issuer);
  });

  it("refuses unknown options, a private_key_jwt without a private key, and odd issuers", () => {
    expect(
      issuesOf(() => resolveConfig({ ...valid, extra: 1 } as PortvaktClientConfig)),
    ).toHaveLength(1);
    expect(
      issuesOf(() =>
        resolveConfig({
          ...valid,
          clientAuth: { method: "private_key_jwt", privateJwk: { kty: "EC", kid: "k1" } },
        }),
      )[0],
    ).toMatch(/^clientAuth\.privateJwk\.d:/);
    expect(
      issuesOf(() => resolveConfig({ ...valid, issuer: "https://x.example/t/a?b=1" })),
    ).toHaveLength(1);
    expect(issuesOf(() => resolveConfig({ ...valid, issuer: "not a url" }))).toHaveLength(1);
  });
});

describe("bff and middleware options", () => {
  const key = Buffer.alloc(32, 7).toString("base64");
  const cookie = { name: "app_session", secrets: ["a-cookie-secret-of-at-least-32-chars!"] };

  it("validates the BFF options", () => {
    const portvakt = createPortvaktClient(valid);
    expect(() =>
      portvakt.bff({ sessionStore: new MemoryStore(), encryptionKey: key, cookie }),
    ).not.toThrow();
    const issues = issuesOf(() =>
      portvakt.bff({
        sessionStore: new MemoryStore(),
        encryptionKey: key,
        cookie: { name: "bad name", secrets: ["short"] },
        mountPath: "auth/",
      }),
    );
    expect(issues.some((issue) => issue.startsWith("bff.cookie.name:"))).toBe(true);
    expect(issues.some((issue) => issue.startsWith("bff.cookie.secrets.0:"))).toBe(true);
    expect(issues.some((issue) => issue.startsWith("bff.mountPath:"))).toBe(true);
    expect(
      issuesOf(() =>
        portvakt.bff({ sessionStore: new MemoryStore(), encryptionKey: "dG9vIHNob3J0", cookie }),
      ),
    ).toEqual(["encryptionKey[0]: must be 32 random bytes, base64-encoded"]);
  });

  it("requires a redirectUri at the BFF callback", () => {
    const { redirectUri: _r, ...withoutRedirect } = valid;
    void _r;
    expect(
      issuesOf(() =>
        createPortvaktClient(withoutRedirect).bff({
          sessionStore: new MemoryStore(),
          encryptionKey: key,
          cookie,
        }),
      ),
    ).toEqual(["redirectUri: required for the BFF"]);
    expect(
      issuesOf(() =>
        createPortvaktClient({ ...valid, redirectUri: "https://case.example.org/cb" }).bff({
          sessionStore: new MemoryStore(),
          encryptionKey: key,
          cookie,
        }),
      ),
    ).toEqual(["redirectUri: must point at the BFF callback (/auth/callback)"]);
  });

  it("validates requireAccessToken requirements and clientCredentials audiences", () => {
    const portvakt = createPortvaktClient(valid);
    expect(() => portvakt.requireAccessToken({ audience: "" })).toThrow(PortvaktConfigError);
    expect(() => portvakt.requireAccessToken({ audience: "a", anyRole: [] })).toThrow(
      PortvaktConfigError,
    );
    expect(() => portvakt.clientCredentials({ audience: "with space" })).toThrow(
      PortvaktConfigError,
    );
    expect(portvakt.clientCredentials()).toBe(
      portvakt.clientCredentials({ audience: "case-service" }),
    );
  });
});
