import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { parseEnv } from "node:util";
import { describe, expect, it } from "vitest";
import { testLoginUiDir } from "../testing/test-server.js";
import { parseDurationSeconds } from "./duration.js";
import { report } from "./report.js";
import {
  checkConfig,
  ConfigError,
  DEFAULT_ACR_RANKING,
  DEV_COOKIE_KEYS,
  DEV_MASTER_KEYS,
  loadAuditPruneConfig,
  loadConfig,
  loadDatabaseConfig,
} from "./index.js";

const devEnv = {
  DATABASE_URL: "postgres://portvakt:portvakt@localhost:5433/portvakt",
  MASTER_KEY: DEV_MASTER_KEYS[0],
  COOKIE_KEYS: DEV_COOKIE_KEYS.join(","),
};

const strongKey = () => randomBytes(32).toString("base64");

const productionEnv = {
  NODE_ENV: "production",
  PUBLIC_URL: "https://login.example.org",
  DATABASE_URL: "postgres://portvakt_app:s3cure-Pa55@db.internal:5432/portvakt",
  MIGRATION_DATABASE_URL: "postgres://portvakt_owner:an0ther-Pa55@db.internal:5432/portvakt",
  MASTER_KEY: strongKey(),
  COOKIE_KEYS: `${randomBytes(32).toString("base64url")},${randomBytes(32).toString("base64url")}`,
  METRICS_TOKEN: randomBytes(32).toString("base64url"),
};

function issuesOf(env: NodeJS.ProcessEnv): readonly string[] {
  try {
    loadConfig(env);
  } catch (error) {
    if (error instanceof ConfigError) return error.issues;
    throw error;
  }
  return [];
}

describe("parseDurationSeconds", () => {
  it.each([
    ["45s", 45],
    ["30m", 1800],
    ["36h", 129_600],
    ["90d", 7_776_000],
    ["2w", 1_209_600],
    ["1h30m", 5400],
    [" 2D ", 172_800],
  ])("parses %s", (input, expected) => {
    expect(parseDurationSeconds(input)).toBe(expected);
  });

  it.each(["", "0s", "10", "1y", "-5m", "1.5h", "h", "1h 30m"])("rejects %j", (input) => {
    expect(parseDurationSeconds(input)).toBeUndefined();
  });
});

describe("loadConfig", () => {
  it("separates the runtime and migration roles, falling back outside production", () => {
    const fallback = loadConfig(devEnv).database;
    expect(fallback).toMatchObject({
      url: devEnv.DATABASE_URL,
      migrationUrl: devEnv.DATABASE_URL,
      runtimeRole: "portvakt",
      separateRoles: false,
    });
    const separate = loadDatabaseConfig({
      DATABASE_URL: "postgres://portvakt_app:portvakt_app@localhost:5433/portvakt",
      MIGRATION_DATABASE_URL: "postgres://portvakt:portvakt@localhost:5433/portvakt",
    });
    expect(separate).toMatchObject({ runtimeRole: "portvakt_app", separateRoles: true });
    expect(() =>
      loadDatabaseConfig({ NODE_ENV: "production", DATABASE_URL: productionEnv.DATABASE_URL }),
    ).toThrow(/MIGRATION_DATABASE_URL: required in production/);
    expect(loadDatabaseConfig(productionEnv).migrationUrl).toBe(
      productionEnv.MIGRATION_DATABASE_URL,
    );
  });

  it("loads a development config with defaults", () => {
    const config = loadConfig(devEnv);
    expect(config.nodeEnv).toBe("development");
    expect(config.port).toBe(3000);
    expect(config.publicUrl).toBe("http://localhost:3000");
    expect(config.masterKeys.current).toHaveLength(32);
    expect(config.masterKeys.previous).toEqual([]);
    expect(config.cookieKeys).toEqual(DEV_COOKIE_KEYS);
    expect(config.logLevel).toBe("info");
    expect(config.keyRotation).toEqual({
      intervalSeconds: 90 * 86_400,
      publishAheadSeconds: 2 * 86_400,
      retireAfterSeconds: 2 * 86_400,
      manualPublishAheadSeconds: 600,
    });
    expect(config.bootstrap).toEqual({ idp: undefined, adminSubject: undefined });
  });

  it("accepts .env.example as is, and refuses it in production", () => {
    const example = parseEnv(
      readFileSync(new URL("../../../../.env.example", import.meta.url), "utf8"),
    );
    expect(loadConfig(example).nodeEnv).toBe("development");
    const issues = issuesOf({ ...example, NODE_ENV: "production" });
    expect(loadConfig(example).database.separateRoles).toBe(true);
    for (const variable of [
      "PUBLIC_URL",
      "MASTER_KEY",
      "COOKIE_KEYS",
      "DATABASE_URL",
      "MIGRATION_DATABASE_URL",
    ]) {
      expect(issues.some((issue) => issue.startsWith(`${variable}:`))).toBe(true);
    }
  });

  it("parses previous master keys, durations and strips a trailing slash", () => {
    const config = loadConfig({
      ...devEnv,
      PUBLIC_URL: "https://auth.example.org/",
      MASTER_KEY_PREVIOUS: `${DEV_MASTER_KEYS[1]}, ${strongKey()}`,
      KEY_ROTATION_INTERVAL: "30d",
      KEY_PUBLISH_AHEAD: "1d",
      KEY_RETIRE_AFTER: "12h",
      LOG_LEVEL: "debug",
      PORT: "8080",
    });
    expect(config.publicUrl).toBe("https://auth.example.org");
    expect(config.masterKeys.previous).toHaveLength(2);
    expect(config.keyRotation.retireAfterSeconds).toBe(43_200);
    expect(config.port).toBe(8080);
    expect(config.logLevel).toBe("debug");
  });

  it("reports every missing or invalid variable by name, without values", () => {
    const secret = "not-base64-but-secret!";
    const issues = issuesOf({ MASTER_KEY: secret, PORT: "99999", KEY_ROTATION_INTERVAL: "soon" });
    const names = issues.map((issue) => issue.split(":")[0]);
    expect(names).toEqual(
      expect.arrayContaining([
        "DATABASE_URL",
        "MASTER_KEY",
        "COOKIE_KEYS",
        "PORT",
        "KEY_ROTATION_INTERVAL",
      ]),
    );
    expect(issues.join("\n")).not.toContain(secret);
  });

  it("requires a 32-byte master key", () => {
    expect(issuesOf({ ...devEnv, MASTER_KEY: randomBytes(16).toString("base64") })).toEqual([
      "MASTER_KEY: must be 32 bytes, base64 encoded",
    ]);
  });

  it("rejects inconsistent rotation intervals and duplicate master keys", () => {
    const issues = issuesOf({
      ...devEnv,
      KEY_ROTATION_INTERVAL: "1d",
      KEY_PUBLISH_AHEAD: "2d",
      MASTER_KEY_PREVIOUS: devEnv.MASTER_KEY,
    });
    expect(issues).toEqual(
      expect.arrayContaining([
        expect.stringMatching(/^KEY_PUBLISH_AHEAD:/),
        expect.stringMatching(/^KEY_RETIRE_AFTER:/),
        expect.stringMatching(/^MASTER_KEY_PREVIOUS:/),
      ]),
    );
  });

  it("validates bootstrap variables as a group", () => {
    expect(issuesOf({ ...devEnv, BOOTSTRAP_IDP_CLIENT_ID: "portvakt" })).toEqual(
      expect.arrayContaining([
        expect.stringMatching(/^BOOTSTRAP_IDP_ISSUER: required/),
        expect.stringMatching(/^BOOTSTRAP_ADMIN_SUBJECT:/),
      ]),
    );
    const config = loadConfig({
      ...devEnv,
      BOOTSTRAP_IDP_ISSUER: "http://localhost:4000/entra",
      BOOTSTRAP_IDP_CLIENT_ID: "portvakt",
      BOOTSTRAP_ADMIN_SUBJECT: "admin-oid",
    });
    expect(config.bootstrap.idp).toMatchObject({
      issuer: "http://localhost:4000/entra",
      clientId: "portvakt",
      scopes: ["openid", "profile", "email"],
      kind: "employee",
    });
    expect(config.bootstrap.adminSubject).toBe("admin-oid");
  });

  it("accepts a proper production config", () => {
    const config = loadConfig(productionEnv);
    expect(config.isProduction).toBe(true);
    expect(config.publicUrl).toBe("https://login.example.org");
  });

  it.each([
    ["missing PUBLIC_URL", { PUBLIC_URL: undefined }, "PUBLIC_URL"],
    ["http PUBLIC_URL", { PUBLIC_URL: "http://login.example.org" }, "PUBLIC_URL"],
    ["localhost PUBLIC_URL", { PUBLIC_URL: "https://localhost:3000" }, "PUBLIC_URL"],
    ["dev master key", { MASTER_KEY: DEV_MASTER_KEYS[0] }, "MASTER_KEY"],
    ["dev previous key", { MASTER_KEY_PREVIOUS: DEV_MASTER_KEYS[1] }, "MASTER_KEY_PREVIOUS"],
    ["all-zero master key", { MASTER_KEY: Buffer.alloc(32).toString("base64") }, "MASTER_KEY"],
    ["dev cookie keys", { COOKIE_KEYS: DEV_COOKIE_KEYS.join(",") }, "COOKIE_KEYS"],
    ["short cookie key", { COOKIE_KEYS: "sixteen-chars-ok-but-short" }, "COOKIE_KEYS"],
    [
      "dev database password",
      { DATABASE_URL: "postgres://portvakt_app:portvakt_app@db:5432/portvakt" },
      "DATABASE_URL",
    ],
    [
      "missing MIGRATION_DATABASE_URL",
      { MIGRATION_DATABASE_URL: undefined },
      "MIGRATION_DATABASE_URL",
    ],
    [
      "migrations and runtime sharing one role",
      { MIGRATION_DATABASE_URL: "postgres://portvakt_app:other-Pa55@db.internal:5432/portvakt" },
      "MIGRATION_DATABASE_URL",
    ],
    [
      "dev migration password",
      { MIGRATION_DATABASE_URL: "postgres://portvakt:portvakt@db.internal:5432/portvakt" },
      "MIGRATION_DATABASE_URL",
    ],
    [
      "http bootstrap issuer",
      {
        BOOTSTRAP_IDP_ISSUER: "http://idp.example.org",
        BOOTSTRAP_IDP_CLIENT_ID: "portvakt",
        BOOTSTRAP_ADMIN_SUBJECT: "x",
      },
      "BOOTSTRAP_IDP_ISSUER",
    ],
  ])("refuses to start in production with %s", (_label, override, variable) => {
    const env: NodeJS.ProcessEnv = { ...productionEnv, ...override };
    const issues = issuesOf(env);
    expect(issues.some((issue) => issue.startsWith(`${variable}:`))).toBe(true);
  });
});

describe("loadConfig: OIDC core settings", () => {
  it("defaults token lifetimes, intervals, proxy trust and start-up migrations", () => {
    const config = loadConfig(devEnv);
    expect(config.tokens).toEqual({
      accessTokenSeconds: 300,
      idTokenSeconds: 300,
      refreshTokenSeconds: 8 * 3600,
      sessionSeconds: 8 * 3600,
      interactionSeconds: 900,
    });
    expect(config.intervals).toEqual({
      providerReloadSeconds: 30,
      keyRotationCheckSeconds: 3600,
      payloadCleanupSeconds: 900,
      samlMetadataCheckSeconds: 300,
    });
    expect(config.shutdownTimeoutSeconds).toBe(15);
    expect(config.shutdownDrainDelaySeconds).toBe(5);
    expect(loadConfig({ ...devEnv, SHUTDOWN_DRAIN_DELAY: "0" }).shutdownDrainDelaySeconds).toBe(0);
    expect(config.trustProxy).toBe(false);
    expect(config.migrateOnStart).toBe(true);
    expect(loadConfig(productionEnv).migrateOnStart).toBe(false);
    expect(loadConfig({ ...productionEnv, MIGRATE_ON_START: "true" }).migrateOnStart).toBe(true);
    expect(loadConfig({ ...devEnv, MIGRATE_ON_START: "0" }).migrateOnStart).toBe(false);
  });

  it.each([
    ["true", true],
    ["false", false],
    ["0", false],
    ["2", 2],
    ["10", 10],
  ])("reads TRUST_PROXY=%s", (value, expected) => {
    expect(loadConfig({ ...devEnv, TRUST_PROXY: value }).trustProxy).toBe(expected);
  });

  it.each([
    [{ TRUST_PROXY: "loopback" }, "TRUST_PROXY"],
    [{ TRUST_PROXY: "1d" }, "TRUST_PROXY"],
    [{ TRUST_PROXY: "100" }, "TRUST_PROXY"],
    [{ PUBLIC_URL: "https://auth.example.org/portvakt" }, "PUBLIC_URL"],
    [{ NODE_ENV: "test", PUBLIC_URL: "https://login.example.org" }, "NODE_ENV"],
    [{ NODE_ENV: "test", PUBLIC_URL: "http://10.0.0.5:3000" }, "NODE_ENV"],
    [{ SESSION_TTL: "3d", REFRESH_TOKEN_TTL: "1h" }, "KEY_RETIRE_AFTER"],
    [{ SHUTDOWN_DRAIN_DELAY: "-1s" }, "SHUTDOWN_DRAIN_DELAY"],
    [{ MIGRATE_ON_START: "yes" }, "MIGRATE_ON_START"],
    [{ ACCESS_TOKEN_TTL: "0s" }, "ACCESS_TOKEN_TTL"],
    [{ ID_TOKEN_TTL: "3d" }, "KEY_RETIRE_AFTER"],
    [{ REFRESH_TOKEN_TTL: "9h" }, "REFRESH_TOKEN_TTL"],
    [{ PROVIDER_RELOAD_INTERVAL: "soon" }, "PROVIDER_RELOAD_INTERVAL"],
  ])("refuses %j", (override, variable) => {
    const issues = issuesOf({ ...devEnv, ...override });
    expect(issues.some((issue) => issue.startsWith(`${variable}:`))).toBe(true);
  });
});

describe("loadConfig: test mode", () => {
  it.each([
    "http://localhost:3000",
    "http://127.0.0.1:4000",
    "http://[::1]:4000",
    "https://portvakt.test",
    "http://app.localhost",
  ])("allows NODE_ENV=test with PUBLIC_URL %s", (url) => {
    expect(loadConfig({ ...devEnv, NODE_ENV: "test", PUBLIC_URL: url }).nodeEnv).toBe("test");
  });
});

describe("loadConfig: federation settings", () => {
  it("defaults the acr ranking to the Swedish eID levels and the upstream timeouts", () => {
    const config = loadConfig(devEnv);
    expect(config.acrRanking).toEqual([...DEFAULT_ACR_RANKING]);
    expect(config.federation).toEqual({
      upstreamTimeoutSeconds: 10,
      metadataTtlSeconds: 3600,
      failureCacheSeconds: 5,
      samlMetadataMaxAgeSeconds: 604800,
      allowPrivateUpstreamHosts: [],
      samlXmlMaxElements: 20000,
    });
    expect(config.loginUiDir).toBeUndefined();
  });

  it("reads an ordered ACR_RANKING and refuses duplicates", () => {
    expect(loadConfig({ ...devEnv, ACR_RANKING: "urn:low, urn:high" }).acrRanking).toEqual([
      "urn:low",
      "urn:high",
    ]);
    expect(issuesOf({ ...devEnv, ACR_RANKING: "urn:a,urn:a" })).toEqual([
      "ACR_RANKING: acr values must be unique",
    ]);
  });
});

describe("AUDIT_RETENTION", () => {
  it("defaults to 400 days and refuses less than 90 days", () => {
    expect(loadConfig(devEnv).audit.retentionSeconds).toBe(400 * 24 * 3600);
    expect(loadConfig({ ...devEnv, AUDIT_RETENTION: "90d" }).audit.retentionSeconds).toBe(
      90 * 24 * 3600,
    );
    expect(issuesOf({ ...devEnv, AUDIT_RETENTION: "89d" })).toContain(
      "AUDIT_RETENTION: must be at least 90 days",
    );
    expect(() => loadAuditPruneConfig({ ...devEnv, AUDIT_RETENTION: "30d" })).toThrow(
      /AUDIT_RETENTION: must be at least 90 days/,
    );
    const prune = loadAuditPruneConfig({
      ...devEnv,
      MIGRATION_DATABASE_URL: "postgres://owner:pw@localhost:5433/portvakt",
    });
    expect(prune).toMatchObject({
      retentionSeconds: 400 * 24 * 3600,
      database: { migrationUrl: "postgres://owner:pw@localhost:5433/portvakt" },
    });
  });
});

describe("DATABASE_POOL_MAX", () => {
  it("needs room for a transaction and a statement beside it", () => {
    expect(issuesOf({ ...devEnv, DATABASE_POOL_MAX: "1" }).join("\n")).toMatch(/DATABASE_POOL_MAX/);
    expect(loadConfig({ ...devEnv, DATABASE_POOL_MAX: "2" }).database.poolMax).toBe(2);
  });
});

describe("M8 hardening settings", () => {
  it("defaults rate limits, HTTP and database limits and metrics", () => {
    const config = loadConfig(devEnv);
    expect(config.rateLimits).toEqual({
      authorizeIp: { capacity: 120, periodSeconds: 60 },
      authorizeClient: { capacity: 3000, periodSeconds: 60 },
      interactionIp: { capacity: 60, periodSeconds: 60 },
      federationIp: { capacity: 120, periodSeconds: 60 },
      tokenIp: { capacity: 600, periodSeconds: 60 },
      tokenClient: { capacity: 1200, periodSeconds: 60 },
      adminApi: { capacity: 600, periodSeconds: 60 },
    });
    expect(config.http).toEqual({
      requestTimeoutSeconds: 30,
      headersTimeoutSeconds: 20,
      keepAliveTimeoutSeconds: 65,
      maxUrlLength: 8192,
      maxHeaderBytes: 16_384,
    });
    expect(config.database).toMatchObject({
      statementTimeoutSeconds: 15,
      idleInTransactionTimeoutSeconds: 60,
      connectionTimeoutSeconds: 5,
    });
    expect(config.metrics).toEqual({
      enabled: true,
      port: undefined,
      host: "0.0.0.0",
      token: undefined,
    });
    expect(config.warnings).toEqual([]);
  });

  it("parses rate limits, turns them off, and refuses malformed ones", () => {
    const config = loadConfig({
      ...devEnv,
      RATE_LIMIT_TOKEN_IP: "10/30s",
      RATE_LIMIT_ADMIN_API: "off",
    });
    expect(config.rateLimits.tokenIp).toEqual({ capacity: 10, periodSeconds: 30 });
    expect(config.rateLimits.adminApi).toBeNull();
    expect(issuesOf({ ...devEnv, RATE_LIMIT_INTERACTION_IP: "lots" }).join("\n")).toMatch(
      /^RATE_LIMIT_INTERACTION_IP: must be <count>\/<period>/,
    );
  });

  it("refuses inconsistent HTTP timeouts and a metrics port equal to PORT", () => {
    expect(
      issuesOf({ ...devEnv, HTTP_HEADERS_TIMEOUT: "60s", HTTP_REQUEST_TIMEOUT: "30s" }),
    ).toContain("HTTP_HEADERS_TIMEOUT: must not exceed HTTP_REQUEST_TIMEOUT");
    expect(issuesOf({ ...devEnv, PORT: "3000", METRICS_PORT: "3000" })).toContain(
      "METRICS_PORT: must differ from PORT",
    );
  });

  it.each([
    [
      "unprotected metrics on the main port",
      { METRICS_TOKEN: undefined },
      "METRICS_TOKEN: required in production",
    ],
    ["a short metrics token", { METRICS_TOKEN: "short" }, "METRICS_TOKEN: at least 32"],
    [
      "a cookie key that is the master key",
      { MASTER_KEY: randomBytes(32).toString("base64") },
      "COOKIE_KEYS: reuses the value of MASTER_KEY",
    ],
    [
      "the metrics token reused as the admin client secret",
      { ADMIN_CLIENT_SECRET: "the-same-secret-twice-0123456789abcdefgh" },
      "METRICS_TOKEN: reuses the value of ADMIN_CLIENT_SECRET",
    ],
    [
      "one database password for both roles",
      {
        DATABASE_URL: "postgres://portvakt_app:shared-Pa55w0rd@db.internal/portvakt",
        MIGRATION_DATABASE_URL: "postgres://portvakt_owner:shared-Pa55w0rd@db.internal/portvakt",
      },
      "MIGRATION_DATABASE_URL: reuses the value of DATABASE_URL",
    ],
    [
      "a repeated cookie key",
      {
        COOKIE_KEYS:
          "one-cookie-key-0123456789abcdef0123456,one-cookie-key-0123456789abcdef0123456",
      },
      "COOKIE_KEYS: the same value appears twice",
    ],
    [
      "a mock IdP bootstrap issuer",
      {
        BOOTSTRAP_IDP_ISSUER: "https://localhost:4500/entra",
        BOOTSTRAP_IDP_CLIENT_ID: "portvakt",
        BOOTSTRAP_ADMIN_SUBJECT: "x",
        ADMIN_PUBLIC_URL: "https://admin.example.org",
        ADMIN_CLIENT_SECRET: "a-production-admin-client-secret-0123456789",
      },
      "BOOTSTRAP_IDP_ISSUER: must not point at a local or .test host",
    ],
    [
      "a short manual publish-ahead",
      { KEY_MANUAL_PUBLISH_AHEAD: "1m" },
      "KEY_MANUAL_PUBLISH_AHEAD: at least 390s in production",
    ],
  ])("refuses production with %s", (_label, overrides, message) => {
    const override = overrides as Readonly<Record<string, string | undefined>>;
    const env: NodeJS.ProcessEnv = {
      ...productionEnv,
      ...(override.MASTER_KEY === undefined
        ? {}
        : { COOKIE_KEYS: `${override.MASTER_KEY},${randomBytes(32).toString("base64url")}` }),
      ...(override.ADMIN_CLIENT_SECRET === "the-same-secret-twice-0123456789abcdefgh"
        ? { METRICS_TOKEN: override.ADMIN_CLIENT_SECRET }
        : {}),
      ...override,
    };
    const issues = issuesOf(env);
    expect(issues.some((issue) => issue.startsWith(message))).toBe(true);
    // Names only, never values.
    for (const value of Object.values(override)) {
      if (typeof value === "string" && value.length > 8) {
        expect(issues.join("\n")).not.toContain(value);
      }
    }
  });

  it("accepts production metrics on a port of their own (with a warning without a token)", () => {
    const config = loadConfig({ ...productionEnv, METRICS_TOKEN: undefined, METRICS_PORT: "9464" });
    expect(config.metrics).toMatchObject({ enabled: true, port: 9464, token: undefined });
    expect(config.warnings.join("\n")).toMatch(/^METRICS_TOKEN: not set/m);
    expect(() =>
      loadConfig({ ...productionEnv, METRICS_TOKEN: undefined, METRICS_ENABLED: "false" }),
    ).not.toThrow();
  });

  it("warns about trusting every proxy hop, verbose logs and rate limits turned off", () => {
    const config = loadConfig({
      ...productionEnv,
      TRUST_PROXY: "true",
      LOG_LEVEL: "debug",
      RATE_LIMIT_TOKEN_IP: "off",
    });
    expect(config.warnings).toEqual(
      expect.arrayContaining([
        expect.stringMatching(/^TRUST_PROXY: true trusts every X-Forwarded-For hop/),
        expect.stringMatching(/^LOG_LEVEL: debug and trace are verbose/),
        expect.stringMatching(/^RATE_LIMIT_TOKEN_IP: off/),
      ]),
    );
    expect(loadConfig({ ...devEnv, TRUST_PROXY: "true" }).warnings).toEqual([]);
  });

  it("reports every problem and warning without throwing (config:check)", () => {
    expect(checkConfig(productionEnv)).toEqual({
      ok: true,
      nodeEnv: "production",
      issues: [],
      warnings: [],
    });
    const report = checkConfig({
      ...productionEnv,
      PUBLIC_URL: "http://login.example.org",
      MASTER_KEY: DEV_MASTER_KEYS[0],
      TRUST_PROXY: "true",
    });
    expect(report.ok).toBe(false);
    expect(report.issues).toEqual(
      expect.arrayContaining([
        "PUBLIC_URL: must use https in production",
        "MASTER_KEY: the development key from .env.example is not allowed in production",
      ]),
    );
    expect(report.warnings.join("\n")).toMatch(/TRUST_PROXY/);
    expect(checkConfig({}).issues).toContain("DATABASE_URL: required");
  });
});

describe("config:check report", () => {
  it("lists problems and warnings by name, including the missing login UI build", () => {
    const ok = report({ ...productionEnv, LOGIN_UI_DIR: testLoginUiDir() });
    expect(ok.ok).toBe(true);
    expect(ok.text).toContain("No problems");
    const bad = report({
      ...productionEnv,
      LOGIN_UI_DIR: "/nonexistent/login-ui",
      TRUST_PROXY: "true",
      ADMIN_CLIENT_SECRET: productionEnv.METRICS_TOKEN,
    });
    expect(bad.ok).toBe(false);
    expect(bad.text).toMatch(/^ {2}- LOGIN_UI_DIR: the login UI build/m);
    expect(bad.text).toMatch(/^ {2}- METRICS_TOKEN: reuses the value of ADMIN_CLIENT_SECRET/m);
    expect(bad.text).toMatch(/1 warning\(s\):\n {2}- TRUST_PROXY/);
    // Never a value.
    expect(bad.text).not.toContain(productionEnv.METRICS_TOKEN);
    expect(bad.text).not.toContain(productionEnv.MASTER_KEY);
  });
});
