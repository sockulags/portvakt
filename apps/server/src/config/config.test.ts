import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { parseEnv } from "node:util";
import { describe, expect, it } from "vitest";
import { parseDurationSeconds } from "./duration.js";
import {
  ConfigError,
  DEFAULT_ACR_RANKING,
  DEV_COOKIE_KEYS,
  DEV_MASTER_KEYS,
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
