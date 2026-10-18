import { z } from "zod";
import { LOGIN_METHOD_KINDS, type LoginMethodKind } from "../domain/login-method.js";
import { parseDurationSeconds } from "./duration.js";

/**
 * Values that ship in `.env.example` (or are otherwise well known). They are fine for
 * development and tests, and refused when NODE_ENV=production.
 */
export const DEV_MASTER_KEYS: readonly string[] = [
  "ZGV2LW9ubHktbWFzdGVyLWtleS1kby1ub3QtdXNlISE=",
  "ZGV2LW9ubHktcHJldmlvdXMta2V5LWRvLW5vdC11c2U=",
];
export const DEV_COOKIE_KEYS: readonly string[] = [
  "dev-only-cookie-key-1-do-not-use-in-production",
  "dev-only-cookie-key-2-do-not-use-in-production",
];
/** Database credentials used by deploy/docker-compose.dev.yml. */
const DEV_DATABASE_PASSWORDS: readonly string[] = [
  "portvakt",
  "portvakt_app",
  "postgres",
  "password",
];

/** Swedish eID Framework levels of assurance, lowest first (the default ACR_RANKING). */
export const DEFAULT_ACR_RANKING: readonly string[] = [
  "http://id.elegnamnden.se/loa/1.0/loa2",
  "http://id.elegnamnden.se/loa/1.0/loa3",
  "http://id.elegnamnden.se/loa/1.0/loa4",
];

export const LOG_LEVELS = ["fatal", "error", "warn", "info", "debug", "trace", "silent"] as const;
export type LogLevel = (typeof LOG_LEVELS)[number];

export const NODE_ENVS = ["development", "test", "production"] as const;
export type NodeEnv = (typeof NODE_ENVS)[number];

export interface MasterKeys {
  /** Key used for all new encryptions. */
  readonly current: Buffer;
  /** Older keys, accepted for decryption only (rotation). */
  readonly previous: readonly Buffer[];
}

export interface BootstrapIdpConfig {
  readonly issuer: string;
  readonly clientId: string;
  readonly clientSecret: string | undefined;
  readonly scopes: readonly string[];
  readonly kind: LoginMethodKind;
  readonly displayName: string;
  readonly acr: string;
}

/** Express `trust proxy`: `false`, `true` (trust every hop) or the number of trusted hops. */
export type TrustProxy = boolean | number;

export interface TokenLifetimes {
  /** Access tokens (JWT, per-app `aud`), also for client_credentials. */
  readonly accessTokenSeconds: number;
  readonly idTokenSeconds: number;
  /** Default refresh token lifetime; never beyond the broker session (session policies, M3). */
  readonly refreshTokenSeconds: number;
  /** Default absolute broker session lifetime (login method session policies refine it, M3). */
  readonly sessionSeconds: number;
  /** How long a login interaction may take. */
  readonly interactionSeconds: number;
}

export interface Config {
  readonly nodeEnv: NodeEnv;
  readonly isProduction: boolean;
  readonly port: number;
  /** Proxy hops trusted for X-Forwarded-* (client IP, protocol, host). */
  readonly trustProxy: TrustProxy;
  /** Apply pending migrations at start-up (default: on outside production, off in production). */
  readonly migrateOnStart: boolean;
  readonly tokens: TokenLifetimes;
  readonly intervals: {
    /** Periodic provider/key reload, the fallback when a change notification was missed. */
    readonly providerReloadSeconds: number;
    /** How often the key rotation job checks whether a transition is due. */
    readonly keyRotationCheckSeconds: number;
    /** How often expired oidc-provider rows are deleted. */
    readonly payloadCleanupSeconds: number;
  };
  /** Graceful shutdown: how long in-flight requests may take before connections are closed. */
  readonly shutdownTimeoutSeconds: number;
  /**
   * Graceful shutdown: how long readiness reports 503 before the listener closes, so load
   * balancers stop routing new requests first (0 in tests).
   */
  readonly shutdownDrainDelaySeconds: number;
  /** Origin and optional path prefix, without a trailing slash. Issuers are `${publicUrl}/t/{slug}`. */
  readonly publicUrl: string;
  readonly database: DatabaseConfig;
  readonly masterKeys: MasterKeys;
  readonly cookieKeys: readonly string[];
  readonly logLevel: LogLevel;
  readonly keyRotation: {
    /** How often a new signing key is introduced. */
    readonly intervalSeconds: number;
    /** How long a `next` key is published in JWKS before it becomes `active`. */
    readonly publishAheadSeconds: number;
    /** How long a `retiring` key stays in JWKS; must cover the longest token lifetime. */
    readonly retireAfterSeconds: number;
  };
  readonly bootstrap: {
    readonly idp: BootstrapIdpConfig | undefined;
    readonly adminSubject: string | undefined;
  };
  /**
   * Assurance levels from lowest to highest (ACR_RANKING). A login method whose asserted acr
   * ranks below a requested `acr_values` entry is not offered; unranked values only match
   * themselves.
   */
  readonly acrRanking: readonly string[];
  readonly federation: {
    /** Timeout of every request to an upstream IdP (discovery, token, userinfo, JWKS). */
    readonly upstreamTimeoutSeconds: number;
    /** How long discovered upstream metadata is reused before it is fetched again. */
    readonly metadataTtlSeconds: number;
    /** A failed discovery is not retried for this long (0: always retried). */
    readonly failureCacheSeconds: number;
  };
  /** Directory of the built login UI (apps/login/dist); `undefined` uses the default location. */
  readonly loginUiDir: string | undefined;
}

export interface DatabaseConfig {
  /** Runtime connection (restricted role: DML only, audit_events SELECT/INSERT). */
  readonly url: string;
  /** Owner connection for migrations. Falls back to `url` outside production only. */
  readonly migrationUrl: string;
  /** Role name of `url`, which the migration runner grants runtime privileges to. */
  readonly runtimeRole: string;
  /** False when both URLs use the same role (development fallback): no grants are applied. */
  readonly separateRoles: boolean;
  readonly poolMax: number;
}

export class ConfigError extends Error {
  readonly issues: readonly string[];

  constructor(issues: readonly string[]) {
    super(`Invalid configuration:\n${issues.map((issue) => `  - ${issue}`).join("\n")}`);
    this.name = "ConfigError";
    this.issues = issues;
  }
}

const emptyToUndefined = (value: unknown): unknown =>
  typeof value === "string" && value.trim() === "" ? undefined : value;

const optionalString = z.preprocess(emptyToUndefined, z.string().trim().optional());

const masterKey = z
  .string()
  .trim()
  .transform((value, ctx) => {
    const isBase64 = /^[A-Za-z0-9+/]+={0,2}$/.test(value) || /^[A-Za-z0-9_-]+$/.test(value);
    const bytes = isBase64 ? Buffer.from(value, "base64") : Buffer.alloc(0);
    if (bytes.length !== 32) {
      ctx.addIssue({ code: "custom", message: "must be 32 bytes, base64 encoded" });
      return z.NEVER;
    }
    return bytes;
  });

const commaList = (value: string): string[] =>
  value
    .split(",")
    .map((item) => item.trim())
    .filter((item) => item.length > 0);

const duration = (fallback: string, options: { readonly allowZero?: boolean } = {}) =>
  z.preprocess(emptyToUndefined, z.string().default(fallback)).transform((value, ctx) => {
    if (options.allowZero === true && /^0[smhdw]?$/i.test(value.trim())) return 0;
    const seconds = parseDurationSeconds(value);
    if (seconds === undefined) {
      ctx.addIssue({
        code: "custom",
        message: "must be a positive duration such as 90d, 36h, 1h30m or 45s",
      });
      return z.NEVER;
    }
    return seconds;
  });

const trustProxy = z.preprocess(
  emptyToUndefined,
  z
    .string()
    .trim()
    .toLowerCase()
    .default("false")
    .transform((value, ctx): TrustProxy => {
      if (value === "false" || value === "0") return false;
      if (value === "true") return true;
      if (/^[1-9][0-9]?$/.test(value)) return Number(value);
      ctx.addIssue({ code: "custom", message: "must be false, true or a number of proxy hops" });
      return z.NEVER;
    }),
);

const booleanFlag = z.preprocess(
  emptyToUndefined,
  z
    .enum(["true", "false", "1", "0"])
    .optional()
    .transform((value) => (value === undefined ? undefined : value === "true" || value === "1")),
);

const envSchema = z.object({
  NODE_ENV: z.preprocess(emptyToUndefined, z.enum(NODE_ENVS).default("development")),
  PORT: z.preprocess(emptyToUndefined, z.coerce.number().int().min(1).max(65535).default(3000)),
  TRUST_PROXY: trustProxy,
  MIGRATE_ON_START: booleanFlag,
  ACCESS_TOKEN_TTL: duration("5m"),
  ID_TOKEN_TTL: duration("5m"),
  REFRESH_TOKEN_TTL: duration("8h"),
  SESSION_TTL: duration("8h"),
  INTERACTION_TTL: duration("15m"),
  PROVIDER_RELOAD_INTERVAL: duration("30s"),
  KEY_ROTATION_CHECK_INTERVAL: duration("1h"),
  PAYLOAD_CLEANUP_INTERVAL: duration("15m"),
  SHUTDOWN_TIMEOUT: duration("15s"),
  SHUTDOWN_DRAIN_DELAY: duration("5s", { allowZero: true }),
  PUBLIC_URL: optionalString,
  DATABASE_URL: z.preprocess(emptyToUndefined, z.string().trim()),
  MIGRATION_DATABASE_URL: optionalString,
  DATABASE_POOL_MAX: z.preprocess(
    emptyToUndefined,
    z.coerce.number().int().min(1).max(200).default(10),
  ),
  MASTER_KEY: z.preprocess(emptyToUndefined, masterKey),
  MASTER_KEY_PREVIOUS: z.preprocess(
    emptyToUndefined,
    z
      .string()
      .optional()
      .transform((value) => (value === undefined ? [] : commaList(value)))
      .pipe(z.array(masterKey)),
  ),
  COOKIE_KEYS: z.preprocess(
    emptyToUndefined,
    z
      .string()
      .transform(commaList)
      .pipe(z.array(z.string().min(16, "each key must be at least 16 characters")).min(1)),
  ),
  LOG_LEVEL: z.preprocess(emptyToUndefined, z.enum(LOG_LEVELS).default("info")),
  KEY_ROTATION_INTERVAL: duration("90d"),
  KEY_PUBLISH_AHEAD: duration("2d"),
  KEY_RETIRE_AFTER: duration("2d"),
  BOOTSTRAP_IDP_ISSUER: optionalString,
  BOOTSTRAP_IDP_CLIENT_ID: optionalString,
  BOOTSTRAP_IDP_CLIENT_SECRET: optionalString,
  BOOTSTRAP_IDP_SCOPES: optionalString,
  BOOTSTRAP_IDP_KIND: z.preprocess(emptyToUndefined, z.enum(LOGIN_METHOD_KINDS).optional()),
  BOOTSTRAP_IDP_DISPLAY_NAME: optionalString,
  BOOTSTRAP_IDP_ACR: optionalString,
  BOOTSTRAP_ADMIN_SUBJECT: optionalString,
  ACR_RANKING: z.preprocess(
    emptyToUndefined,
    z
      .string()
      .default(DEFAULT_ACR_RANKING.join(","))
      .transform(commaList)
      .pipe(
        z
          .array(z.string().min(1).max(255).regex(/^\S+$/, "acr values must not contain spaces"))
          .min(1)
          .refine((values) => new Set(values).size === values.length, "acr values must be unique"),
      ),
  ),
  UPSTREAM_TIMEOUT: duration("10s"),
  UPSTREAM_METADATA_TTL: duration("1h"),
  UPSTREAM_FAILURE_CACHE: duration("5s", { allowZero: true }),
  LOGIN_UI_DIR: optionalString,
});

type Env = z.infer<typeof envSchema>;

const LOCAL_HOSTNAMES = new Set(["localhost", "127.0.0.1", "[::1]", "0.0.0.0"]);

function isLocalHostname(hostname: string): boolean {
  return (
    LOCAL_HOSTNAMES.has(hostname) || hostname.endsWith(".localhost") || hostname.endsWith(".test")
  );
}

/** Hosts a test-mode server may use: loopback addresses and the reserved test domains. */
function isLoopbackOrTestHost(hostname: string): boolean {
  return (
    hostname === "localhost" ||
    hostname === "127.0.0.1" ||
    hostname === "[::1]" ||
    hostname.endsWith(".localhost") ||
    hostname.endsWith(".test")
  );
}

function parseHttpUrl(value: string, name: string, issues: string[]): URL | undefined {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    issues.push(`${name}: must be an absolute URL`);
    return undefined;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    issues.push(`${name}: must use http or https`);
    return undefined;
  }
  if (url.search !== "" || url.hash !== "" || url.username !== "" || url.password !== "") {
    issues.push(`${name}: must not contain credentials, a query or a fragment`);
    return undefined;
  }
  return url;
}

function isLowEntropyKey(key: Buffer): boolean {
  return new Set(key).size < 8;
}

/**
 * Checks that only matter in production: refuses dev defaults and insecure settings.
 * Each issue names the variable, never its value.
 */
function productionIssues(env: Env, publicUrl: URL | undefined): string[] {
  const issues: string[] = [];

  if (env.PUBLIC_URL === undefined) {
    issues.push("PUBLIC_URL: required in production");
  } else if (publicUrl !== undefined) {
    if (publicUrl.protocol !== "https:") issues.push("PUBLIC_URL: must use https in production");
    if (isLocalHostname(publicUrl.hostname)) {
      issues.push("PUBLIC_URL: must not point at a local or .test host in production");
    }
  }

  const masterKeys = [
    { name: "MASTER_KEY", key: env.MASTER_KEY },
    ...env.MASTER_KEY_PREVIOUS.map((key) => ({ name: "MASTER_KEY_PREVIOUS", key })),
  ];
  for (const { name, key } of masterKeys) {
    if (DEV_MASTER_KEYS.includes(key.toString("base64"))) {
      issues.push(`${name}: the development key from .env.example is not allowed in production`);
    } else if (isLowEntropyKey(key)) {
      issues.push(`${name}: looks like a placeholder (too few distinct bytes); generate a key`);
    }
  }

  for (const key of env.COOKIE_KEYS) {
    if (DEV_COOKIE_KEYS.includes(key)) {
      issues.push("COOKIE_KEYS: development keys from .env.example are not allowed in production");
      break;
    }
  }
  if (env.COOKIE_KEYS.some((key) => key.length < 32)) {
    issues.push("COOKIE_KEYS: each key must be at least 32 characters in production");
  }

  if (env.BOOTSTRAP_IDP_ISSUER !== undefined && !env.BOOTSTRAP_IDP_ISSUER.startsWith("https://")) {
    issues.push("BOOTSTRAP_IDP_ISSUER: must use https in production");
  }

  return issues;
}

function bootstrapConfig(env: Env, issues: string[]): Config["bootstrap"] {
  const idpVariables = [
    env.BOOTSTRAP_IDP_ISSUER,
    env.BOOTSTRAP_IDP_CLIENT_ID,
    env.BOOTSTRAP_IDP_CLIENT_SECRET,
    env.BOOTSTRAP_IDP_SCOPES,
    env.BOOTSTRAP_IDP_KIND,
    env.BOOTSTRAP_IDP_DISPLAY_NAME,
    env.BOOTSTRAP_IDP_ACR,
  ];
  if (idpVariables.every((value) => value === undefined)) {
    return { idp: undefined, adminSubject: env.BOOTSTRAP_ADMIN_SUBJECT };
  }

  if (env.BOOTSTRAP_IDP_ISSUER === undefined) issues.push("BOOTSTRAP_IDP_ISSUER: required");
  if (env.BOOTSTRAP_IDP_CLIENT_ID === undefined) issues.push("BOOTSTRAP_IDP_CLIENT_ID: required");
  if (env.BOOTSTRAP_ADMIN_SUBJECT === undefined) {
    issues.push("BOOTSTRAP_ADMIN_SUBJECT: required when BOOTSTRAP_IDP_* is set");
  }
  if (env.BOOTSTRAP_IDP_ISSUER !== undefined) {
    parseHttpUrl(env.BOOTSTRAP_IDP_ISSUER, "BOOTSTRAP_IDP_ISSUER", issues);
  }
  const scopes = commaOrSpaceList(env.BOOTSTRAP_IDP_SCOPES ?? "openid profile email");
  if (!scopes.includes("openid")) issues.push("BOOTSTRAP_IDP_SCOPES: must include openid");

  if (env.BOOTSTRAP_IDP_ISSUER === undefined || env.BOOTSTRAP_IDP_CLIENT_ID === undefined) {
    return { idp: undefined, adminSubject: env.BOOTSTRAP_ADMIN_SUBJECT };
  }
  return {
    idp: {
      issuer: env.BOOTSTRAP_IDP_ISSUER,
      clientId: env.BOOTSTRAP_IDP_CLIENT_ID,
      clientSecret: env.BOOTSTRAP_IDP_CLIENT_SECRET,
      scopes,
      kind: env.BOOTSTRAP_IDP_KIND ?? "employee",
      displayName: env.BOOTSTRAP_IDP_DISPLAY_NAME ?? "Administrator sign-in",
      acr: env.BOOTSTRAP_IDP_ACR ?? "urn:portvakt:acr:employee",
    },
    adminSubject: env.BOOTSTRAP_ADMIN_SUBJECT,
  };
}

function commaOrSpaceList(value: string): string[] {
  return value.split(/[\s,]+/).filter((item) => item.length > 0);
}

function formatZodIssues(error: z.ZodError): string[] {
  return error.issues.map((issue) => {
    const name = issue.path.join(".") || "environment";
    const message = issue.code === "invalid_type" ? "required" : issue.message;
    return `${name}: ${message}`;
  });
}

/**
 * Loads and validates configuration from the environment. Throws {@link ConfigError} listing
 * every problem (variable names only, never values).
 */
export function loadConfig(source: NodeJS.ProcessEnv = process.env): Config {
  const parsed = envSchema.safeParse(source);
  if (!parsed.success) throw new ConfigError(formatZodIssues(parsed.error));
  const env = parsed.data;
  const issues: string[] = [];
  const isProduction = env.NODE_ENV === "production";

  const publicUrlValue =
    env.PUBLIC_URL ?? (isProduction ? undefined : `http://localhost:${env.PORT}`);
  const publicUrl =
    publicUrlValue === undefined ? undefined : parseHttpUrl(publicUrlValue, "PUBLIC_URL", issues);

  const database = resolveDatabase(env, issues);

  if (env.KEY_PUBLISH_AHEAD >= env.KEY_ROTATION_INTERVAL) {
    issues.push("KEY_PUBLISH_AHEAD: must be shorter than KEY_ROTATION_INTERVAL");
  }
  if (env.KEY_RETIRE_AFTER >= env.KEY_ROTATION_INTERVAL) {
    issues.push("KEY_RETIRE_AFTER: must be shorter than KEY_ROTATION_INTERVAL");
  }
  const longestSignedToken = Math.max(env.ACCESS_TOKEN_TTL, env.ID_TOKEN_TTL);
  if (env.KEY_RETIRE_AFTER < longestSignedToken) {
    issues.push(
      "KEY_RETIRE_AFTER: must be at least the longest signed token lifetime (ACCESS_TOKEN_TTL, ID_TOKEN_TTL)",
    );
  }
  // ID tokens come back as id_token_hint (logout) for as long as the broker session lasts, so a
  // key must stay published for the longest session too. M3 caps login method maxAge to it.
  if (env.KEY_RETIRE_AFTER < env.SESSION_TTL) {
    issues.push("KEY_RETIRE_AFTER: must be at least SESSION_TTL (the longest broker session)");
  }
  if (env.REFRESH_TOKEN_TTL > env.SESSION_TTL) {
    issues.push("REFRESH_TOKEN_TTL: must not exceed SESSION_TTL");
  }
  const allMasterKeys = [env.MASTER_KEY, ...env.MASTER_KEY_PREVIOUS];
  const distinct = new Set(allMasterKeys.map((key) => key.toString("base64")));
  if (distinct.size !== allMasterKeys.length) {
    issues.push("MASTER_KEY_PREVIOUS: must not repeat MASTER_KEY or another previous key");
  }

  if (publicUrl !== undefined && publicUrl.pathname !== "/") {
    issues.push("PUBLIC_URL: must be an origin without a path (issuers are {PUBLIC_URL}/t/{slug})");
  }
  if (
    env.NODE_ENV === "test" &&
    publicUrl !== undefined &&
    !isLoopbackOrTestHost(publicUrl.hostname)
  ) {
    // NODE_ENV=test mounts a login route that needs no authentication: never on a real host.
    issues.push(
      "NODE_ENV: test mode is only allowed with a loopback, .localhost or .test PUBLIC_URL",
    );
  }

  const bootstrap = bootstrapConfig(env, issues);
  if (isProduction) issues.push(...productionIssues(env, publicUrl));
  if (issues.length > 0 || publicUrl === undefined || database === undefined) {
    throw new ConfigError(issues);
  }

  return {
    nodeEnv: env.NODE_ENV,
    isProduction,
    port: env.PORT,
    trustProxy: env.TRUST_PROXY,
    migrateOnStart: env.MIGRATE_ON_START ?? !isProduction,
    tokens: {
      accessTokenSeconds: env.ACCESS_TOKEN_TTL,
      idTokenSeconds: env.ID_TOKEN_TTL,
      refreshTokenSeconds: env.REFRESH_TOKEN_TTL,
      sessionSeconds: env.SESSION_TTL,
      interactionSeconds: env.INTERACTION_TTL,
    },
    intervals: {
      providerReloadSeconds: env.PROVIDER_RELOAD_INTERVAL,
      keyRotationCheckSeconds: env.KEY_ROTATION_CHECK_INTERVAL,
      payloadCleanupSeconds: env.PAYLOAD_CLEANUP_INTERVAL,
    },
    shutdownTimeoutSeconds: env.SHUTDOWN_TIMEOUT,
    shutdownDrainDelaySeconds: env.SHUTDOWN_DRAIN_DELAY,
    publicUrl: publicUrl.href.replace(/\/+$/, ""),
    database,
    masterKeys: { current: env.MASTER_KEY, previous: env.MASTER_KEY_PREVIOUS },
    cookieKeys: env.COOKIE_KEYS,
    logLevel: env.LOG_LEVEL,
    keyRotation: {
      intervalSeconds: env.KEY_ROTATION_INTERVAL,
      publishAheadSeconds: env.KEY_PUBLISH_AHEAD,
      retireAfterSeconds: env.KEY_RETIRE_AFTER,
    },
    bootstrap,
    acrRanking: env.ACR_RANKING,
    federation: {
      upstreamTimeoutSeconds: env.UPSTREAM_TIMEOUT,
      metadataTtlSeconds: env.UPSTREAM_METADATA_TTL,
      failureCacheSeconds: env.UPSTREAM_FAILURE_CACHE,
    },
    loginUiDir: env.LOGIN_UI_DIR,
  };
}

function parseDatabaseUrl(name: string, value: string, issues: string[]): URL | undefined {
  try {
    const url = new URL(value);
    if (url.protocol !== "postgres:" && url.protocol !== "postgresql:") {
      issues.push(`${name}: must be a postgres:// or postgresql:// URL`);
      return undefined;
    }
    return url;
  } catch {
    issues.push(`${name}: must be a postgres:// URL`);
    return undefined;
  }
}

type DatabaseEnv = Pick<
  Env,
  "NODE_ENV" | "DATABASE_URL" | "MIGRATION_DATABASE_URL" | "DATABASE_POOL_MAX"
>;

/**
 * Two roles: the app connects with DATABASE_URL (restricted runtime role), migrations with
 * MIGRATION_DATABASE_URL (owner). Outside production MIGRATION_DATABASE_URL defaults to
 * DATABASE_URL. In production it is required, must use another role, and neither may use a
 * development password.
 */
function resolveDatabase(env: DatabaseEnv, issues: string[]): DatabaseConfig | undefined {
  const isProduction = env.NODE_ENV === "production";
  const runtime = parseDatabaseUrl("DATABASE_URL", env.DATABASE_URL, issues);
  if (isProduction && env.MIGRATION_DATABASE_URL === undefined) {
    issues.push("MIGRATION_DATABASE_URL: required in production (the owner role for migrations)");
  }
  const migrationValue = env.MIGRATION_DATABASE_URL ?? env.DATABASE_URL;
  const migration = parseDatabaseUrl("MIGRATION_DATABASE_URL", migrationValue, issues);
  if (runtime === undefined || migration === undefined) return undefined;

  const runtimeRole = decodeURIComponent(runtime.username);
  const migrationRole = decodeURIComponent(migration.username);
  if (isProduction) {
    if (runtimeRole === "") issues.push("DATABASE_URL: must name the runtime role");
    if (runtimeRole !== "" && runtimeRole === migrationRole) {
      issues.push("MIGRATION_DATABASE_URL: must use another role than DATABASE_URL in production");
    }
    for (const [name, url] of [
      ["DATABASE_URL", runtime],
      ["MIGRATION_DATABASE_URL", migration],
    ] as const) {
      if (DEV_DATABASE_PASSWORDS.includes(decodeURIComponent(url.password))) {
        issues.push(`${name}: uses a development password`);
      }
    }
  }
  return {
    url: env.DATABASE_URL,
    migrationUrl: migrationValue,
    runtimeRole,
    separateRoles: runtimeRole !== "" && runtimeRole !== migrationRole,
    poolMax: env.DATABASE_POOL_MAX,
  };
}

/**
 * Narrow loader for tools that only need the database (the migration CLI), so a migration job
 * does not need MASTER_KEY or cookie keys.
 */
export function loadDatabaseConfig(source: NodeJS.ProcessEnv = process.env): DatabaseConfig {
  const schema = envSchema.pick({
    NODE_ENV: true,
    DATABASE_URL: true,
    MIGRATION_DATABASE_URL: true,
    DATABASE_POOL_MAX: true,
  });
  const parsed = schema.safeParse(source);
  if (!parsed.success) throw new ConfigError(formatZodIssues(parsed.error));
  const issues: string[] = [];
  const database = resolveDatabase(parsed.data, issues);
  if (issues.length > 0 || database === undefined) throw new ConfigError(issues);
  return database;
}
