import { z } from "zod";
import {
  LOGIN_METHOD_KINDS,
  PIN_REPRESENTATION_MIN_ACR,
  type LoginMethodKind,
} from "../domain/login-method.js";
import { parseRateLimit, type RateLimit } from "@portvakt/http-kit";
import { parsePersonnummer } from "../domain/personnummer.js";
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
/** The admin portal's development client secret (.env.example); refused in production. */
export const DEV_ADMIN_CLIENT_SECRET = "dev-only-admin-client-secret-0123456789abcdef";
/** Where the admin portal runs outside production unless ADMIN_PUBLIC_URL says otherwise. */
export const DEFAULT_DEV_ADMIN_PUBLIC_URL = "http://localhost:3400";
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

/** AUDIT_RETENTION may not be shorter (the database function refuses a later cutoff too). */
export const MIN_AUDIT_RETENTION_SECONDS = 90 * 24 * 3600;
/** Default AUDIT_RETENTION: 400 days, a year plus a margin for annual reviews. */
export const DEFAULT_AUDIT_RETENTION = "400d";

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
  /** Upstream claims (BOOTSTRAP_IDP_*_CLAIM); `subject` defaults to `sub`. */
  readonly claims: {
    readonly subject: string;
    readonly name: string | undefined;
    readonly email: string | undefined;
    readonly pin: string | undefined;
    readonly acr: string | undefined;
  };
  /** Map the email claim without `email_verified` (Entra ID work accounts). */
  readonly trustEmail: boolean;
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

/**
 * What the SDKs cache by default (both SDKs: `jwks.cacheMaxAgeSeconds` 5 minutes, unknown-kid
 * refetches at most every 30 s) plus the `Cache-Control` max-age of the JWKS endpoint (60 s). A
 * manually rotated key is published at least this long before it signs, so every verifier with
 * the default cache has fetched it by then.
 */
export const SDK_JWKS_CACHE_SECONDS = 300;
export const SDK_JWKS_COOLDOWN_SECONDS = 30;
export const JWKS_HTTP_MAX_AGE_SECONDS = 60;
export const MIN_MANUAL_PUBLISH_AHEAD_SECONDS =
  SDK_JWKS_CACHE_SECONDS + SDK_JWKS_COOLDOWN_SECONDS + JWKS_HTTP_MAX_AGE_SECONDS;

/**
 * Rate limits, per replica (token buckets in memory): `<count>/<period>`, or `off`. Keys: the
 * client IP (as TRUST_PROXY resolves it), the client_id (per tenant), or the admin API caller.
 */
export const RATE_LIMIT_NAMES = [
  "authorizeIp",
  "authorizeClient",
  "interactionIp",
  "federationIp",
  "tokenIp",
  "tokenClient",
  "adminApi",
] as const;
export type RateLimitName = (typeof RATE_LIMIT_NAMES)[number];

export interface HttpLimits {
  /** `server.requestTimeout`: the whole request, headers and body (HTTP_REQUEST_TIMEOUT). */
  readonly requestTimeoutSeconds: number;
  /** `server.headersTimeout` (HTTP_HEADERS_TIMEOUT). */
  readonly headersTimeoutSeconds: number;
  /** `server.keepAliveTimeout` (HTTP_KEEP_ALIVE_TIMEOUT): above the load balancer's idle timeout. */
  readonly keepAliveTimeoutSeconds: number;
  /** Longest request URL (MAX_URL_LENGTH); longer ones get 414. */
  readonly maxUrlLength: number;
  /** Largest request header block in bytes (HTTP_MAX_HEADER_SIZE); larger ones get 431. */
  readonly maxHeaderBytes: number;
}

export interface MetricsConfig {
  /** METRICS_ENABLED (default true). */
  readonly enabled: boolean;
  /** METRICS_PORT: a separate listener for `/metrics` (otherwise the main port). */
  readonly port: number | undefined;
  /** METRICS_HOST: the separate listener's address (default 0.0.0.0). */
  readonly host: string;
  /** METRICS_TOKEN: bearer token required to scrape. */
  readonly token: string | undefined;
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
    /**
     * How often SAML metadata URLs are checked for a due refresh (each login method refreshes
     * after its own `metadataRefreshSeconds`).
     */
    readonly samlMetadataCheckSeconds: number;
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
    /**
     * Manual rotation without `emergency` (admin API): the new key is published at once and
     * signs after this long (KEY_MANUAL_PUBLISH_AHEAD); longer than the SDKs' JWKS caching.
     */
    readonly manualPublishAheadSeconds: number;
  };
  /** Rate limits per replica; `null` when off. */
  readonly rateLimits: Readonly<Record<RateLimitName, RateLimit | null>>;
  readonly http: HttpLimits;
  readonly metrics: MetricsConfig;
  readonly bootstrap: {
    readonly idp: BootstrapIdpConfig | undefined;
    /** The upstream subject of the first platform admin at the bootstrap login method. */
    readonly adminSubject: string | undefined;
    /** Or their personal identity number (canonical); the method must map and trust it. */
    readonly adminPin: string | undefined;
  };
  /** The admin portal (apps/admin), a separate deployable. */
  readonly admin: {
    /** ADMIN_PUBLIC_URL: the portal's origin (redirect URIs of `portvakt-admin`). */
    readonly publicUrl: string | undefined;
    /** ADMIN_CLIENT_SECRET: the `portvakt-admin` client secret the bootstrap registers. */
    readonly clientSecret: string | undefined;
    /**
     * ADMIN_MIN_ACR: a ranked acr; the admin API refuses tokens whose acr ranks lower (unranked
     * values included). Unset: any login method of a tenant may administer it.
     */
    readonly minAcr: string | undefined;
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
    /**
     * Cached SAML metadata without a validUntil is used at most this long after its last
     * successful refresh (then the login method fails closed until a refresh succeeds).
     */
    readonly samlMetadataMaxAgeSeconds: number;
    /**
     * Hosts outbound requests may reach although they resolve to loopback or private addresses
     * (development and tests only; refused in production).
     */
    readonly allowPrivateUpstreamHosts: readonly string[];
    /** Largest element count of a SAML Response Portvakt parses (bounded parsing). */
    readonly samlXmlMaxElements: number;
  };
  /** Directory of the built login UI (apps/login/dist); `undefined` uses the default location. */
  readonly loginUiDir: string | undefined;
  readonly audit: {
    /** AUDIT_RETENTION: audit events older than this are deleted by `npm run audit:prune`. */
    readonly retentionSeconds: number;
  };
  /** Allowed but notable settings (production only), logged at start and by config:check. */
  readonly warnings: readonly string[];
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
  /** `statement_timeout` of runtime connections (DATABASE_STATEMENT_TIMEOUT). */
  readonly statementTimeoutSeconds: number;
  /** `idle_in_transaction_session_timeout` (DATABASE_IDLE_IN_TRANSACTION_TIMEOUT). */
  readonly idleInTransactionTimeoutSeconds: number;
  /** How long acquiring a pool connection may take (DATABASE_CONNECTION_TIMEOUT). */
  readonly connectionTimeoutSeconds: number;
}

export class ConfigError extends Error {
  readonly issues: readonly string[];
  /** Warnings found along the way (when the variables could be parsed at all). */
  readonly warnings: readonly string[];

  constructor(issues: readonly string[], warnings: readonly string[] = []) {
    super(`Invalid configuration:\n${issues.map((issue) => `  - ${issue}`).join("\n")}`);
    this.name = "ConfigError";
    this.issues = issues;
    this.warnings = warnings;
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

const rateLimit = (fallback: string) =>
  z.preprocess(emptyToUndefined, z.string().default(fallback)).transform((value, ctx) => {
    const parsed = parseRateLimit(value);
    if (parsed === undefined) {
      ctx.addIssue({
        code: "custom",
        message: "must be <count>/<period> such as 60/1m or 10/30s, or off",
      });
      return z.NEVER;
    }
    return parsed;
  });

const port = z.coerce.number().int().min(1).max(65535);

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
  SAML_METADATA_CHECK_INTERVAL: duration("5m"),
  SHUTDOWN_TIMEOUT: duration("15s"),
  SHUTDOWN_DRAIN_DELAY: duration("5s", { allowZero: true }),
  PUBLIC_URL: optionalString,
  DATABASE_URL: z.preprocess(emptyToUndefined, z.string().trim()),
  MIGRATION_DATABASE_URL: optionalString,
  DATABASE_POOL_MAX: z.preprocess(
    emptyToUndefined,
    // At least 2: a transaction and a statement outside it (an audit event) may overlap.
    z.coerce.number().int().min(2).max(200).default(10),
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
  KEY_MANUAL_PUBLISH_AHEAD: duration("10m"),
  RATE_LIMIT_AUTHORIZE_IP: rateLimit("120/1m"),
  RATE_LIMIT_AUTHORIZE_CLIENT: rateLimit("3000/1m"),
  RATE_LIMIT_INTERACTION_IP: rateLimit("60/1m"),
  RATE_LIMIT_FEDERATION_IP: rateLimit("120/1m"),
  RATE_LIMIT_TOKEN_IP: rateLimit("600/1m"),
  RATE_LIMIT_TOKEN_CLIENT: rateLimit("1200/1m"),
  RATE_LIMIT_ADMIN_API: rateLimit("600/1m"),
  HTTP_REQUEST_TIMEOUT: duration("30s"),
  HTTP_HEADERS_TIMEOUT: duration("20s"),
  HTTP_KEEP_ALIVE_TIMEOUT: duration("65s"),
  MAX_URL_LENGTH: z.preprocess(
    emptyToUndefined,
    z.coerce.number().int().min(1024).max(65_536).default(8192),
  ),
  HTTP_MAX_HEADER_SIZE: z.preprocess(
    emptyToUndefined,
    z.coerce.number().int().min(4096).max(65_536).default(16_384),
  ),
  DATABASE_STATEMENT_TIMEOUT: duration("15s"),
  DATABASE_IDLE_IN_TRANSACTION_TIMEOUT: duration("60s"),
  DATABASE_CONNECTION_TIMEOUT: duration("5s"),
  METRICS_ENABLED: booleanFlag,
  METRICS_PORT: z.preprocess(emptyToUndefined, port.optional()),
  METRICS_HOST: z.preprocess(
    emptyToUndefined,
    z
      .string()
      .trim()
      .regex(/^[A-Za-z0-9.:-]{1,253}$/, "must be a host name or IP address")
      .default("0.0.0.0"),
  ),
  METRICS_TOKEN: optionalString,
  BOOTSTRAP_IDP_ISSUER: optionalString,
  BOOTSTRAP_IDP_CLIENT_ID: optionalString,
  BOOTSTRAP_IDP_CLIENT_SECRET: optionalString,
  BOOTSTRAP_IDP_SCOPES: optionalString,
  BOOTSTRAP_IDP_KIND: z.preprocess(emptyToUndefined, z.enum(LOGIN_METHOD_KINDS).optional()),
  BOOTSTRAP_IDP_DISPLAY_NAME: optionalString,
  BOOTSTRAP_IDP_ACR: optionalString,
  BOOTSTRAP_IDP_SUBJECT_CLAIM: optionalString,
  BOOTSTRAP_IDP_NAME_CLAIM: optionalString,
  BOOTSTRAP_IDP_EMAIL_CLAIM: optionalString,
  BOOTSTRAP_IDP_PIN_CLAIM: optionalString,
  BOOTSTRAP_IDP_ACR_CLAIM: optionalString,
  BOOTSTRAP_IDP_TRUST_EMAIL: booleanFlag,
  BOOTSTRAP_ADMIN_SUBJECT: optionalString,
  BOOTSTRAP_ADMIN_PIN: optionalString,
  ADMIN_PUBLIC_URL: optionalString,
  ADMIN_CLIENT_SECRET: optionalString,
  ADMIN_MIN_ACR: optionalString,
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
  SAML_METADATA_MAX_AGE: duration("7d"),
  SAML_XML_MAX_ELEMENTS: z.preprocess(
    emptyToUndefined,
    z.coerce.number().int().min(100).max(1_000_000).default(20_000),
  ),
  ALLOW_PRIVATE_UPSTREAM_HOSTS: z.preprocess(
    emptyToUndefined,
    z
      .string()
      .default("")
      .transform(commaList)
      .pipe(
        z
          .array(z.string().regex(/^[A-Za-z0-9.:-]{1,253}$/, "must be a host name or IP address"))
          .max(50),
      ),
  ),
  LOGIN_UI_DIR: optionalString,
  AUDIT_RETENTION: duration(DEFAULT_AUDIT_RETENTION),
});

type Env = z.infer<typeof envSchema>;

const LOCAL_HOSTNAMES = new Set(["localhost", "127.0.0.1", "[::1]", "0.0.0.0"]);

function isLocalHostname(hostname: string): boolean {
  return (
    LOCAL_HOSTNAMES.has(hostname) || hostname.endsWith(".localhost") || hostname.endsWith(".test")
  );
}

/**
 * Hosts a development or test-mode server may use: loopback addresses and `*.localhost` (which
 * resolves to loopback). `.test` is not among them: anyone can point a `.test` name at any
 * address, and test mode mounts a login route that needs no authentication.
 */
export function isLoopbackHost(hostname: string): boolean {
  return (
    hostname === "localhost" ||
    /^127(?:\.\d{1,3}){3}$/.test(hostname) ||
    hostname === "[::1]" ||
    hostname.endsWith(".localhost")
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
  if (env.ALLOW_PRIVATE_UPSTREAM_HOSTS.length > 0) {
    issues.push("ALLOW_PRIVATE_UPSTREAM_HOSTS: refused in production");
  }

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
  if (env.BOOTSTRAP_IDP_ISSUER !== undefined) {
    // The bootstrap registers portvakt-admin; a generated secret would be unknown to the portal.
    if (env.ADMIN_CLIENT_SECRET === undefined) {
      issues.push("ADMIN_CLIENT_SECRET: required in production for the bootstrap");
    }
    if (env.ADMIN_PUBLIC_URL === undefined) {
      issues.push("ADMIN_PUBLIC_URL: required in production for the bootstrap");
    }
  }
  if (env.ADMIN_CLIENT_SECRET === DEV_ADMIN_CLIENT_SECRET) {
    issues.push("ADMIN_CLIENT_SECRET: the development secret is not allowed in production");
  }
  if (
    env.BOOTSTRAP_IDP_ISSUER !== undefined &&
    URL.canParse(env.BOOTSTRAP_IDP_ISSUER) &&
    isLocalHostname(new URL(env.BOOTSTRAP_IDP_ISSUER).hostname)
  ) {
    // The mock IdP (and anything else on this machine) is never an upstream in production.
    issues.push("BOOTSTRAP_IDP_ISSUER: must not point at a local or .test host in production");
  }

  // Metrics: on a port of their own (not exposed through the ingress) or behind a token.
  if (env.METRICS_ENABLED !== false && env.METRICS_PORT === undefined) {
    if (env.METRICS_TOKEN === undefined) {
      issues.push(
        "METRICS_TOKEN: required in production unless METRICS_PORT serves metrics separately (or METRICS_ENABLED=false)",
      );
    }
  }
  if (env.METRICS_TOKEN !== undefined && env.METRICS_TOKEN.length < 32) {
    issues.push("METRICS_TOKEN: at least 32 characters in production");
  }
  if (env.KEY_MANUAL_PUBLISH_AHEAD < MIN_MANUAL_PUBLISH_AHEAD_SECONDS) {
    issues.push(
      `KEY_MANUAL_PUBLISH_AHEAD: at least ${MIN_MANUAL_PUBLISH_AHEAD_SECONDS}s in production (the SDKs' JWKS cache, refetch cooldown and the JWKS max-age)`,
    );
  }
  issues.push(...reusedSecretIssues(env));
  if (env.ADMIN_PUBLIC_URL !== undefined && URL.canParse(env.ADMIN_PUBLIC_URL)) {
    const url = new URL(env.ADMIN_PUBLIC_URL);
    if (url.protocol !== "https:") issues.push("ADMIN_PUBLIC_URL: must use https in production");
    if (isLocalHostname(url.hostname)) {
      issues.push("ADMIN_PUBLIC_URL: must not point at a local or .test host in production");
    }
  }

  return issues;
}

/**
 * Secrets that must be independent of each other: a value used for two purposes (a cookie key
 * that is also the master key, a metrics token that is also a client secret, a database password
 * shared by both roles) is refused. Names only, never values.
 */
function reusedSecretIssues(env: Env): string[] {
  const secrets: { readonly name: string; readonly forms: readonly string[] }[] = [];
  const masterForms = (key: Buffer): string[] => [
    key.toString("base64"),
    key.toString("base64url"),
    key.toString("hex"),
    key.toString("latin1"),
  ];
  secrets.push({ name: "MASTER_KEY", forms: masterForms(env.MASTER_KEY) });
  for (const key of env.MASTER_KEY_PREVIOUS) {
    secrets.push({ name: "MASTER_KEY_PREVIOUS", forms: masterForms(key) });
  }
  for (const key of env.COOKIE_KEYS) secrets.push({ name: "COOKIE_KEYS", forms: [key] });
  for (const [name, value] of [
    ["ADMIN_CLIENT_SECRET", env.ADMIN_CLIENT_SECRET],
    ["METRICS_TOKEN", env.METRICS_TOKEN],
    ["BOOTSTRAP_IDP_CLIENT_SECRET", env.BOOTSTRAP_IDP_CLIENT_SECRET],
  ] as const) {
    if (value !== undefined) secrets.push({ name, forms: [value] });
  }
  for (const [name, value] of [
    ["DATABASE_URL", env.DATABASE_URL],
    ["MIGRATION_DATABASE_URL", env.MIGRATION_DATABASE_URL],
  ] as const) {
    if (value === undefined || !URL.canParse(value)) continue;
    const password = decodeURIComponent(new URL(value).password);
    if (password !== "") secrets.push({ name, forms: [password] });
  }

  const issues = new Set<string>();
  const seen = new Map<string, string>();
  for (const { name, forms } of secrets) {
    const owners = new Set<string>();
    for (const form of forms) {
      const owner = seen.get(form);
      if (owner !== undefined) owners.add(owner);
    }
    for (const owner of owners) {
      issues.add(
        owner === name
          ? `${name}: the same value appears twice`
          : `${name}: reuses the value of ${owner}; every secret must be generated separately`,
      );
    }
    for (const form of forms) if (!seen.has(form)) seen.set(form, name);
  }
  return [...issues];
}

/**
 * Settings that are allowed in production but deserve an operator's attention (printed by
 * `npm run config:check` and logged at start).
 */
function productionWarnings(env: Env): string[] {
  const warnings: string[] = [];
  if (env.TRUST_PROXY === true) {
    warnings.push(
      "TRUST_PROXY: true trusts every X-Forwarded-For hop, so clients can choose their IP (rate limits per IP); set the number of proxies instead",
    );
  }
  if (env.LOG_LEVEL === "debug" || env.LOG_LEVEL === "trace") {
    warnings.push("LOG_LEVEL: debug and trace are verbose; use info in production");
  }
  for (const variable of Object.keys(RATE_LIMIT_ENV) as (keyof typeof RATE_LIMIT_ENV)[]) {
    if (env[variable] === null) {
      warnings.push(`${variable}: off; this replica does not limit these requests`);
    }
  }
  if (env.METRICS_PORT !== undefined && env.METRICS_TOKEN === undefined) {
    warnings.push(
      "METRICS_TOKEN: not set; keep METRICS_PORT reachable from the metrics scraper only",
    );
  }
  if (env.ADMIN_MIN_ACR === undefined) {
    warnings.push(
      "ADMIN_MIN_ACR: not set; any login method of a tenant can sign in its administrators (recommended: a ranked level such as loa3)",
    );
  }
  if (env.MIGRATE_ON_START === true) {
    warnings.push(
      "MIGRATE_ON_START: the runtime replicas need the owner role; prefer a separate migration job",
    );
  }
  return warnings;
}

/** The RATE_LIMIT_* variable of each limit. */
export const RATE_LIMIT_ENV = {
  RATE_LIMIT_AUTHORIZE_IP: "authorizeIp",
  RATE_LIMIT_AUTHORIZE_CLIENT: "authorizeClient",
  RATE_LIMIT_INTERACTION_IP: "interactionIp",
  RATE_LIMIT_FEDERATION_IP: "federationIp",
  RATE_LIMIT_TOKEN_IP: "tokenIp",
  RATE_LIMIT_TOKEN_CLIENT: "tokenClient",
  RATE_LIMIT_ADMIN_API: "adminApi",
} as const satisfies Record<string, RateLimitName>;

function bootstrapConfig(env: Env, issues: string[]): Config["bootstrap"] {
  const idpVariables = [
    env.BOOTSTRAP_IDP_ISSUER,
    env.BOOTSTRAP_IDP_CLIENT_ID,
    env.BOOTSTRAP_IDP_CLIENT_SECRET,
    env.BOOTSTRAP_IDP_SCOPES,
    env.BOOTSTRAP_IDP_KIND,
    env.BOOTSTRAP_IDP_DISPLAY_NAME,
    env.BOOTSTRAP_IDP_ACR,
    env.BOOTSTRAP_IDP_SUBJECT_CLAIM,
    env.BOOTSTRAP_IDP_NAME_CLAIM,
    env.BOOTSTRAP_IDP_EMAIL_CLAIM,
    env.BOOTSTRAP_IDP_PIN_CLAIM,
    env.BOOTSTRAP_IDP_ACR_CLAIM,
    env.BOOTSTRAP_IDP_TRUST_EMAIL,
  ];
  let adminPin: string | undefined;
  if (env.BOOTSTRAP_ADMIN_PIN !== undefined) {
    adminPin = parsePersonnummer(env.BOOTSTRAP_ADMIN_PIN)?.canonical;
    if (adminPin === undefined) {
      issues.push("BOOTSTRAP_ADMIN_PIN: must be a valid personnummer or samordningsnummer");
    }
  }
  const none = { idp: undefined, adminSubject: env.BOOTSTRAP_ADMIN_SUBJECT, adminPin };
  if (idpVariables.every((value) => value === undefined)) return none;

  if (env.BOOTSTRAP_IDP_ISSUER === undefined) issues.push("BOOTSTRAP_IDP_ISSUER: required");
  if (env.BOOTSTRAP_IDP_CLIENT_ID === undefined) issues.push("BOOTSTRAP_IDP_CLIENT_ID: required");
  if (env.BOOTSTRAP_ADMIN_SUBJECT === undefined && env.BOOTSTRAP_ADMIN_PIN === undefined) {
    issues.push(
      "BOOTSTRAP_ADMIN_SUBJECT: required when BOOTSTRAP_IDP_* is set (or BOOTSTRAP_ADMIN_PIN)",
    );
  }
  if (env.BOOTSTRAP_ADMIN_SUBJECT !== undefined && env.BOOTSTRAP_ADMIN_PIN !== undefined) {
    issues.push("BOOTSTRAP_ADMIN_PIN: set either BOOTSTRAP_ADMIN_SUBJECT or BOOTSTRAP_ADMIN_PIN");
  }
  if (env.BOOTSTRAP_ADMIN_SUBJECT !== undefined && env.BOOTSTRAP_ADMIN_SUBJECT.length > 255) {
    issues.push("BOOTSTRAP_ADMIN_SUBJECT: at most 255 characters");
  }
  if (env.BOOTSTRAP_ADMIN_PIN !== undefined) {
    if (env.BOOTSTRAP_IDP_PIN_CLAIM === undefined) {
      issues.push("BOOTSTRAP_IDP_PIN_CLAIM: required with BOOTSTRAP_ADMIN_PIN");
    }
    // The method is then trusted for personal identity numbers: it must assert at least loa3,
    // which the upstream must prove (a ranked acr needs the acr claim).
    const rank = env.ACR_RANKING.indexOf(env.BOOTSTRAP_IDP_ACR ?? "");
    const minimum = env.ACR_RANKING.indexOf(PIN_REPRESENTATION_MIN_ACR);
    if (minimum < 0 || rank < minimum) {
      issues.push(
        "BOOTSTRAP_IDP_ACR: with BOOTSTRAP_ADMIN_PIN it must be ranked at least loa3 in ACR_RANKING",
      );
    }
    if (env.BOOTSTRAP_IDP_ACR_CLAIM === undefined) {
      issues.push("BOOTSTRAP_IDP_ACR_CLAIM: required with BOOTSTRAP_ADMIN_PIN");
    }
  }
  if (env.BOOTSTRAP_IDP_ISSUER !== undefined) {
    parseHttpUrl(env.BOOTSTRAP_IDP_ISSUER, "BOOTSTRAP_IDP_ISSUER", issues);
  }
  const claimVariables = [
    ["BOOTSTRAP_IDP_SUBJECT_CLAIM", env.BOOTSTRAP_IDP_SUBJECT_CLAIM],
    ["BOOTSTRAP_IDP_NAME_CLAIM", env.BOOTSTRAP_IDP_NAME_CLAIM],
    ["BOOTSTRAP_IDP_EMAIL_CLAIM", env.BOOTSTRAP_IDP_EMAIL_CLAIM],
    ["BOOTSTRAP_IDP_PIN_CLAIM", env.BOOTSTRAP_IDP_PIN_CLAIM],
    ["BOOTSTRAP_IDP_ACR_CLAIM", env.BOOTSTRAP_IDP_ACR_CLAIM],
  ] as const;
  for (const [name, value] of claimVariables) {
    if (value !== undefined && (value.length > 255 || !CLAIM_NAME.test(value))) {
      issues.push(`${name}: must be a claim name or dotted path`);
    }
  }
  const scopes = commaOrSpaceList(env.BOOTSTRAP_IDP_SCOPES ?? "openid profile email");
  if (!scopes.includes("openid")) issues.push("BOOTSTRAP_IDP_SCOPES: must include openid");

  if (env.BOOTSTRAP_IDP_ISSUER === undefined || env.BOOTSTRAP_IDP_CLIENT_ID === undefined) {
    return none;
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
      claims: {
        subject: env.BOOTSTRAP_IDP_SUBJECT_CLAIM ?? "sub",
        name: env.BOOTSTRAP_IDP_NAME_CLAIM ?? "name",
        email: env.BOOTSTRAP_IDP_EMAIL_CLAIM ?? "email",
        pin: env.BOOTSTRAP_IDP_PIN_CLAIM,
        acr: env.BOOTSTRAP_IDP_ACR_CLAIM,
      },
      trustEmail: env.BOOTSTRAP_IDP_TRUST_EMAIL ?? false,
    },
    adminSubject: env.BOOTSTRAP_ADMIN_SUBJECT,
    adminPin,
  };
}

/** Upstream claim name, optionally a dotted path (as `claimMapping` accepts). */
const CLAIM_NAME = /^[A-Za-z0-9_:/-]+(?:\.[A-Za-z0-9_:/-]+)*$/;

function adminConfig(env: Env, isProduction: boolean, issues: string[]): Config["admin"] {
  const value = env.ADMIN_PUBLIC_URL ?? (isProduction ? undefined : DEFAULT_DEV_ADMIN_PUBLIC_URL);
  let publicUrl: string | undefined;
  if (value !== undefined) {
    const url = parseHttpUrl(value, "ADMIN_PUBLIC_URL", issues);
    if (url !== undefined && url.pathname !== "/") {
      issues.push("ADMIN_PUBLIC_URL: must be an origin without a path");
    }
    publicUrl = url?.origin;
  }
  if (env.ADMIN_CLIENT_SECRET !== undefined && env.ADMIN_CLIENT_SECRET.length < 32) {
    issues.push("ADMIN_CLIENT_SECRET: at least 32 characters");
  }
  if (env.ADMIN_MIN_ACR !== undefined && !env.ACR_RANKING.includes(env.ADMIN_MIN_ACR)) {
    issues.push("ADMIN_MIN_ACR: must be one of the values of ACR_RANKING");
  }
  return { publicUrl, clientSecret: env.ADMIN_CLIENT_SECRET, minAcr: env.ADMIN_MIN_ACR };
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
  if (env.AUDIT_RETENTION < MIN_AUDIT_RETENTION_SECONDS) {
    issues.push("AUDIT_RETENTION: must be at least 90 days");
  }
  if (env.KEY_MANUAL_PUBLISH_AHEAD >= env.KEY_ROTATION_INTERVAL) {
    issues.push("KEY_MANUAL_PUBLISH_AHEAD: must be shorter than KEY_ROTATION_INTERVAL");
  }
  // Node refuses a headers timeout above the request timeout.
  if (env.HTTP_HEADERS_TIMEOUT > env.HTTP_REQUEST_TIMEOUT) {
    issues.push("HTTP_HEADERS_TIMEOUT: must not exceed HTTP_REQUEST_TIMEOUT");
  }
  if (env.METRICS_PORT !== undefined && env.METRICS_PORT === env.PORT) {
    issues.push("METRICS_PORT: must differ from PORT");
  }
  const allMasterKeys = [env.MASTER_KEY, ...env.MASTER_KEY_PREVIOUS];
  const distinct = new Set(allMasterKeys.map((key) => key.toString("base64")));
  if (distinct.size !== allMasterKeys.length) {
    issues.push("MASTER_KEY_PREVIOUS: must not repeat MASTER_KEY or another previous key");
  }

  if (publicUrl !== undefined && publicUrl.pathname !== "/") {
    issues.push("PUBLIC_URL: must be an origin without a path (issuers are {PUBLIC_URL}/t/{slug})");
  }
  if (!isProduction && publicUrl !== undefined && !isLoopbackHost(publicUrl.hostname)) {
    // Development and test mode relax the production refusals (dev keys, http, one database
    // role), and test mode mounts a login route that needs no authentication: never on a host
    // other people can reach. A real deployment sets NODE_ENV=production.
    issues.push(
      `NODE_ENV: ${env.NODE_ENV} mode is only allowed with a loopback or .localhost PUBLIC_URL; set NODE_ENV=production for any other host`,
    );
  }

  const bootstrap = bootstrapConfig(env, issues);
  const admin = adminConfig(env, isProduction, issues);
  if (isProduction) issues.push(...productionIssues(env, publicUrl));
  if (issues.length > 0 || publicUrl === undefined || database === undefined) {
    throw new ConfigError(issues, isProduction ? productionWarnings(env) : []);
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
      samlMetadataCheckSeconds: env.SAML_METADATA_CHECK_INTERVAL,
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
      manualPublishAheadSeconds: env.KEY_MANUAL_PUBLISH_AHEAD,
    },
    rateLimits: {
      authorizeIp: env.RATE_LIMIT_AUTHORIZE_IP,
      authorizeClient: env.RATE_LIMIT_AUTHORIZE_CLIENT,
      interactionIp: env.RATE_LIMIT_INTERACTION_IP,
      federationIp: env.RATE_LIMIT_FEDERATION_IP,
      tokenIp: env.RATE_LIMIT_TOKEN_IP,
      tokenClient: env.RATE_LIMIT_TOKEN_CLIENT,
      adminApi: env.RATE_LIMIT_ADMIN_API,
    },
    http: {
      requestTimeoutSeconds: env.HTTP_REQUEST_TIMEOUT,
      headersTimeoutSeconds: env.HTTP_HEADERS_TIMEOUT,
      keepAliveTimeoutSeconds: env.HTTP_KEEP_ALIVE_TIMEOUT,
      maxUrlLength: env.MAX_URL_LENGTH,
      maxHeaderBytes: env.HTTP_MAX_HEADER_SIZE,
    },
    metrics: {
      enabled: env.METRICS_ENABLED ?? true,
      port: env.METRICS_PORT,
      host: env.METRICS_HOST,
      token: env.METRICS_TOKEN,
    },
    bootstrap,
    admin,
    acrRanking: env.ACR_RANKING,
    federation: {
      upstreamTimeoutSeconds: env.UPSTREAM_TIMEOUT,
      metadataTtlSeconds: env.UPSTREAM_METADATA_TTL,
      failureCacheSeconds: env.UPSTREAM_FAILURE_CACHE,
      samlMetadataMaxAgeSeconds: env.SAML_METADATA_MAX_AGE,
      allowPrivateUpstreamHosts: env.ALLOW_PRIVATE_UPSTREAM_HOSTS,
      samlXmlMaxElements: env.SAML_XML_MAX_ELEMENTS,
    },
    loginUiDir: env.LOGIN_UI_DIR,
    audit: { retentionSeconds: env.AUDIT_RETENTION },
    warnings: isProduction ? productionWarnings(env) : [],
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
  | "NODE_ENV"
  | "DATABASE_URL"
  | "MIGRATION_DATABASE_URL"
  | "DATABASE_POOL_MAX"
  | "DATABASE_STATEMENT_TIMEOUT"
  | "DATABASE_IDLE_IN_TRANSACTION_TIMEOUT"
  | "DATABASE_CONNECTION_TIMEOUT"
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
    statementTimeoutSeconds: env.DATABASE_STATEMENT_TIMEOUT,
    idleInTransactionTimeoutSeconds: env.DATABASE_IDLE_IN_TRANSACTION_TIMEOUT,
    connectionTimeoutSeconds: env.DATABASE_CONNECTION_TIMEOUT,
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
    DATABASE_STATEMENT_TIMEOUT: true,
    DATABASE_IDLE_IN_TRANSACTION_TIMEOUT: true,
    DATABASE_CONNECTION_TIMEOUT: true,
  });
  const parsed = schema.safeParse(source);
  if (!parsed.success) throw new ConfigError(formatZodIssues(parsed.error));
  const issues: string[] = [];
  const database = resolveDatabase(parsed.data, issues);
  if (issues.length > 0 || database === undefined) throw new ConfigError(issues);
  return database;
}

/**
 * Narrow loader for the audit retention CLI (`npm run audit:prune`): the database (it connects
 * with MIGRATION_DATABASE_URL, the owner) and AUDIT_RETENTION.
 */
export function loadAuditPruneConfig(source: NodeJS.ProcessEnv = process.env): {
  readonly database: DatabaseConfig;
  readonly retentionSeconds: number;
} {
  const schema = envSchema.pick({
    NODE_ENV: true,
    DATABASE_URL: true,
    MIGRATION_DATABASE_URL: true,
    DATABASE_POOL_MAX: true,
    DATABASE_STATEMENT_TIMEOUT: true,
    DATABASE_IDLE_IN_TRANSACTION_TIMEOUT: true,
    DATABASE_CONNECTION_TIMEOUT: true,
    AUDIT_RETENTION: true,
  });
  const parsed = schema.safeParse(source);
  if (!parsed.success) throw new ConfigError(formatZodIssues(parsed.error));
  const issues: string[] = [];
  const database = resolveDatabase(parsed.data, issues);
  if (parsed.data.AUDIT_RETENTION < MIN_AUDIT_RETENTION_SECONDS) {
    issues.push("AUDIT_RETENTION: must be at least 90 days");
  }
  if (issues.length > 0 || database === undefined) throw new ConfigError(issues);
  return { database, retentionSeconds: parsed.data.AUDIT_RETENTION };
}

/** What `npm run config:check` reports: every problem and warning, by variable name only. */
export interface ConfigReport {
  readonly ok: boolean;
  readonly nodeEnv: string;
  readonly issues: readonly string[];
  readonly warnings: readonly string[];
}

/** Validates `source` like the server does at start, without throwing. */
export function checkConfig(source: NodeJS.ProcessEnv = process.env): ConfigReport {
  const nodeEnv =
    source.NODE_ENV === undefined || source.NODE_ENV === "" ? "development" : source.NODE_ENV;
  try {
    const config = loadConfig(source);
    return { ok: true, nodeEnv, issues: [], warnings: config.warnings };
  } catch (error) {
    if (!(error instanceof ConfigError)) throw error;
    return { ok: false, nodeEnv, issues: error.issues, warnings: error.warnings };
  }
}
