import { fileURLToPath } from "node:url";
import { parseRateLimit, type RateLimit } from "@portvakt/http-kit";
import { z } from "zod";

/** Development-only defaults (.env.example); refused with NODE_ENV=production. */
export const DEV_ADMIN_CLIENT_SECRET = "dev-only-admin-client-secret-0123456789abcdef";
export const DEV_COOKIE_SECRET = "dev-only-admin-cookie-secret-do-not-use-in-production";
export const DEV_SESSION_ENCRYPTION_KEY = Buffer.from(
  "dev-only-admin-session-key-32byt",
  "utf8",
).toString("base64");

/** The admin portal's configuration (a deployable of its own: ADMIN_* variables). */
export interface AdminConfig {
  readonly production: boolean;
  readonly port: number;
  /** The portal's browser-facing origin (ADMIN_PUBLIC_URL). */
  readonly publicUrl: string;
  /** Portvakt's PUBLIC_URL: tenant issuers are `{portvaktUrl}/t/{slug}`. */
  readonly portvaktUrl: string;
  /** Where the BFF reaches the admin API (default: Portvakt's PUBLIC_URL). */
  readonly apiUrl: string;
  readonly clientId: string;
  readonly clientSecret: string;
  readonly cookieSecrets: readonly string[];
  readonly cookieSecure: boolean;
  readonly sessionEncryptionKeys: readonly string[];
  /** Postgres for sessions (required in production; memory otherwise). */
  readonly databaseUrl: string | undefined;
  /** Where `/` sends the browser (the system tenant by default). */
  readonly defaultTenant: string;
  readonly idleTimeoutSeconds: number;
  /** The built SPA (`npm run build -w apps/admin`). */
  readonly webDir: string;
  /** Proxy hops trusted for X-Forwarded-For (ADMIN_TRUST_PROXY): the client IP of rate limits. */
  readonly trustProxy: boolean | number;
  /**
   * Per client IP, per replica: the sign-in routes of every tenant's BFF (`/t/{slug}/auth/login`,
   * `step-up`, `select-representation`, `callback`). `null` when off (ADMIN_RATE_LIMIT_LOGIN).
   */
  readonly loginRateLimit: RateLimit | null;
  /**
   * Per client IP, per replica: lookups of tenant slugs the portal does not know yet (each asks
   * Portvakt's discovery). `null` when off (ADMIN_RATE_LIMIT_TENANT_LOOKUP).
   */
  readonly tenantLookupRateLimit: RateLimit | null;
  /** Allowed but notable settings, logged at start (names only, never values). */
  readonly warnings: readonly string[];
  /** `/metrics` (ADMIN_METRICS_ENABLED, default true), behind ADMIN_METRICS_TOKEN when set. */
  readonly metrics: { readonly enabled: boolean; readonly token: string | undefined };
  readonly logLevel: "fatal" | "error" | "warn" | "info" | "debug" | "trace" | "silent";
}

export class AdminConfigError extends Error {
  readonly issues: readonly string[];

  constructor(issues: readonly string[]) {
    super(`Invalid admin portal configuration:\n${issues.map((issue) => `- ${issue}`).join("\n")}`);
    this.name = "AdminConfigError";
    this.issues = issues;
  }
}

const empty = (value: unknown): unknown =>
  typeof value === "string" && value.trim() === "" ? undefined : value;
const list = (value: string): string[] =>
  value
    .split(",")
    .map((item) => item.trim())
    .filter((item) => item !== "");

const origin = z.string().superRefine((value, ctx) => {
  if (!URL.canParse(value)) {
    ctx.addIssue({ code: "custom", message: "must be an absolute URL" });
    return;
  }
  const url = new URL(value);
  if (!["http:", "https:"].includes(url.protocol) || url.pathname !== "/" || url.search !== "") {
    ctx.addIssue({ code: "custom", message: "must be an http(s) origin without a path" });
  }
});

const rateLimit = (fallback: string) =>
  z.preprocess(
    empty,
    z
      .string()
      .default(fallback)
      .refine(
        (value) => parseRateLimit(value) !== undefined,
        "must be <count>/<period> such as 30/1m, or off",
      )
      .transform((value) => parseRateLimit(value) ?? null),
  );

const envSchema = z.object({
  NODE_ENV: z.preprocess(empty, z.string().default("development")),
  ADMIN_PORT: z.preprocess(empty, z.coerce.number().int().min(1).max(65_535).default(3400)),
  ADMIN_PUBLIC_URL: z.preprocess(empty, origin.optional()),
  PORTVAKT_PUBLIC_URL: z.preprocess(empty, origin.optional()),
  PUBLIC_URL: z.preprocess(empty, z.string().optional()),
  ADMIN_API_URL: z.preprocess(empty, origin.optional()),
  ADMIN_CLIENT_ID: z.preprocess(empty, z.string().min(3).max(128).default("portvakt-admin")),
  ADMIN_CLIENT_SECRET: z.preprocess(empty, z.string().min(32).default(DEV_ADMIN_CLIENT_SECRET)),
  ADMIN_COOKIE_SECRET: z.preprocess(empty, z.string().default(DEV_COOKIE_SECRET)),
  ADMIN_COOKIE_SECURE: z.preprocess(empty, z.enum(["true", "false"]).optional()),
  ADMIN_SESSION_ENCRYPTION_KEY: z.preprocess(empty, z.string().default(DEV_SESSION_ENCRYPTION_KEY)),
  ADMIN_DATABASE_URL: z.preprocess(empty, z.string().optional()),
  ADMIN_DEFAULT_TENANT: z.preprocess(
    empty,
    z
      .string()
      .regex(/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/)
      .default("system"),
  ),
  ADMIN_IDLE_TIMEOUT_SECONDS: z.preprocess(empty, z.coerce.number().int().min(60).default(1800)),
  ADMIN_WEB_DIR: z.preprocess(empty, z.string().optional()),
  ADMIN_TRUST_PROXY: z.preprocess(
    empty,
    z
      .string()
      .trim()
      .toLowerCase()
      .default("false")
      .refine(
        (value) => /^(true|false|[0-9]{1,2})$/.test(value),
        "must be false, true or a number of proxy hops",
      )
      .transform((value) =>
        value === "true" ? true : value === "false" || value === "0" ? false : Number(value),
      ),
  ),
  ADMIN_RATE_LIMIT_LOGIN: rateLimit("30/1m"),
  ADMIN_RATE_LIMIT_TENANT_LOOKUP: rateLimit("30/1m"),
  ADMIN_METRICS_ENABLED: z.preprocess(empty, z.enum(["true", "false"]).default("true")),
  ADMIN_METRICS_TOKEN: z.preprocess(empty, z.string().optional()),
  ADMIN_LOG_LEVEL: z.preprocess(
    empty,
    z.enum(["fatal", "error", "warn", "info", "debug", "trace", "silent"]).default("info"),
  ),
});

const LOCAL = new Set(["localhost", "127.0.0.1", "[::1]"]);

/** Loopback hosts: plain http to the admin API is allowed only there, and never in production. */
const isLoopback = (hostname: string): boolean =>
  LOCAL.has(hostname) || /^127(?:\.\d{1,3}){3}$/.test(hostname) || hostname.endsWith(".localhost");

/** Reads the configuration; throws {@link AdminConfigError} naming variables, never values. */
export function loadAdminConfig(env: NodeJS.ProcessEnv = process.env): AdminConfig {
  const parsed = envSchema.safeParse(env);
  if (!parsed.success) {
    throw new AdminConfigError(
      parsed.error.issues.map((issue) => `${issue.path.join(".")}: ${issue.message}`),
    );
  }
  const data = parsed.data;
  const production = data.NODE_ENV === "production";
  const issues: string[] = [];
  const publicUrl = (data.ADMIN_PUBLIC_URL ?? `http://localhost:${data.ADMIN_PORT}`).replace(
    /\/+$/,
    "",
  );
  // The server's own PUBLIC_URL (shared .env) names Portvakt's origin too.
  const portvaktValue =
    data.PORTVAKT_PUBLIC_URL ??
    (production ? undefined : (data.PUBLIC_URL ?? "http://localhost:3000"));
  if (portvaktValue === undefined) issues.push("PORTVAKT_PUBLIC_URL: required in production");
  const portvaktUrl = (portvaktValue ?? "").replace(/\/+$/, "");
  const cookieSecrets = list(data.ADMIN_COOKIE_SECRET);
  const keys = list(data.ADMIN_SESSION_ENCRYPTION_KEY);
  if (cookieSecrets.some((secret) => secret.length < 32)) {
    issues.push("ADMIN_COOKIE_SECRET: each secret must be at least 32 characters");
  }
  // The proxy sends administrators' access tokens there: https, or http to this machine in
  // development only.
  if (data.ADMIN_API_URL !== undefined) {
    const api = new URL(data.ADMIN_API_URL);
    if (api.protocol !== "https:" && (production || !isLoopback(api.hostname))) {
      issues.push(
        production
          ? "ADMIN_API_URL: must use https in production"
          : "ADMIN_API_URL: http is allowed only to a loopback host (use https)",
      );
    }
  }
  const warnings: string[] = [];
  if (data.ADMIN_TRUST_PROXY === true) {
    warnings.push(
      "ADMIN_TRUST_PROXY: true trusts every X-Forwarded-For hop, so clients can choose their IP (rate limits per IP); set the number of proxies instead",
    );
  }
  if (production) {
    if (data.ADMIN_PUBLIC_URL === undefined)
      issues.push("ADMIN_PUBLIC_URL: required in production");
    for (const [name, value] of [
      ["ADMIN_PUBLIC_URL", publicUrl],
      ["PORTVAKT_PUBLIC_URL", portvaktUrl],
    ] as const) {
      if (value !== "" && !value.startsWith("https://"))
        issues.push(`${name}: must use https in production`);
    }
    if (data.ADMIN_CLIENT_SECRET === DEV_ADMIN_CLIENT_SECRET) {
      issues.push("ADMIN_CLIENT_SECRET: the development secret is not allowed in production");
    }
    if (cookieSecrets.includes(DEV_COOKIE_SECRET)) {
      issues.push("ADMIN_COOKIE_SECRET: the development secret is not allowed in production");
    }
    if (keys.includes(DEV_SESSION_ENCRYPTION_KEY)) {
      issues.push("ADMIN_SESSION_ENCRYPTION_KEY: the development key is not allowed in production");
    }
    if (data.ADMIN_DATABASE_URL === undefined) {
      issues.push("ADMIN_DATABASE_URL: required in production (sessions live in Postgres)");
    }
    if (data.ADMIN_COOKIE_SECURE === "false") {
      issues.push("ADMIN_COOKIE_SECURE: cookies must be Secure in production");
    }
    if (data.ADMIN_METRICS_ENABLED === "true") {
      if (data.ADMIN_METRICS_TOKEN === undefined) {
        issues.push("ADMIN_METRICS_TOKEN: required in production (or ADMIN_METRICS_ENABLED=false)");
      } else if (data.ADMIN_METRICS_TOKEN.length < 32) {
        issues.push("ADMIN_METRICS_TOKEN: at least 32 characters in production");
      }
    }
    // Every secret is generated on its own: one leaked value must not open another door.
    const secrets: [string, string | undefined][] = [
      ["ADMIN_CLIENT_SECRET", data.ADMIN_CLIENT_SECRET],
      ...cookieSecrets.map((value): [string, string] => ["ADMIN_COOKIE_SECRET", value]),
      ...keys.map((value): [string, string] => ["ADMIN_SESSION_ENCRYPTION_KEY", value]),
      ["ADMIN_METRICS_TOKEN", data.ADMIN_METRICS_TOKEN],
    ];
    const seen = new Map<string, string>();
    for (const [name, value] of secrets) {
      if (value === undefined) continue;
      const owner = seen.get(value);
      if (owner !== undefined) {
        issues.push(
          owner === name
            ? `${name}: the same value appears twice`
            : `${name}: reuses the value of ${owner}; every secret must be generated separately`,
        );
      } else seen.set(value, name);
    }
  }
  if (issues.length > 0) throw new AdminConfigError(issues);
  const url = new URL(publicUrl);
  return {
    production,
    port: data.ADMIN_PORT,
    publicUrl,
    portvaktUrl,
    apiUrl: (data.ADMIN_API_URL ?? portvaktUrl).replace(/\/+$/, ""),
    clientId: data.ADMIN_CLIENT_ID,
    clientSecret: data.ADMIN_CLIENT_SECRET,
    cookieSecrets,
    // Secure unless the portal runs over plain http on this machine (local development).
    cookieSecure:
      data.ADMIN_COOKIE_SECURE === undefined
        ? !(url.protocol === "http:" && LOCAL.has(url.hostname))
        : data.ADMIN_COOKIE_SECURE === "true",
    sessionEncryptionKeys: keys,
    databaseUrl: data.ADMIN_DATABASE_URL,
    defaultTenant: data.ADMIN_DEFAULT_TENANT,
    idleTimeoutSeconds: data.ADMIN_IDLE_TIMEOUT_SECONDS,
    webDir: data.ADMIN_WEB_DIR ?? fileURLToPath(new URL("../dist/web", import.meta.url)),
    trustProxy: data.ADMIN_TRUST_PROXY,
    loginRateLimit: data.ADMIN_RATE_LIMIT_LOGIN,
    tenantLookupRateLimit: data.ADMIN_RATE_LIMIT_TENANT_LOOKUP,
    warnings,
    metrics: {
      enabled: data.ADMIN_METRICS_ENABLED === "true",
      token: data.ADMIN_METRICS_TOKEN,
    },
    logLevel: data.ADMIN_LOG_LEVEL,
  };
}
