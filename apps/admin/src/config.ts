import { fileURLToPath } from "node:url";
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
});

const LOCAL = new Set(["localhost", "127.0.0.1", "[::1]"]);

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
  };
}
