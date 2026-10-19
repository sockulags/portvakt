import { fileURLToPath } from "node:url";
import { z } from "zod";

/** Development-only defaults; refused with NODE_ENV=production. */
export const DEV_COOKIE_SECRET = "dev-only-demo-cookie-secret-do-not-use-in-production";
export const DEV_SESSION_ENCRYPTION_KEY = Buffer.from(
  "dev-only-demo-session-key-32byte",
  "utf8",
).toString("base64");

const LOA4 = "http://id.elegnamnden.se/loa/1.0/loa4";

/** The demo service's configuration (one codebase, run as Service A and Service B). */
export interface DemoConfig {
  readonly appName: string;
  readonly port: number;
  /** The browser-facing origin of this instance. */
  readonly publicUrl: string;
  /** Where the BFF calls its own API (the instance itself, from the inside). */
  readonly apiUrl: string;
  readonly issuer: string;
  readonly clientId: string;
  readonly clientSecret: string;
  readonly cookieName: string;
  readonly cookieSecrets: readonly string[];
  readonly cookieSecure: boolean;
  readonly sessionEncryptionKeys: readonly string[];
  readonly stepUpAcr: string;
  readonly scopes: readonly string[];
  readonly outageGraceSeconds: number;
  readonly idleTimeoutSeconds: number;
  /** The built SPA (`npm run build -w examples/demo-service`). */
  readonly webDir: string;
  readonly production: boolean;
}

const list = (value: string): string[] =>
  value
    .split(",")
    .map((item) => item.trim())
    .filter((item) => item !== "");

const empty = (value: unknown): unknown => (value === "" ? undefined : value);

const envSchema = z.object({
  NODE_ENV: z.preprocess(empty, z.string().default("development")),
  APP_NAME: z.preprocess(empty, z.string().min(1).max(100).default("Demotjänst")),
  PORT: z.preprocess(empty, z.coerce.number().int().min(1).max(65_535).default(3100)),
  PUBLIC_URL: z.preprocess(empty, z.url().optional()),
  API_URL: z.preprocess(empty, z.url().optional()),
  ISSUER: z.url(),
  CLIENT_ID: z.string().min(1).max(255),
  CLIENT_SECRET: z.string().min(32),
  COOKIE_NAME: z.preprocess(
    empty,
    z
      .string()
      .regex(/^[A-Za-z0-9_-]{1,64}$/)
      .optional(),
  ),
  COOKIE_SECRET: z.preprocess(empty, z.string().default(DEV_COOKIE_SECRET)),
  COOKIE_SECURE: z.preprocess(empty, z.enum(["true", "false"]).optional()),
  SESSION_ENCRYPTION_KEY: z.preprocess(empty, z.string().default(DEV_SESSION_ENCRYPTION_KEY)),
  STEP_UP_ACR: z.preprocess(empty, z.string().min(1).max(255).default(LOA4)),
  SCOPES: z.preprocess(empty, z.string().default("openid profile email")),
  OUTAGE_GRACE_SECONDS: z.preprocess(empty, z.coerce.number().int().min(0).default(0)),
  IDLE_TIMEOUT_SECONDS: z.preprocess(empty, z.coerce.number().int().min(60).default(1800)),
  WEB_DIR: z.preprocess(empty, z.string().optional()),
});

export class DemoConfigError extends Error {}

const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

/** An http origin on this machine, where a Secure cookie would never be sent. */
function isLocalHttp(origin: string): boolean {
  const url = new URL(origin);
  return url.protocol === "http:" && LOCAL_HOSTS.has(url.hostname);
}

/** Reads the configuration from the environment; throws {@link DemoConfigError} listing issues. */
export function loadDemoConfig(env: NodeJS.ProcessEnv = process.env): DemoConfig {
  const parsed = envSchema.safeParse(env);
  if (!parsed.success) {
    throw new DemoConfigError(
      `Invalid demo-service configuration:\n${parsed.error.issues
        .map((issue) => `- ${issue.path.join(".")}: ${issue.message}`)
        .join("\n")}`,
    );
  }
  const data = parsed.data;
  const production = data.NODE_ENV === "production";
  const publicUrl = (data.PUBLIC_URL ?? `http://localhost:${data.PORT}`).replace(/\/+$/, "");
  const cookieSecrets = list(data.COOKIE_SECRET);
  const keys = list(data.SESSION_ENCRYPTION_KEY);
  const issues: string[] = [];
  if (production && cookieSecrets.includes(DEV_COOKIE_SECRET)) {
    issues.push("COOKIE_SECRET: the development secret is not allowed in production");
  }
  if (production && keys.includes(DEV_SESSION_ENCRYPTION_KEY)) {
    issues.push("SESSION_ENCRYPTION_KEY: the development key is not allowed in production");
  }
  if (issues.length > 0) {
    throw new DemoConfigError(`Invalid demo-service configuration:\n- ${issues.join("\n- ")}`);
  }
  return {
    appName: data.APP_NAME,
    port: data.PORT,
    publicUrl,
    apiUrl: (data.API_URL ?? `http://127.0.0.1:${data.PORT}`).replace(/\/+$/, ""),
    issuer: data.ISSUER,
    clientId: data.CLIENT_ID,
    clientSecret: data.CLIENT_SECRET,
    // Cookies ignore ports: two instances on localhost need different cookie names.
    cookieName: data.COOKIE_NAME ?? `${data.CLIENT_ID.replace(/[^A-Za-z0-9_-]/g, "_")}_session`,
    cookieSecrets,
    // Secure unless the instance runs over plain http on this machine (local development).
    cookieSecure:
      data.COOKIE_SECURE === undefined ? !isLocalHttp(publicUrl) : data.COOKIE_SECURE === "true",
    sessionEncryptionKeys: keys,
    stepUpAcr: data.STEP_UP_ACR,
    scopes: data.SCOPES.split(" ").filter((scope) => scope !== ""),
    outageGraceSeconds: data.OUTAGE_GRACE_SECONDS,
    idleTimeoutSeconds: data.IDLE_TIMEOUT_SECONDS,
    webDir: data.WEB_DIR ?? fileURLToPath(new URL("../dist/web", import.meta.url)),
    production,
  };
}
