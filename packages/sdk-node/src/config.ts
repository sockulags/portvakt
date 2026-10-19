import { z } from "zod";
import { PortvaktConfigError } from "./errors.js";
import { consoleLogger, type PortvaktLogger } from "./logger.js";
import { DEFAULT_ACR_RANKING } from "./principal.js";

/** How the application authenticates at Portvakt's token endpoint. */
export type ClientAuthConfig =
  | {
      readonly method: "client_secret_basic" | "client_secret_post";
      readonly clientSecret: string;
    }
  | {
      readonly method: "private_key_jwt";
      /**
       * The private key as a JWK (EC P-256 `ES256` by default, or RSA/OKP with `alg`). Its public
       * part must be registered with the application in Portvakt, under the same `kid`.
       */
      readonly privateJwk: Readonly<Record<string, unknown>>;
    };

/** Configuration of {@link createPortvaktClient}. */
export interface PortvaktClientConfig {
  /**
   * The tenant's issuer, exactly as Portvakt publishes it: `{PUBLIC_URL}/t/{tenant}`. Tokens are
   * accepted only with this exact `iss` (Portvakt's signing keys are shared by all tenants).
   */
  readonly issuer: string;
  readonly clientId: string;
  readonly clientAuth: ClientAuthConfig;
  /** The BFF callback (`{origin}{mountPath}/callback`). Required for {@link PortvaktClient.bff}. */
  readonly redirectUri?: string;
  /** Where Portvakt sends the browser after logout; must be registered with the application. */
  readonly postLogoutRedirectUri?: string;
  /** Default `openid profile email`; must include `openid`. */
  readonly scopes?: readonly string[];
  /** Tolerated clock difference for token times, in seconds. Default 30. */
  readonly clockSkewSeconds?: number;
  /** Timeout of every request to Portvakt, in seconds. Default 10. */
  readonly httpTimeoutSeconds?: number;
  /** How long discovery metadata is reused before it is fetched again. Default 3600 seconds. */
  readonly discoveryCacheSeconds?: number;
  /**
   * When discovery or the JWKS could not be fetched and nothing is cached, requests fail at once
   * for this long instead of each trying again. Default 5 seconds.
   */
  readonly failureCacheSeconds?: number;
  readonly jwks?: {
    /** Keys are refetched in the background of a request after this. Default 600 seconds. */
    readonly cacheMaxAgeSeconds?: number;
    /**
     * At most one fetch per this many seconds (unknown `kid`s and refreshes alike); an unknown
     * `kid` within it is refused without a fetch. Default 30.
     */
    readonly cooldownSeconds?: number;
    /**
     * While refetches fail, the last keys stay in use until `cacheMaxAgeSeconds` plus this long
     * after their last successful fetch; then validation fails as unavailable. Default 86400 s.
     */
    readonly staleMaxAgeSeconds?: number;
  };
  /**
   * How long a BFF session survives when its access token needs refreshing while Portvakt is
   * unreachable. Default 0: the session ends at the first failed refresh.
   */
  readonly outageGraceSeconds?: number;
  /** Assurance level ordering, lowest first. Default {@link DEFAULT_ACR_RANKING}. */
  readonly acrRanking?: readonly string[];
  /** Allows an `http:` issuer (local development only). Default false. */
  readonly allowInsecureRequests?: boolean;
  readonly logger?: PortvaktLogger;
  /** A fetch implementation for every request to Portvakt (proxies, tests). */
  readonly fetch?: typeof fetch;
}

/** The validated configuration, with defaults applied. */
export interface ResolvedConfig {
  readonly issuer: string;
  readonly clientId: string;
  readonly clientAuth: ClientAuthConfig;
  readonly redirectUri: string | undefined;
  readonly postLogoutRedirectUri: string | undefined;
  readonly scopes: readonly string[];
  readonly clockSkewSeconds: number;
  readonly httpTimeoutSeconds: number;
  readonly discoveryCacheSeconds: number;
  readonly failureCacheSeconds: number;
  readonly jwks: {
    readonly cacheMaxAgeSeconds: number;
    readonly cooldownSeconds: number;
    readonly staleMaxAgeSeconds: number;
  };
  readonly outageGraceSeconds: number;
  readonly acrRanking: readonly string[];
  readonly allowInsecureRequests: boolean;
  readonly logger: PortvaktLogger;
  readonly fetch: typeof fetch | undefined;
}

const httpUrl = (allowInsecure: () => boolean) =>
  z.string().superRefine((value, ctx) => {
    let url: URL;
    try {
      url = new URL(value);
    } catch {
      ctx.addIssue({ code: "custom", message: "must be an absolute URL" });
      return;
    }
    if (url.protocol !== "https:" && !(url.protocol === "http:" && allowInsecure())) {
      ctx.addIssue({
        code: "custom",
        message: "must be https (http only with allowInsecureRequests, for local development)",
      });
    }
    if (url.hash !== "" || url.username !== "" || url.password !== "") {
      ctx.addIssue({ code: "custom", message: "must not carry a fragment or credentials" });
    }
  });

const secondsSchema = (max: number) => z.number().int().min(0).max(max);

const privateJwkSchema = z
  .object({ kty: z.enum(["EC", "RSA", "OKP"]), d: z.string().min(1), kid: z.string().min(1) })
  .catchall(z.unknown());

const clientAuthSchema = z.discriminatedUnion("method", [
  z
    .object({
      method: z.enum(["client_secret_basic", "client_secret_post"]),
      clientSecret: z.string().min(16, "clientSecret: at least 16 characters").max(4096),
    })
    .strict(),
  z.object({ method: z.literal("private_key_jwt"), privateJwk: privateJwkSchema }).strict(),
]);

function configSchema(allowInsecure: () => boolean) {
  const url = httpUrl(allowInsecure);
  return z
    .object({
      issuer: url.refine(
        (value) => !value.endsWith("/") && !value.includes("?"),
        "must be the issuer exactly, without a trailing slash or query",
      ),
      clientId: z.string().min(1).max(255),
      clientAuth: clientAuthSchema,
      redirectUri: url.optional(),
      postLogoutRedirectUri: url.optional(),
      scopes: z
        .array(z.string().regex(/^[\x21\x23-\x5B\x5D-\x7E]+$/, "invalid scope"))
        .min(1)
        .max(50)
        .refine((scopes) => scopes.includes("openid"), "must include openid")
        .default(["openid", "profile", "email"]),
      clockSkewSeconds: secondsSchema(300).default(30),
      httpTimeoutSeconds: z.number().min(1).max(120).default(10),
      discoveryCacheSeconds: secondsSchema(86_400).default(3600),
      failureCacheSeconds: secondsSchema(300).default(5),
      jwks: z
        .object({
          cacheMaxAgeSeconds: secondsSchema(86_400).default(600),
          cooldownSeconds: secondsSchema(3600).default(30),
          staleMaxAgeSeconds: secondsSchema(7 * 86_400).default(86_400),
        })
        .strict()
        .default({ cacheMaxAgeSeconds: 600, cooldownSeconds: 30, staleMaxAgeSeconds: 86_400 }),
      outageGraceSeconds: secondsSchema(7 * 86_400).default(0),
      acrRanking: z
        .array(z.string().min(1).max(255))
        .max(50)
        .default([...DEFAULT_ACR_RANKING]),
      allowInsecureRequests: z.boolean().default(false),
      logger: z
        .custom<PortvaktLogger>(
          (value) =>
            typeof value === "object" &&
            value !== null &&
            ["debug", "info", "warn", "error"].every(
              (method) => typeof (value as Record<string, unknown>)[method] === "function",
            ),
          "must have debug, info, warn and error methods",
        )
        .optional(),
      fetch: z
        .custom<typeof fetch>((value) => typeof value === "function", "must be a function")
        .optional(),
    })
    .strict();
}

/** Formats zod issues as `path: message`, never echoing the offending values. */
export function formatIssues(error: z.ZodError, prefix = ""): string[] {
  return error.issues.map((issue) => {
    const path = [prefix, ...issue.path.map(String)].filter((part) => part !== "").join(".");
    return path === "" ? issue.message : `${path}: ${issue.message}`;
  });
}

/** Validates the client configuration; throws {@link PortvaktConfigError} listing the problems. */
export function resolveConfig(input: PortvaktClientConfig): ResolvedConfig {
  const allowInsecure =
    typeof input === "object" && input !== null && input.allowInsecureRequests === true;
  const parsed = configSchema(() => allowInsecure).safeParse(input);
  if (!parsed.success) throw new PortvaktConfigError(formatIssues(parsed.error));
  const data = parsed.data;
  const logger = data.logger ?? consoleLogger;
  if (data.allowInsecureRequests && process.env.NODE_ENV === "production") {
    logger.warn({}, "allowInsecureRequests is set in production: Portvakt is reached over http");
  }
  return {
    issuer: data.issuer,
    clientId: data.clientId,
    clientAuth: data.clientAuth,
    redirectUri: data.redirectUri,
    postLogoutRedirectUri: data.postLogoutRedirectUri,
    scopes: data.scopes,
    clockSkewSeconds: data.clockSkewSeconds,
    httpTimeoutSeconds: data.httpTimeoutSeconds,
    discoveryCacheSeconds: data.discoveryCacheSeconds,
    failureCacheSeconds: data.failureCacheSeconds,
    jwks: data.jwks,
    outageGraceSeconds: data.outageGraceSeconds,
    acrRanking: data.acrRanking,
    allowInsecureRequests: data.allowInsecureRequests,
    logger,
    fetch: data.fetch,
  };
}
