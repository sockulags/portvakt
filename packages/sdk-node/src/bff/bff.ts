import express, {
  type ErrorRequestHandler,
  type NextFunction,
  type Request,
  type RequestHandler,
  type Response,
  type Router,
} from "express";
import * as client from "openid-client";
import { z } from "zod";
import { formatIssues, type ResolvedConfig } from "../config.js";
import { isUnavailable, type DiscoveryCache } from "../discovery.js";
import {
  LoginFailedError,
  LoginRequiredError,
  PortvaktConfigError,
  PortvaktError,
  PortvaktUnavailableError,
  type SessionEndReason,
} from "../errors.js";
import { errorDetails } from "../logger.js";
import {
  acrAtLeast,
  idTokenClaimsSchema,
  principalFromIdToken,
  type PersonPrincipal,
} from "../principal.js";
import type { SessionStore } from "../stores/types.js";
import { CookieSigner, randomId, safeEqual, Sealer, storeKey } from "./crypto.js";
import {
  escapeHtml,
  hasControlCharacters,
  isBrowserNavigation,
  readCookie,
  safeReturnTo,
  setCookie,
  wantsJson,
  type CookieAttributes,
} from "./http.js";
import { KeyedMutex } from "./lock.js";
import {
  loginTransactionSchema,
  sessionDataSchema,
  type LoginKind,
  type LoginTransaction,
  type SessionData,
} from "./session.js";

/** Options of {@link PortvaktClient.bff}. */
export interface BffOptions {
  /** Where sessions live: {@link MemoryStore} (development) or {@link PgSessionStore}. */
  readonly sessionStore: SessionStore;
  /**
   * AES-256-GCM key(s) that encrypt sessions in the store: 32 random bytes, base64. The first
   * encrypts, all decrypt (rotation: put the new key first, drop the old one after the longest
   * session has ended).
   */
  readonly encryptionKey: string | readonly string[];
  readonly cookie: {
    /** Must differ between applications sharing a host (cookies ignore ports). */
    readonly name: string;
    /** HMAC secrets (at least 32 characters each); the first signs, all verify. */
    readonly secrets: readonly string[];
    /** Default true; false only for http on localhost. */
    readonly secure?: boolean;
    /** Default `lax`. `strict` drops the cookie on the first navigation after a login. */
    readonly sameSite?: "lax" | "strict";
    readonly domain?: string;
    /** Default `/`. */
    readonly path?: string;
  };
  /** Path the BFF routes live below. Default `/auth`. */
  readonly mountPath?: string;
  /** The session ends after this long without a request through the SDK. Default 1800 s. */
  readonly idleTimeoutSeconds?: number;
  /** The BFF's own maximum session age; the broker's `session_exp` caps it. Default 43200 s. */
  readonly maxAgeSeconds?: number;
  /** Where to go after a login without `returnTo`, and after logout. Default `/`. */
  readonly defaultReturnTo?: string;
  /** How long a started login may take. Default 600 s. */
  readonly loginTimeoutSeconds?: number;
  /**
   * Renders errors of the BFF routes (failed login, Portvakt unavailable, CSRF). Default: a
   * minimal HTML page, or JSON for fetch requests.
   */
  readonly onError?: (error: PortvaktError, req: Request, res: Response) => void;
  /**
   * The JSON of `GET {mountPath}/session` for a signed-in person. Default: `authenticated`,
   * `principal` (without `pin`), `expiresAt`, `sessionEndsAt` and `csrfToken`. Never tokens.
   */
  readonly sessionResponse?: (session: SessionInfo) => Record<string, unknown>;
}

/** A signed-in BFF session as the application sees it. */
export interface SessionInfo {
  readonly principal: PersonPrincipal;
  /** When the session ends unless used again (idle timeout), or at its absolute end. */
  readonly expiresAt: Date;
  /** The absolute end (`session_exp` of the broker session, capped by `maxAgeSeconds`). */
  readonly sessionEndsAt: Date;
  /** Send it with `POST {mountPath}/logout` (`_csrf` form field or `X-CSRF-Token` header). */
  readonly csrfToken: string;
}

export interface GetAccessTokenOptions {
  /**
   * The token must stay valid at least this long, or it is refreshed first. Default: the clock
   * skew plus 30 seconds.
   */
  readonly minValiditySeconds?: number;
}

/** The BFF helpers, on the Express router that serves the BFF routes. */
export interface BffHelpers {
  readonly mountPath: string;
  /** Requires a session: browser navigations are redirected to the login, XHR gets 401 JSON. */
  requireLogin(): RequestHandler;
  /**
   * Requires a session whose acr is at least `acr`: browser navigations are sent to the step-up
   * (`{mountPath}/step-up?acr=...`), XHR gets 401 `{ error: "step_up_required", ... }`.
   */
  requireAcr(acr: string): RequestHandler;
  /**
   * A fresh access token of the request's session, refreshed (with rotation) when it is about
   * to expire. Refreshes of one session never run concurrently (per-session lock, across
   * replicas when the store supports it). Counts as activity (moves the idle timeout). Throws
   * {@link LoginRequiredError} when the session ended (also when a refresh fails while Portvakt
   * has been unreachable for longer than the outage grace) and {@link PortvaktUnavailableError}
   * during an outage within the grace period.
   */
  getAccessToken(req: Request, options?: GetAccessTokenOptions): Promise<string>;
  /** The principal loaded for this request by `requireLogin`, `requireAcr` or `loadSession`. */
  principal(req: Request): PersonPrincipal | undefined;
  /** Loads the request's session (counts as activity), or `undefined` when signed out. */
  loadSession(req: Request): Promise<SessionInfo | undefined>;
  /**
   * Express error middleware for errors of {@link BffHelpers.getAccessToken} in your routes:
   * {@link LoginRequiredError} becomes 401 `{ error: "login_required", loginUrl }` (a redirect for
   * browser navigations), {@link PortvaktUnavailableError} 503. Other errors pass on.
   */
  errorHandler(): ErrorRequestHandler;
  /** `{mountPath}/login?returnTo=...` */
  loginUrl(returnTo?: string): string;
  /** `{mountPath}/step-up?acr=...&returnTo=...` */
  stepUpUrl(acr: string, returnTo?: string): string;
}

export type PortvaktBff = Router & BffHelpers;

const ACR_VALUE = /^[\x21-\x7e]{1,255}$/;

const optionsSchema = z
  .object({
    sessionStore: z.custom<SessionStore>(
      (value) =>
        typeof value === "object" &&
        value !== null &&
        ["get", "set", "destroy"].every(
          (method) => typeof (value as Record<string, unknown>)[method] === "function",
        ),
      "must implement get, set and destroy",
    ),
    encryptionKey: z.union([z.string(), z.array(z.string()).min(1).max(10)]),
    cookie: z
      .object({
        name: z.string().regex(/^[A-Za-z0-9_-]{1,64}$/, "letters, digits, _ and - only"),
        secrets: z
          .array(z.string().min(32, "each secret must be at least 32 characters"))
          .min(1)
          .max(10),
        secure: z.boolean().default(true),
        sameSite: z.enum(["lax", "strict"]).default("lax"),
        domain: z
          .string()
          .regex(/^[A-Za-z0-9.-]{1,253}$/)
          .optional(),
        path: z
          .string()
          .regex(/^\/[\x21-\x3a\x3c-\x7e]*$/, "must be a path")
          .default("/"),
      })
      .strict(),
    mountPath: z
      .string()
      .regex(/^(\/[A-Za-z0-9._~-]+)+$/, "must be a path such as /auth, without a trailing slash")
      .default("/auth"),
    idleTimeoutSeconds: z
      .number()
      .int()
      .min(60)
      .max(7 * 86_400)
      .default(1800),
    maxAgeSeconds: z
      .number()
      .int()
      .min(60)
      .max(30 * 86_400)
      .default(43_200),
    defaultReturnTo: z.string().default("/"),
    loginTimeoutSeconds: z.number().int().min(60).max(3600).default(600),
    onError: z
      .custom<NonNullable<BffOptions["onError"]>>((v) => typeof v === "function")
      .optional(),
    sessionResponse: z
      .custom<NonNullable<BffOptions["sessionResponse"]>>((v) => typeof v === "function")
      .optional(),
  })
  .strict();

const optionalString = (max: number, pattern?: RegExp) => {
  const base = z.string().min(1).max(max);
  return (pattern === undefined ? base : base.regex(pattern)).optional();
};

/** Query of the login routes; every value must be a single string. */
const loginQuerySchema = z.object({
  returnTo: z.string().max(4096).optional(),
  acr: optionalString(255, ACR_VALUE),
  prompt: z.enum(["login", "select_account", "none"]).optional(),
  loginHint: optionalString(320).refine(
    (value) => value === undefined || !hasControlCharacters(value),
    "control characters",
  ),
  csrf: optionalString(128),
  uiLocales: optionalString(
    100,
    /^[A-Za-z]{2,8}(-[A-Za-z0-9]{1,8})*( [A-Za-z]{2,8}(-[A-Za-z0-9]{1,8})*)*$/,
  ),
});

const callbackQuerySchema = z.object({
  state: z.string().max(512).optional(),
  error: z.string().max(256).optional(),
});

const OAUTH_ERROR = /^[a-z_]{1,64}$/;

interface Loaded {
  readonly key: string;
  readonly data: SessionData;
  readonly principal: PersonPrincipal;
}

const epochNow = (): number => Math.floor(Date.now() / 1000);

/** The BFF: routes, session handling and token refresh. */
export function createBff(
  deps: { readonly config: ResolvedConfig; readonly discovery: DiscoveryCache },
  input: BffOptions,
): PortvaktBff {
  const parsed = optionsSchema.safeParse(input);
  if (!parsed.success) throw new PortvaktConfigError(formatIssues(parsed.error, "bff"));
  const options = parsed.data;
  const { config, discovery } = deps;
  const issues: string[] = [];
  if (config.redirectUri === undefined) issues.push("redirectUri: required for the BFF");
  else if (!new URL(config.redirectUri).pathname.endsWith(`${options.mountPath}/callback`)) {
    issues.push(`redirectUri: must point at the BFF callback (${options.mountPath}/callback)`);
  }
  if (safeReturnTo(options.defaultReturnTo) === undefined) {
    issues.push("bff.defaultReturnTo: must be a same-origin path");
  }
  const keys =
    typeof options.encryptionKey === "string" ? [options.encryptionKey] : options.encryptionKey;
  if (issues.length > 0) throw new PortvaktConfigError(issues);
  const sealer = new Sealer(keys);
  const signer = new CookieSigner(options.cookie.secrets);
  const engine = new BffEngine(config, discovery, options, sealer, signer);
  return engine.router();
}

type ParsedOptions = z.output<typeof optionsSchema>;

class BffEngine {
  readonly #config: ResolvedConfig;
  readonly #discovery: DiscoveryCache;
  readonly #options: ParsedOptions;
  readonly #store: SessionStore;
  readonly #sealer: Sealer;
  readonly #signer: CookieSigner;
  readonly #mutex = new KeyedMutex();
  readonly #loaded = new WeakMap<Request, Loaded | null>();
  readonly #redirectUri: string;
  readonly #mount: string;
  readonly #txCookie: string;
  /** The application's own origin (of the redirect URI). */
  readonly #origin: string;

  constructor(
    config: ResolvedConfig,
    discovery: DiscoveryCache,
    options: ParsedOptions,
    sealer: Sealer,
    signer: CookieSigner,
  ) {
    this.#config = config;
    this.#discovery = discovery;
    this.#options = options;
    this.#store = options.sessionStore;
    this.#sealer = sealer;
    this.#signer = signer;
    this.#redirectUri = config.redirectUri!;
    this.#mount = options.mountPath;
    this.#txCookie = `${options.cookie.name}_tx`;
    this.#origin = new URL(config.redirectUri!).origin;
  }

  router(): PortvaktBff {
    const router = express.Router();
    const mount = this.#mount;
    const body = [
      express.urlencoded({ extended: false, limit: "8kb" }),
      express.json({ limit: "8kb" }),
    ];
    router.get(
      `${mount}/login`,
      this.#route((req, res) => this.#startLogin(req, res, "login")),
    );
    router.get(
      `${mount}/step-up`,
      this.#route((req, res) => this.#startLogin(req, res, "step_up")),
    );
    router.get(
      `${mount}/select-representation`,
      this.#route((req, res) => this.#startLogin(req, res, "select_representation")),
    );
    router.get(
      `${mount}/callback`,
      this.#route((req, res) => this.#callback(req, res)),
    );
    router.post(
      `${mount}/logout`,
      ...body,
      this.#route((req, res) => this.#logout(req, res)),
    );
    router.get(
      `${mount}/session`,
      this.#route((req, res) => this.#session(req, res)),
    );

    const helpers: BffHelpers = {
      mountPath: mount,
      requireLogin: () => this.#requireLogin(),
      requireAcr: (acr) => this.#requireAcr(acr),
      getAccessToken: (req, getOptions) => this.#getAccessToken(req, getOptions ?? {}),
      principal: (req) => this.#loaded.get(req)?.principal,
      loadSession: async (req) => {
        const loaded = await this.#load(req, undefined, true);
        return loaded === null ? undefined : this.#info(loaded);
      },
      errorHandler: () => (error: unknown, req, res, next) => {
        if (res.headersSent) {
          next(error);
          return;
        }
        if (error instanceof LoginRequiredError) {
          this.#unauthenticated(req, res);
          return;
        }
        if (error instanceof PortvaktUnavailableError) {
          res
            .status(503)
            .set("Retry-After", "5")
            .set("Cache-Control", "no-store")
            .json({ error: error.code });
          return;
        }
        next(error);
      },
      loginUrl: (returnTo) => this.#loginUrl(returnTo),
      stepUpUrl: (acr, returnTo) => this.#stepUpUrl(acr, returnTo),
    };
    return Object.assign(router, helpers) as PortvaktBff;
  }

  // Routes ---------------------------------------------------------------------------------------

  /** Async route with Express 4 and 5 semantics: SDK errors are rendered, others go to `next`. */
  #route(fn: (req: Request, res: Response) => Promise<void>): RequestHandler {
    return (req, res, next) => {
      fn(req, res).catch((error: unknown) => {
        if (error instanceof PortvaktError) {
          this.#renderError(req, res, error);
          return;
        }
        next(error);
      });
    };
  }

  async #startLogin(req: Request, res: Response, kind: LoginKind): Promise<void> {
    const query = loginQuerySchema.safeParse(req.query);
    if (!query.success) throw new LoginFailedError("invalid_request", "invalid login parameters");
    const { acr, prompt, loginHint, uiLocales } = query.data;
    if (kind === "step_up" && acr === undefined) {
      throw new LoginFailedError("invalid_request", "acr is required for a step-up");
    }
    if (kind !== "login") await this.#requireSameSiteInitiation(req, query.data.csrf);
    const returnTo = safeReturnTo(query.data.returnTo) ?? this.#options.defaultReturnTo;
    const configuration = await this.#discovery.get();

    // A login already pending in this browser is replaced.
    const previous = this.#signedCookie(req, this.#txCookie);
    if (previous !== undefined) await this.#store.destroy(storeKey("t", previous));

    const transaction: LoginTransaction = {
      v: 1,
      kind,
      state: client.randomState(),
      nonce: client.randomNonce(),
      codeVerifier: client.randomPKCECodeVerifier(),
      returnTo,
      ...(acr === undefined || kind === "select_representation" ? {} : { acr }),
      createdAt: epochNow(),
    };
    const txId = randomId();
    const txKey = storeKey("t", txId);
    const timeout = this.#options.loginTimeoutSeconds;
    await this.#store.set(
      txKey,
      this.#sealer.seal(JSON.stringify(transaction), txKey),
      new Date(Date.now() + timeout * 1000),
    );
    // Lax: the cookie must arrive on the top-level redirect back from Portvakt.
    setCookie(res, this.#txCookie, this.#signer.sign(txId), {
      ...this.#cookieBase(),
      path: this.#mount,
      sameSite: "lax",
      maxAge: timeout,
    });

    const parameters: Record<string, string> = {
      redirect_uri: this.#redirectUri,
      scope: this.#config.scopes.join(" "),
      code_challenge: await client.calculatePKCECodeChallenge(transaction.codeVerifier),
      code_challenge_method: "S256",
      state: transaction.state,
      nonce: transaction.nonce,
    };
    if (transaction.acr !== undefined) parameters.acr_values = transaction.acr;
    if (kind === "select_representation") parameters.prompt = "select_account";
    else if (kind === "login" && prompt !== undefined) parameters.prompt = prompt;
    if (loginHint !== undefined) parameters.login_hint = loginHint;
    if (uiLocales !== undefined) parameters.ui_locales = uiLocales;
    const url = client.buildAuthorizationUrl(configuration, parameters);
    res.set("Cache-Control", "no-store").redirect(302, url.href);
  }

  /**
   * A step-up or representation switch replaces the session's login, so another site must not be
   * able to start one: `Sec-Fetch-Site` must be same-origin (or none: typed or bookmarked) when
   * the browser sends it; otherwise a same-origin Referer or the session's CSRF token (`csrf`
   * query parameter) is required.
   */
  async #requireSameSiteInitiation(req: Request, csrf: string | undefined): Promise<void> {
    const site = req.get("sec-fetch-site");
    if (site !== undefined && site !== "") {
      if (site === "same-origin" || site === "none") return;
      throw new PortvaktError("cross_site_request", "started from another site", 403);
    }
    const referer = req.get("referer");
    if (referer !== undefined) {
      try {
        if (new URL(referer).origin === this.#origin) return;
      } catch {
        // Not a URL: fall through to the CSRF token.
      }
    }
    const loaded = await this.#load(req, undefined, false);
    if (csrf !== undefined && loaded !== null && safeEqual(csrf, loaded.data.csrfToken)) return;
    throw new PortvaktError("cross_site_request", "started from another site", 403);
  }

  async #callback(req: Request, res: Response): Promise<void> {
    res.set("Cache-Control", "no-store");
    const txId = this.#signedCookie(req, this.#txCookie);
    setCookie(res, this.#txCookie, "", { ...this.#cookieBase(), path: this.#mount, maxAge: 0 });
    if (txId === undefined) throw new LoginFailedError("login_expired", "no pending login");
    const txKey = storeKey("t", txId);
    // Single use, atomically: of two callbacks with the same cookie only one gets the login.
    const transaction = await this.#locked(txKey, async () => {
      const pending = await this.#readSealed(txKey, loginTransactionSchema);
      if (pending !== undefined) await this.#store.destroy(txKey);
      return pending;
    });
    if (
      transaction === undefined ||
      epochNow() - transaction.createdAt > this.#options.loginTimeoutSeconds
    ) {
      throw new LoginFailedError("login_expired", "the pending login expired");
    }
    const query = callbackQuerySchema.safeParse(req.query);
    if (!query.success) throw new LoginFailedError("invalid_request", "invalid callback");
    if (query.data.error !== undefined) {
      const code = OAUTH_ERROR.test(query.data.error) ? query.data.error : "login_failed";
      throw new LoginFailedError(code, "Portvakt refused the login", 400);
    }
    if (query.data.state === undefined || !safeEqual(query.data.state, transaction.state)) {
      throw new LoginFailedError("state_mismatch", "the login does not belong to this browser");
    }

    const configuration = await this.#discovery.get();
    const callbackUrl = new URL(this.#redirectUri);
    callbackUrl.search = new URL(req.originalUrl, "http://callback.invalid").search;
    let tokens: Awaited<ReturnType<typeof client.authorizationCodeGrant>>;
    try {
      tokens = await client.authorizationCodeGrant(configuration, callbackUrl, {
        pkceCodeVerifier: transaction.codeVerifier,
        expectedState: transaction.state,
        expectedNonce: transaction.nonce,
        idTokenExpected: true,
      });
    } catch (error) {
      this.#config.logger.warn(errorDetails(error), "login callback failed");
      if (isUnavailable(error)) throw new PortvaktUnavailableError(undefined, { cause: error });
      throw new LoginFailedError("login_failed", "the code exchange failed", 400, { cause: error });
    }
    const claims = idTokenClaimsSchema.safeParse(tokens.claims());
    if (!claims.success || tokens.id_token === undefined) {
      this.#config.logger.warn(
        { issues: claims.error?.issues.length },
        "unexpected ID token claims",
      );
      throw new LoginFailedError("login_failed", "the ID token does not follow the contract", 502);
    }
    const now = epochNow();
    const endsAt = Math.min(claims.data.session_exp ?? Infinity, now + this.#options.maxAgeSeconds);
    if (endsAt <= now) throw new LoginFailedError("login_failed", "the broker session has ended");
    // A step-up that did not reach its level changes nothing: the existing session stays as it
    // was, and no session is made from this login.
    if (
      transaction.acr !== undefined &&
      !acrAtLeast(claims.data.acr, transaction.acr, this.#config.acrRanking)
    ) {
      throw new LoginFailedError("acr_not_met", "the login did not reach the requested level", 403);
    }

    // Session fixation: a login always starts a new session id; the old session is gone.
    const oldId = this.#signedCookie(req, this.#options.cookie.name);
    if (oldId !== undefined) {
      const oldKey = storeKey("s", oldId);
      await this.#locked(oldKey, () => this.#store.destroy(oldKey));
    }
    const id = randomId();
    const key = storeKey("s", id);
    const data: SessionData = {
      v: 1,
      createdAt: now,
      lastSeenAt: now,
      endsAt,
      claims: claims.data,
      idToken: tokens.id_token,
      accessToken: tokens.access_token,
      accessTokenExpiresAt: now + (tokens.expiresIn() ?? 60),
      ...(tokens.refresh_token === undefined ? {} : { refreshToken: tokens.refresh_token }),
      csrfToken: randomId(),
    };
    await this.#write(key, data);
    setCookie(res, this.#options.cookie.name, this.#signer.sign(id), {
      ...this.#cookieBase(),
      maxAge: endsAt - now,
    });
    const loaded: Loaded = { key, data, principal: principalFromIdToken(data.claims) };
    this.#loaded.set(req, loaded);
    res.redirect(303, transaction.returnTo);
  }

  async #logout(req: Request, res: Response): Promise<void> {
    res.set("Cache-Control", "no-store");
    const loaded = await this.#load(req, res, false);
    const local = this.#config.postLogoutRedirectUri ?? this.#options.defaultReturnTo;
    if (loaded === null) {
      this.#redirectOrJson(req, res, local);
      return;
    }
    const bodyToken = (req.body as { _csrf?: unknown } | undefined)?._csrf;
    const presented = typeof bodyToken === "string" ? bodyToken : req.get("x-csrf-token");
    if (presented === undefined || !safeEqual(presented, loaded.data.csrfToken)) {
      throw new PortvaktError("invalid_csrf_token", "the CSRF token is missing or wrong", 403);
    }
    await this.#locked(loaded.key, () => this.#store.destroy(loaded.key));
    this.#loaded.set(req, null);
    this.#clearSessionCookie(res);
    let target = local;
    try {
      const configuration = await this.#discovery.get();
      if (configuration.serverMetadata().end_session_endpoint !== undefined) {
        target = client.buildEndSessionUrl(configuration, {
          id_token_hint: loaded.data.idToken,
          client_id: this.#config.clientId,
          ...(this.#config.postLogoutRedirectUri === undefined
            ? {}
            : { post_logout_redirect_uri: this.#config.postLogoutRedirectUri }),
        }).href;
      }
    } catch (error) {
      // Signed out locally; Portvakt's session stays until it ends on its own.
      this.#config.logger.warn(errorDetails(error), "RP-initiated logout skipped");
    }
    this.#redirectOrJson(req, res, target);
  }

  async #session(req: Request, res: Response): Promise<void> {
    res.set("Cache-Control", "no-store");
    // Reading the session state is not activity: a polling SPA must not defeat the idle timeout.
    const loaded = await this.#load(req, res, false);
    if (loaded === null) {
      res.json({ authenticated: false });
      return;
    }
    const info = this.#info(loaded);
    if (this.#options.sessionResponse !== undefined) {
      res.json({ authenticated: true, ...this.#options.sessionResponse(info) });
      return;
    }
    const { pin: _pin, ...principal } = info.principal;
    void _pin;
    res.json({
      authenticated: true,
      principal,
      expiresAt: info.expiresAt.toISOString(),
      sessionEndsAt: info.sessionEndsAt.toISOString(),
      csrfToken: info.csrfToken,
    });
  }

  // Middleware -----------------------------------------------------------------------------------

  #requireLogin(): RequestHandler {
    return this.#middleware(async (req, res, next) => {
      const loaded = await this.#load(req, res, true);
      if (loaded === null) {
        this.#unauthenticated(req, res);
        return;
      }
      next();
    });
  }

  #requireAcr(acr: string): RequestHandler {
    if (!ACR_VALUE.test(acr)) throw new PortvaktConfigError(["requireAcr: invalid acr value"]);
    return this.#middleware(async (req, res, next) => {
      const loaded = await this.#load(req, res, true);
      if (loaded === null) {
        this.#unauthenticated(req, res);
        return;
      }
      if (acrAtLeast(loaded.principal.acr, acr, this.#config.acrRanking)) {
        next();
        return;
      }
      const stepUpUrl = this.#stepUpUrl(acr, this.#returnToOf(req));
      if (isBrowserNavigation(req)) {
        res.set("Cache-Control", "no-store").redirect(302, stepUpUrl);
        return;
      }
      res
        .status(401)
        .set("Cache-Control", "no-store")
        .json({ error: "step_up_required", acr, stepUpUrl });
    });
  }

  #middleware(
    fn: (req: Request, res: Response, next: NextFunction) => Promise<void>,
  ): RequestHandler {
    return (req, res, next) => {
      fn(req, res, next).catch((error: unknown) => {
        if (error instanceof PortvaktError && !res.headersSent) {
          res.status(error.status).set("Cache-Control", "no-store").json({ error: error.code });
          return;
        }
        next(error);
      });
    };
  }

  #unauthenticated(req: Request, res: Response): void {
    const loginUrl = this.#loginUrl(this.#returnToOf(req));
    res.set("Cache-Control", "no-store");
    if (isBrowserNavigation(req)) {
      res.redirect(302, loginUrl);
      return;
    }
    res.status(401).json({ error: "login_required", loginUrl });
  }

  /**
   * Where to come back to after a login or step-up: the current URL of a browser navigation
   * (GET); for XHR the default (the SPA builds its own URL from the page it is on, as the API
   * URL is no page to return to).
   */
  #returnToOf(req: Request): string {
    const own =
      req.method === "GET" && isBrowserNavigation(req) ? safeReturnTo(req.originalUrl) : undefined;
    return own ?? this.#options.defaultReturnTo;
  }

  #loginUrl(returnTo?: string): string {
    const target = safeReturnTo(returnTo) ?? this.#options.defaultReturnTo;
    return `${this.#mount}/login?${new URLSearchParams({ returnTo: target }).toString()}`;
  }

  #stepUpUrl(acr: string, returnTo?: string): string {
    const target = safeReturnTo(returnTo) ?? this.#options.defaultReturnTo;
    return `${this.#mount}/step-up?${new URLSearchParams({ acr, returnTo: target }).toString()}`;
  }

  // Sessions -------------------------------------------------------------------------------------

  /** The request's session, cached for the request; ended sessions are removed. */
  async #load(req: Request, res: Response | undefined, touch: boolean): Promise<Loaded | null> {
    const cached = this.#loaded.get(req);
    if (cached !== undefined) return cached;
    const id = this.#signedCookie(req, this.#options.cookie.name);
    if (id === undefined) {
      this.#loaded.set(req, null);
      return null;
    }
    const key = storeKey("s", id);
    let data = await this.#readSealed(key, sessionDataSchema);
    const now = epochNow();
    const ended = data === undefined ? "no_session" : this.#endReason(data, now);
    if (data === undefined || ended !== undefined) {
      if (data !== undefined) await this.#locked(key, () => this.#store.destroy(key));
      if (res !== undefined) this.#clearSessionCookie(res);
      this.#loaded.set(req, null);
      return null;
    }
    if (touch && now - data.lastSeenAt >= this.#touchInterval()) {
      // Read-modify-write under the session lock, so a concurrent refresh is never overwritten.
      data =
        (await this.#locked(key, async () => {
          const current = await this.#readSealed(key, sessionDataSchema);
          if (current === undefined || this.#endReason(current, now) !== undefined) {
            return undefined;
          }
          const touched = { ...current, lastSeenAt: now };
          await this.#write(key, touched);
          return touched;
        })) ?? data;
    }
    const loaded: Loaded = { key, data, principal: principalFromIdToken(data.claims) };
    this.#loaded.set(req, loaded);
    return loaded;
  }

  #touchInterval(): number {
    return Math.min(60, Math.floor(this.#options.idleTimeoutSeconds / 4));
  }

  #endReason(data: SessionData, now: number): SessionEndReason | undefined {
    if (now >= data.endsAt) return "session_expired";
    if (now - data.lastSeenAt > this.#options.idleTimeoutSeconds) return "session_expired";
    // An outage marker alone never ends a session: only a refresh that fails after the grace
    // does (#outage), and a successful refresh clears the marker.
    return undefined;
  }

  #info(loaded: Loaded): SessionInfo {
    const idleEnd = loaded.data.lastSeenAt + this.#options.idleTimeoutSeconds;
    return {
      principal: loaded.principal,
      expiresAt: new Date(Math.min(loaded.data.endsAt, idleEnd) * 1000),
      sessionEndsAt: new Date(loaded.data.endsAt * 1000),
      csrfToken: loaded.data.csrfToken,
    };
  }

  async #getAccessToken(req: Request, options: GetAccessTokenOptions): Promise<string> {
    const minValidity = options.minValiditySeconds ?? this.#config.clockSkewSeconds + 30;
    const fresh = (data: SessionData): boolean =>
      data.accessTokenExpiresAt - epochNow() > minValidity;
    // Using the session's token is activity: it moves the idle timeout like requireLogin does.
    const loaded = await this.#load(req, undefined, true);
    if (loaded === null) throw new LoginRequiredError("no_session");
    if (fresh(loaded.data)) return loaded.data.accessToken;

    return this.#locked(loaded.key, async () => {
      // Another request (or replica) may have refreshed meanwhile.
      const current = await this.#readSealed(loaded.key, sessionDataSchema);
      if (current === undefined) throw new LoginRequiredError("no_session");
      const ended = this.#endReason(current, epochNow());
      if (ended !== undefined) {
        await this.#store.destroy(loaded.key);
        throw new LoginRequiredError(ended);
      }
      if (fresh(current)) {
        this.#remember(req, loaded.key, current);
        return current.accessToken;
      }
      const refreshed = await this.#refresh(loaded.key, current);
      this.#remember(req, loaded.key, refreshed);
      return refreshed.accessToken;
    });
  }

  /** One refresh (rotation) inside the session lock; the session ends on `invalid_grant`. */
  async #refresh(key: string, current: SessionData): Promise<SessionData> {
    if (current.refreshToken === undefined) {
      await this.#store.destroy(key);
      throw new LoginRequiredError("refresh_failed");
    }
    let response: Awaited<ReturnType<typeof client.refreshTokenGrant>>;
    try {
      const configuration = await this.#discovery.get();
      response = await client.refreshTokenGrant(configuration, current.refreshToken);
    } catch (error) {
      if (isUnavailable(error)) return this.#outage(key, current, error);
      if (error instanceof client.ResponseBodyError && error.error === "invalid_client") {
        // The application's own credentials are wrong: a configuration problem, not the
        // person's session. Keep the session and fail the request.
        this.#config.logger.error(errorDetails(error), "refresh refused: invalid_client");
        throw new PortvaktError("invalid_client", "Portvakt refused the client", 502, {
          cause: error,
        });
      }
      // invalid_grant (revoked, replayed, broker session ended) and anything else: the end.
      this.#config.logger.info(errorDetails(error), "refresh refused; the session ends");
      await this.#store.destroy(key);
      throw new LoginRequiredError("refresh_failed");
    }
    const now = epochNow();
    let claims = current.claims;
    let idToken = current.idToken;
    if (response.id_token !== undefined) {
      const parsed = idTokenClaimsSchema.safeParse(response.claims());
      if (!parsed.success || parsed.data.sub !== current.claims.sub) {
        await this.#store.destroy(key);
        throw new LoginRequiredError("refresh_failed");
      }
      claims = parsed.data;
      idToken = response.id_token;
    }
    const endsAt = Math.min(
      current.createdAt + this.#options.maxAgeSeconds,
      claims.session_exp ?? current.endsAt,
    );
    const { outageSince: _outage, ...rest } = current;
    void _outage;
    const next: SessionData = {
      ...rest,
      claims,
      idToken,
      endsAt,
      accessToken: response.access_token,
      accessTokenExpiresAt: now + (response.expiresIn() ?? 60),
      ...(response.refresh_token === undefined ? {} : { refreshToken: response.refresh_token }),
    };
    if (endsAt <= now) {
      await this.#store.destroy(key);
      throw new LoginRequiredError("session_expired");
    }
    await this.#write(key, next);
    return next;
  }

  /** Portvakt is unreachable: grace 0 ends the session, otherwise it survives the grace. */
  async #outage(key: string, current: SessionData, error: unknown): Promise<never> {
    const now = epochNow();
    this.#config.logger.warn(errorDetails(error), "Portvakt unreachable during refresh");
    const since = current.outageSince ?? now;
    if (this.#config.outageGraceSeconds === 0 || now - since > this.#config.outageGraceSeconds) {
      await this.#store.destroy(key);
      throw new LoginRequiredError("outage_grace_exceeded");
    }
    if (current.outageSince === undefined) await this.#write(key, { ...current, outageSince: now });
    throw new PortvaktUnavailableError("Portvakt is unavailable; the session continues", {
      cause: error,
    });
  }

  #remember(req: Request, key: string, data: SessionData): void {
    this.#loaded.set(req, { key, data, principal: principalFromIdToken(data.claims) });
  }

  /** Runs `fn` holding the session's lock: in this process, and in the store if it can. */
  #locked<T>(key: string, fn: () => Promise<T>): Promise<T> {
    const store = this.#store;
    return this.#mutex.run(key, () =>
      store.withLock === undefined ? fn() : store.withLock(key, fn),
    );
  }

  async #write(key: string, data: SessionData): Promise<void> {
    const idleEnd = data.lastSeenAt + this.#options.idleTimeoutSeconds;
    const expiresAt = new Date(Math.min(data.endsAt, idleEnd) * 1000);
    await this.#store.set(key, this.#sealer.seal(JSON.stringify(data), key), expiresAt);
  }

  async #readSealed<T>(key: string, schema: z.ZodType<T>): Promise<T | undefined> {
    const sealed = await this.#store.get(key);
    if (sealed === undefined) return undefined;
    const plaintext = this.#sealer.open(sealed, key);
    if (plaintext === undefined) {
      this.#config.logger.warn({}, "a stored session could not be decrypted");
      return undefined;
    }
    try {
      const parsed = schema.safeParse(JSON.parse(plaintext));
      return parsed.success ? parsed.data : undefined;
    } catch {
      return undefined;
    }
  }

  // Responses ------------------------------------------------------------------------------------

  #signedCookie(req: Request, name: string): string | undefined {
    const value = readCookie(req, name);
    if (value === undefined || value.length > 512) return undefined;
    return this.#signer.verify(value);
  }

  #cookieBase(): CookieAttributes {
    const cookie = this.#options.cookie;
    return {
      path: cookie.path,
      domain: cookie.domain,
      secure: cookie.secure,
      sameSite: cookie.sameSite,
    };
  }

  #clearSessionCookie(res: Response): void {
    if (res.headersSent) return;
    setCookie(res, this.#options.cookie.name, "", { ...this.#cookieBase(), maxAge: 0 });
  }

  #redirectOrJson(req: Request, res: Response, target: string): void {
    if (wantsJson(req)) {
      res.json({ redirectTo: target });
      return;
    }
    res.redirect(303, target);
  }

  #renderError(req: Request, res: Response, error: PortvaktError): void {
    if (res.headersSent) return;
    if (this.#options.onError !== undefined) {
      this.#options.onError(error, req, res);
      return;
    }
    res.status(error.status).set("Cache-Control", "no-store");
    if (wantsJson(req)) {
      res.json({ error: error.code });
      return;
    }
    const unavailable = error instanceof PortvaktUnavailableError;
    const title = unavailable
      ? "Inloggningstjänsten är inte tillgänglig just nu"
      : "Inloggningen kunde inte genomföras";
    const english = unavailable
      ? "The sign-in service is unavailable right now. Please try again in a moment."
      : "The sign-in could not be completed.";
    res
      .set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
      .type("html")
      .send(
        [
          "<!doctype html>",
          '<html lang="sv"><head><meta charset="utf-8">',
          '<meta name="viewport" content="width=device-width, initial-scale=1">',
          `<title>${escapeHtml(title)}</title></head><body>`,
          `<h1>${escapeHtml(title)}</h1>`,
          `<p lang="en">${escapeHtml(english)}</p>`,
          `<p>Felkod / error code: <code data-testid="portvakt-error-code">${escapeHtml(error.code)}</code></p>`,
          `<p><a href="${escapeHtml(this.#options.defaultReturnTo)}">Tillbaka / Back</a></p>`,
          "</body></html>",
        ].join("\n"),
      );
  }
}
