import express, { Router, type NextFunction, type Request, type Response } from "express";
import {
  basicClientId,
  bodyClientId,
  BodyTooLargeError,
  readReplayableForm,
} from "../http/client-id.js";
import {
  clientIpKey,
  tooManyRequests,
  type RateLimitCheck,
  type RequestLimits,
} from "../http/rate-limits.js";
import type { Logger } from "../logging/logger.js";
import {
  InteractionError,
  type InteractionContext,
  type InteractionService,
} from "./interactions.js";
import type { TenantProvider } from "./provider.js";
import { ProvidersNotReadyError, type ProviderRegistry } from "./registry.js";

export interface TenantRoutesOptions {
  readonly registry: ProviderRegistry;
  readonly interactions: InteractionService;
  readonly logger: Logger;
  /**
   * Mounts `POST /t/{slug}/interaction/{uid}/__test__/login`, which completes a login with the
   * JSON body given. Only ever true when NODE_ENV=test.
   */
  readonly testRoutes: boolean;
  /** `PUBLIC_URL` (an origin): the only host and protocol the providers ever see. */
  readonly publicUrl: string;
  /**
   * The login flow (interaction pages and API, upstream federation callbacks), mounted below
   * `/t/{slug}` once the tenant is resolved; it reads the tenant with {@link tenantOf}.
   */
  readonly loginRoutes?: Router;
  /** Rate limits of the authorization and token endpoints (none: unlimited, tests). */
  readonly limits?: RequestLimits;
  /** The login UI page shown when an authorization request is rate limited (HTML, 429). */
  readonly rateLimitedPage?: (req: Request, res: Response) => void;
}

/**
 * The baseline CSP of responses oidc-provider renders itself: nothing loads but own scripts and
 * styles, nothing frames them. Its auto-submitting `form_post` page (the session switch during a
 * login, `response_mode=form_post`) adds the hash of its one inline script to `script-src`
 * (`helpers/script_src_sha.js`), so no `'unsafe-inline'` is needed. Pages Portvakt renders for
 * the provider (errors, logout) set the login UI's own CSP.
 */
export const PROVIDER_CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "base-uri 'none'",
  "frame-ancestors 'none'",
].join("; ");

/** Provider endpoints that authenticate a client: limited per IP, then per client_id. */
const CLIENT_ENDPOINTS = new Set([
  "/token",
  "/token/introspection",
  "/token/revocation",
  "/request",
]);

/**
 * Pins what oidc-provider (Koa, with `proxy` on) derives from the request to `PUBLIC_URL`:
 * endpoint URLs in discovery and redirects must never follow a client-supplied `Host` or
 * `X-Forwarded-Host`, and whether cookies are Secure must not depend on `X-Forwarded-Proto`.
 * The client IP is the one Express resolved under TRUST_PROXY (`req.ip`), passed on as the only
 * `X-Forwarded-For` entry, so TRUST_PROXY affects the client IP and nothing else.
 */
export function pinRequestOrigin(req: Request, origin: URL): void {
  const ip = req.ip ?? req.socket.remoteAddress ?? "";
  req.headers.host = origin.host;
  req.headers["x-forwarded-host"] = origin.host;
  req.headers["x-forwarded-proto"] = origin.protocol.slice(0, -1);
  req.headers["x-forwarded-for"] = ip;
  delete req.headers.forwarded;
}

/** The tenant provider resolved for this request (inside the `/t/{slug}` routes). */
export const tenantOf = (res: Response): TenantProvider => {
  const tenant = (res.locals as { tenantProvider?: TenantProvider }).tenantProvider;
  if (tenant === undefined) throw new Error("tenant provider not resolved");
  return tenant;
};

const STATUS_BY_CODE: Readonly<Record<InteractionError["code"], number>> = {
  invalid_input: 400,
  interaction_not_found: 404,
  person_not_found: 403,
  login_method_unavailable: 403,
  wrong_prompt: 409,
  step_up_person_mismatch: 403,
};

function interactionContext(req: Request, res: Response): InteractionContext {
  const uid = req.params.uid;
  if (typeof uid !== "string") throw new InteractionError("interaction_not_found", "No uid");
  return { tenantProvider: tenantOf(res), uid, req, res };
}

/** Async route handler that maps interaction errors to JSON and passes the rest on. */
const handle =
  (fn: (req: Request, res: Response) => Promise<void>) =>
  (req: Request, res: Response, next: NextFunction): void => {
    res.setHeader("Cache-Control", "no-store");
    fn(req, res).catch((error: unknown) => {
      if (error instanceof InteractionError) {
        res.status(STATUS_BY_CODE[error.code]).json({ error: error.code });
        return;
      }
      next(error);
    });
  };

/**
 * Everything below `/t/{slug}`: the interaction routes (Express) and the tenant's oidc-provider
 * (discovery, JWKS, authorization, token, revocation, introspection, end session). An unknown or
 * suspended tenant gets 404 before anything is built.
 */
export function tenantRoutes(options: TenantRoutesOptions): Router {
  const router = Router();

  const origin = new URL(options.publicUrl);
  const resolveTenant = (req: Request, res: Response, next: NextFunction): void => {
    const slug = (req.params as { slug?: string }).slug ?? "";
    pinRequestOrigin(req, origin);
    options.registry
      .get(slug)
      .then((tenantProvider) => {
        if (tenantProvider === null) {
          res.status(404).json({ error: "not_found" });
          return;
        }
        (res.locals as { tenantProvider?: TenantProvider }).tenantProvider = tenantProvider;
        next();
      })
      .catch((error: unknown) => {
        if (error instanceof ProvidersNotReadyError) {
          res.status(503).set("Retry-After", "5").json({ error: "temporarily_unavailable" });
          return;
        }
        next(error);
      });
  };

  const interactions = Router();
  if (options.testRoutes) {
    interactions.post(
      "/interaction/:uid/__test__/login",
      express.json({ limit: "4kb" }),
      handle(async (req, res) => {
        const { returnTo } = await options.interactions.completeLogin(
          interactionContext(req, res),
          req.body as never,
        );
        res.redirect(303, returnTo);
      }),
    );
  }

  const limits = options.limits;
  /**
   * Rate limits in front of the provider: authorization requests per IP and per client_id (from
   * the query, or the form body of a POST), the client-authenticating endpoints per IP before
   * the provider, and per client_id (HTTP Basic, or the form body's client_id or
   * client_assertion) only for failed client authentication, after the provider answered (see
   * `chargeFailedClientAuthentication`). Refusals: OAuth error JSON (`temporarily_unavailable`)
   * on the token endpoints, the login UI page on authorization. IPv6 clients are keyed by /64.
   */
  const limitProvider = (req: Request, res: Response, next: NextFunction): void => {
    if (limits === undefined) {
      next();
      return;
    }
    const slug = (req.params as { slug?: string }).slug ?? "";
    const ip = clientIpKey(req);
    const path = req.path.replace(/\/+$/, "");
    const bodyTooLarge = (error: unknown): void => {
      if (error instanceof BodyTooLargeError) {
        res.status(413).set("Cache-Control", "no-store").json({
          error: "invalid_request",
          error_description: "request body too large",
        });
        return;
      }
      next(error);
    };
    if (path === "/auth" && (req.method === "GET" || req.method === "POST")) {
      const authorize = (clientId: string | undefined): void => {
        const checks: RateLimitCheck[] = [["authorizeIp", ip]];
        if (clientId !== undefined && clientId.length <= 255) {
          checks.push(["authorizeClient", `${slug}:${clientId}`]);
        }
        const outcome = limits.check(checks);
        if (outcome.allowed) {
          next();
          return;
        }
        tooManyRequests(res, outcome.retryAfterSeconds);
        if (options.rateLimitedPage === undefined) res.json({ error: "temporarily_unavailable" });
        else options.rateLimitedPage(req, res);
      };
      const fromQuery = typeof req.query.client_id === "string" ? req.query.client_id : undefined;
      if (req.method === "GET" || fromQuery !== undefined) {
        authorize(fromQuery);
        return;
      }
      // A POSTed authorization request carries its client_id in the form body.
      readReplayableForm(req).then((form) => {
        const fromBody = form?.get("client_id");
        authorize(fromBody === null ? undefined : fromBody);
      }, bodyTooLarge);
      return;
    }
    if (req.method !== "POST" || !CLIENT_ENDPOINTS.has(path)) {
      next();
      return;
    }
    const refuse = (retryAfterSeconds: number): void => {
      tooManyRequests(res, retryAfterSeconds).json({
        error: "temporarily_unavailable",
        error_description: "Too many requests; retry later",
      });
    };
    const byIp = limits.check([["tokenIp", ip]]);
    if (!byIp.allowed) {
      refuse(byIp.retryAfterSeconds);
      return;
    }
    const fromHeader = basicClientId(req.get("authorization"));
    const clientIdOf = async (): Promise<string | undefined> => {
      if (fromHeader !== undefined) return fromHeader;
      const form = await readReplayableForm(req);
      return form === undefined ? undefined : bodyClientId(form);
    };
    clientIdOf().then((clientId) => {
      if (clientId !== undefined) {
        chargeFailedClientAuthentication(res, limits, `${slug}:${clientId}`);
      }
      next();
    }, bodyTooLarge);
  };

  /**
   * The per-client bucket of the client-authenticating endpoints is charged only when the
   * provider refused the client's authentication (401 `invalid_client`), so a successful
   * authentication is never blocked by what other parties send in the client's name. Once the
   * bucket is empty, further failed authentications for that client answer 429 with
   * Retry-After instead of 401 (the per-IP limit before the provider bounds each sender).
   */
  function chargeFailedClientAuthentication(
    res: Response,
    limiter: RequestLimits,
    key: string,
  ): void {
    const end = res.end.bind(res) as (...args: unknown[]) => Response;
    (res as unknown as { end: (...args: unknown[]) => Response }).end = (...args: unknown[]) => {
      if (res.headersSent || res.statusCode !== 401) return end(...args);
      const outcome = limiter.check([["tokenClient", key]]);
      if (outcome.allowed) return end(...args);
      const body = JSON.stringify({
        error: "temporarily_unavailable",
        error_description: "Too many requests; retry later",
      });
      res.removeHeader("WWW-Authenticate");
      res.statusCode = 429;
      res.setHeader("Retry-After", String(outcome.retryAfterSeconds));
      res.setHeader("Cache-Control", "no-store");
      res.setHeader("Content-Type", "application/json; charset=utf-8");
      res.setHeader("Content-Length", String(Buffer.byteLength(body)));
      const callback = args.find((arg) => typeof arg === "function");
      return callback === undefined ? end(body) : end(body, callback);
    };
  }

  const toProvider = (req: Request, res: Response): void => {
    const tenantProvider = tenantOf(res);
    res.setHeader("Content-Security-Policy", PROVIDER_CSP);
    // oidc-provider derives its mount path from `originalUrl.indexOf(url)`, which picks the wrong
    // prefix for a slug that starts with a route name (`/t/authority/auth`). Without
    // `originalUrl` it uses `baseUrl`, which is exactly the tenant's base path.
    Reflect.deleteProperty(req, "originalUrl");
    req.baseUrl = tenantProvider.basePath;
    tenantProvider.handle(req, res);
  };

  const tenantScoped =
    options.loginRoutes === undefined ? [interactions] : [interactions, options.loginRoutes];
  router.use("/t/:slug", resolveTenant, ...tenantScoped, limitProvider, toProvider);
  return router;
}
