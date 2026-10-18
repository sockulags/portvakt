import express, { Router, type NextFunction, type Request, type Response } from "express";
import type { Logger } from "../logging/logger.js";
import {
  InteractionError,
  loadInteraction,
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
}

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

const tenantOf = (res: Response): TenantProvider => {
  const tenant = (res.locals as { tenantProvider?: TenantProvider }).tenantProvider;
  if (tenant === undefined) throw new Error("tenant provider not resolved");
  return tenant;
};

const STATUS_BY_CODE: Readonly<Record<InteractionError["code"], number>> = {
  invalid_input: 400,
  interaction_not_found: 404,
  person_not_found: 403,
  login_method_unavailable: 403,
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
  // The login UI (M3) replaces this: for now the route only proves the interaction exists.
  interactions.get(
    "/interaction/:uid",
    handle(async (req, res) => {
      const details = await loadInteraction(interactionContext(req, res));
      res.status(501).json({
        error: "not_implemented",
        error_description: "The login interface is not available yet",
        prompt: details.prompt,
      });
    }),
  );
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

  const toProvider = (req: Request, res: Response): void => {
    const tenantProvider = tenantOf(res);
    // oidc-provider derives its mount path from `originalUrl.indexOf(url)`, which picks the wrong
    // prefix for a slug that starts with a route name (`/t/authority/auth`). Without
    // `originalUrl` it uses `baseUrl`, which is exactly the tenant's base path.
    Reflect.deleteProperty(req, "originalUrl");
    req.baseUrl = tenantProvider.basePath;
    tenantProvider.handle(req, res);
  };

  router.use("/t/:slug", resolveTenant, interactions, toProvider);
  return router;
}
