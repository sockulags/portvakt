import { existsSync } from "node:fs";
import { join } from "node:path";
import {
  httpMetricsMiddleware,
  metricsHandler,
  MetricRegistry,
  requestContextMiddleware,
  runWithRequest,
  currentRequest,
  securityHeadersMiddleware,
  TokenBucketLimiter,
} from "@portvakt/http-kit";
import {
  MemoryStore,
  silentLogger,
  type PortvaktLogger,
  type SessionStore,
} from "@portvakt/sdk-node";
import express, { type Express, type RequestHandler } from "express";
import type { AdminConfig } from "./config.js";
import { adminRouteTemplate } from "./observability.js";
import { apiProxy } from "./proxy.js";
import { SLUG, TenantClients, TenantLookupError } from "./tenants.js";

export interface AdminAppOptions {
  /** Default: a MemoryStore (development; production configures Postgres in main.ts). */
  readonly sessionStore?: SessionStore;
  /** Request lines, errors and the SDK's own logs (default: silent). */
  readonly logger?: PortvaktLogger;
  /** How the BFF asks Portvakt whether a tenant exists (tests). */
  readonly fetch?: typeof fetch;
  /** Where the portal's metrics are recorded (default: a registry of its own). */
  readonly metrics?: MetricRegistry;
}

const TENANT_PATH = /^\/t\/([^/?#]+)(?:[/?#]|$)/;
/** The BFF routes that start or finish a sign-in: rate limited per client IP. */
const LOGIN_ROUTE = /^\/t\/[^/]+\/auth\/(login|step-up|select-representation|callback)\/?$/;
const MAX_URL_LENGTH = 8192;

/**
 * The SPA's page CSP: own scripts, styles, fonts and API only, no framing, forms only to the
 * portal itself (sign-out posts to the BFF, which redirects).
 */
export const ADMIN_PAGE_CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self'",
  "manifest-src 'self'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join("; ");

const RATE_LIMITED_PAGE = `<!doctype html>
<html lang="sv">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Portvakt</title></head>
<body>
<h1>För många inloggningsförsök</h1>
<p>Vänta en stund och försök sedan igen.</p>
<p lang="en">Too many sign-in attempts. Please wait a moment and try again.</p>
</body>
</html>`;

/**
 * The admin portal: per tenant `/t/{slug}/auth/*` (the SDK's BFF for that tenant's issuer),
 * `/t/{slug}/api/*` (the proxy to the admin API) and `/t/{slug}/*` (the SPA). `/` goes to the
 * default tenant (the system tenant: platform administrators). Every request runs in a request
 * context (W3C traceparent, ids on every log line and problem response), is logged and counted
 * by route template, and gets the baseline security headers; sign-in routes are rate limited.
 */
export function createAdminApp(config: AdminConfig, options: AdminAppOptions = {}): Express {
  const logger = options.logger ?? silentLogger;
  const metrics = options.metrics ?? new MetricRegistry({ prefix: "portvakt_admin" });
  const clients = new TenantClients(
    config,
    options.sessionStore ?? new MemoryStore(),
    options.logger,
    options.fetch,
  );
  const app = express();
  app.disable("x-powered-by");
  app.set("trust proxy", config.trustProxy);

  app.use(requestContextMiddleware());
  app.use((req, res, next) => {
    const started = performance.now();
    const path = req.path;
    const context = currentRequest();
    res.on("finish", () => {
      const write = (): void => {
        const line = {
          req: { method: req.method, path },
          res: { status: res.statusCode },
          durationMs: Math.round(performance.now() - started),
        };
        if (res.statusCode >= 500) logger.error(line, "request failed");
        else if (path === "/healthz" || path === "/metrics") logger.debug(line, "request");
        else logger.info(line, "request");
      };
      if (context === undefined) write();
      else runWithRequest(context, write);
    });
    next();
  });
  app.use(
    httpMetricsMiddleware(metrics, {
      prefix: "portvakt_admin",
      routeOf: (req) => adminRouteTemplate((req.url ?? "").split("?", 1)[0] ?? ""),
    }),
  );
  // HSTS whenever the portal is served over https (ADMIN_PUBLIC_URL).
  app.use(securityHeadersMiddleware({ hsts: config.publicUrl.startsWith("https://") }));
  app.use((req, res, next) => {
    if (req.originalUrl.length > MAX_URL_LENGTH) {
      res.status(414).set("Cache-Control", "no-store").json({ error: "uri_too_long" });
      return;
    }
    next();
  });

  app.get("/healthz", (_req, res) => {
    res.set("Cache-Control", "no-store").json({ status: "ok" });
  });
  if (config.metrics.enabled) {
    app.all("/metrics", metricsHandler(metrics, { token: config.metrics.token }));
  }
  app.get("/", (_req, res) => {
    res.redirect(302, `/t/${config.defaultTenant}/`);
  });

  const refused = metrics.counter(
    "portvakt_admin_rate_limited_total",
    "Requests refused by a rate limit of the admin portal",
  );
  const loginLimit =
    config.loginRateLimit === null ? undefined : new TokenBucketLimiter(config.loginRateLimit);
  const limitLogins: RequestHandler = (req, res, next) => {
    if (loginLimit === undefined || req.method !== "GET" || !LOGIN_ROUTE.test(req.path)) {
      next();
      return;
    }
    const decision = loginLimit.take(req.ip ?? req.socket.remoteAddress ?? "unknown");
    if (decision.allowed) {
      next();
      return;
    }
    refused.inc({ limit: "login" });
    res
      .status(429)
      .set({
        "Retry-After": String(decision.retryAfterSeconds),
        "Cache-Control": "no-store",
        "Content-Type": "text/html; charset=utf-8",
      })
      .send(RATE_LIMITED_PAGE);
  };
  app.use(limitLogins);

  const bffOf = async (path: string) => {
    const slug = TENANT_PATH.exec(path)?.[1];
    return slug === undefined ? undefined : clients.get(slug);
  };
  const unavailable = (res: express.Response): void => {
    res.status(503).set("Retry-After", "5").json({ error: "unavailable" });
  };

  // The tenant's BFF routes (its mount path is /t/{slug}/auth); unknown tenants get 404.
  app.use((req, res, next) => {
    if (!req.path.includes("/auth/")) {
      next();
      return;
    }
    bffOf(req.path).then(
      (bff) => {
        if (bff === undefined) next();
        else bff(req, res, next);
      },
      (error: unknown) => {
        if (error instanceof TenantLookupError) unavailable(res);
        else next(error);
      },
    );
  });

  app.all(
    "/t/:slug/api/*rest",
    apiProxy(config, (req) => bffOf(req.path), logger),
  );

  const webDir = config.webDir;
  const built = existsSync(join(webDir, "index.html"));
  if (built)
    app.use(
      "/assets",
      express.static(join(webDir, "assets"), {
        index: false,
        immutable: config.production,
        maxAge: config.production ? "365d" : 0,
        fallthrough: false,
      }),
    );

  app.get("/t/:slug", (req, res, next) => {
    // Routing ignores a trailing slash: `/t/{slug}/` is the SPA below, not this redirect.
    if (req.path.endsWith("/")) {
      next();
      return;
    }
    if (!SLUG.test(req.params.slug)) {
      res.status(404).json({ error: "not_found" });
      return;
    }
    res.redirect(302, `/t/${req.params.slug}/`);
  });
  app.get("/t/:slug/{*page}", async (req, res) => {
    let bff;
    try {
      bff = await clients.get(req.params.slug);
    } catch (error) {
      if (!(error instanceof TenantLookupError)) throw error;
      unavailable(res);
      return;
    }
    if (bff === undefined) {
      res.status(404).type("text").send("This address does not point at an organisation.");
      return;
    }
    res.set("Cache-Control", "no-store");
    if (!built) {
      res.type("text").send("The admin portal is not built. Run: npm run build -w apps/admin");
      return;
    }
    res.set("Content-Security-Policy", ADMIN_PAGE_CSP);
    res.sendFile(join(webDir, "index.html"));
  });

  app.use((_req, res) => {
    res.status(404).json({ error: "not_found" });
  });
  app.use(((error: unknown, _req, res, next) => {
    if (res.headersSent) {
      next(error);
      return;
    }
    logger.error(
      { error: error instanceof Error ? error.name : "error" },
      "admin portal request failed",
    );
    res.status(500).json({ error: "server_error" });
  }) as express.ErrorRequestHandler);
  return app;
}
