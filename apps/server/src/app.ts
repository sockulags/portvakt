import {
  httpMetricsMiddleware,
  requestContextMiddleware,
  securityHeadersMiddleware,
} from "@portvakt/http-kit";
import express, {
  type ErrorRequestHandler,
  type Express,
  type Request,
  type RequestHandler,
  type Response,
  type Router,
} from "express";
import type { TrustProxy } from "./config/index.js";
import { routeTemplate } from "./http/route-template.js";
import type { Logger } from "./logging/logger.js";
import { requestLogger } from "./logging/request-logger.js";
import type { MetricRegistry } from "./metrics/registry.js";

export interface ReadinessReport {
  readonly ready: boolean;
  readonly checks: Readonly<Record<string, boolean>>;
}

export interface AppOptions {
  readonly logger: Logger;
  readonly trustProxy: TrustProxy;
  /** `/readyz`: database reachable and signing keys loaded (and not shutting down). */
  readonly readiness: () => Promise<ReadinessReport>;
  /** True once graceful shutdown started: responses ask clients to close the connection. */
  readonly isDraining?: () => boolean;
  readonly routes?: readonly Router[];
  /** HSTS on every response (PUBLIC_URL is https). */
  readonly hsts?: boolean;
  /** Longest request URL (MAX_URL_LENGTH); longer ones get 414 before routing. */
  readonly maxUrlLength?: number;
  /** HTTP request counts and latency by route template are recorded here. */
  readonly metrics?: MetricRegistry;
  /** `GET /metrics` on this app (when metrics are not served on a port of their own). */
  readonly metricsEndpoint?: RequestHandler;
}

/** `res.locals` key a router may set to name its route template (the admin API does). */
export const ROUTE_TEMPLATE = "routeTemplate";

type Locals = { routeTemplate?: string; requestPath?: string };

/** The route template of a finished request (metrics labels: never raw paths). */
function templateOf(res: Response): string {
  const locals = res.locals as Locals;
  return locals.routeTemplate ?? routeTemplate(locals.requestPath ?? "");
}

/**
 * The HTTP surface: the request context (W3C traceparent, request ids in every log line),
 * request logging and metrics, the baseline security headers (`@portvakt/http-kit`; pages set
 * their own CSP), the URL length bound, health probes, then the mounted routers (tenant issuers
 * below `/t/{slug}`). No global body parser: oidc-provider reads request bodies itself, and
 * every route that reads one sets its own limit.
 */
export function createApp(options: AppOptions): Express {
  const app = express();
  app.disable("x-powered-by");
  app.set("trust proxy", options.trustProxy);
  app.use(requestContextMiddleware());
  app.use((req: Request, res: Response, next) => {
    (res.locals as Locals).requestPath = req.path;
    next();
  });
  app.use(requestLogger(options.logger));
  if (options.metrics !== undefined) {
    app.use(
      httpMetricsMiddleware(options.metrics, {
        prefix: "portvakt",
        routeOf: (_req, res) => templateOf(res as Response),
      }),
    );
  }
  app.use(securityHeadersMiddleware({ hsts: options.hsts ?? false }));

  const maxUrlLength = options.maxUrlLength;
  if (maxUrlLength !== undefined) {
    app.use((req, res, next) => {
      if (req.originalUrl.length > maxUrlLength) {
        res.status(414).set("Cache-Control", "no-store").json({ error: "uri_too_long" });
        return;
      }
      next();
    });
  }

  const draining: RequestHandler = (_req, res, next) => {
    if (options.isDraining?.() === true) res.setHeader("Connection", "close");
    next();
  };
  app.use(draining);

  app.get("/healthz", (_req, res) => {
    res.set("Cache-Control", "no-store").json({ status: "ok" });
  });

  app.get("/readyz", (_req, res, next) => {
    options
      .readiness()
      .then((report) => {
        res
          .status(report.ready ? 200 : 503)
          .set("Cache-Control", "no-store")
          .json({ status: report.ready ? "ready" : "not_ready", checks: report.checks });
      })
      .catch(next);
  });

  if (options.metricsEndpoint !== undefined) app.all("/metrics", options.metricsEndpoint);

  for (const router of options.routes ?? []) app.use(router);

  app.use((_req, res) => {
    res.status(404).json({ error: "not_found" });
  });

  const onError: ErrorRequestHandler = (error: unknown, _req, res, next) => {
    if (res.headersSent) {
      next(error);
      return;
    }
    const status = (error as { status?: unknown }).status;
    if (typeof status === "number" && status >= 400 && status < 500) {
      // Body parser and similar client errors; the message is the library's, not user data.
      res.status(status).json({ error: "invalid_request" });
      return;
    }
    options.logger.error({ err: error }, "unhandled request error");
    res.status(500).json({ error: "server_error" });
  };
  app.use(onError);

  return app;
}
