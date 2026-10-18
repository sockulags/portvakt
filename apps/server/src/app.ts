import express, {
  type ErrorRequestHandler,
  type Express,
  type RequestHandler,
  type Router,
} from "express";
import type { TrustProxy } from "./config/index.js";
import type { Logger } from "./logging/logger.js";
import { requestLogger } from "./logging/request-logger.js";

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
}

/**
 * The HTTP surface: health probes, then the mounted routers (tenant issuers below `/t/{slug}`).
 * No global body parser: oidc-provider reads request bodies itself.
 */
export function createApp(options: AppOptions): Express {
  const app = express();
  app.disable("x-powered-by");
  app.set("trust proxy", options.trustProxy);
  app.use(requestLogger(options.logger));

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
