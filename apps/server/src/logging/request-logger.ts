import { currentRequest, runWithRequest } from "@portvakt/http-kit";
import type { RequestHandler } from "express";
import type { Logger } from "./logger.js";

/** Health probes and scrapes run every few seconds; they are logged at debug level only. */
const QUIET = new Set(["/healthz", "/readyz", "/metrics"]);

/**
 * Logs one line per request when the response finishes: method, path, status and duration, with
 * the request and trace ids of the request context (the logger's mixin adds them). The query
 * string is never logged (authorization requests carry codes, hints and state), nor are headers
 * or bodies. Runs inside the request context (`requestContextMiddleware`), which also echoes the
 * ids in the response.
 */
export function requestLogger(logger: Logger): RequestHandler {
  return (req, res, next) => {
    const started = performance.now();
    const path = req.originalUrl.split("?", 1)[0] ?? "";
    const context = currentRequest();
    const write = (): void => {
      const status = res.statusCode;
      const line = {
        req: { method: req.method, path },
        res: { status },
        durationMs: Math.round(performance.now() - started),
      };
      if (status >= 500) logger.error(line, "request failed");
      else if (QUIET.has(path)) logger.debug(line, "request");
      else logger.info(line, "request");
    };
    // 'finish' is emitted outside the request's async context: restore it for the ids.
    res.on("finish", () => (context === undefined ? write() : runWithRequest(context, write)));
    next();
  };
}
