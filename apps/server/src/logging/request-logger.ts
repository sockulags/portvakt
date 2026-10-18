import { randomUUID } from "node:crypto";
import type { RequestHandler } from "express";
import type { Logger } from "./logger.js";

const REQUEST_ID = /^[A-Za-z0-9._-]{1,128}$/;
/** Health probes run every few seconds; they are logged at debug level only. */
const PROBES = new Set(["/healthz", "/readyz"]);

/**
 * Logs one line per request when the response finishes: method, path, status and duration.
 * The query string is never logged (authorization requests carry codes, hints and state), nor
 * are headers or bodies. A well-formed incoming `X-Request-Id` is kept, otherwise one is
 * generated; it is echoed in the response.
 */
export function requestLogger(logger: Logger): RequestHandler {
  return (req, res, next) => {
    const started = performance.now();
    const incoming = req.get("x-request-id");
    const id = incoming !== undefined && REQUEST_ID.test(incoming) ? incoming : randomUUID();
    res.setHeader("X-Request-Id", id);
    const path = req.originalUrl.split("?", 1)[0] ?? "";
    res.on("finish", () => {
      const status = res.statusCode;
      const line = {
        req: { id, method: req.method, path },
        res: { status },
        durationMs: Math.round(performance.now() - started),
      };
      if (status >= 500) logger.error(line, "request failed");
      else if (PROBES.has(path)) logger.debug(line, "request");
      else logger.info(line, "request");
    });
    next();
  };
}
