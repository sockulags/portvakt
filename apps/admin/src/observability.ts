import { currentRequest, logIds } from "@portvakt/http-kit";
import type { PortvaktLogger } from "@portvakt/sdk-node";
import { pino, type DestinationStream } from "pino";
import type { AdminConfig } from "./config.js";

/**
 * The portal's structured JSON logger: one object per line, with the request and trace ids of
 * the request being handled (`@portvakt/http-kit` request context) on every line. Credentials
 * that slip into a log call are censored; callers log ids and reason codes only (never tokens,
 * names or personal identity numbers).
 */
export function createAdminLogger(
  level: AdminConfig["logLevel"],
  destination?: DestinationStream,
): PortvaktLogger & pino.Logger {
  const settings: pino.LoggerOptions = {
    level,
    base: { service: "portvakt-admin" },
    timestamp: pino.stdTimeFunctions.isoTime,
    mixin: () => ({ ...logIds() }),
    formatters: { level: (label: string) => ({ level: label }) },
    redact: {
      paths: [
        "*.authorization",
        "*.cookie",
        "*.token",
        "*.access_token",
        "*.refresh_token",
        "*.id_token",
        "*.code",
        "*.secret",
        "*.client_secret",
      ],
      censor: "[redacted]",
    },
  };
  return destination === undefined ? pino(settings) : pino(settings, destination);
}

/** The ids a problem response carries (support and log correlation). */
export function requestIds(): { readonly requestId?: string; readonly traceId?: string } {
  const context = currentRequest();
  return context === undefined ? {} : { requestId: context.requestId, traceId: context.traceId };
}

/** Route templates of the portal for metrics: never slugs, ids or asset names. */
export function adminRouteTemplate(path: string): string {
  if (path === "/" || path === "/healthz" || path === "/metrics") return path;
  if (path.startsWith("/assets/")) return "/assets/{asset}";
  const tenant = /^\/t\/[^/]+(\/.*)?$/.exec(path);
  if (tenant === null) return "other";
  const rest = tenant[1] ?? "";
  const auth = /^\/auth\/(login|step-up|select-representation|callback|logout|session)\/?$/.exec(
    rest,
  );
  if (auth !== null) return `/t/{slug}/auth/${auth[1] ?? ""}`;
  if (rest.startsWith("/auth/")) return "/t/{slug}/auth/{other}";
  if (rest.startsWith("/api/")) return "/t/{slug}/api/{path}";
  return "/t/{slug}/{page}";
}
