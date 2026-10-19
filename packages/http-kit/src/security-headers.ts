import type { IncomingMessage, ServerResponse } from "node:http";

/**
 * Response headers every Portvakt deployable sends on every response (HTML pages set their own,
 * stricter or page-specific Content-Security-Policy on top):
 *
 * - `Content-Security-Policy` for non-HTML responses: nothing may load, nothing may frame it;
 * - `X-Frame-Options: DENY` for browsers without `frame-ancestors`;
 * - `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`;
 * - `Cross-Origin-Opener-Policy: same-origin` (no cross-origin window references);
 * - `Permissions-Policy` turning off powerful features nothing here uses;
 * - `Strict-Transport-Security` when the deployable's public URL is https.
 */
export const JSON_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'";

export const PERMISSIONS_POLICY = [
  "accelerometer=()",
  "camera=()",
  "display-capture=()",
  "geolocation=()",
  "gyroscope=()",
  "magnetometer=()",
  "microphone=()",
  "midi=()",
  "payment=()",
  "usb=()",
].join(", ");

/** One year, subdomains included (no `preload`: that is an operator's decision). */
export const HSTS = "max-age=31536000; includeSubDomains";

export interface SecurityHeaderOptions {
  /** Send HSTS (the public URL is https). */
  readonly hsts: boolean;
}

export function baselineSecurityHeaders(options: SecurityHeaderOptions): Record<string, string> {
  return {
    "Content-Security-Policy": JSON_CSP,
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": PERMISSIONS_POLICY,
    ...(options.hsts ? { "Strict-Transport-Security": HSTS } : {}),
  };
}

/** Middleware setting {@link baselineSecurityHeaders}; handlers may override any of them. */
export function securityHeadersMiddleware(options: SecurityHeaderOptions) {
  const headers = Object.entries(baselineSecurityHeaders(options));
  return (_req: IncomingMessage, res: ServerResponse, next: () => void): void => {
    for (const [name, value] of headers) res.setHeader(name, value);
    next();
  };
}
