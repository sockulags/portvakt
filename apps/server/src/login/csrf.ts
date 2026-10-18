import { createHmac, timingSafeEqual } from "node:crypto";
import type { NextFunction, Request, Response } from "express";

/**
 * CSRF protection of the state-changing interaction endpoints (JSON POSTs from the login UI):
 *
 * - a synchronizer token bound to the tenant and the interaction, an HMAC under the cookie keys
 *   (the first signs, all verify, like oidc-provider's cookies), handed out by the details
 *   endpoint and sent back in `X-CSRF-Token`;
 * - `Content-Type: application/json` (a cross-site form cannot send it without a CORS
 *   preflight, which is never granted);
 * - `Origin` (and `Sec-Fetch-Site`, when sent) must be this server's own origin.
 *
 * The interaction itself is bound to the browser by oidc-provider's interaction cookie.
 */
export const CSRF_HEADER = "x-csrf-token";

const mac = (key: string, tenantId: string, uid: string): Buffer =>
  createHmac("sha256", key).update(`portvakt-csrf\0${tenantId}\0${uid}`, "utf8").digest();

export function csrfToken(keys: readonly string[], tenantId: string, uid: string): string {
  const [key] = keys;
  if (key === undefined) throw new Error("No cookie key configured");
  return mac(key, tenantId, uid).toString("base64url");
}

export function verifyCsrfToken(
  keys: readonly string[],
  tenantId: string,
  uid: string,
  token: string,
): boolean {
  const presented = Buffer.from(token, "base64url");
  if (presented.length !== 32) return false;
  return keys.some((key) => timingSafeEqual(mac(key, tenantId, uid), presented));
}

/**
 * Express guard for the JSON POSTs of an interaction. `tenantId` and `uid` come from the
 * resolved route; failures answer 403 `{ error: "csrf" }` without detail.
 */
export function csrfGuard(options: {
  readonly keys: readonly string[];
  readonly origin: string;
  readonly tenantIdOf: (res: Response) => string;
}) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const refuse = (): void => {
      res.status(403).json({ error: "csrf" });
    };
    const origin = req.get("origin");
    if (origin !== undefined && origin !== options.origin) return refuse();
    const site = req.get("sec-fetch-site");
    if (site !== undefined && site !== "same-origin") return refuse();
    if (!req.is("application/json")) return refuse();
    const token = req.get(CSRF_HEADER);
    const uid = req.params.uid;
    if (token === undefined || typeof uid !== "string") return refuse();
    if (!verifyCsrfToken(options.keys, options.tenantIdOf(res), uid, token)) return refuse();
    next();
  };
}
