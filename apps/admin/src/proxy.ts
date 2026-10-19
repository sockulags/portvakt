import { timingSafeEqual } from "node:crypto";
import { LoginRequiredError, PortvaktUnavailableError, type PortvaktBff } from "@portvakt/sdk-node";
import express, { type Request, type RequestHandler, type Response } from "express";
import type { AdminConfig } from "./config.js";
import { TenantLookupError } from "./tenants.js";

/** The admin API below Portvakt's origin. */
export const ADMIN_API_PATH = "/admin/api/v1";

const SEGMENT = /^[A-Za-z0-9._~-]{1,200}$/;
const METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE"]);
const MUTATING = new Set(["POST", "PUT", "PATCH", "DELETE"]);
const MAX_QUERY = 4096;
const TIMEOUT_MS = 30_000;
/** Inline SAML metadata may be up to 10 MB. */
const raw = express.raw({ type: "application/json", limit: "11mb" });

function safeEqual(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

function fail(res: Response, status: number, code: string): void {
  res
    .status(status)
    .set("Cache-Control", "no-store")
    .type("application/problem+json")
    .send(JSON.stringify({ type: `urn:portvakt:problem:${code}`, title: code, status, code }));
}

/**
 * The API URL a proxied request goes to: only below the configured admin API base, built from
 * validated path segments (no dot segments, no encoded slashes) and the request's query.
 * `undefined` when the request names anything else.
 */
export function apiTarget(
  apiUrl: string,
  segments: readonly string[],
  query: string,
): URL | undefined {
  if (segments.length === 0 || segments.length > 12) return undefined;
  if (!segments.every((segment) => SEGMENT.test(segment) && segment !== "." && segment !== "..")) {
    return undefined;
  }
  if (query.length > MAX_QUERY || /[\s#]/.test(query)) return undefined;
  const base = new URL(`${apiUrl}${ADMIN_API_PATH}/`);
  const target = new URL(segments.join("/"), base);
  if (target.origin !== base.origin || !target.pathname.startsWith(base.pathname)) return undefined;
  target.search = query;
  return target;
}

/**
 * `ALL /t/{slug}/api/*` -> the admin API, with the session's access token. The SPA never sees a
 * token. Mutating requests need the session's CSRF token (`X-CSRF-Token`), a same-origin
 * `Sec-Fetch-Site`/`Origin` when the browser sends them, and a JSON body.
 */
export function apiProxy(
  config: AdminConfig,
  bffOf: (req: Request) => Promise<PortvaktBff | undefined>,
): RequestHandler {
  const portalOrigin = new URL(config.publicUrl).origin;
  return (req, res) => {
    void (async () => {
      const bff = await bffOf(req);
      if (bff === undefined || !METHODS.has(req.method)) {
        fail(res, 404, "not_found");
        return;
      }
      const session = await bff.loadSession(req);
      const slug = req.params.slug;
      if (session === undefined || session.principal.tenant !== slug) {
        fail(res, 401, "login_required");
        return;
      }
      if (MUTATING.has(req.method)) {
        const site = req.get("sec-fetch-site");
        const origin = req.get("origin");
        const token = req.get("x-csrf-token");
        if (
          (site !== undefined && site !== "same-origin") ||
          (origin !== undefined && origin !== portalOrigin) ||
          token === undefined ||
          !safeEqual(token, session.csrfToken)
        ) {
          fail(res, 403, "csrf_failed");
          return;
        }
      }
      const rest = (req.params as { rest?: string[] | string }).rest;
      const segments = Array.isArray(rest) ? rest : typeof rest === "string" ? rest.split("/") : [];
      const queryIndex = req.originalUrl.indexOf("?");
      const query = queryIndex < 0 ? "" : req.originalUrl.slice(queryIndex);
      const target = apiTarget(config.apiUrl, segments, query);
      if (target === undefined) {
        fail(res, 404, "not_found");
        return;
      }

      let body: Buffer | undefined;
      const hasBody =
        (req.get("content-length") ?? "0") !== "0" || req.get("transfer-encoding") !== undefined;
      if (hasBody) {
        if (!MUTATING.has(req.method) || !req.is("application/json")) {
          fail(res, 415, "unsupported_media_type");
          return;
        }
        const parsed = await new Promise<boolean>((resolve) => {
          raw(req, res, (error?: unknown) => resolve(error === undefined));
        });
        if (!parsed) {
          fail(res, 413, "payload_too_large");
          return;
        }
        body = Buffer.isBuffer(req.body) ? req.body : undefined;
      }

      const accessToken = await bff.getAccessToken(req);
      const headers: Record<string, string> = {
        authorization: `Bearer ${accessToken}`,
        accept: "application/json",
      };
      if (body !== undefined) headers["content-type"] = "application/json";
      const ifMatch = req.get("if-match");
      if (ifMatch !== undefined && ifMatch.length <= 256) headers["if-match"] = ifMatch;
      const upstream = await fetch(target, {
        method: req.method,
        headers,
        ...(body === undefined ? {} : { body: new Uint8Array(body) }),
        redirect: "manual",
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
      if (upstream.status === 401) {
        // The token was refused (roles changed, tenant suspended): sign in again.
        await upstream.body?.cancel();
        fail(res, 401, "login_required");
        return;
      }
      const type = upstream.headers.get("content-type") ?? "";
      res.status(upstream.status).set("Cache-Control", "no-store");
      const etag = upstream.headers.get("etag");
      if (etag !== null) res.set("ETag", etag);
      if (upstream.status === 204 || upstream.status === 304) {
        res.end();
        return;
      }
      if (!/^application\/(problem\+)?json\b/.test(type)) {
        await upstream.body?.cancel();
        fail(res, 502, "bad_gateway");
        return;
      }
      res.type(type).send(Buffer.from(await upstream.arrayBuffer()));
    })().catch((error: unknown) => {
      if (res.headersSent) return;
      if (error instanceof LoginRequiredError) {
        fail(res, 401, "login_required");
        return;
      }
      if (
        error instanceof TenantLookupError ||
        error instanceof PortvaktUnavailableError ||
        (error instanceof Error && error.name === "TimeoutError")
      ) {
        fail(res, 503, "unavailable");
        return;
      }
      console.error("admin proxy failed:", error instanceof Error ? error.name : "error");
      fail(res, 502, "bad_gateway");
    });
  };
}
