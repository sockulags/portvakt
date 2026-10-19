import { Router } from "express";
import { ADMIN_API_BASE } from "../constants.js";
import { AdminAuthenticator } from "./auth.js";
import type { AdminDeps } from "./context.js";
import { ApiError, sendProblem } from "./problem.js";
import { mountRoutes, openApiDocument, type AdminRoute } from "./registry.js";
import { accessRoutes } from "./routes/access.js";
import { applicationRoutes } from "./routes/applications.js";
import { auditRoutes } from "./routes/audit.js";
import { dashboardRoutes } from "./routes/dashboard.js";
import { keyRoutes } from "./routes/keys.js";
import { loginMethodRoutes } from "./routes/login-methods.js";
import { personRoutes } from "./routes/persons.js";
import { representationRoutes } from "./routes/representation.js";
import { tenantRoutes } from "./routes/tenants.js";

export type { AdminDeps } from "./context.js";
export type { Caller } from "./auth.js";

/** Every operation of admin API v1. */
export function adminRoutes(deps: AdminDeps): AdminRoute[] {
  return [
    ...tenantRoutes(deps),
    ...dashboardRoutes(deps),
    ...applicationRoutes(deps),
    ...loginMethodRoutes(deps),
    ...accessRoutes(deps),
    ...personRoutes(deps),
    ...representationRoutes(deps),
    ...keyRoutes(deps),
    ...auditRoutes(deps),
  ];
}

export const OPENAPI_PATH = "/openapi.json";

/** The OpenAPI 3.1 document of admin API v1 (generated from the routes' zod schemas). */
export function adminOpenApi(deps: AdminDeps, routes = adminRoutes(deps)) {
  return openApiDocument(routes, {
    title: "Portvakt admin API",
    version: "1.0.0",
    description:
      "Administration of tenants, applications, login methods, roles, persons, representation, " +
      "signing keys and the audit log. Bearer access tokens of `portvakt-admin` from any active " +
      "tenant's issuer; platform administrators (platform-admin in the system tenant) manage " +
      "every tenant, tenant administrators only their own. Mutable resources carry an `etag`: " +
      "updates require If-Match. Errors are RFC 9457 problem details. See docs/admin-api.md.",
    serverUrl: `${deps.config.publicUrl}${ADMIN_API_BASE}`,
  });
}

/** The admin API router, mounted at {@link ADMIN_API_BASE}. */
export function adminApiRouter(deps: AdminDeps): Router {
  const routes = adminRoutes(deps);
  const document = adminOpenApi(deps, routes);
  const outer = Router();
  const api = Router();
  api.get(OPENAPI_PATH, (_req, res) => {
    res.set("Cache-Control", "no-cache").json(document);
  });
  api.use(
    mountRoutes({
      routes,
      authenticator: new AdminAuthenticator({
        publicUrl: deps.config.publicUrl,
        keyCache: deps.keyCache,
        repos: deps.repos,
      }),
      logger: deps.logger,
      limits: deps.limits,
    }),
  );
  api.use((_req, res) => {
    sendProblem(res, new ApiError("not_found"));
  });
  // The baseline security headers (app.ts) cover the API: nothing loads, nothing frames it.
  outer.use(
    ADMIN_API_BASE,
    (_req, res, next) => {
      res.set("Cache-Control", "no-store");
      next();
    },
    api,
  );
  return outer;
}
