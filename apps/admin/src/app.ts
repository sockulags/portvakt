import { existsSync } from "node:fs";
import { join } from "node:path";
import { MemoryStore, type PortvaktLogger, type SessionStore } from "@portvakt/sdk-node";
import express, { type Express, type RequestHandler } from "express";
import type { AdminConfig } from "./config.js";
import { apiProxy } from "./proxy.js";
import { SLUG, TenantClients, TenantLookupError } from "./tenants.js";

export interface AdminAppOptions {
  /** Default: a MemoryStore (development; production configures Postgres in main.ts). */
  readonly sessionStore?: SessionStore;
  readonly logger?: PortvaktLogger;
  /** How the BFF asks Portvakt whether a tenant exists (tests). */
  readonly fetch?: typeof fetch;
}

const TENANT_PATH = /^\/t\/([^/?#]+)(?:[/?#]|$)/;

/**
 * The admin portal: per tenant `/t/{slug}/auth/*` (the SDK's BFF for that tenant's issuer),
 * `/t/{slug}/api/*` (the proxy to the admin API) and `/t/{slug}/*` (the SPA). `/` goes to the
 * default tenant (the system tenant: platform administrators).
 */
export function createAdminApp(config: AdminConfig, options: AdminAppOptions = {}): Express {
  const clients = new TenantClients(
    config,
    options.sessionStore ?? new MemoryStore(),
    options.logger,
    options.fetch,
  );
  const app = express();
  app.disable("x-powered-by");
  app.set("trust proxy", false);

  // HSTS whenever the portal is served over https (ADMIN_PUBLIC_URL).
  const hsts = config.publicUrl.startsWith("https://");
  const securityHeaders: RequestHandler = (_req, res, next) => {
    res.set({
      "Content-Security-Policy": [
        "default-src 'self'",
        "img-src 'self' data:",
        "object-src 'none'",
        "base-uri 'none'",
        "frame-ancestors 'none'",
        "form-action 'self'",
      ].join("; "),
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
      "X-Frame-Options": "DENY",
      "Cross-Origin-Opener-Policy": "same-origin",
      ...(hsts ? { "Strict-Transport-Security": "max-age=31536000; includeSubDomains" } : {}),
    });
    next();
  };
  app.use(securityHeaders);

  app.get("/healthz", (_req, res) => {
    res.set("Cache-Control", "no-store").json({ status: "ok" });
  });
  app.get("/", (_req, res) => {
    res.redirect(302, `/t/${config.defaultTenant}/`);
  });

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
    apiProxy(config, (req) => bffOf(req.path)),
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
    console.error("admin portal request failed:", error instanceof Error ? error.name : "error");
    res.status(500).json({ error: "server_error" });
  }) as express.ErrorRequestHandler);
  return app;
}
