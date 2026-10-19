import { existsSync } from "node:fs";
import { join } from "node:path";
import {
  createPortvaktClient,
  MemoryStore,
  PortvaktUnavailableError,
  type PortvaktLogger,
  type Principal,
  type SessionStore,
} from "@portvakt/sdk-node";
import express, { type Express, type RequestHandler } from "express";
import type { DemoConfig } from "./config.js";

export interface DemoAppOptions {
  /** Default: a MemoryStore (the demo runs as one instance). */
  readonly sessionStore?: SessionStore;
  readonly logger?: PortvaktLogger;
}

/** What the demo API answers: who called, as the access token says. */
function describe(principal: Principal | undefined): Record<string, unknown> {
  if (principal === undefined) return {};
  if (principal.isService) {
    return { isService: true, clientId: principal.clientId, tenant: principal.tenant };
  }
  return {
    isService: false,
    sub: principal.sub,
    tenant: principal.tenant,
    idpKind: principal.idpKind,
    acr: principal.acr,
    roles: principal.roles,
    rep: principal.rep ?? null,
    clientId: principal.clientId,
  };
}

/**
 * The demo service: the SDK's BFF below `/auth`, a small JSON API below `/api` protected by
 * access tokens, `/app/*` routes for the SPA, and the SPA itself.
 */
export function createDemoApp(config: DemoConfig, options: DemoAppOptions = {}): Express {
  // http to Portvakt only for local development; in production the SDK then refuses the issuer.
  const insecure = !config.production && new URL(config.issuer).protocol === "http:";
  const portvakt = createPortvaktClient({
    issuer: config.issuer,
    clientId: config.clientId,
    clientAuth: { method: "client_secret_basic", clientSecret: config.clientSecret },
    redirectUri: `${config.publicUrl}/auth/callback`,
    postLogoutRedirectUri: `${config.publicUrl}/`,
    scopes: config.scopes,
    outageGraceSeconds: config.outageGraceSeconds,
    allowInsecureRequests: insecure,
    ...(options.logger === undefined ? {} : { logger: options.logger }),
  });
  const bff = portvakt.bff({
    sessionStore: options.sessionStore ?? new MemoryStore(),
    encryptionKey: config.sessionEncryptionKeys,
    cookie: {
      name: config.cookieName,
      secrets: config.cookieSecrets,
      secure: config.cookieSecure,
    },
    idleTimeoutSeconds: config.idleTimeoutSeconds,
  });

  const app = express();
  app.disable("x-powered-by");
  const issuerOrigin = new URL(config.issuer).origin;
  const hsts = config.publicUrl.startsWith("https://");
  const securityHeaders: RequestHandler = (_req, res, next) => {
    res.set({
      // Logout posts a form here and is redirected to Portvakt: form-action must allow it.
      "Content-Security-Policy": [
        "default-src 'self'",
        "img-src 'self' data:",
        "object-src 'none'",
        "base-uri 'none'",
        "frame-ancestors 'none'",
        `form-action 'self' ${issuerOrigin}`,
      ].join("; "),
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
      "X-Frame-Options": "DENY",
      "Cross-Origin-Opener-Policy": "same-origin",
      "Permissions-Policy": "camera=(), geolocation=(), microphone=(), payment=(), usb=()",
      ...(hsts ? { "Strict-Transport-Security": "max-age=31536000; includeSubDomains" } : {}),
    });
    next();
  };
  app.use(securityHeaders);

  app.get("/healthz", (_req, res) => {
    res.set("Cache-Control", "no-store").json({ status: "ok", app: config.appName });
  });

  app.use(bff);

  app.get("/app/config", (_req, res) => {
    res.set("Cache-Control", "no-store").json({
      appName: config.appName,
      clientId: config.clientId,
      stepUpAcr: config.stepUpAcr,
    });
  });

  // "Anropa API": the BFF fetches its own API with the session's access token.
  app.get("/app/api-call", bff.requireLogin(), (req, res, next) => {
    bff
      .getAccessToken(req)
      .then(async (token) => {
        const response = await fetch(`${config.apiUrl}/api/whoami`, {
          headers: { authorization: `Bearer ${token}`, accept: "application/json" },
          signal: AbortSignal.timeout(10_000),
        });
        const body: unknown = await response.json().catch(() => null);
        res.set("Cache-Control", "no-store").json({ status: response.status, body });
      })
      .catch(next);
  });

  app.get(
    "/api/whoami",
    portvakt.requireAccessToken({ audience: config.clientId, allowService: true }),
    (req, res) => {
      res.set("Cache-Control", "no-store").json({
        app: config.appName,
        principal: describe(portvakt.principal(req)),
      });
    },
  );
  app.use("/api", (_req, res) => {
    res.status(404).json({ error: "not_found" });
  });
  app.use(bff.errorHandler());

  const webDir = config.webDir;
  if (existsSync(join(webDir, "index.html"))) {
    app.use(express.static(webDir, { index: false, maxAge: "1h" }));
    app.get(/^\/(?!auth\/|api\/|app\/).*/, (_req, res) => {
      res.set("Cache-Control", "no-store").sendFile(join(webDir, "index.html"));
    });
  } else {
    app.get("/", (_req, res) => {
      res
        .type("text")
        .send(
          `${config.appName}: the web UI is not built. Run: npm run build -w examples/demo-service`,
        );
    });
  }

  app.use(((error: unknown, _req, res, next) => {
    if (res.headersSent) {
      next(error);
      return;
    }
    if (error instanceof PortvaktUnavailableError) {
      res.status(503).json({ error: "portvakt_unavailable" });
      return;
    }
    console.error("demo-service request failed:", error instanceof Error ? error.name : "error");
    res.status(500).json({ error: "server_error" });
  }) as express.ErrorRequestHandler);

  return app;
}
