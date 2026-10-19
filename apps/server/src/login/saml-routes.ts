import express, { Router, type NextFunction, type Request, type Response } from "express";
import type { FederationService } from "../federation/service.js";
import type { AutoPostForm, SloOutcome } from "../federation/saml/service.js";
import type { TenantProvider } from "../oidc/provider.js";
import { LOGIN_UI_HEADERS, localeHints, type LoginUiShell } from "./ui-shell.js";

/** The script that submits the HTTP-POST binding forms (the pages allow no inline script). */
export const SAML_AUTOSUBMIT_PATH = "/ui/saml/autosubmit.js";

const AUTOSUBMIT_SCRIPT = `"use strict";
(function () {
  var form = document.querySelector("form[data-pv-autosubmit]");
  if (form) form.submit();
})();
`;

/** Serves {@link SAML_AUTOSUBMIT_PATH} (mounted at the application root). */
export function samlAssetRoutes(): Router {
  const router = Router();
  router.get(SAML_AUTOSUBMIT_PATH, (_req, res) => {
    res
      .set({
        "Content-Type": "text/javascript; charset=utf-8",
        "Cache-Control": "public, max-age=3600",
        "X-Content-Type-Options": "nosniff",
      })
      .send(AUTOSUBMIT_SCRIPT);
  });
  return router;
}

const ESCAPES: Readonly<Record<string, string>> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
};
const escapeHtml = (value: string): string =>
  value.replace(/[&<>"']/g, (char) => ESCAPES[char] ?? char);

/**
 * An HTTP-POST binding page: a form to `form.action` with the SAML message, submitted by the
 * external autosubmit script (a button without JavaScript). Its CSP allows the form to go to the
 * IdP's origin only.
 */
function renderAutoPost(res: Response, form: AutoPostForm): void {
  const inputs = Object.entries(form.fields)
    .map(
      ([name, value]) =>
        `<input type="hidden" name="${escapeHtml(name)}" value="${escapeHtml(value)}">`,
    )
    .join("\n");
  const html = `<!doctype html>
<html lang="sv">
<head>
<meta charset="utf-8">
<meta name="robots" content="noindex">
<title>Portvakt</title>
<script src="${SAML_AUTOSUBMIT_PATH}" defer></script>
</head>
<body>
<form method="post" action="${escapeHtml(form.action)}" data-pv-autosubmit>
${inputs}
<noscript><button type="submit">Fortsätt / Continue</button></noscript>
</form>
</body>
</html>`;
  res
    .status(200)
    .set({
      ...LOGIN_UI_HEADERS,
      "Content-Security-Policy": [
        "default-src 'none'",
        "script-src 'self'",
        `form-action ${new URL(form.action).origin}`,
        "base-uri 'none'",
        "frame-ancestors 'none'",
      ].join("; "),
    })
    .send(html);
}

export interface SamlRoutesOptions {
  readonly federation: FederationService;
  readonly shell: LoginUiShell;
  readonly tenantOf: (res: Response) => TenantProvider;
  /**
   * Rate limit of every SP endpoint (per IP; answers with the login UI's page): the metadata,
   * the HTTP-POST pages, the ACS and SLO.
   */
  readonly limit?: (req: Request, res: Response, next: NextFunction) => void;
}

/** String-valued fields of a query or form body (repeated or nested values are dropped). */
function stringFields(source: unknown): Record<string, string> {
  const fields: Record<string, string> = {};
  if (typeof source !== "object" || source === null) return fields;
  for (const [key, value] of Object.entries(source)) {
    if (typeof value === "string") fields[key] = value;
  }
  return fields;
}

/**
 * The SP endpoints of SAML login methods below `/t/{slug}/saml/{loginMethodId}` (the SP's
 * entityID):
 *
 * - `GET  /metadata`: SP metadata (what the tenant registers with the federation or IdP);
 * - `GET  /post?RelayState=`: the HTTP-POST binding page of a pending AuthnRequest;
 * - `POST /acs`: the AssertionConsumerService (HTTP-POST, cross-site: no cookies are used);
 * - `GET|POST /slo`: single logout (HTTP-Redirect and HTTP-POST bindings);
 * - `GET  /logout?RelayState=`: the HTTP-POST page of an SP-initiated LogoutRequest.
 */
export function samlRoutes(options: SamlRoutesOptions): Router {
  const { federation, shell, tenantOf } = options;
  const saml = federation.saml;
  const router = Router();
  const limit = options.limit ?? ((_req: Request, _res: Response, next: NextFunction) => next());
  // A Response is at most 512 KB of XML (federation/saml/xml.ts): about 700 KB base64 encoded,
  // more once form-encoded.
  const form = express.urlencoded({ extended: false, limit: "1mb", parameterLimit: 10 });
  // Logout messages are at most 64 KB of XML.
  const logoutForm = express.urlencoded({ extended: false, limit: "128kb", parameterLimit: 10 });
  type Handler = (req: Request, res: Response) => Promise<void>;
  const run =
    (fn: Handler) =>
    (req: Request, res: Response, next: NextFunction): void => {
      res.setHeader("Cache-Control", "no-store");
      fn(req, res).catch(next);
    };
  const methodId = (req: Request): string =>
    typeof req.params.loginMethodId === "string" ? req.params.loginMethodId : "";
  const sendError = (req: Request, res: Response, status: number): void => {
    res
      .status(status)
      .set(LOGIN_UI_HEADERS)
      .send(
        shell.render({
          view: "error",
          code: "request_failed",
          oauthError: status === 404 ? "not_found" : "invalid_request",
          locale: localeHints(undefined, req.get("accept-language")),
        }),
      );
  };
  const sendSlo = (req: Request, res: Response, outcome: SloOutcome): void => {
    if (outcome.kind === "redirect") {
      res.redirect(303, outcome.url);
      return;
    }
    if (outcome.kind === "post") {
      renderAutoPost(res, outcome.form);
      return;
    }
    if (outcome.kind === "logged_out") {
      res
        .status(200)
        .set(LOGIN_UI_HEADERS)
        .send(
          shell.render({
            view: "logged_out",
            locale: localeHints(undefined, req.get("accept-language")),
          }),
        );
      return;
    }
    sendError(req, res, outcome.status);
  };

  router.get(
    "/saml/:loginMethodId/metadata",
    limit,
    run(async (req, res) => {
      const xml = await saml.spMetadata(tenantOf(res), methodId(req));
      if (xml === null) {
        res.status(404).json({ error: "not_found" });
        return;
      }
      res
        .set({
          "Content-Type": "application/samlmetadata+xml; charset=utf-8",
          "Cache-Control": "public, max-age=300",
          "X-Content-Type-Options": "nosniff",
        })
        .send(xml);
    }),
  );

  router.get(
    "/saml/:loginMethodId/post",
    limit,
    run(async (req, res) => {
      const relayState = typeof req.query.RelayState === "string" ? req.query.RelayState : "";
      const message = await saml.postForm(tenantOf(res), methodId(req), relayState);
      if (message === null) {
        sendError(req, res, 404);
        return;
      }
      renderAutoPost(res, message);
    }),
  );

  // The HTTP-POST page of an SP-initiated LogoutRequest (rendered once).
  router.get(
    "/saml/:loginMethodId/logout",
    limit,
    run(async (req, res) => {
      const relayState = typeof req.query.RelayState === "string" ? req.query.RelayState : "";
      const message = await saml.logoutForm(tenantOf(res), relayState);
      if (message === null) {
        sendError(req, res, 404);
        return;
      }
      renderAutoPost(res, message);
    }),
  );

  router.post(
    "/saml/:loginMethodId/acs",
    limit,
    form,
    run(async (req, res) => {
      res.redirect(303, await saml.acs(tenantOf(res), methodId(req), req.body));
    }),
  );

  router.get(
    "/saml/:loginMethodId/slo",
    limit,
    run(async (req, res) => {
      const query = req.originalUrl.includes("?")
        ? req.originalUrl.slice(req.originalUrl.indexOf("?") + 1)
        : "";
      sendSlo(
        req,
        res,
        await saml.slo(tenantOf(res), methodId(req), {
          binding: "redirect",
          fields: stringFields(req.query),
          rawQuery: query,
        }),
      );
    }),
  );

  router.post(
    "/saml/:loginMethodId/slo",
    limit,
    logoutForm,
    run(async (req, res) => {
      sendSlo(
        req,
        res,
        await saml.slo(tenantOf(res), methodId(req), {
          binding: "post",
          fields: stringFields(req.body),
          rawQuery: "",
        }),
      );
    }),
  );

  return router;
}
