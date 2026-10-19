import { readFileSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Logger } from "../logging/logger.js";

/**
 * The login UI (apps/login, a React SPA) is served by the server: every page of the login flow
 * (choose a login method, choose whom to act for, errors, logout confirmation, signed out) is
 * the SPA's `index.html` with a bootstrap JSON block telling it which view to show. The block is
 * `type="application/json"`, so it is data, never executed, and the strict CSP below needs no
 * inline script.
 *
 * The built assets are served from {@link LOGIN_UI_BASE} (the SPA's Vite `base`).
 */
export const LOGIN_UI_BASE = "/ui/login/";

/** Error views of the login UI. The codes are shared with apps/login (`src/api.ts`). */
export const LOGIN_ERROR_CODES = [
  "interaction_expired",
  "app_unavailable",
  "no_acceptable_method",
  "login_method_unavailable",
  "upstream_denied",
  "upstream_cancelled",
  "authentication_failed",
  "upstream_error",
  "upstream_response_invalid",
  "upstream_unavailable",
  "insufficient_assurance",
  "account_not_allowed",
  "invalid_identity",
  "state_invalid",
  "state_replayed",
  "state_expired",
  "no_representation_available",
  "representation_not_allowed",
  "step_up_person_mismatch",
  "rate_limited",
  "request_failed",
] as const;
export type LoginErrorCode = (typeof LOGIN_ERROR_CODES)[number];

export const isLoginErrorCode = (value: unknown): value is LoginErrorCode =>
  typeof value === "string" && (LOGIN_ERROR_CODES as readonly string[]).includes(value);

/** Language preferences; the SPA picks Swedish or English from them (ui_locales first). */
export interface LocaleHints {
  readonly uiLocales: readonly string[];
  readonly acceptLanguage: readonly string[];
}

export type UiBootstrap = { readonly locale: LocaleHints } & (
  | {
      /** Choose a login method; the SPA loads `/t/{slug}/interaction/{uid}/details`. */
      readonly view: "login";
      readonly tenant: string;
      readonly uid: string;
      /** Set after a failed upstream login: shown above the methods, with a retry. */
      readonly error?: LoginErrorCode;
    }
  | {
      /**
       * Choose whom to act for (representation); the SPA loads
       * `/t/{slug}/interaction/{uid}/representation`.
       */
      readonly view: "representation";
      readonly tenant: string;
      readonly uid: string;
      /** `no_representation_available`: nothing to choose; only the way back is offered. */
      readonly error?: LoginErrorCode;
    }
  | {
      readonly view: "error";
      readonly code: LoginErrorCode;
      /** OAuth error code, for `request_failed` only (no descriptions, no request values). */
      readonly oauthError?: string;
    }
  /** RP-initiated logout: the SPA's buttons submit oidc-provider's `op.logoutForm`. */
  | { readonly view: "logout" }
  | { readonly view: "logged_out" }
);

/** CSP of every login UI page: own scripts, styles and API only; no framing. */
export const LOGIN_UI_CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self'",
  "base-uri 'none'",
  // No form-action: the logout form ends in a redirect to the application, which browsers check
  // against form-action as well.
  "frame-ancestors 'none'",
].join("; ");

/** Headers of every login UI page. */
export const LOGIN_UI_HEADERS: Readonly<Record<string, string>> = {
  "Content-Type": "text/html; charset=utf-8",
  "Cache-Control": "no-store",
  "Content-Security-Policy": LOGIN_UI_CSP,
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
};

/** apps/login/dist, next to this workspace (src/login -> apps/server -> apps). */
export const DEFAULT_LOGIN_UI_DIR = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../../../login/dist",
);

/** JSON for embedding in HTML: `<`, `>` and `&` are escaped, so the data cannot end the script block. */
function embedJson(value: unknown): string {
  return JSON.stringify(value)
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/&/g, "\\u0026");
}

const FALLBACK_SHELL = `<!doctype html>
<html lang="sv">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Portvakt</title>
</head>
<body>
<div id="root"><p>The login interface is not built. Run <code>npm run build -w apps/login</code>.</p></div>
</body>
</html>`;

export interface LoginUiShellOptions {
  /** Directory with the built SPA (`index.html`); defaults to apps/login/dist. */
  readonly dir?: string | undefined;
  /** Production: the build must exist (checked at start) and is read once. */
  readonly production: boolean;
  readonly logger: Logger;
}

export class LoginUiShell {
  readonly dir: string;
  readonly #production: boolean;
  readonly #logger: Logger;
  #cached: { readonly html: string; readonly mtimeMs: number } | undefined;
  #warned = false;

  constructor(options: LoginUiShellOptions) {
    this.dir = options.dir ?? DEFAULT_LOGIN_UI_DIR;
    this.#production = options.production;
    this.#logger = options.logger;
  }

  get #indexPath(): string {
    return join(this.dir, "index.html");
  }

  /** Throws unless the built SPA exists (production start-up check). */
  assertBuilt(): void {
    statSync(this.#indexPath);
  }

  /**
   * The page for `bootstrap`. `bodyPrefix` is trusted, library-generated markup placed before
   * the SPA root (oidc-provider's hidden logout form).
   */
  render(bootstrap: UiBootstrap, bodyPrefix = ""): string {
    const shell = this.#shell();
    const data = `<script type="application/json" id="pv-bootstrap">${embedJson(bootstrap)}</script>`;
    // Replacer functions: a string replacement would interpret `$&` and friends in the data.
    const withData = shell.includes("</head>")
      ? shell.replace("</head>", () => `${data}\n</head>`)
      : `${data}${shell}`;
    if (bodyPrefix === "") return withData;
    return withData.replace(/<body([^>]*)>/, (_match, attributes: string) => {
      return `<body${attributes}>\n${bodyPrefix}`;
    });
  }

  #shell(): string {
    if (this.#production && this.#cached !== undefined) return this.#cached.html;
    try {
      const { mtimeMs } = statSync(this.#indexPath);
      if (this.#cached?.mtimeMs !== mtimeMs) {
        this.#cached = { html: readFileSync(this.#indexPath, "utf8"), mtimeMs };
      }
      return this.#cached.html;
    } catch {
      if (this.#production) throw new Error("The login UI build is missing");
      if (!this.#warned) {
        this.#warned = true;
        this.#logger.warn({ dir: this.dir }, "login UI build not found; serving a fallback page");
      }
      return FALLBACK_SHELL;
    }
  }
}

/** Language preferences of a request: `ui_locales` (space-separated) and Accept-Language. */
export function localeHints(uiLocales: unknown, acceptLanguage: string | undefined): LocaleHints {
  const ui =
    typeof uiLocales === "string"
      ? uiLocales.split(" ").filter((tag) => /^[A-Za-z]{1,8}(-[A-Za-z0-9]{1,8})*$/.test(tag))
      : [];
  const accepted = (acceptLanguage ?? "")
    .split(",")
    .map((part) => {
      const [tag = "", ...params] = part.trim().split(";");
      const q = params.map((p) => p.trim()).find((p) => p.startsWith("q="));
      return { tag: tag.trim(), q: q === undefined ? 1 : Number(q.slice(2)) };
    })
    .filter(
      ({ tag, q }) =>
        /^[A-Za-z]{1,8}(-[A-Za-z0-9]{1,8})*$/.test(tag) && Number.isFinite(q) && q > 0,
    )
    .sort((a, b) => b.q - a.q)
    .map(({ tag }) => tag);
  return { uiLocales: ui.slice(0, 10), acceptLanguage: accepted.slice(0, 10) };
}
