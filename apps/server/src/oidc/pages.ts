import type { ErrorOut, KoaContextWithOIDC } from "oidc-provider";
import {
  LOGIN_UI_HEADERS,
  localeHints,
  type LoginErrorCode,
  type LoginUiShell,
  type UiBootstrap,
} from "../login/ui-shell.js";

/**
 * The pages oidc-provider renders itself (errors on the authorization endpoint, the
 * RP-initiated logout confirmation and its success page), as login UI views. No error details
 * beyond the OAuth error code reach the page.
 */
export interface ProviderPages {
  renderError(ctx: KoaContextWithOIDC, out: ErrorOut): void;
  logoutSource(ctx: KoaContextWithOIDC, form: string): void;
  postLogoutSuccessSource(ctx: KoaContextWithOIDC): void;
}

const OAUTH_ERROR = /^[\x20-\x21\x23-\x5B\x5D-\x7E]{1,64}$/;

function errorView(ctx: KoaContextWithOIDC, out: ErrorOut): UiBootstrap {
  const locale = localeHints(undefined, ctx.get("accept-language"));
  const error = typeof out.error === "string" && OAUTH_ERROR.test(out.error) ? out.error : "";
  let code: LoginErrorCode = "request_failed";
  // Unknown client: the application is not registered or not enabled in this tenant.
  if (error === "invalid_client") code = "app_unavailable";
  // The resume of an interaction whose cookie or record is gone.
  else if (ctx.oidc?.route === "resume" && error === "invalid_request")
    code = "interaction_expired";
  return code === "request_failed"
    ? { view: "error", code, oauthError: error === "" ? "server_error" : error, locale }
    : { view: "error", code, locale };
}

export function createProviderPages(shell: LoginUiShell): ProviderPages {
  const send = (ctx: KoaContextWithOIDC, html: string): void => {
    for (const [name, value] of Object.entries(LOGIN_UI_HEADERS)) ctx.set(name, value);
    ctx.body = html;
  };
  return {
    renderError(ctx, out) {
      send(ctx, shell.render(errorView(ctx, out)));
    },
    // `form` is oidc-provider's hidden logout form (`id="op.logoutForm"`, with its xsrf token);
    // the SPA renders the buttons that submit it.
    logoutSource(ctx, form) {
      const locale = localeHints(undefined, ctx.get("accept-language"));
      send(ctx, shell.render({ view: "logout", locale }, form));
    },
    postLogoutSuccessSource(ctx) {
      const locale = localeHints(undefined, ctx.get("accept-language"));
      send(ctx, shell.render({ view: "logged_out", locale }));
    },
  };
}
