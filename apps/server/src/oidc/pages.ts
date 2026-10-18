import type { ErrorOut, KoaContextWithOIDC } from "oidc-provider";

/**
 * The few pages oidc-provider renders itself (errors on the authorization endpoint, the
 * RP-initiated logout confirmation). Deliberately plain and self-contained: no external fonts or
 * scripts, nothing user-controlled without escaping, no error details beyond the OAuth error code
 * and its description. The login UI (M3) owns everything else.
 */

const ESCAPES: Readonly<Record<string, string>> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
};

export function escapeHtml(value: unknown): string {
  return String(value).replace(/[&<>"']/g, (char) => ESCAPES[char] ?? char);
}

function page(title: string, body: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>${escapeHtml(title)}</title>
<style>body{font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem;line-height:1.5}button{font:inherit;padding:.5rem 1rem;margin-right:.5rem}</style>
</head>
<body>
${body}
</body>
</html>`;
}

function setHtml(ctx: KoaContextWithOIDC, html: string): void {
  ctx.type = "html";
  ctx.set("Cache-Control", "no-store");
  // No form-action: the logout form ends in a redirect to the application, which browsers
  // check against form-action as well.
  ctx.set(
    "Content-Security-Policy",
    "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'",
  );
  ctx.body = html;
}

export function renderErrorPage(ctx: KoaContextWithOIDC, out: ErrorOut): void {
  const description =
    typeof out.error_description === "string" ? `<p>${escapeHtml(out.error_description)}</p>` : "";
  setHtml(
    ctx,
    page(
      "Sign-in failed",
      `<h1>Sign-in failed</h1>
<p>The request could not be completed. Return to the application and try again.</p>
<p><code>${escapeHtml(out.error)}</code></p>
${description}`,
    ),
  );
}

/** `form` is oidc-provider's hidden logout form (`id="op.logoutForm"`, with its xsrf token). */
export function renderLogoutPage(ctx: KoaContextWithOIDC, form: string): void {
  setHtml(
    ctx,
    page(
      "Sign out",
      `<h1>Sign out?</h1>
${form}
<button autofocus type="submit" form="op.logoutForm" value="yes" name="logout">Sign out</button>
<button type="submit" form="op.logoutForm">Stay signed in</button>`,
    ),
  );
}

export function renderLogoutSuccessPage(ctx: KoaContextWithOIDC): void {
  setHtml(ctx, page("Signed out", "<h1>You are signed out</h1>"));
}
