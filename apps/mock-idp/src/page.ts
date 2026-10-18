import type { IssuerKind } from "./clients.js";

const ESCAPES: Readonly<Record<string, string>> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
};

const escapeHtml = (value: string): string =>
  value.replace(/[&<>"']/g, (char) => ESCAPES[char] ?? char);

const TITLES: Record<IssuerKind, string> = {
  entra: "Mock Entra ID",
  "entra-mt": "Mock Entra ID (multi-tenant)",
  bankid: "Mock BankID",
};

/**
 * The mock IdP's login page: one button per persona (`data-testid="persona-{id}"`) and a cancel
 * button (`data-testid="cancel"`). Plain, accessible HTML without scripts: it is a development
 * tool, never shown to real users.
 */
export function renderLoginPage(options: {
  readonly kind: IssuerKind;
  readonly action: string;
  readonly personas: readonly { id: string; label: string; detail: string }[];
}): string {
  const title = TITLES[options.kind];
  const buttons = options.personas
    .map(
      (
        persona,
      ) => `<li><button type="submit" name="persona" value="${escapeHtml(persona.id)}" data-testid="persona-${escapeHtml(persona.id)}">
<span class="label">${escapeHtml(persona.label)}</span>
<span class="detail">${escapeHtml(persona.detail)}</span>
</button></li>`,
    )
    .join("\n");
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>${title} (development)</title>
<style>
body{font-family:system-ui,sans-serif;max-width:34rem;margin:3rem auto;padding:0 1rem;line-height:1.5;color:#1d1d1f}
ul{list-style:none;padding:0;display:grid;gap:.5rem}
button{font:inherit;width:100%;text-align:left;padding:.75rem 1rem;border:1px solid #c7c7cc;border-radius:.5rem;background:#fff;cursor:pointer}
button:hover{background:#f2f2f7}
button:focus-visible{outline:3px solid #0a58ca;outline-offset:2px}
.label{display:block;font-weight:600}.detail{display:block;font-size:.875rem;color:#555}
.notice{background:#fff3cd;border:1px solid #e0c56e;padding:.5rem .75rem;border-radius:.5rem}
.cancel{margin-top:1.5rem;width:auto}
</style>
</head>
<body>
<main>
<h1>${title}</h1>
<p class="notice">Development identity provider. Never use it in production.</p>
<form method="post" action="${escapeHtml(options.action)}/login">
<h2>Choose a persona</h2>
<ul>
${buttons}
</ul>
</form>
<form method="post" action="${escapeHtml(options.action)}/cancel">
<button type="submit" class="cancel" data-testid="cancel">Cancel</button>
</form>
</main>
</body>
</html>`;
}
