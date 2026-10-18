import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { createLogger } from "../logging/logger.js";
import { csrfToken, verifyCsrfToken } from "./csrf.js";
import { LoginUiShell, localeHints } from "./ui-shell.js";

const logger = createLogger({ level: "silent" });
const dir = mkdtempSync(join(tmpdir(), "portvakt-shell-"));
afterAll(() => rmSync(dir, { recursive: true, force: true }));
writeFileSync(
  join(dir, "index.html"),
  '<!doctype html><html lang="sv"><head><title>x</title></head><body class="b"><div id="root"></div></body></html>',
);

describe("CSRF tokens", () => {
  const keys = ["current-cookie-key-0123456789abcdef", "previous-cookie-key-0123456789abcdef"];
  const tenant = "7d0b5a52-6a43-4f4e-9b8a-0f1d2c3b4a59";

  it("bind to the tenant and the interaction and verify under every key", () => {
    const token = csrfToken(keys, tenant, "uid-1");
    expect(verifyCsrfToken(keys, tenant, "uid-1", token)).toBe(true);
    expect(verifyCsrfToken(keys, tenant, "uid-2", token)).toBe(false);
    expect(verifyCsrfToken(keys, "8d0b5a52-6a43-4f4e-9b8a-0f1d2c3b4a59", "uid-1", token)).toBe(
      false,
    );
    // After a cookie key rotation the previous key still verifies.
    const old = csrfToken([keys[1]!], tenant, "uid-1");
    expect(verifyCsrfToken(keys, tenant, "uid-1", old)).toBe(true);
    expect(verifyCsrfToken([keys[0]!], tenant, "uid-1", old)).toBe(false);
    expect(verifyCsrfToken(keys, tenant, "uid-1", "short")).toBe(false);
  });
});

describe("LoginUiShell", () => {
  it("embeds the bootstrap as inert JSON that cannot close the script block", () => {
    const shell = new LoginUiShell({ dir, production: false, logger });
    const html = shell.render(
      {
        view: "error",
        code: "request_failed",
        oauthError: "</script><script>alert(1)</script>$&",
        locale: { uiLocales: [], acceptLanguage: [] },
      },
      '<form id="op.logoutForm"></form>',
    );
    expect(html).toContain('<script type="application/json" id="pv-bootstrap">');
    expect(html).not.toContain("</script><script>alert(1)");
    expect(html).toContain("\\u003c/script\\u003e");
    // `&` is escaped too, and `$&` is not read as a replacement pattern.
    expect(html).toContain("$\\u0026");
    expect(html).toContain('<body class="b">\n<form id="op.logoutForm"></form>');
    const data = /id="pv-bootstrap">([^<]*)</.exec(html)?.[1];
    expect(JSON.parse(data!)).toMatchObject({ oauthError: "</script><script>alert(1)</script>$&" });
  });

  it("falls back to a minimal page outside production and refuses a missing build in production", () => {
    const missing = join(dir, "missing");
    const dev = new LoginUiShell({ dir: missing, production: false, logger });
    expect(
      dev.render({ view: "logged_out", locale: { uiLocales: [], acceptLanguage: [] } }),
    ).toContain("pv-bootstrap");
    const production = new LoginUiShell({ dir: missing, production: true, logger });
    expect(() => production.assertBuilt()).toThrow();
    expect(() =>
      production.render({ view: "logged_out", locale: { uiLocales: [], acceptLanguage: [] } }),
    ).toThrow();
  });
});

describe("localeHints", () => {
  it("orders Accept-Language by quality and keeps ui_locales first", () => {
    expect(localeHints("en sv", "sv-SE;q=0.5, en;q=0.9, *;q=0.1, de")).toEqual({
      uiLocales: ["en", "sv"],
      acceptLanguage: ["de", "en", "sv-SE"],
    });
    expect(localeHints(undefined, undefined)).toEqual({ uiLocales: [], acceptLanguage: [] });
    expect(localeHints("<x>", "en;q=0")).toEqual({ uiLocales: [], acceptLanguage: [] });
  });
});
