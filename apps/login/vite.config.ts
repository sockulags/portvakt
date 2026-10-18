import react from "@vitejs/plugin-react";
import type { Plugin } from "vite";
import { defineConfig } from "vitest/config";

/**
 * The design system's tokens.css imports its web fonts from Google Fonts. The login page must
 * not send visitors' IP addresses to a third party (and its CSP allows only its own origin), so
 * the remote import is dropped from the build; the token font stacks fall back to system fonts.
 */
function dropRemoteFontImports(): Plugin {
  return {
    name: "portvakt-drop-remote-font-imports",
    enforce: "pre",
    transform(code, id) {
      if (!id.split("?")[0]!.endsWith(".css")) return null;
      const stripped = code.replace(/@import\s+url\(\s*["']?https?:[^)]*\)\s*;?/g, "");
      return stripped === code ? null : { code: stripped, map: null };
    },
  };
}

export default defineConfig({
  // Served by the server below /ui/login/ (apps/server/src/login/ui-shell.ts, LOGIN_UI_BASE).
  base: "/ui/login/",
  plugins: [dropRemoteFontImports(), react()],
  build: {
    // No inline modulepreload polyfill or assets: the CSP allows scripts and styles from 'self'.
    modulePreload: { polyfill: false },
    assetsInlineLimit: 0,
  },
  test: {
    environment: "jsdom",
    css: false,
    setupFiles: ["./src/test-setup.ts"],
  },
});
