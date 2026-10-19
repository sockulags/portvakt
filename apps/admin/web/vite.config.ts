import { fileURLToPath } from "node:url";
import react from "@vitejs/plugin-react";
import { defineConfig, type Plugin } from "vite";

/**
 * The design system's tokens.css imports its fonts from Google Fonts; the portal self-hosts them
 * through @portvakt/fonts instead (no third-party requests, CSP `default-src 'self'`).
 */
function dropRemoteFontImports(): Plugin {
  return {
    name: "admin-drop-remote-font-imports",
    enforce: "pre",
    transform(code, id) {
      if (!id.split("?")[0]!.endsWith(".css")) return null;
      const stripped = code.replace(/@import\s+url\(\s*["']?https?:[^)]*\)\s*;?/g, "");
      return stripped === code ? null : { code: stripped, map: null };
    },
  };
}

export default defineConfig({
  root: fileURLToPath(new URL(".", import.meta.url)),
  // Assets are served from /assets for every tenant path (/t/{slug}/...).
  base: "/",
  plugins: [dropRemoteFontImports(), react()],
  build: {
    outDir: fileURLToPath(new URL("../dist/web", import.meta.url)),
    emptyOutDir: true,
    // No inline scripts or styles: the BFF's CSP allows only 'self'.
    modulePreload: { polyfill: false },
    assetsInlineLimit: 0,
  },
});
