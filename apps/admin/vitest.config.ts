import react from "@vitejs/plugin-react";
import { defaultClientConditions, defaultServerConditions } from "vite";
import { defineConfig } from "vitest/config";

/**
 * The BFF tests run in Node; the SPA's (web/src) declare `@vitest-environment jsdom` per file.
 * CSS is not processed in tests. `@portvakt/http-kit` and `@portvakt/sdk-node` resolve to their
 * TypeScript source (the `portvakt-source` condition), so nothing has to be built first.
 */
export default defineConfig({
  plugins: [react()],
  resolve: { conditions: ["portvakt-source", ...defaultClientConditions] },
  ssr: { resolve: { conditions: ["portvakt-source", ...defaultServerConditions] } },
  test: {
    include: ["src/**/*.test.ts", "web/src/**/*.test.{ts,tsx}"],
    css: false,
  },
});
