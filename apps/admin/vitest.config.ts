import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

/**
 * The BFF tests run in Node; the SPA's (web/src) declare `@vitest-environment jsdom` per file.
 * CSS is not processed in tests.
 */
export default defineConfig({
  plugins: [react()],
  test: {
    include: ["src/**/*.test.ts", "web/src/**/*.test.{ts,tsx}"],
    css: false,
  },
});
