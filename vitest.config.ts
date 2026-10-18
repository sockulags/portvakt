import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Each workspace is a Vitest project; Vite apps use their own vite.config.ts.
    // e2e is excluded: it runs under Playwright (`npm run test:e2e`).
    projects: ["apps/*", "packages/*", "examples/*"],
  },
});
