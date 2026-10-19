import { defaultClientConditions, defaultServerConditions } from "vite";
import { defineConfig } from "vitest/config";

/**
 * `@portvakt/http-kit` and `@portvakt/sdk-node` export their TypeScript source under the
 * `portvakt-source` condition (their default export is the build in dist/); tests use the source.
 */
export default defineConfig({
  resolve: { conditions: ["portvakt-source", ...defaultClientConditions] },
  ssr: { resolve: { conditions: ["portvakt-source", ...defaultServerConditions] } },
});
