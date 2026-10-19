import { defaultClientConditions, defaultServerConditions } from "vite";
import { defineConfig } from "vitest/config";

/**
 * `@portvakt/http-kit` and `@portvakt/sdk-node` export their TypeScript source under the
 * `portvakt-source` condition (their default export is the build in dist/); tests use the source.
 */
export default defineConfig({
  // SAML suites generate RSA-3072 keys and some tests spawn CLIs; Vitest's 5 s default is too
  // tight on shared CI runners (they timed out there while passing locally).
  test: { testTimeout: 30_000, hookTimeout: 60_000 },
  resolve: { conditions: ["portvakt-source", ...defaultClientConditions] },
  ssr: { resolve: { conditions: ["portvakt-source", ...defaultServerConditions] } },
});
