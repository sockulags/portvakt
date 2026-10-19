import { defineConfig, devices } from "@playwright/test";

/**
 * The end-to-end suite over the stack that `npm run test:e2e` (scripts/e2e.js) starts. Three
 * projects decide what may run at the same time:
 *
 * - `demo-tenant`: scenarios in the seeded `demo` tenant, whose state they change (Service B
 *   enabled, grants, a short-session login method): one worker, files in name order;
 * - `own-tenant`: scenarios that create their own tenant, and the admin accessibility checks:
 *   one worker, next to `demo-tenant`;
 * - `key-rotation`: scenario 9 rotates the signing keys every tenant shares, so it runs alone
 *   after both.
 *
 * No retries: a scenario that passes only on a retry is a failure of the release gate.
 */
const CI = process.env.CI !== undefined && process.env.CI !== "";

export default defineConfig({
  testDir: "./tests",
  outputDir: "./.artifacts/test-results",
  forbidOnly: CI,
  retries: 0,
  workers: 2,
  fullyParallel: false,
  timeout: 90_000,
  expect: { timeout: 10_000 },
  reporter: [
    ["list"],
    ["html", { outputFolder: "./.artifacts/playwright-report", open: "never" }],
    ...(CI ? ([["github"]] as const) : []),
  ],
  use: {
    ...devices["Desktop Chrome"],
    locale: "sv-SE",
    timezoneId: "Europe/Stockholm",
    actionTimeout: 15_000,
    navigationTimeout: 30_000,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
  },
  projects: [
    { name: "demo-tenant", testDir: "./tests/demo-tenant", workers: 1 },
    { name: "own-tenant", testDir: "./tests/own-tenant", workers: 1 },
    {
      name: "key-rotation",
      testDir: "./tests/key-rotation",
      workers: 1,
      dependencies: ["demo-tenant", "own-tenant"],
    },
  ],
});
