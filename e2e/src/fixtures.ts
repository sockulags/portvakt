import { closeSync, existsSync, openSync, readdirSync, readSync, statSync } from "node:fs";
import { join } from "node:path";
import { test as base, type Browser, type BrowserContext, type Page } from "@playwright/test";
import { DEMO_TENANT, LOG_DIR, SYSTEM_TENANT } from "./env";
import type { AdminApi, Tenant } from "./admin-api";
import { AdminPortal } from "./pages/admin";

/** Sizes of the stack's log files, to attach what a test added to them. */
function logSizes(): Map<string, number> {
  const sizes = new Map<string, number>();
  if (LOG_DIR === "" || !existsSync(LOG_DIR)) return sizes;
  for (const name of readdirSync(LOG_DIR)) {
    if (name.endsWith(".log")) sizes.set(name, statSync(join(LOG_DIR, name)).size);
  }
  return sizes;
}

function readFrom(path: string, offset: number): string {
  const size = statSync(path).size;
  const length = Math.min(size - offset, 2 * 1024 * 1024);
  if (length <= 0) return "";
  const buffer = Buffer.alloc(length);
  const fd = openSync(path, "r");
  try {
    readSync(fd, buffer, 0, length, size - length);
  } finally {
    closeSync(fd);
  }
  return buffer.toString("utf8");
}

/** A signed-in admin portal session in its own browser context. */
export interface AdminSession {
  readonly context: BrowserContext;
  readonly page: Page;
  readonly portal: AdminPortal;
  readonly api: AdminApi;
}

async function adminSession(
  browser: Browser,
  slug: string,
  signIn: (portal: AdminPortal) => Promise<void>,
): Promise<AdminSession> {
  const context = await browser.newContext({ locale: "sv-SE" });
  const page = await context.newPage();
  const portal = new AdminPortal(page, slug);
  await signIn(portal);
  return { context, page, portal, api: portal.api };
}

interface WorkerFixtures {
  /** Erik (`erik-admin`), platform administrator, signed in to /t/system/ once per worker. */
  platformAdmin: AdminSession;
  /** The seeded demo tenant (`demo`). */
  demoTenant: Tenant;
}

interface TestFixtures {
  /** Attaches the stack's log lines written during a failed test. */
  stackLogs: void;
}

export const test = base.extend<TestFixtures, WorkerFixtures>({
  stackLogs: [
    // Playwright reads a fixture's dependencies from the first parameter's destructuring
    // pattern, so a fixture without dependencies must use an empty one.
    // eslint-disable-next-line no-empty-pattern
    async ({}, use, testInfo) => {
      const before = logSizes();
      await use();
      if (testInfo.status === testInfo.expectedStatus) return;
      for (const [name] of logSizes()) {
        const text = readFrom(join(LOG_DIR, name), before.get(name) ?? 0);
        if (text !== "") {
          await testInfo.attach(`log: ${name}`, { body: text, contentType: "text/plain" });
        }
      }
    },
    { auto: true },
  ],
  platformAdmin: [
    async ({ browser }, use) => {
      const session = await adminSession(browser, SYSTEM_TENANT, (portal) =>
        portal.signIn("erik-admin"),
      );
      await use(session);
      await session.context.close();
    },
    { scope: "worker", timeout: 60_000 },
  ],
  demoTenant: [
    async ({ platformAdmin }, use) => {
      await use(await platformAdmin.api.tenant(DEMO_TENANT));
    },
    { scope: "worker" },
  ],
});

export { expect } from "@playwright/test";

/** Anna (`anna-handlaggare`), the demo tenant's administrator, in a new context. */
export function tenantAdmin(browser: Browser): Promise<AdminSession> {
  return adminSession(browser, DEMO_TENANT, (portal) =>
    portal.signInWithHint("anna.andersson@kommun.example"),
  );
}

/** A Luhn-valid organisationsnummer (`NNNNNN-NNNN`) from 9 digits. */
export function organisationNumber(nineDigits: string): string {
  let sum = 0;
  for (let index = 0; index < 9; index += 1) {
    let digit = Number(nineDigits[index]) * (index % 2 === 0 ? 2 : 1);
    if (digit > 9) digit -= 9;
    sum += digit;
  }
  const check = (10 - (sum % 10)) % 10;
  return `${nineDigits.slice(0, 6)}-${nineDigits.slice(6)}${check}`;
}
