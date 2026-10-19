/**
 * Where the stack runs. `npm run test:e2e` (scripts/e2e.js) starts it and passes these as E2E_*
 * variables; the defaults are the same ports, so `npx playwright test` in e2e/ works against a
 * stack left running with `npm run test:e2e -- --keep`.
 */
const value = (name: string, fallback: string): string => {
  const configured = process.env[name]?.trim();
  return configured === undefined || configured === "" ? fallback : configured;
};

export const URLS = {
  portvakt: value("E2E_PORTVAKT_URL", "http://localhost:3800"),
  mockIdp: value("E2E_MOCK_IDP_URL", "http://localhost:4800"),
  serviceA: value("E2E_SERVICE_A_URL", "http://localhost:3810"),
  serviceB: value("E2E_SERVICE_B_URL", "http://localhost:3820"),
  serviceC: value("E2E_SERVICE_C_URL", "http://localhost:3830"),
  admin: value("E2E_ADMIN_URL", "http://localhost:3840"),
} as const;

/** Client secrets the orchestrator gave the seeded demo applications. */
export const SECRETS = {
  serviceA: value("E2E_SERVICE_A_SECRET", "e2e-only-service-a-client-secret-0123456789"),
  serviceB: value("E2E_SERVICE_B_SECRET", "e2e-only-service-b-client-secret-0123456789"),
} as const;

/** The owner role of the e2e database (test fixtures that the product offers no way to set). */
export const DATABASE_URL = value(
  "E2E_DATABASE_URL",
  "postgres://portvakt:portvakt@localhost:5433/portvakt_e2e",
);

/** Process logs of the stack (attached to failing tests). */
export const LOG_DIR = process.env.E2E_LOG_DIR?.trim() ?? "";

/** Whether the Java demo (Tjänst C) runs; `--no-java` skips its scenario variants. */
export const JAVA = value("E2E_JAVA", "1") === "1";

export const DEMO_TENANT = "demo";
export const SYSTEM_TENANT = "system";

export const LOA3 = "http://id.elegnamnden.se/loa/1.0/loa3";
export const LOA4 = "http://id.elegnamnden.se/loa/1.0/loa4";

/** Seeded login methods of the demo tenant (apps/server/src/dev/seed.ts), by display name. */
export const METHODS = {
  entra: "Mock Entra (anställda)",
  bankidOidc: "Mock BankID (OIDC)",
  bankidHigh: "Mock BankID hög (OIDC)",
  bankidSaml: "Mock BankID (SAML)",
  siths: "Mock SITHS (SAML)",
  systemEntra: "Mock Entra (administratörer)",
} as const;

/** A suffix that keeps names unique when the suite runs twice against one stack (`--keep`). */
export const RUN_ID = Date.now().toString(36).slice(-6);
/** Three digits of the same kind, for identifiers that must be numbers (organisationsnummer). */
export const RUN_DIGITS = String(Date.now() % 1000).padStart(3, "0");
