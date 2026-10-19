import { ConfigError, loadConfig } from "../config/index.js";
import { createPool } from "../db/database.js";
import { ValidationError } from "../repositories/errors.js";
import { createLogger } from "../logging/logger.js";
import { createPortvakt } from "../server.js";
import { seedDev, type SeedService } from "./seed.js";

/**
 * `npm run seed:dev -w apps/server`: the `demo` tenant of the local stack (see seed.ts).
 * Development only. Needs a migrated database and a running mock IdP (SAML metadata is fetched
 * from it). Environment, besides the server's own:
 *
 * - MOCK_IDP_PUBLIC_URL (default http://localhost:4500);
 * - DEMO_SERVICE_A_URL / DEMO_SERVICE_B_URL (default http://localhost:3100 / :3200);
 * - DEMO_SERVICE_A_CLIENT_SECRET / DEMO_SERVICE_B_CLIENT_SECRET: set (or reset) the client
 *   secrets; without them a new application gets a generated secret, printed once;
 * - MOCK_IDP_ENTRA_CLIENT_SECRET / MOCK_IDP_BANKID_CLIENT_SECRET: the mock's `portvakt-dev`
 *   client secrets (defaults as in .env.example).
 */
const PRODUCTION_REFUSAL = "seed:dev is for development only and refuses NODE_ENV=production";

async function main(): Promise<void> {
  const env = process.env;
  // Refused before anything else is read or connected: development data never reaches production.
  if (env.NODE_ENV === "production") throw new ConfigError([PRODUCTION_REFUSAL]);
  const config = loadConfig();
  if (config.isProduction) throw new ConfigError([PRODUCTION_REFUSAL]);
  const value = (name: string, fallback: string): string => {
    const configured = env[name]?.trim();
    return configured === undefined || configured === "" ? fallback : configured;
  };
  const optional = (name: string): string | undefined => {
    const configured = env[name]?.trim();
    return configured === undefined || configured === "" ? undefined : configured;
  };
  const services: SeedService[] = [
    {
      clientId: "service-a",
      name: "Tjänst A",
      url: value("DEMO_SERVICE_A_URL", "http://localhost:3100").replace(/\/+$/, ""),
      secret: optional("DEMO_SERVICE_A_CLIENT_SECRET"),
      enabled: true,
    },
    {
      clientId: "service-b",
      name: "Tjänst B",
      url: value("DEMO_SERVICE_B_URL", "http://localhost:3200").replace(/\/+$/, ""),
      secret: optional("DEMO_SERVICE_B_CLIENT_SECRET"),
      enabled: false,
    },
  ];

  const pool = createPool({
    url: config.database.url,
    poolMax: 2,
    applicationName: "portvakt-seed",
  });
  try {
    const portvakt = createPortvakt({
      config,
      pool,
      logger: createLogger({ level: "warn" }),
    });
    const report = await seedDev(portvakt, {
      mockIdpUrl: value("MOCK_IDP_PUBLIC_URL", "http://localhost:4500").replace(/\/+$/, ""),
      services,
      entraClient: {
        clientId: "portvakt-dev",
        secret: value("MOCK_IDP_ENTRA_CLIENT_SECRET", "dev-only-entra-client-secret"),
      },
      bankidClient: {
        clientId: "portvakt-dev",
        secret: value("MOCK_IDP_BANKID_CLIENT_SECRET", "dev-only-bankid-client-secret"),
      },
    });
    console.log(`demo tenant: ${config.publicUrl}/t/${report.tenant.slug}`);
    for (const change of report.changes) console.log(`  ${change}`);
    if (report.changes.length === 0) console.log("  nothing to change");
    for (const [clientId, secret] of Object.entries(report.generatedSecrets)) {
      // Printed once, for local development only: the secret is not retrievable later.
      console.log(`  generated client secret for ${clientId} (local use only): ${secret}`);
    }
  } finally {
    await pool.end();
  }
}

main().catch((error: unknown) => {
  if (error instanceof ConfigError || error instanceof ValidationError) {
    console.error(error.message);
    if (error instanceof ValidationError) {
      console.error("Is the mock IdP running? (npm run dev -w apps/mock-idp)");
    }
  } else {
    console.error("seed failed:", error instanceof Error ? error.message : error);
  }
  process.exitCode = 1;
});
