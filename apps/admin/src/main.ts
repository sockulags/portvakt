import { PgSessionStore, type SessionStore } from "@portvakt/sdk-node";
import pg from "pg";
import { createAdminApp } from "./app.js";
import { AdminConfigError, loadAdminConfig, type AdminConfig } from "./config.js";

/** Sessions table of the portal (`npm run migrate-sessions -w apps/admin` creates it). */
export const SESSION_TABLE = "portvakt_admin_sessions";

function configOrExit(): AdminConfig {
  try {
    return loadAdminConfig();
  } catch (error) {
    if (error instanceof AdminConfigError) {
      console.error(error.message);
      process.exit(1);
    }
    throw error;
  }
}

/** Entry point of the admin portal (a deployable of its own, ADMIN_* variables). */
function main(): void {
  const config = configOrExit();
  let store: SessionStore | undefined;
  let pool: pg.Pool | undefined;
  let stopCleanup: (() => void) | undefined;
  if (config.databaseUrl !== undefined) {
    pool = new pg.Pool({
      connectionString: config.databaseUrl,
      max: 10,
      connectionTimeoutMillis: 10_000,
    });
    pool.on("error", () => undefined);
    const pgStore = new PgSessionStore({ pool, tableName: SESSION_TABLE });
    stopCleanup = pgStore.startCleanup(300);
    store = pgStore;
  }
  const app = createAdminApp(config, store === undefined ? {} : { sessionStore: store });
  const server = app.listen(config.port, () => {
    console.log(`admin portal listening on ${config.publicUrl} (Portvakt ${config.portvaktUrl})`);
  });
  const stop = (): void => {
    stopCleanup?.();
    server.close(() => {
      void (pool?.end() ?? Promise.resolve()).then(() => process.exit(0));
    });
    server.closeIdleConnections();
    setTimeout(() => server.closeAllConnections(), 10_000).unref();
  };
  process.on("SIGTERM", stop);
  process.on("SIGINT", stop);
}

main();
