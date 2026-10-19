import { createServer } from "node:http";
import { MetricRegistry, registerProcessMetrics } from "@portvakt/http-kit";
import { PgSessionStore, type SessionStore } from "@portvakt/sdk-node";
import pg from "pg";
import { createAdminApp } from "./app.js";
import { AdminConfigError, loadAdminConfig, type AdminConfig } from "./config.js";
import { createAdminLogger } from "./observability.js";

/** Sessions table of the portal (`npm run migrate-sessions -w apps/admin` creates it). */
export const SESSION_TABLE = "portvakt_admin_sessions";

/** Server timeouts (as Portvakt's defaults): slow clients cannot hold connections open. */
const REQUEST_TIMEOUT_MS = 30_000;
const HEADERS_TIMEOUT_MS = 20_000;
/** Above common load balancer idle timeouts (60 s), so they never reuse a closed connection. */
const KEEP_ALIVE_TIMEOUT_MS = 65_000;
/** Postgres session limits of the session store's connections. */
const STATEMENT_TIMEOUT_MS = 15_000;
/** A refresh inside the session lock talks to Portvakt (SDK timeout 10 s) in a transaction. */
const IDLE_IN_TRANSACTION_TIMEOUT_MS = 60_000;

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
  const logger = createAdminLogger(config.logLevel);
  for (const warning of config.warnings) logger.warn({}, warning);
  const metrics = new MetricRegistry({ prefix: "portvakt_admin" });
  const stopProcessMetrics = registerProcessMetrics(metrics);
  let store: SessionStore | undefined;
  let pool: pg.Pool | undefined;
  let stopCleanup: (() => void) | undefined;
  if (config.databaseUrl !== undefined) {
    pool = new pg.Pool({
      connectionString: config.databaseUrl,
      max: 10,
      connectionTimeoutMillis: 5_000,
      options: `-c statement_timeout=${STATEMENT_TIMEOUT_MS} -c idle_in_transaction_session_timeout=${IDLE_IN_TRANSACTION_TIMEOUT_MS}`,
    });
    pool.on("error", (error) =>
      logger.warn({ error: error.name }, "idle database connection failed"),
    );
    const sessions = pool;
    metrics.collect(
      "portvakt_admin_db_pool_connections",
      "Session store pool connections",
      "gauge",
      () => [
        { labels: { state: "total" }, value: sessions.totalCount },
        { labels: { state: "idle" }, value: sessions.idleCount },
        { labels: { state: "waiting" }, value: sessions.waitingCount },
      ],
    );
    const pgStore = new PgSessionStore({ pool, tableName: SESSION_TABLE });
    stopCleanup = pgStore.startCleanup(300);
    store = pgStore;
  }
  const app = createAdminApp(config, {
    logger,
    metrics,
    ...(store === undefined ? {} : { sessionStore: store }),
  });
  const server = createServer({ maxHeaderSize: 16_384 }, app);
  server.requestTimeout = REQUEST_TIMEOUT_MS;
  server.headersTimeout = HEADERS_TIMEOUT_MS;
  server.keepAliveTimeout = KEEP_ALIVE_TIMEOUT_MS;
  server.listen(config.port, () => {
    logger.info(
      { publicUrl: config.publicUrl, portvaktUrl: config.portvaktUrl },
      "admin portal listening",
    );
  });
  const stop = (): void => {
    stopCleanup?.();
    stopProcessMetrics();
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
