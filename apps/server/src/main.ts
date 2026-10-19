import { type Config, ConfigError, loadConfig } from "./config/index.js";
import { createDb, createPool } from "./db/database.js";
import { migrate } from "./db/migrate.js";
import { assertRestrictedRuntimeRole } from "./db/runtime-role.js";
import { createLogger, type Logger } from "./logging/logger.js";
import { createPortvakt } from "./server.js";

function loadConfigOrExit(): Config {
  try {
    return loadConfig();
  } catch (error) {
    if (error instanceof ConfigError) {
      console.error(error.message);
      process.exit(1);
    }
    throw error;
  }
}

/** Applies migrations as the owner role, then grants the runtime role (MIGRATE_ON_START). */
async function migrateOnStart(config: Config, logger: Logger): Promise<void> {
  const owner = createPool({
    url: config.database.migrationUrl,
    poolMax: 1,
    applicationName: "portvakt-migrate",
  });
  try {
    const result = await migrate(owner, {
      ...(config.database.separateRoles ? { runtimeRole: config.database.runtimeRole } : {}),
      onApplied: (migration, durationMs) => {
        logger.info({ migration: migration.fileName, durationMs }, "migration applied");
      },
    });
    logger.info({ applied: result.applied.length }, "migrations up to date");
  } finally {
    await owner.end();
  }
}

async function main(): Promise<void> {
  const config = loadConfigOrExit();
  const logger = createLogger({ level: config.logLevel });
  for (const warning of config.warnings) logger.warn({ warning }, "configuration warning");

  process.on("unhandledRejection", (reason) => {
    logger.fatal({ err: reason }, "unhandled promise rejection");
    process.exit(1);
  });
  process.on("uncaughtException", (error) => {
    logger.fatal({ err: error }, "uncaught exception");
    process.exit(1);
  });

  if (config.migrateOnStart) await migrateOnStart(config, logger);

  const pool = createPool({
    url: config.database.url,
    poolMax: config.database.poolMax,
    statementTimeoutSeconds: config.database.statementTimeoutSeconds,
    idleInTransactionTimeoutSeconds: config.database.idleInTransactionTimeoutSeconds,
    connectionTimeoutMillis: config.database.connectionTimeoutSeconds * 1000,
    onIdleError: (error) => logger.warn({ err: error }, "idle database connection failed"),
  });
  if (config.isProduction) {
    const role = await assertRestrictedRuntimeRole(createDb(pool));
    logger.info({ role: role.role }, "runtime database role is restricted");
  }

  const portvakt = createPortvakt({ config, pool, logger });
  await portvakt.start();
  await portvakt.listen(config.port);
  if (config.metrics.enabled && config.metrics.port !== undefined) {
    await portvakt.listenMetrics(config.metrics.port, config.metrics.host);
  }

  let stopping = false;
  const stop = (signal: NodeJS.Signals): void => {
    if (stopping) {
      logger.warn({ signal }, "second signal, exiting immediately");
      process.exit(1);
    }
    stopping = true;
    logger.info({ signal }, "signal received");
    portvakt
      .shutdown()
      .then(() => pool.end())
      .then(() => process.exit(0))
      .catch((error: unknown) => {
        logger.error({ err: error }, "shutdown failed");
        process.exit(1);
      });
  };
  process.on("SIGTERM", stop);
  process.on("SIGINT", stop);
}

main().catch((error: unknown) => {
  // The logger may not exist yet; the error serializer keeps personal data out either way.
  console.error("portvakt failed to start:", error instanceof Error ? error.message : error);
  process.exit(1);
});
