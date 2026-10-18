import { ConfigError, loadDatabaseConfig } from "../config/index.js";
import { createPool } from "./database.js";
import { migrate, MigrationError } from "./migrate.js";

/**
 * `npm run migrate -w apps/server`: applies pending migrations as the owner role
 * (MIGRATION_DATABASE_URL) and grants the runtime role (the DATABASE_URL user) its privileges.
 */
async function main(): Promise<void> {
  const database = loadDatabaseConfig();
  const pool = createPool({
    url: database.migrationUrl,
    poolMax: 1,
    applicationName: "portvakt-migrate",
  });
  try {
    const result = await migrate(pool, {
      ...(database.separateRoles ? { runtimeRole: database.runtimeRole } : {}),
      onApplied: (migration, durationMs) => {
        console.log(`applied ${migration.fileName} (${durationMs} ms)`);
      },
    });
    console.log(
      result.applied.length === 0
        ? `database is up to date (${result.alreadyApplied.length} migrations applied earlier)`
        : `applied ${result.applied.length} migration(s)`,
    );
  } finally {
    await pool.end();
  }
}

main().catch((error: unknown) => {
  if (error instanceof ConfigError || error instanceof MigrationError) {
    console.error(error.message);
  } else {
    console.error("migration failed:", error instanceof Error ? error.message : error);
  }
  process.exitCode = 1;
});
