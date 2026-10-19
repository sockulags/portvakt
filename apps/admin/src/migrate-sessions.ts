import { migratePgSessionStore } from "@portvakt/sdk-node";
import pg from "pg";

/**
 * `npm run migrate-sessions -w apps/admin`: creates the portal's session table
 * (`portvakt_admin_sessions`) with ADMIN_MIGRATION_DATABASE_URL (a role that may create tables),
 * or ADMIN_DATABASE_URL when that role may. Grant the runtime role SELECT, INSERT, UPDATE and
 * DELETE on it.
 */
async function run(): Promise<void> {
  const url = process.env.ADMIN_MIGRATION_DATABASE_URL ?? process.env.ADMIN_DATABASE_URL;
  if (url === undefined || url === "") {
    throw new Error("ADMIN_MIGRATION_DATABASE_URL (or ADMIN_DATABASE_URL) is required");
  }
  const pool = new pg.Pool({ connectionString: url, max: 1 });
  try {
    await migratePgSessionStore(pool, { tableName: "portvakt_admin_sessions" });
    console.log("portvakt_admin_sessions is up to date");
  } finally {
    await pool.end();
  }
}

run().catch((error: unknown) => {
  console.error("migrate-sessions failed:", error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
