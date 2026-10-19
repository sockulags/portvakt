import { ConfigError, loadAuditPruneConfig } from "../config/index.js";
import { createDb, createPool } from "../db/database.js";
import { pruneAuditEvents } from "./retention.js";

/**
 * `npm run audit:prune -w apps/server`: deletes audit events older than AUDIT_RETENTION (default
 * 400 days, at least 90) in batches. It connects as the owner role (MIGRATION_DATABASE_URL), the
 * only role that may run `audit_events_prune`; the runtime role (DATABASE_URL) can never delete
 * audit events. Run it on a schedule (for example a daily Kubernetes CronJob next to the
 * migration job's credentials).
 */
async function main(): Promise<void> {
  const { database, retentionSeconds } = loadAuditPruneConfig();
  const pool = createPool({
    url: database.migrationUrl,
    poolMax: 1,
    applicationName: "portvakt-audit-prune",
  });
  try {
    const result = await pruneAuditEvents(createDb(pool), { retentionSeconds });
    console.log(
      `deleted ${result.deleted} audit event(s) that occurred before ${result.before.toISOString()}`,
    );
  } finally {
    await pool.end();
  }
}

main().catch((error: unknown) => {
  if (error instanceof ConfigError || error instanceof RangeError) {
    console.error(error.message);
  } else {
    console.error("audit prune failed:", error instanceof Error ? error.message : error);
  }
  process.exitCode = 1;
});
