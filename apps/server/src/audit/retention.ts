import { MIN_AUDIT_RETENTION_SECONDS } from "../config/index.js";
import type { Db } from "../db/database.js";
import { AuditRepository } from "../repositories/audit.js";
import { auditEvent } from "./catalogue.js";

const DEFAULT_BATCH_SIZE = 5000;
/** Upper bound per run; a later run continues. */
const DEFAULT_MAX_BATCHES = 10_000;

export interface PruneOptions {
  readonly retentionSeconds: number;
  readonly batchSize?: number;
  readonly maxBatches?: number;
  /** The clock (tests). */
  readonly now?: Date;
}

export interface PruneResult {
  readonly deleted: number;
  /** Events that occurred before this instant were deleted. */
  readonly before: Date;
}

/**
 * Deletes audit events older than the retention period, in batches of one transaction each,
 * through `audit_events_prune` (migration 0004). `ownerDb` must connect as the owner of
 * audit_events (MIGRATION_DATABASE_URL): the runtime role can neither execute the function nor
 * delete, and the append-only trigger refuses every other delete, the owner's included. The run
 * is itself audited (`audit.pruned`) when it deleted anything.
 */
export async function pruneAuditEvents(ownerDb: Db, options: PruneOptions): Promise<PruneResult> {
  if (!Number.isSafeInteger(options.retentionSeconds)) {
    throw new RangeError("retentionSeconds must be an integer");
  }
  if (options.retentionSeconds < MIN_AUDIT_RETENTION_SECONDS) {
    throw new RangeError("audit retention must be at least 90 days");
  }
  const batchSize = options.batchSize ?? DEFAULT_BATCH_SIZE;
  const maxBatches = options.maxBatches ?? DEFAULT_MAX_BATCHES;
  const now = options.now ?? new Date();
  const before = new Date(now.getTime() - options.retentionSeconds * 1000);
  let deleted = 0;
  for (let batch = 0; batch < maxBatches; batch += 1) {
    const [row] = await ownerDb.query<{ deleted: number }>(
      "SELECT audit_events_prune($1::timestamptz, $2::integer) AS deleted",
      [before, batchSize],
    );
    const count = row?.deleted ?? 0;
    deleted += count;
    if (count < batchSize) break;
  }
  if (deleted > 0) {
    await new AuditRepository(ownerDb).append(
      auditEvent({
        action: "audit.pruned",
        tenantId: null,
        actor: { type: "system", id: null },
        details: {
          deleted,
          before: before.toISOString(),
          retentionDays: Math.floor(options.retentionSeconds / (24 * 3600)),
        },
      }),
    );
  }
  return { deleted, before };
}
