import type { Db } from "../db/database.js";

/** First half of every job lock key ("PVJB"); the second half names the job and schema. */
const LOCK_NAMESPACE = 0x50_56_4a_42;

/** Jobs that must run on one replica at a time. */
export const JOB_LOCKS = {
  payloadCleanup: "payload-cleanup",
  keyRotation: "key-rotation",
  samlMetadataRefresh: "saml-metadata-refresh",
} as const;
export type JobLock = (typeof JOB_LOCKS)[keyof typeof JOB_LOCKS];

export type ExclusiveResult<T> =
  { readonly ran: true; readonly value: T } | { readonly ran: false };

/**
 * Runs `fn` in a transaction holding a transaction-scoped advisory lock, so only one replica
 * runs it at a time; the lock is released at commit or rollback, also when the connection dies.
 * The key includes the current schema, so isolated test schemas never contend.
 *
 * `wait: false` (scheduled jobs): if another replica holds the lock, skip and return
 * `{ ran: false }`. `wait: true` (start-up, admin actions): wait for the lock.
 */
export async function runExclusive<T>(
  db: Db,
  lock: JobLock,
  options: { readonly wait: boolean },
  fn: (tx: Db) => Promise<T>,
): Promise<ExclusiveResult<T>> {
  return db.transaction(async (tx): Promise<ExclusiveResult<T>> => {
    const key = "hashtext(current_schema() || ':' || $2)";
    if (options.wait) {
      await tx.query(`SELECT pg_advisory_xact_lock($1, ${key})`, [LOCK_NAMESPACE, lock]);
    } else {
      const [row] = await tx.query<{ locked: boolean }>(
        `SELECT pg_try_advisory_xact_lock($1, ${key}) AS locked`,
        [LOCK_NAMESPACE, lock],
      );
      if (row?.locked !== true) return { ran: false };
    }
    return { ran: true, value: await fn(tx) };
  });
}
