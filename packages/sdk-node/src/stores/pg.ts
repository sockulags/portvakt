import { AsyncLocalStorage } from "node:async_hooks";
import { PortvaktConfigError, PortvaktUnavailableError } from "../errors.js";
import { errorDetails, consoleLogger, type PortvaktLogger } from "../logger.js";
import type { SessionStore } from "./types.js";

/** The parts of a `pg` result the store reads. */
export interface PgQueryResultLike {
  readonly rows: readonly unknown[];
  readonly rowCount: number | null;
}

/** A `pg.PoolClient` (or compatible). */
export interface PgClientLike {
  query(text: string, values?: unknown[]): Promise<PgQueryResultLike>;
  release(error?: Error | boolean): void;
}

/** A `pg.Pool` (or compatible). `pg` itself is an optional peer dependency of the SDK. */
export interface PgPoolLike {
  query(text: string, values?: unknown[]): Promise<PgQueryResultLike>;
  connect(): Promise<PgClientLike>;
}

export const DEFAULT_SESSION_TABLE = "portvakt_sessions";

const IDENTIFIER = /^[a-z_][a-z0-9_]{0,62}$/;

/** SQLSTATE of a `lock_timeout` that expired. */
const LOCK_NOT_AVAILABLE = "55P03";

/** `table` or `schema.table`, lower case, quoted for SQL. */
function quotedTable(tableName: string): string {
  const parts = tableName.split(".");
  if (parts.length > 2 || !parts.every((part) => IDENTIFIER.test(part))) {
    throw new PortvaktConfigError([
      "tableName: must be a lower-case identifier, optionally schema-qualified (schema.table)",
    ]);
  }
  return parts.map((part) => `"${part}"`).join(".");
}

/**
 * The DDL of the session table (idempotent): run it with your migrations, or call
 * {@link migratePgSessionStore}. The table holds hashed keys, ciphertexts and expiry times only.
 */
export function pgSessionStoreSchema(tableName = DEFAULT_SESSION_TABLE): string {
  const table = quotedTable(tableName);
  const index = `"${tableName.split(".").at(-1)!}_expires_at_idx"`;
  return [
    `CREATE TABLE IF NOT EXISTS ${table} (`,
    "  key text PRIMARY KEY,",
    "  value text NOT NULL,",
    "  expires_at timestamptz NOT NULL",
    ");",
    `CREATE INDEX IF NOT EXISTS ${index} ON ${table} (expires_at);`,
  ].join("\n");
}

/** Creates the session table if it does not exist (needs CREATE privileges). */
export async function migratePgSessionStore(
  pool: Pick<PgPoolLike, "query">,
  options: { readonly tableName?: string } = {},
): Promise<void> {
  await pool.query(pgSessionStoreSchema(options.tableName));
}

export interface PgSessionStoreOptions {
  readonly pool: PgPoolLike;
  /** Default `portvakt_sessions`; `schema.table` is allowed. */
  readonly tableName?: string;
  readonly logger?: PortvaktLogger;
  /**
   * How long `withLock` waits for a pool connection before failing (the pool's own
   * `connectionTimeoutMillis` is often unlimited). Default 10 seconds.
   */
  readonly connectTimeoutSeconds?: number;
  /**
   * How long `withLock` waits for another holder of the same session lock; then it fails with
   * {@link PortvaktUnavailableError} (503). Default 15 s.
   */
  readonly lockTimeoutSeconds?: number;
}

/**
 * Sessions in PostgreSQL (`pg`), shared by every replica. Create the table with
 * {@link pgSessionStoreSchema} or {@link migratePgSessionStore}; delete expired rows with
 * {@link PgSessionStore.deleteExpired} or {@link PgSessionStore.startCleanup}. Refreshes are
 * serialised across replicas with a transaction-scoped advisory lock per session.
 *
 * Pool sizing: a lock holds one connection for the duration of a refresh (one HTTP round trip to
 * Portvakt), and every store operation inside the lock runs on that same connection, so the store
 * never needs a second connection while it holds one. Size the pool for the expected number of
 * concurrent refreshes plus ordinary reads (for example `max: 10` per instance); when the pool is
 * exhausted, `withLock` fails after `connectTimeoutSeconds` instead of waiting forever.
 */
export class PgSessionStore implements SessionStore {
  readonly #pool: PgPoolLike;
  readonly #table: string;
  readonly #lockPrefix: string;
  readonly #logger: PortvaktLogger;
  readonly #connectTimeoutMs: number;
  readonly #lockTimeoutMs: number;
  /** The lock's connection, for the store operations of the code running inside `withLock`. */
  readonly #lockConnection = new AsyncLocalStorage<PgClientLike>();

  constructor(options: PgSessionStoreOptions) {
    const tableName = options.tableName ?? DEFAULT_SESSION_TABLE;
    this.#pool = options.pool;
    this.#table = quotedTable(tableName);
    this.#lockPrefix = `portvakt-sdk:${tableName}:`;
    this.#logger = options.logger ?? consoleLogger;
    this.#connectTimeoutMs = (options.connectTimeoutSeconds ?? 10) * 1000;
    this.#lockTimeoutMs = (options.lockTimeoutSeconds ?? 15) * 1000;
  }

  /** The lock's own connection inside `withLock`, the pool otherwise. */
  #db(): Pick<PgPoolLike, "query"> {
    return this.#lockConnection.getStore() ?? this.#pool;
  }

  async get(key: string): Promise<string | undefined> {
    const result = await this.#db().query(
      `SELECT value FROM ${this.#table} WHERE key = $1 AND expires_at > $2`,
      [key, new Date()],
    );
    const row = result.rows[0] as { value?: unknown } | undefined;
    return typeof row?.value === "string" ? row.value : undefined;
  }

  async set(key: string, value: string, expiresAt: Date): Promise<void> {
    await this.#db().query(
      `INSERT INTO ${this.#table} (key, value, expires_at) VALUES ($1, $2, $3)
       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, expires_at = EXCLUDED.expires_at`,
      [key, value, expiresAt],
    );
  }

  async destroy(key: string): Promise<void> {
    await this.#db().query(`DELETE FROM ${this.#table} WHERE key = $1`, [key]);
  }

  async withLock<T>(key: string, fn: () => Promise<T>): Promise<T> {
    const connection = await this.#connect();
    try {
      await connection.query("BEGIN");
      await connection.query(`SET LOCAL lock_timeout = ${Math.floor(this.#lockTimeoutMs)}`);
      await connection.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [
        `${this.#lockPrefix}${key}`,
      ]);
    } catch (error) {
      connection.release(true);
      if ((error as { code?: unknown } | null)?.code === LOCK_NOT_AVAILABLE) {
        // Another request (or replica) held the session's lock for lockTimeoutSeconds: retry
        // later (503), not a server error.
        throw new PortvaktUnavailableError("the session is locked by another request", {
          cause: error,
        });
      }
      throw error;
    }
    let result: T;
    try {
      // Store operations inside fn run on this connection (never a second one: a pool exhausted
      // by lock holders would otherwise deadlock).
      result = await this.#lockConnection.run(connection, fn);
    } catch (error) {
      // Writes made before the error stand (a session ended before a LoginRequiredError must
      // stay ended). The caller's error wins; a failed COMMIT only discards the connection.
      await this.#finish(connection).catch((commitError: unknown) => {
        this.#logger.warn(errorDetails(commitError), "session lock release failed");
      });
      throw error;
    }
    await this.#finish(connection);
    return result;
  }

  /** A pool connection, or {@link PortvaktUnavailableError} after `connectTimeoutSeconds`. */
  async #connect(): Promise<PgClientLike> {
    let timedOut = false;
    let timer: NodeJS.Timeout | undefined;
    const pending = this.#pool.connect();
    const timeout = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => {
        timedOut = true;
        reject(new PortvaktUnavailableError("no session store connection available"));
      }, this.#connectTimeoutMs);
    });
    try {
      return await Promise.race([pending, timeout]);
    } finally {
      clearTimeout(timer);
      if (timedOut) {
        // A connection that arrives after the timeout goes straight back to the pool.
        pending.then((late) => late.release()).catch(() => undefined);
      }
    }
  }

  /** Ends the lock's transaction and returns the connection (discarded when that fails). */
  async #finish(connection: PgClientLike): Promise<void> {
    try {
      // After a failed statement PostgreSQL turns COMMIT into a rollback by itself.
      await connection.query("COMMIT");
    } catch (error) {
      connection.release(true);
      throw error;
    }
    connection.release();
  }

  /** Deletes up to `limit` expired rows; returns how many. */
  async deleteExpired(limit = 1000): Promise<number> {
    const result = await this.#pool.query(
      `DELETE FROM ${this.#table} WHERE key IN (
         SELECT key FROM ${this.#table} WHERE expires_at <= $1 LIMIT $2
       )`,
      [new Date(), limit],
    );
    return result.rowCount ?? 0;
  }

  /** Deletes expired rows every `intervalSeconds` (default 300); call the result to stop. */
  startCleanup(intervalSeconds = 300): () => void {
    const run = async (): Promise<void> => {
      try {
        while ((await this.deleteExpired()) >= 1000) {
          // Another batch: keep each statement short.
        }
      } catch (error) {
        this.#logger.warn(errorDetails(error), "session cleanup failed");
      }
    };
    const timer = setInterval(() => void run(), intervalSeconds * 1000);
    timer.unref();
    return () => clearInterval(timer);
  }
}
