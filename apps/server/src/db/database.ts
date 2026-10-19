import pg, { type Pool, type PoolClient, type QueryResultRow } from "pg";

export interface PoolOptions {
  readonly url: string;
  readonly poolMax?: number;
  /** Overrides search_path for every connection (used by tests to isolate a schema). */
  readonly searchPath?: string;
  readonly applicationName?: string;
  readonly connectionTimeoutMillis?: number;
  /**
   * `statement_timeout` of every connection (seconds; the runtime role's pool). A statement
   * running longer is cancelled by Postgres.
   */
  readonly statementTimeoutSeconds?: number;
  /**
   * `idle_in_transaction_session_timeout` (seconds): a connection idle inside a transaction this
   * long is terminated, so a stuck caller cannot hold row or advisory locks forever.
   */
  readonly idleInTransactionTimeoutSeconds?: number;
  /**
   * Channel of the change notifications written through these connections
   * (`portvakt.change_channel`; default CHANGE_CHANNEL). Tests give each schema its own.
   */
  readonly changeChannel?: string;
  /** Receives errors from idle clients (for example the server restarting). */
  readonly onIdleError?: (error: Error) => void;
}

const IDENTIFIER = /^[a-z_][a-z0-9_]*$/;

export function createPool(options: PoolOptions): Pool {
  const runtimeOptions: string[] = [];
  if (options.searchPath !== undefined) {
    if (!IDENTIFIER.test(options.searchPath)) throw new TypeError("Invalid search_path schema");
    runtimeOptions.push(`-c search_path=${options.searchPath}`);
  }
  if (options.changeChannel !== undefined) {
    if (!IDENTIFIER.test(options.changeChannel)) throw new TypeError("Invalid change channel");
    runtimeOptions.push(`-c portvakt.change_channel=${options.changeChannel}`);
  }
  for (const [name, seconds] of [
    ["statement_timeout", options.statementTimeoutSeconds],
    ["idle_in_transaction_session_timeout", options.idleInTransactionTimeoutSeconds],
  ] as const) {
    if (seconds === undefined) continue;
    if (!Number.isInteger(seconds) || seconds < 0) throw new TypeError(`Invalid ${name}`);
    runtimeOptions.push(`-c ${name}=${seconds * 1000}`);
  }
  const pool = new pg.Pool({
    connectionString: options.url,
    max: options.poolMax ?? 10,
    application_name: options.applicationName ?? "portvakt",
    connectionTimeoutMillis: options.connectionTimeoutMillis ?? 10_000,
    ...(runtimeOptions.length > 0 ? { options: runtimeOptions.join(" ") } : {}),
  });
  // An idle client erroring (for example the server restarting) must not crash the process; the
  // pool discards the client and the next query reconnects.
  pool.on("error", (error) => options.onIdleError?.(error));
  return pool;
}

/**
 * Minimal query interface shared by the pool and by a transaction. Repositories depend on this,
 * so the same repository code runs inside or outside a transaction.
 */
export interface Db {
  query<R extends QueryResultRow>(text: string, values?: readonly unknown[]): Promise<R[]>;
  /**
   * Runs `fn` in a transaction (or a savepoint when already inside one). Commits when `fn`
   * resolves, rolls back when it throws.
   */
  transaction<T>(fn: (tx: Db) => Promise<T>): Promise<T>;
}

class PoolDb implements Db {
  readonly #pool: Pool;

  constructor(pool: Pool) {
    this.#pool = pool;
  }

  async query<R extends QueryResultRow>(text: string, values?: readonly unknown[]): Promise<R[]> {
    const result = await this.#pool.query<R>(text, values === undefined ? undefined : [...values]);
    return result.rows;
  }

  async transaction<T>(fn: (tx: Db) => Promise<T>): Promise<T> {
    const client = await this.#pool.connect();
    // A connection that errors while checked out (for example terminated by the server) must not
    // crash the process through an unhandled 'error' event, and must not return to the pool.
    let broken = false;
    const onError = (): void => {
      broken = true;
    };
    client.on("error", onError);
    try {
      await client.query("BEGIN").catch((error: unknown) => {
        // BEGIN only fails on a broken connection.
        broken = true;
        throw error;
      });
      try {
        const result = await fn(new TransactionDb(client));
        await client.query("COMMIT");
        return result;
      } catch (error) {
        await client.query("ROLLBACK").catch(() => {
          broken = true;
        });
        throw error;
      }
    } finally {
      client.off("error", onError);
      client.release(broken);
    }
  }
}

class TransactionDb implements Db {
  readonly #client: PoolClient;
  #savepoints = 0;

  constructor(client: PoolClient) {
    this.#client = client;
  }

  async query<R extends QueryResultRow>(text: string, values?: readonly unknown[]): Promise<R[]> {
    const result = await this.#client.query<R>(
      text,
      values === undefined ? undefined : [...values],
    );
    return result.rows;
  }

  async transaction<T>(fn: (tx: Db) => Promise<T>): Promise<T> {
    const name = `sp_${++this.#savepoints}`;
    await this.#client.query(`SAVEPOINT ${name}`);
    try {
      const result = await fn(this);
      await this.#client.query(`RELEASE SAVEPOINT ${name}`);
      return result;
    } catch (error) {
      await this.#client.query(`ROLLBACK TO SAVEPOINT ${name}`);
      throw error;
    }
  }
}

export function createDb(pool: Pool): Db {
  return new PoolDb(pool);
}
