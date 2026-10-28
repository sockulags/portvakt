import { describe, expect, it } from "vitest";
import { PortvaktUnavailableError } from "../errors.js";
import { silentLogger } from "../logger.js";
import { PgSessionStore, type PgClientLike, type PgPoolLike } from "./pg.js";

/** A pool whose connections fail the advisory lock statement with `failure`. */
function poolFailingTheLock(failure: Error) {
  const released: (Error | boolean | undefined)[] = [];
  const statements: string[] = [];
  const connection: PgClientLike = {
    query: (text) => {
      statements.push(text);
      if (text.includes("pg_advisory_xact_lock")) return Promise.reject(failure);
      return Promise.resolve({ rows: [], rowCount: 0 });
    },
    release: (error) => {
      released.push(error);
    },
  };
  const pool: PgPoolLike = {
    query: () => Promise.resolve({ rows: [], rowCount: 0 }),
    connect: () => Promise.resolve(connection),
  };
  return { pool, released, statements };
}

describe("PgSessionStore.withLock without a database", () => {
  it("answers a lock held past lockTimeoutSeconds as unavailable (503), not a server error", async () => {
    const lockTimeout = Object.assign(new Error("canceling statement due to lock timeout"), {
      code: "55P03",
    });
    const { pool, released, statements } = poolFailingTheLock(lockTimeout);
    const store = new PgSessionStore({ pool, logger: silentLogger, lockTimeoutSeconds: 2 });
    let ran = false;
    const error = await store
      .withLock("s:key", () => {
        ran = true;
        return Promise.resolve();
      })
      .catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(PortvaktUnavailableError);
    expect((error as PortvaktUnavailableError).status).toBe(503);
    expect(ran).toBe(false);
    expect(statements).toContain("SET LOCAL lock_timeout = 2000");
    // The connection is discarded, never returned to the pool mid-transaction.
    expect(released).toEqual([true]);
  });

  it("passes other database errors on unchanged", async () => {
    const other = Object.assign(new Error("connection terminated"), { code: "57P01" });
    const { pool, released } = poolFailingTheLock(other);
    const store = new PgSessionStore({ pool, logger: silentLogger });
    await expect(store.withLock("s:key", () => Promise.resolve())).rejects.toBe(other);
    expect(released).toEqual([true]);
  });
});
