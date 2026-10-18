import { afterAll, describe, expect, it } from "vitest";
import { setupTestDatabase } from "../testing/test-database.js";
import { createDb, createPool } from "./database.js";
import { assertRestrictedRuntimeRole, checkRuntimeRole, RuntimeRoleError } from "./runtime-role.js";

const testDb = await setupTestDatabase();

describe.skipIf(testDb === undefined)("Db", () => {
  const database = testDb!;
  const { db } = database;
  const pools: ReturnType<typeof createPool>[] = [];
  afterAll(async () => {
    await Promise.all(pools.map((pool) => pool.end()));
  });

  async function count(name: string): Promise<number> {
    const [row] = await db.query<{ count: number }>(
      "SELECT count(*)::int AS count FROM tenants WHERE slug = $1",
      [name],
    );
    return row?.count ?? -1;
  }

  async function insertTenant(tx: typeof db, slug: string): Promise<void> {
    await tx.query("INSERT INTO tenants (slug, name) VALUES ($1, $1)", [slug]);
  }

  it("commits a transaction and rolls it back on error", async () => {
    await db.transaction((tx) => insertTenant(tx, "tx-commit"));
    expect(await count("tx-commit")).toBe(1);

    const failure = new Error("boom");
    await expect(
      db.transaction(async (tx) => {
        await insertTenant(tx, "tx-rollback");
        throw failure;
      }),
    ).rejects.toBe(failure);
    expect(await count("tx-rollback")).toBe(0);
  });

  it("rolls back an inner savepoint while the outer transaction commits", async () => {
    await db.transaction(async (tx) => {
      await insertTenant(tx, "sp-outer");
      await expect(
        tx.transaction(async (inner) => {
          await insertTenant(inner, "sp-inner");
          throw new Error("inner failure");
        }),
      ).rejects.toThrow("inner failure");
      await tx.transaction((inner) => insertTenant(inner, "sp-inner-ok"));
    });
    expect(await count("sp-outer")).toBe(1);
    expect(await count("sp-inner")).toBe(0);
    expect(await count("sp-inner-ok")).toBe(1);
  });

  it("an inner savepoint is undone when the outer transaction rolls back", async () => {
    await expect(
      db.transaction(async (tx) => {
        await tx.transaction((inner) => insertTenant(inner, "sp-undone"));
        throw new Error("outer failure");
      }),
    ).rejects.toThrow("outer failure");
    expect(await count("sp-undone")).toBe(0);
  });

  it("destroys a connection whose ROLLBACK failed instead of returning it to the pool", async () => {
    const pool = createPool({ url: database.url, searchPath: database.schema, poolMax: 1 });
    pools.push(pool);
    const isolated = createDb(pool);
    const failure = new Error("work failed after the connection died");

    await expect(
      isolated.transaction(async (tx) => {
        const [row] = await tx.query<{ pid: number }>("SELECT pg_backend_pid() AS pid");
        // The owner (superuser in dev and CI) kills this backend, so ROLLBACK cannot succeed.
        await database.ownerDb.query("SELECT pg_terminate_backend($1)", [row?.pid]);
        throw failure;
      }),
    ).rejects.toBe(failure);

    expect(pool.totalCount).toBe(0);
    // The pool recovers with a fresh connection.
    const [row] = await isolated.query<{ ok: number }>("SELECT 1 AS ok");
    expect(row?.ok).toBe(1);
  });
});

describe.skipIf(testDb === undefined)("runtime role check", () => {
  const database = testDb!;

  it("accepts the restricted runtime role", async () => {
    const check = await assertRestrictedRuntimeRole(database.db);
    expect(check).toEqual({
      role: database.runtimeRole,
      superuser: false,
      ownsAuditEvents: false,
      canChangeAuditEvents: false,
    });
  });

  it("refuses the owner of audit_events", async () => {
    const check = await checkRuntimeRole(database.ownerDb);
    expect(check.ownsAuditEvents).toBe(true);
    await expect(assertRestrictedRuntimeRole(database.ownerDb)).rejects.toBeInstanceOf(
      RuntimeRoleError,
    );
  });
});
