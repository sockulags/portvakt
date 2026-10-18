import { randomBytes } from "node:crypto";
import { copyFile, mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { setupTestDatabase } from "../testing/test-database.js";
import { createPool } from "./database.js";
import { MIGRATIONS_DIR, migrate, migrationChecksum, MigrationError } from "./migrate.js";

const testDb = await setupTestDatabase();

describe.skipIf(testDb === undefined)("migrations", () => {
  const database = testDb!;
  const tempDirs: string[] = [];
  const extraPools: ReturnType<typeof createPool>[] = [];
  const extraSchemas: string[] = [];

  afterAll(async () => {
    await Promise.all(extraPools.map((pool) => pool.end()));
    for (const schema of extraSchemas) {
      await database.ownerPool.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
    }
    await Promise.all(tempDirs.map((dir) => rm(dir, { recursive: true, force: true })));
  });

  /** A fresh schema with its own pool, so each case starts from an empty database. */
  async function freshSchema() {
    const schema = `${database.schema}_${randomBytes(3).toString("hex")}`;
    await database.ownerPool.query(`CREATE SCHEMA ${schema}`);
    const pool = createPool({ url: database.migrationUrl, searchPath: schema, poolMax: 3 });
    extraPools.push(pool);
    extraSchemas.push(schema);
    return pool;
  }

  async function copyOfMigrations(): Promise<string> {
    const dir = await mkdtemp(path.join(tmpdir(), "portvakt-migrations-"));
    tempDirs.push(dir);
    for (const file of (await readdir(MIGRATIONS_DIR)).filter((name) => name.endsWith(".sql"))) {
      await copyFile(path.join(MIGRATIONS_DIR, file), path.join(dir, file));
    }
    return dir;
  }

  it("applied every migration when the test schema was set up, and a rerun is a no-op", async () => {
    const files = (await readdir(MIGRATIONS_DIR)).filter((file) => file.endsWith(".sql")).sort();
    const rerun = await migrate(database.ownerPool, { runtimeRole: database.runtimeRole });
    expect(rerun.applied).toEqual([]);
    expect(rerun.alreadyApplied).toEqual(files);

    const rows = await database.db.query<{ version: string; checksum: string }>(
      "SELECT version, checksum FROM schema_migrations ORDER BY version",
    );
    expect(rows.map((row) => row.version)).toEqual(files.map((file) => file.slice(0, 4)));
    expect(rows.every((row) => /^[0-9a-f]{64}$/.test(row.checksum))).toBe(true);
  });

  it("is idempotent from an empty schema", async () => {
    const pool = await freshSchema();
    const first = await migrate(pool);
    expect(first.applied.length).toBeGreaterThan(0);
    const second = await migrate(pool);
    expect(second.applied).toEqual([]);
    expect(second.alreadyApplied).toEqual(first.applied);
  });

  it("serialises concurrent runners with the advisory lock", async () => {
    const pool = await freshSchema();
    const results = await Promise.all([migrate(pool), migrate(pool), migrate(pool)]);
    const appliedCounts = results.map((result) => result.applied.length).sort();
    expect(appliedCounts[0]).toBe(0);
    expect(appliedCounts[1]).toBe(0);
    expect(appliedCounts[2]).toBeGreaterThan(0);
  });

  it("refuses to run when an applied migration changed", async () => {
    const pool = await freshSchema();
    const dir = await copyOfMigrations();
    await migrate(pool, { dir });
    const [first] = (await readdir(dir)).sort();
    await writeFile(path.join(dir, first ?? ""), "-- edited after being applied\n", { flag: "a" });
    await expect(migrate(pool, { dir })).rejects.toThrow(/has changed since it was applied/);
  });

  it("ignores line-ending differences in the checksum", () => {
    expect(migrationChecksum("SELECT 1;\r\nSELECT 2;\r\n")).toBe(
      migrationChecksum("SELECT 1;\nSELECT 2;\n"),
    );
  });

  it("refuses to run when an applied migration is missing", async () => {
    const pool = await freshSchema();
    const dir = await copyOfMigrations();
    await writeFile(path.join(dir, "9000_extra.sql"), "CREATE TABLE extra_table (id int);\n");
    await migrate(pool, { dir });
    await rm(path.join(dir, "9000_extra.sql"));
    await expect(migrate(pool, { dir })).rejects.toThrow(/is missing/);
  });

  it("refuses a new migration that sorts before the latest applied one", async () => {
    const pool = await freshSchema();
    const dir = await copyOfMigrations();
    await writeFile(path.join(dir, "9000_later.sql"), "SELECT 1;\n");
    await migrate(pool, { dir });
    await writeFile(path.join(dir, "8000_earlier.sql"), "SELECT 1;\n");
    await expect(migrate(pool, { dir })).rejects.toThrow(/sorts before/);
  });

  it("rolls back a failing migration completely", async () => {
    const pool = await freshSchema();
    const dir = await copyOfMigrations();
    await writeFile(
      path.join(dir, "9000_broken.sql"),
      "CREATE TABLE half_done (id int);\nSELECT * FROM table_that_does_not_exist;\n",
    );
    const error = await migrate(pool, { dir }).catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(MigrationError);
    const { rows } = await pool.query(
      "SELECT to_regclass('half_done') AS half_done, " +
        "(SELECT count(*)::int FROM schema_migrations WHERE version = '9000') AS recorded",
    );
    expect(rows[0]).toEqual({ half_done: null, recorded: 0 });
    // Earlier migrations of the same run stay applied.
    await rm(path.join(dir, "9000_broken.sql"));
    expect((await migrate(pool, { dir })).applied).toEqual([]);
  });

  it("rejects badly named migration files", async () => {
    const pool = await freshSchema();
    const dir = await copyOfMigrations();
    await writeFile(path.join(dir, "add-things.sql"), "SELECT 1;\n");
    await expect(migrate(pool, { dir })).rejects.toThrow(/does not match/);
  });

  describe("runtime role", () => {
    it("can read and write domain tables but only read and insert audit events", async () => {
      const { db, runtimeRole } = database;
      const privileges = await db.query<{ table: string; privilege: string }>(
        `SELECT table_name AS table, privilege_type AS privilege
           FROM information_schema.role_table_grants
          WHERE grantee = $1 AND table_schema = current_schema()
            AND table_name IN ('audit_events', 'tenants', 'schema_migrations')
          ORDER BY 1, 2`,
        [runtimeRole],
      );
      const byTable = (table: string) =>
        privileges.filter((p) => p.table === table).map((p) => p.privilege);
      expect(byTable("audit_events")).toEqual(["INSERT", "SELECT"]);
      expect(byTable("tenants")).toEqual(["DELETE", "INSERT", "SELECT", "UPDATE"]);
      expect(byTable("schema_migrations")).toEqual(["SELECT"]);
    });

    it("cannot create objects in the schema", async () => {
      await expect(database.db.query("CREATE TABLE sneaky (id int)")).rejects.toMatchObject({
        code: "42501",
      });
    });

    it("re-applies grants on every run and refuses the owner as runtime role", async () => {
      const [{ owner } = { owner: "" }] = await database.ownerDb.query<{ owner: string }>(
        "SELECT current_user AS owner",
      );
      await expect(migrate(database.ownerPool, { runtimeRole: owner })).rejects.toThrow(
        /must differ from the migration role/,
      );
      await expect(
        migrate(database.ownerPool, { runtimeRole: "role_that_does_not_exist" }),
      ).rejects.toThrow(/Granting runtime privileges failed/);
    });
  });
});
