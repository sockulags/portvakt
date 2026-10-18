import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { Pool, PoolClient } from "pg";

/** Default location: apps/server/migrations. */
export const MIGRATIONS_DIR = fileURLToPath(new URL("../../migrations", import.meta.url));

/** Repeatable, idempotent privileges script for the runtime role, run after every migration run. */
export const RUNTIME_GRANTS_FILE = path.join(MIGRATIONS_DIR, "grants", "runtime-role.sql");

/** First half of the advisory lock key; the second half is derived from the target schema. */
const LOCK_NAMESPACE = 0x50_56_4d_47; // "PVMG"

const FILE_PATTERN = /^(\d{4})_([a-z0-9_]+)\.sql$/;

export interface MigrationFile {
  readonly version: string;
  readonly name: string;
  readonly fileName: string;
  readonly sql: string;
  readonly checksum: string;
}

export interface MigrationResult {
  /** Migrations applied by this run, in order. */
  readonly applied: readonly string[];
  /** Migrations that were already applied before this run. */
  readonly alreadyApplied: readonly string[];
}

export class MigrationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "MigrationError";
  }
}

/**
 * Checksum over the file content with line endings normalised, so a CRLF checkout on Windows
 * does not look like a changed migration.
 */
export function migrationChecksum(sql: string): string {
  return createHash("sha256").update(sql.replace(/\r\n/g, "\n"), "utf8").digest("hex");
}

export async function loadMigrationFiles(dir: string = MIGRATIONS_DIR): Promise<MigrationFile[]> {
  const entries = await readdir(dir);
  const files: MigrationFile[] = [];
  const versions = new Set<string>();
  for (const fileName of entries.sort()) {
    if (!fileName.endsWith(".sql")) continue;
    const match = FILE_PATTERN.exec(fileName);
    if (match === null) {
      throw new MigrationError(
        `Migration file name ${fileName} does not match NNNN_lower_snake_name.sql`,
      );
    }
    const version = match[1] as string;
    if (versions.has(version)) throw new MigrationError(`Duplicate migration version ${version}`);
    versions.add(version);
    const sql = await readFile(path.join(dir, fileName), "utf8");
    files.push({
      version,
      name: match[2] as string,
      fileName,
      sql,
      checksum: migrationChecksum(sql),
    });
  }
  return files;
}

interface AppliedRow {
  version: string;
  name: string;
  checksum: string;
}

export interface MigrateOptions {
  readonly dir?: string;
  /** Called after each migration is applied (for CLI output). */
  readonly onApplied?: (migration: MigrationFile, durationMs: number) => void;
  /**
   * Role the application runs as (the DATABASE_URL user). When set, the runtime privileges script
   * is applied for it after the migrations; it must differ from the migrating (owner) role.
   * Omitted only when the app and the migrations share one role (development fallback).
   */
  readonly runtimeRole?: string;
  /** Overrides {@link RUNTIME_GRANTS_FILE} (tests). */
  readonly grantsFile?: string;
}

/**
 * Applies pending migrations in the first schema of the connection's search_path.
 *
 * - A session-level advisory lock (keyed by schema) serialises concurrent runners, so replicas
 *   starting together cannot race; the others wait and then find nothing to do.
 * - Applied migrations are recorded in `schema_migrations` with a SHA-256 checksum. The run is
 *   refused when an applied file changed, an applied file is missing, or a new file sorts before
 *   the latest applied version.
 * - Each migration runs in its own transaction together with its bookkeeping row.
 */
export async function migrate(pool: Pool, options: MigrateOptions = {}): Promise<MigrationResult> {
  const files = await loadMigrationFiles(options.dir);
  const client = await pool.connect();
  let locked = false;
  let broken = false;
  try {
    await client.query("SELECT pg_advisory_lock($1, hashtext(current_schema()))", [LOCK_NAMESPACE]);
    locked = true;
    await ensureMigrationsTable(client);

    const { rows } = await client.query<AppliedRow>(
      "SELECT version, name, checksum FROM schema_migrations ORDER BY version",
    );
    const pending = planPending(files, rows);
    const applied: string[] = [];

    for (const migration of pending) {
      const started = performance.now();
      await client.query("BEGIN");
      try {
        await client.query(migration.sql);
        await client.query(
          "INSERT INTO schema_migrations (version, name, checksum) VALUES ($1, $2, $3)",
          [migration.version, migration.name, migration.checksum],
        );
        await client.query("COMMIT");
      } catch (error) {
        await client.query("ROLLBACK");
        throw new MigrationError(
          `Migration ${migration.fileName} failed: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
      applied.push(migration.fileName);
      options.onApplied?.(migration, Math.round(performance.now() - started));
    }

    if (options.runtimeRole !== undefined) {
      await applyRuntimeGrants(
        client,
        options.runtimeRole,
        options.grantsFile ?? RUNTIME_GRANTS_FILE,
      );
    }

    return { applied, alreadyApplied: rows.map((row) => `${row.version}_${row.name}.sql`) };
  } finally {
    if (locked) {
      await client
        .query("SELECT pg_advisory_unlock($1, hashtext(current_schema()))", [LOCK_NAMESPACE])
        .catch(() => {
          broken = true;
        });
    }
    // A connection whose unlock failed may still hold the lock: destroy it rather than reuse it.
    client.release(broken);
  }
}

async function applyRuntimeGrants(
  client: PoolClient,
  runtimeRole: string,
  grantsFile: string,
): Promise<void> {
  const [{ current_user: owner } = { current_user: "" }] = (
    await client.query<{ current_user: string }>("SELECT current_user")
  ).rows;
  if (runtimeRole === owner) {
    throw new MigrationError(
      "The runtime role must differ from the migration role; set MIGRATION_DATABASE_URL",
    );
  }
  const sql = await readFile(grantsFile, "utf8");
  await client.query("BEGIN");
  try {
    await client.query("SELECT set_config('portvakt.runtime_role', $1, true)", [runtimeRole]);
    await client.query(sql);
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw new MigrationError(
      `Granting runtime privileges failed: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

async function ensureMigrationsTable(client: PoolClient): Promise<void> {
  await client.query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version    text PRIMARY KEY,
      name       text NOT NULL,
      checksum   text NOT NULL,
      applied_at timestamptz NOT NULL DEFAULT now()
    )
  `);
}

function planPending(
  files: readonly MigrationFile[],
  applied: readonly AppliedRow[],
): MigrationFile[] {
  const byVersion = new Map(files.map((file) => [file.version, file]));
  for (const row of applied) {
    const file = byVersion.get(row.version);
    if (file === undefined) {
      throw new MigrationError(
        `Applied migration ${row.version}_${row.name}.sql is missing from the migrations directory; ` +
          "the database is newer than this code",
      );
    }
    if (file.checksum !== row.checksum) {
      throw new MigrationError(
        `Applied migration ${file.fileName} has changed since it was applied ` +
          "(checksum mismatch); add a new migration instead of editing an applied one",
      );
    }
  }
  const appliedVersions = new Set(applied.map((row) => row.version));
  const latest = applied.at(-1)?.version;
  const pending = files.filter((file) => !appliedVersions.has(file.version));
  for (const file of pending) {
    if (latest !== undefined && file.version < latest) {
      throw new MigrationError(
        `Migration ${file.fileName} sorts before the latest applied version ${latest}; ` +
          "renumber it after the latest migration",
      );
    }
  }
  return pending;
}
