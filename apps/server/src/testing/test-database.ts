import { randomBytes } from "node:crypto";
import pg, { type Pool } from "pg";
import { afterAll } from "vitest";
import { createKeyRing, type KeyRing } from "../crypto/keyring.js";
import { createDb, createPool, type Db } from "../db/database.js";
import { migrate } from "../db/migrate.js";
import { createRepositories, type Repositories } from "../repositories/index.js";

/**
 * Integration test support, mirroring production's two database roles:
 *
 * - TEST_MIGRATION_DATABASE_URL (owner, `portvakt` locally) creates a private schema per test
 *   file, applies every migration and grants the runtime role its privileges;
 * - TEST_DATABASE_URL (runtime role, `portvakt_app` locally) is what the repositories use.
 *
 * Schemas are dropped afterwards; schemas left behind by crashed runs are removed when they are
 * older than an hour, so the suite runs repeatedly without manual cleanup.
 *
 * Without a reachable database the tests are skipped locally with a message. On CI (`CI` is set)
 * an unreachable database fails the run instead, so integration tests can never be skipped
 * silently there.
 */

/** Match deploy/docker-compose.dev.yml and deploy/postgres-init; used locally when unset. */
const LOCAL_DEFAULT_URL = "postgres://portvakt_app:portvakt_app@localhost:5433/portvakt_test";
const LOCAL_DEFAULT_MIGRATION_URL = "postgres://portvakt:portvakt@localhost:5433/portvakt_test";
const SCHEMA_PREFIX = "test_";
const STALE_AFTER_SECONDS = 60 * 60;

export const testMasterKeys = {
  current: Buffer.from("test-master-key-current-32-bytes", "utf8"),
  previous: [Buffer.from("test-master-key-previous-32bytes", "utf8")],
} as const;

export interface TestDatabase {
  /** Runtime role URL. */
  readonly url: string;
  /** Owner role URL. */
  readonly migrationUrl: string;
  readonly runtimeRole: string;
  readonly schema: string;
  /** The schema's change notification channel (`portvakt.change_channel` of both pools). */
  readonly changeChannel: string;
  /** Runtime role pool on the test schema: what the repositories use. */
  readonly pool: Pool;
  readonly db: Db;
  /** Owner pool on the test schema, for DDL and checks the runtime role must not be able to do. */
  readonly ownerPool: Pool;
  readonly ownerDb: Db;
  readonly keys: KeyRing;
  readonly repos: Repositories;
}

function configuredUrl(name: string, localDefault: string): string | undefined {
  const configured = process.env[name]?.trim();
  if (configured !== undefined && configured !== "") return configured;
  return process.env.CI === undefined ? localDefault : undefined;
}

/** Connection failures are often AggregateErrors with an empty message (IPv4 and IPv6 refused). */
function describeConnectError(error: unknown): string {
  if (error instanceof AggregateError && error.errors.length > 0) {
    return describeConnectError(error.errors[0]);
  }
  if (error instanceof Error) {
    const code = (error as NodeJS.ErrnoException).code;
    return error.message !== "" ? error.message : (code ?? error.name);
  }
  return String(error);
}

async function connect(url: string): Promise<pg.Client | string> {
  const client = new pg.Client({ connectionString: url, connectionTimeoutMillis: 3000 });
  try {
    await client.connect();
    return client;
  } catch (error) {
    await client.end().catch(() => undefined);
    return describeConnectError(error);
  }
}

async function dropStaleSchemas(admin: pg.Client): Promise<void> {
  const { rows } = await admin.query<{ nspname: string }>(
    "SELECT nspname FROM pg_namespace WHERE starts_with(nspname, $1)",
    [SCHEMA_PREFIX],
  );
  const cutoff = Math.floor(Date.now() / 1000) - STALE_AFTER_SECONDS;
  for (const { nspname } of rows) {
    const createdAt = Number(/^test_(\d+)_/.exec(nspname)?.[1]);
    if (Number.isFinite(createdAt) && createdAt < cutoff) {
      await admin.query(`DROP SCHEMA IF EXISTS ${nspname} CASCADE`).catch(() => undefined);
    }
  }
}

function skipOrFail(reason: string): undefined {
  if (process.env.CI !== undefined) {
    throw new Error(`Integration test database unusable on CI: ${reason}`);
  }
  console.warn(
    `[integration] skipping database tests: ${reason}. Start Postgres with \`npm run db:up\` ` +
      "(on an old volume, also run deploy/postgres-init/02-create-app-role.sql, see CLAUDE.md).",
  );
  return undefined;
}

/**
 * Creates and migrates a private schema for the calling test file and registers its cleanup.
 * Returns `undefined` when the tests should be skipped (local run without a database).
 */
export async function setupTestDatabase(): Promise<TestDatabase | undefined> {
  const url = configuredUrl("TEST_DATABASE_URL", LOCAL_DEFAULT_URL);
  const migrationUrl = configuredUrl("TEST_MIGRATION_DATABASE_URL", LOCAL_DEFAULT_MIGRATION_URL);
  if (url === undefined || migrationUrl === undefined) {
    throw new Error(
      "TEST_DATABASE_URL and TEST_MIGRATION_DATABASE_URL must be set on CI; " +
        "integration tests cannot be skipped",
    );
  }
  const runtimeRole = decodeURIComponent(new URL(url).username);

  const admin = await connect(migrationUrl);
  if (typeof admin === "string") {
    return skipOrFail(`TEST_MIGRATION_DATABASE_URL unreachable (${admin})`);
  }
  const probe = await connect(url);
  if (typeof probe === "string") {
    await admin.end();
    return skipOrFail(`TEST_DATABASE_URL unreachable (${probe})`);
  }
  await probe.end();

  const schema = `${SCHEMA_PREFIX}${Math.floor(Date.now() / 1000)}_${randomBytes(6).toString("hex")}`;
  try {
    await dropStaleSchemas(admin);
    await admin.query(`CREATE SCHEMA ${schema}`);
  } catch (error) {
    await admin.end();
    throw error;
  }

  // Change notifications per schema: parallel test files never invalidate each other's caches.
  const changeChannel = `portvakt_changes_${schema}`;
  const ownerPool = createPool({
    url: migrationUrl,
    searchPath: schema,
    poolMax: 3,
    applicationName: "portvakt-test-owner",
    changeChannel,
  });
  const pool = createPool({
    url,
    searchPath: schema,
    poolMax: 5,
    applicationName: "portvakt-test",
    changeChannel,
    // As in production (DATABASE_STATEMENT_TIMEOUT, DATABASE_IDLE_IN_TRANSACTION_TIMEOUT).
    statementTimeoutSeconds: 30,
    idleInTransactionTimeoutSeconds: 60,
  });
  afterAll(async () => {
    await pool.end();
    await ownerPool.end();
    await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
    await admin.end();
  });

  await migrate(ownerPool, { runtimeRole });
  const db = createDb(pool);
  const keys = createKeyRing(testMasterKeys);
  return {
    url,
    migrationUrl,
    runtimeRole,
    schema,
    changeChannel,
    pool,
    db,
    ownerPool,
    ownerDb: createDb(ownerPool),
    keys,
    repos: createRepositories(db, keys),
  };
}
