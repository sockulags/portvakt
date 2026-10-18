import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { createLogger } from "../logging/logger.js";
import { emitChange, type ChangeEvent } from "../repositories/change-events.js";
import { setupTestDatabase } from "../testing/test-database.js";
import { ChangeListener } from "./change-listener.js";

const testDb = await setupTestDatabase();

describe.skipIf(testDb === undefined)("ChangeListener", () => {
  const { db, ownerDb, url } = testDb!;

  it("reconnects after its connection is killed, resyncs, and receives events again", async () => {
    const applicationName = `portvakt-listener-test-${randomBytes(4).toString("hex")}`;
    // A private channel, so events of parallel test files cannot interfere.
    const channel = `portvakt_test_${randomBytes(4).toString("hex")}`;
    const events: ChangeEvent[] = [];
    let resyncs = 0;
    const listener = new ChangeListener({
      url,
      channel,
      applicationName,
      logger: createLogger({ level: "silent" }),
      onEvent: (event) => {
        events.push(event);
      },
      onResync: () => {
        resyncs += 1;
      },
    });
    const notify = (event: ChangeEvent) =>
      db.query("SELECT pg_notify($1, $2)", [channel, JSON.stringify(event)]);
    try {
      await listener.start();
      await notify({ type: "signing_keys" });
      await expect.poll(() => events.length).toBe(1);
      expect(resyncs).toBe(0);

      const killed = await ownerDb.query<{ ok: boolean }>(
        `SELECT pg_terminate_backend(pid) AS ok FROM pg_stat_activity WHERE application_name = $1`,
        [applicationName],
      );
      expect(killed).toEqual([{ ok: true }]);
      await expect.poll(() => resyncs, { timeout: 10_000 }).toBe(1);
      expect(listener.connected).toBe(true);

      await notify({ type: "tenant", tenantId: "5f1c4b8e-0000-4000-8000-000000000001" });
      await expect.poll(() => events.at(-1)?.type).toBe("tenant");
    } finally {
      await listener.stop();
    }
    expect(listener.connected).toBe(false);
  });

  it("ignores malformed payloads and other channels", async () => {
    const channel = `portvakt_test_${randomBytes(4).toString("hex")}`;
    const events: ChangeEvent[] = [];
    const listener = new ChangeListener({
      url,
      channel,
      logger: createLogger({ level: "silent" }),
      onEvent: (event) => {
        events.push(event);
      },
      onResync: () => undefined,
    });
    try {
      await listener.start();
      await db.query("SELECT pg_notify($1, $2)", [channel, "not json"]);
      await emitChange(db, { type: "signing_keys" }); // the default channel, not ours
      await db.query("SELECT pg_notify($1, $2)", [channel, '{"type":"signing_keys"}']);
      await expect.poll(() => events.length).toBe(1);
    } finally {
      await listener.stop();
    }
  });
});
