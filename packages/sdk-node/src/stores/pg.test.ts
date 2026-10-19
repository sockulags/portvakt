import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { setupTestDatabase } from "@portvakt/server/testing";
import express from "express";
import pg from "pg";
import { describe, expect, it, vi } from "vitest";
import { createPortvaktClient } from "../client.js";
import { PortvaktConfigError } from "../errors.js";
import { silentLogger } from "../logger.js";
import { MiniBrowser } from "../testing/browser.js";
import { startFakeOp } from "../testing/fake-op.js";
import { migratePgSessionStore, pgSessionStoreSchema, PgSessionStore } from "./pg.js";

const db = await setupTestDatabase();

/** The migration as the owner, then DML for the restricted runtime role (as a real deploy). */
async function migrate(tableName = "portvakt_sessions"): Promise<void> {
  await migratePgSessionStore(db!.ownerPool, { tableName });
  await db!.ownerPool.query(
    `GRANT SELECT, INSERT, UPDATE, DELETE ON "${tableName}" TO "${db!.runtimeRole}"`,
  );
}

describe.skipIf(db === undefined)("PgSessionStore (test database)", () => {
  it("creates its table idempotently and stores, expires and deletes values", async () => {
    // DDL as the owner (a migration), reads and writes as the restricted runtime role.
    await migrate();
    await migrate();
    const store = new PgSessionStore({ pool: db!.pool });
    await store.set("s:a", "v1.sealed-a", new Date(Date.now() + 60_000));
    expect(await store.get("s:a")).toBe("v1.sealed-a");
    await store.set("s:a", "v1.sealed-b", new Date(Date.now() + 60_000));
    expect(await store.get("s:a")).toBe("v1.sealed-b");
    await store.set("s:old", "v1.old", new Date(Date.now() - 1000));
    expect(await store.get("s:old")).toBeUndefined();
    await store.destroy("s:a");
    expect(await store.get("s:a")).toBeUndefined();
  });

  it("deletes expired rows in batches", async () => {
    await migrate("cleanup_sessions");
    const store = new PgSessionStore({ pool: db!.pool, tableName: "cleanup_sessions" });
    for (let index = 0; index < 5; index += 1) {
      await store.set(`s:${index}`, "v", new Date(Date.now() - 1000));
    }
    await store.set("s:live", "v", new Date(Date.now() + 60_000));
    expect(await store.deleteExpired(3)).toBe(3);
    expect(await store.deleteExpired()).toBe(2);
    expect(await store.get("s:live")).toBe("v");
    const stop = store.startCleanup(3600);
    stop();
  });

  it("serialises holders of one key across connections (advisory lock)", async () => {
    await migrate();
    const one = new PgSessionStore({ pool: db!.pool });
    const two = new PgSessionStore({ pool: db!.pool });
    const events: string[] = [];
    const hold = (store: PgSessionStore, name: string) =>
      store.withLock("s:locked", async () => {
        events.push(`${name}:in`);
        await new Promise((resolve) => setTimeout(resolve, 100));
        events.push(`${name}:out`);
        return name;
      });
    const results = await Promise.all([hold(one, "a"), hold(two, "b")]);
    expect(results).toEqual(["a", "b"]);
    expect(events[1]).toBe(`${events[0]!.split(":")[0]}:out`);
    await expect(one.withLock("s:locked", () => Promise.reject(new Error("boom")))).rejects.toThrow(
      "boom",
    );
    await expect(one.withLock("s:locked", () => Promise.resolve("free"))).resolves.toBe("free");
  });

  it("runs the BFF with a pool of 2 under concurrent refreshes and touches (no deadlock)", async () => {
    await migrate();
    const op = await startFakeOp();
    // Two connections only: lock holders must never wait for a second one.
    const small = new pg.Pool({ connectionString: db!.url, max: 2 });
    const server = createServer();
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    try {
      const portvakt = createPortvaktClient({
        issuer: op.issuer,
        clientId: op.clientId,
        clientAuth: { method: "client_secret_basic", clientSecret: op.clientSecret },
        redirectUri: `${base}/auth/callback`,
        allowInsecureRequests: true,
        logger: silentLogger,
      });
      const bff = portvakt.bff({
        sessionStore: new PgSessionStore({
          pool: small,
          tableName: `${db!.schema}.portvakt_sessions`,
          connectTimeoutSeconds: 20,
        }),
        encryptionKey: Buffer.alloc(32, 5).toString("base64"),
        cookie: {
          name: "pg_session",
          secrets: ["pg-cookie-secret-0123456789abcdef0123"],
          secure: false,
        },
        idleTimeoutSeconds: 240,
      });
      const app = express();
      app.use(bff);
      app.get("/private", bff.requireLogin(), (_req, res) => {
        res.send("ok");
      });
      app.get("/token", bff.requireLogin(), (req, res, next) => {
        bff
          .getAccessToken(req, { minValiditySeconds: 3600 })
          .then((token) => res.json({ token }))
          .catch(next);
      });
      app.use(bff.errorHandler());
      server.on("request", app);
      op.refreshDelayMs = 50;

      const browsers = await Promise.all(
        Array.from({ length: 4 }, async () => {
          const browser = new MiniBrowser();
          const start = await browser.request(`${base}/auth/login`);
          const toCallback = await browser.request(start.headers.get("location")!);
          expect((await browser.request(toCallback.headers.get("location")!)).status).toBe(303);
          return browser;
        }),
      );
      // Touches are due after a minute: every request below also writes under the lock.
      vi.useFakeTimers({ toFake: ["Date"], shouldAdvanceTime: true });
      vi.setSystemTime(Date.now() + 61_000);
      const requests = Array.from({ length: 10 }, (_, index) =>
        browsers[index % browsers.length]!.request(
          `${base}/${index % 3 === 0 ? "private" : "token"}`,
        ),
      );
      const statuses = await Promise.race([
        Promise.all(requests.map(async (request) => (await request).status)),
        new Promise<never>((_resolve, reject) =>
          setTimeout(() => reject(new Error("deadlock: requests did not complete")), 15_000),
        ),
      ]);
      expect(statuses).toEqual(Array.from({ length: 10 }, () => 200));
    } finally {
      vi.useRealTimers();
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await small.end();
      await op.close();
    }
  }, 30_000);

  it("refuses unsafe table names", () => {
    expect(() => pgSessionStoreSchema('sessions"; drop table x; --')).toThrow(PortvaktConfigError);
    expect(() => new PgSessionStore({ pool: db!.pool, tableName: "A.B.C" })).toThrow(
      PortvaktConfigError,
    );
    expect(pgSessionStoreSchema("app.sessions")).toContain('"app"."sessions"');
  });
});
