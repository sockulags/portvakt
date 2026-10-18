import { errors } from "oidc-provider";
import { describe, expect, it } from "vitest";
import { JOB_LOCKS, runExclusive } from "../jobs/exclusive.js";
import { OidcPayloadRepository } from "../repositories/oidc-payloads.js";
import { createTenant } from "../testing/fixtures.js";
import { setupTestDatabase } from "../testing/test-database.js";
import { createAdapterFactory } from "./adapter.js";

const testDb = await setupTestDatabase();

describe.skipIf(testDb === undefined)("oidc-provider adapter over oidc_payloads", () => {
  const { repos, db } = testDb!;

  async function twoTenants() {
    const a = await createTenant(repos, "adapter-a");
    const b = await createTenant(repos, "adapter-b");
    const factory = (tenantId: string) =>
      createAdapterFactory({
        tenantId,
        payloads: repos.oidcPayloads,
        resolveClient: (clientId) =>
          Promise.resolve(clientId === "known" ? { client_id: "known" } : undefined),
      });
    return { a, b, adapterA: factory(a.id), adapterB: factory(b.id) };
  }

  /** Pretends the row expired a second ago. */
  async function expire(tenantId: string, kind: string, id: string): Promise<void> {
    await db.query(
      `UPDATE oidc_payloads SET expires_at = now() - interval '1 second'
        WHERE tenant_id = $1 AND kind = $2 AND id = $3`,
      [tenantId, kind, id],
    );
  }

  it("keeps every tenant's rows apart, even with the same model and id", async () => {
    const { a, adapterA, adapterB } = await twoTenants();
    await adapterA("Session").upsert("same-id", { uid: "uid-a", accountId: "x" }, 60);
    await adapterB("Session").upsert("same-id", { uid: "uid-b", accountId: "y" }, 60);

    expect(await adapterA("Session").find("same-id")).toMatchObject({ uid: "uid-a" });
    expect(await adapterB("Session").find("same-id")).toMatchObject({ uid: "uid-b" });
    expect(await adapterA("Session").findByUid("uid-b")).toBeUndefined();
    expect(await adapterB("Session").findByUid("uid-b")).toMatchObject({ accountId: "y" });
    // Same id, other model: a different row.
    expect(await adapterA("AccessToken").find("same-id")).toBeUndefined();

    await adapterA("Session").destroy("same-id");
    expect(await adapterA("Session").find("same-id")).toBeUndefined();
    expect(await adapterB("Session").find("same-id")).toBeDefined();

    // revokeByGrantId with a grant id another tenant uses as well touches only its own tenant.
    await adapterA("RefreshToken").upsert("rt", { grantId: "g1" }, 60);
    await adapterB("RefreshToken").upsert("rt", { grantId: "g1" }, 60);
    await adapterA("RefreshToken").revokeByGrantId("g1");
    expect(await adapterA("RefreshToken").find("rt")).toBeUndefined();
    expect(await adapterB("RefreshToken").find("rt")).toBeDefined();

    const [row] = await db.query<{ tenant_id: string }>(
      "SELECT tenant_id FROM oidc_payloads WHERE kind = 'Session' AND id = 'same-id'",
    );
    expect(row?.tenant_id).not.toBe(a.id);
  });

  it("never returns an expired row, and stores no expiry when none is given", async () => {
    const { a, adapterA } = await twoTenants();
    await adapterA("Interaction").upsert("i1", { returnTo: "/x" }, 60);
    expect(await adapterA("Interaction").find("i1")).toEqual({ returnTo: "/x" });
    await expire(a.id, "Interaction", "i1");
    expect(await adapterA("Interaction").find("i1")).toBeUndefined();

    await adapterA("Session").upsert("s1", { uid: "u1" }, 60);
    await expire(a.id, "Session", "s1");
    expect(await adapterA("Session").findByUid("u1")).toBeUndefined();

    await adapterA("PushedAuthorizationRequest").upsert("r1", { iat: 1 });
    const [row] = await db.query<{ expires_at: Date | null }>(
      "SELECT expires_at FROM oidc_payloads WHERE tenant_id = $1 AND id = 'r1'",
      [a.id],
    );
    expect(row?.expires_at).toBeNull();
    expect(await adapterA("PushedAuthorizationRequest").find("r1")).toEqual({ iat: 1 });
  });

  it("lets exactly one parallel consume win; a replay revokes the grant", async () => {
    const { adapterA } = await twoTenants();
    const codes = adapterA("AuthorizationCode");
    await adapterA("Grant").upsert("g", { accountId: "p" }, 60);
    await adapterA("AccessToken").upsert("at", { grantId: "g" }, 60);
    await codes.upsert("c1", { grantId: "g", accountId: "p" }, 60);
    expect(await codes.find("c1")).not.toHaveProperty("consumed");

    const results = await Promise.allSettled(Array.from({ length: 8 }, () => codes.consume("c1")));
    expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
    for (const failed of results.filter((r) => r.status === "rejected")) {
      expect(failed.reason).toBeInstanceOf(errors.InvalidGrant);
    }
    // The replays revoked the grant: its tokens and the Grant itself are gone.
    expect(await codes.find("c1")).toBeUndefined();
    expect(await adapterA("AccessToken").find("at")).toBeUndefined();
    expect(await adapterA("Grant").find("g")).toBeUndefined();
  });

  it("keeps the consumed mark across re-saves", async () => {
    const { adapterA } = await twoTenants();
    const tokens = adapterA("RefreshToken");
    await tokens.upsert("rt1", { grantId: "g2" }, 60);
    await tokens.consume("rt1");
    const consumed: unknown = (await tokens.find("rt1"))?.consumed;
    expect(consumed).toBeTypeOf("number");
    await tokens.upsert("rt1", { grantId: "g2" }, 60);
    expect((await tokens.find("rt1"))?.consumed).toBe(consumed);
  });

  it("accepts a client assertion id once, also under parallel use", async () => {
    const { a, adapterA, adapterB } = await twoTenants();
    const replay = adapterA("ReplayDetection");
    const results = await Promise.allSettled(
      Array.from({ length: 8 }, () => replay.upsert("jti-1", { iss: "client" }, 60)),
    );
    expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
    for (const failed of results.filter((r) => r.status === "rejected")) {
      expect(failed.reason).toBeInstanceOf(errors.InvalidClientAuth);
    }
    // Another tenant has its own replay cache; an expired entry may be reused.
    await expect(
      adapterB("ReplayDetection").upsert("jti-1", { iss: "client" }, 60),
    ).resolves.toBeUndefined();
    await expire(a.id, "ReplayDetection", "jti-1");
    await expect(replay.upsert("jti-1", { iss: "client" }, 60)).resolves.toBeUndefined();
  });

  it("revokes the grant-bound tokens of a grant only", async () => {
    const { adapterA } = await twoTenants();
    await adapterA("AuthorizationCode").upsert("code", { grantId: "grant-1" }, 60);
    await adapterA("AccessToken").upsert("at", { grantId: "grant-1" }, 60);
    await adapterA("RefreshToken").upsert("rt", { grantId: "grant-1" }, 60);
    await adapterA("RefreshToken").upsert("other", { grantId: "grant-2" }, 60);
    // An interaction mentions the grant but is not a token of it.
    await adapterA("Interaction").upsert("int", { grantId: "grant-1" }, 60);
    await adapterA("Grant").upsert("grant-1", { accountId: "p" }, 60);

    await adapterA("AccessToken").revokeByGrantId("grant-1");
    expect(await adapterA("AuthorizationCode").find("code")).toBeUndefined();
    expect(await adapterA("AccessToken").find("at")).toBeUndefined();
    expect(await adapterA("RefreshToken").find("rt")).toBeUndefined();
    expect(await adapterA("RefreshToken").find("other")).toBeDefined();
    expect(await adapterA("Interaction").find("int")).toBeDefined();
    expect(await adapterA("Grant").find("grant-1")).toBeDefined();
  });

  it("finds by user code within the model and tenant", async () => {
    const { adapterA, adapterB } = await twoTenants();
    await adapterA("DeviceCode").upsert("d1", { userCode: "ABCD-EFGH" }, 60);
    expect(await adapterA("DeviceCode").findByUserCode("ABCD-EFGH")).toMatchObject({
      userCode: "ABCD-EFGH",
    });
    expect(await adapterB("DeviceCode").findByUserCode("ABCD-EFGH")).toBeUndefined();
  });

  it("resolves clients through the application lookup and never stores them", async () => {
    const { adapterA } = await twoTenants();
    const clients = adapterA("Client");
    expect(await clients.find("known")).toEqual({ client_id: "known" });
    expect(await clients.find("unknown")).toBeUndefined();
    await expect(clients.upsert("known", { client_id: "known" }, 60)).rejects.toThrow();
    await expect(clients.destroy("known")).rejects.toThrow();
  });

  it("deletes expired rows of every tenant and keeps the rest", async () => {
    const { a, b, adapterA, adapterB } = await twoTenants();
    await adapterA("AccessToken").upsert("old-a", { grantId: "g" }, 60);
    await adapterB("AccessToken").upsert("old-b", { grantId: "g" }, 60);
    await adapterA("AccessToken").upsert("fresh", { grantId: "g" }, 60);
    await adapterA("PushedAuthorizationRequest").upsert("forever", {});
    await expire(a.id, "AccessToken", "old-a");
    await expire(b.id, "AccessToken", "old-b");

    const cleanup = new OidcPayloadRepository(db);
    expect(await cleanup.deleteExpiredBatch(1)).toBe(1);
    let deleted = 1;
    while ((await cleanup.deleteExpiredBatch(1)) === 1) deleted += 1;
    expect(deleted).toBeGreaterThanOrEqual(2);
    const remaining = await db.query<{ id: string }>(
      "SELECT id FROM oidc_payloads WHERE tenant_id = ANY ($1::uuid[]) ORDER BY id",
      [[a.id, b.id]],
    );
    expect(remaining.map((row) => row.id)).toEqual(["forever", "fresh"]);
    expect(await db.query("SELECT 1 FROM oidc_payloads WHERE expires_at <= now()")).toHaveLength(0);
  });

  it("runs the cleanup on one replica at a time", async () => {
    const outcome = await runExclusive(db, JOB_LOCKS.payloadCleanup, { wait: true }, () =>
      runExclusive(testDb!.db, JOB_LOCKS.payloadCleanup, { wait: false }, () =>
        Promise.resolve("ran"),
      ),
    );
    expect(outcome).toEqual({ ran: true, value: { ran: false } });
    expect(
      await runExclusive(db, JOB_LOCKS.payloadCleanup, { wait: false }, () => Promise.resolve(1)),
    ).toEqual({ ran: true, value: 1 });
  });
});
