import { describe, expect, it } from "vitest";
import { createTenant } from "../testing/fixtures.js";
import { setupTestDatabase } from "../testing/test-database.js";
import { InvalidIdError, ValidationError } from "./errors.js";

const testDb = await setupTestDatabase();

describe.skipIf(testDb === undefined)("AuditRepository", () => {
  const { repos, db } = testDb!;

  it("appends events and maps them", async () => {
    const tenant = await createTenant(repos);
    const event = await repos.audit.append({
      tenantId: tenant.id,
      actor: { type: "person", id: "p-1" },
      subject: { type: "application", id: "app-1" },
      action: "token.issued",
      details: { clientId: "app-1", scopes: ["openid"] },
    });
    expect(event).toMatchObject({
      tenantId: tenant.id,
      actor: { type: "person", id: "p-1" },
      subject: { type: "application", id: "app-1" },
      action: "token.issued",
      outcome: "success",
      details: { clientId: "app-1", scopes: ["openid"] },
    });
    expect(event.seq).toMatch(/^\d+$/);
    expect(event.occurredAt).toBeInstanceOf(Date);
  });

  it("the runtime role cannot UPDATE, DELETE, TRUNCATE or ALTER audit events", async () => {
    const event = await repos.audit.append({
      tenantId: null,
      actor: { type: "system" },
      action: "key.rotated",
    });
    const denied = { code: "42501" };
    await expect(
      db.query("UPDATE audit_events SET action = 'x.y' WHERE id = $1", [event.id]),
    ).rejects.toMatchObject(denied);
    await expect(
      db.query("DELETE FROM audit_events WHERE id = $1", [event.id]),
    ).rejects.toMatchObject(denied);
    await expect(db.query("TRUNCATE audit_events")).rejects.toMatchObject(denied);
    await expect(
      db.query("ALTER TABLE audit_events DISABLE TRIGGER audit_events_append_only"),
    ).rejects.toMatchObject(denied);
    await expect(db.query("DROP TABLE audit_events")).rejects.toMatchObject(denied);
    const rows = await db.query("SELECT 1 FROM audit_events WHERE id = $1", [event.id]);
    expect(rows).toHaveLength(1);
  });

  it("the trigger still rejects UPDATE, DELETE and TRUNCATE by the owner", async () => {
    const { ownerDb } = testDb!;
    const event = await repos.audit.append({
      tenantId: null,
      actor: { type: "system" },
      action: "key.rotated",
    });
    await expect(
      ownerDb.query("UPDATE audit_events SET action = 'x.y' WHERE id = $1", [event.id]),
    ).rejects.toThrow(/append-only/);
    await expect(
      ownerDb.query("DELETE FROM audit_events WHERE id = $1", [event.id]),
    ).rejects.toThrow(/append-only/);
    await expect(ownerDb.query("TRUNCATE audit_events")).rejects.toThrow(/append-only/);
  });

  it("rejects a cursor outside the bigint range", async () => {
    await expect(
      repos.audit.query({ allTenants: true }, {}, { cursor: "9223372036854775808" }),
    ).rejects.toBeInstanceOf(ValidationError);
    await expect(
      repos.audit.query({ allTenants: true }, {}, { cursor: "9223372036854775807" }),
    ).resolves.toMatchObject({ nextCursor: null });
    await expect(repos.audit.query({ tenantId: "x" })).rejects.toBeInstanceOf(InvalidIdError);
  });

  it("keeps audit history when a tenant is deleted", async () => {
    const tenant = await createTenant(repos);
    await repos.audit.append({ tenantId: tenant.id, actor: { type: "system" }, action: "a.b" });
    expect(await repos.tenants.delete(tenant.id)).toBe(true);
    const page = await repos.audit.query({ tenantId: tenant.id });
    expect(page.events).toHaveLength(1);
  });

  it("filters and paginates newest first", async () => {
    const tenant = await createTenant(repos);
    const other = await createTenant(repos);
    for (let i = 0; i < 5; i += 1) {
      await repos.audit.append({
        tenantId: tenant.id,
        actor: { type: "person", id: i % 2 === 0 ? "even" : "odd" },
        action: i < 3 ? "login.success" : "login.failure",
        outcome: i < 3 ? "success" : "failure",
        details: { i },
      });
    }
    await repos.audit.append({
      tenantId: tenant.id,
      actor: { type: "person", id: "admin" },
      action: "admin.tenant.update",
      subject: { type: "tenant", id: tenant.id },
    });
    await repos.audit.append({
      tenantId: other.id,
      actor: { type: "system" },
      action: "login.success",
    });

    const first = await repos.audit.query(
      { tenantId: tenant.id },
      { actionPrefix: "login" },
      { limit: 2 },
    );
    expect(first.events.map((e) => e.details.i)).toEqual([4, 3]);
    expect(first.nextCursor).not.toBeNull();
    const second = await repos.audit.query(
      { tenantId: tenant.id },
      { actionPrefix: "login" },
      { limit: 2, cursor: first.nextCursor! },
    );
    expect(second.events.map((e) => e.details.i)).toEqual([2, 1]);
    const third = await repos.audit.query(
      { tenantId: tenant.id },
      { actionPrefix: "login" },
      { limit: 2, cursor: second.nextCursor! },
    );
    expect(third.events.map((e) => e.details.i)).toEqual([0]);
    expect(third.nextCursor).toBeNull();

    const failures = await repos.audit.query({ tenantId: tenant.id }, { outcome: "failure" });
    expect(failures.events.map((e) => e.details.i)).toEqual([4, 3]);
    const even = await repos.audit.query({ tenantId: tenant.id }, { actorId: "even" });
    expect(even.events.map((e) => e.details.i)).toEqual([4, 2, 0]);
    const bySubject = await repos.audit.query({ tenantId: tenant.id }, { subjectId: tenant.id });
    expect(bySubject.events.map((e) => e.action)).toEqual(["admin.tenant.update"]);
    const exact = await repos.audit.query({ tenantId: tenant.id }, { actions: ["login.failure"] });
    expect(exact.events).toHaveLength(2);
    // A prefix matches whole segments only.
    const partial = await repos.audit.query({ tenantId: tenant.id }, { actionPrefix: "log" });
    expect(partial.events).toEqual([]);

    const future = await repos.audit.query(
      { tenantId: tenant.id },
      { from: new Date(Date.now() + 60_000) },
    );
    expect(future.events).toEqual([]);

    const platform = await repos.audit.query(
      { allTenants: true },
      { actionPrefix: "login" },
      { limit: 200 },
    );
    const tenantsSeen = new Set(platform.events.map((e) => e.tenantId));
    expect(tenantsSeen.has(tenant.id) && tenantsSeen.has(other.id)).toBe(true);
  });

  it("validates input", async () => {
    await expect(
      repos.audit.append({ tenantId: null, actor: { type: "system" }, action: "NotDotted" }),
    ).rejects.toBeInstanceOf(ValidationError);
    await expect(
      repos.audit.query({ allTenants: true }, {}, { limit: 1000 }),
    ).rejects.toBeInstanceOf(ValidationError);
  });
});
