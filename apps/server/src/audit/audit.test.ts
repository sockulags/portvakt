import { DEFAULT_PERSONAS_PATH, loadPersonas } from "@portvakt/mock-idp";
import * as client from "openid-client";
import { describe, expect, it, vi } from "vitest";
import { assertRestrictedRuntimeRole, checkRuntimeRole } from "../db/runtime-role.js";
import type { AuditEvent } from "../domain/audit.js";
import type { Tenant } from "../domain/tenant.js";
import { createLogger } from "../logging/logger.js";
import { AuditRepository } from "../repositories/audit.js";
import { createTenant, TEST_ORGNR } from "../testing/fixtures.js";
import {
  authorizationRequest,
  createFederatedLoginMethod,
  FlowDriver,
  redeem,
  startTestIdp,
  type Landing,
} from "../testing/federation.js";
import { createTestClient, discoverWithSecret } from "../testing/oidc-flow.js";
import { createSamlLoginMethod } from "../testing/saml.js";
import { startTestServer } from "../testing/test-server.js";
import { AuditLog, type AuditSink } from "./audit-log.js";
import { AUDIT_ACTIONS, AUDIT_EVENTS, auditEvent, AuditCatalogueError } from "./catalogue.js";
import { pruneAuditEvents } from "./retention.js";

const ts = await startTestServer();
const idp = ts === undefined ? undefined : await startTestIdp();

const DAY = 24 * 3600;
const silent = createLogger({ level: "silent" });

describe("audit event catalogue", () => {
  it("names every action in dotted lowercase and describes it", () => {
    for (const action of AUDIT_ACTIONS) {
      expect(action).toMatch(/^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/);
      expect(AUDIT_EVENTS[action].description.length).toBeGreaterThan(10);
    }
  });

  it("takes the outcome from the catalogue and refuses unknown fields and values", () => {
    const tenantId = "8a41c2d0-5e3b-4f7a-9c18-6b2e0d4f3a91";
    expect(
      auditEvent({
        action: "token.refresh_denied",
        tenantId,
        actor: { type: "application", id: "case-service" },
        details: { clientId: "case-service", reason: "representation_invalid" },
      }),
    ).toMatchObject({ outcome: "failure", action: "token.refresh_denied" });
    const refused = (details: Record<string, unknown>) => () =>
      auditEvent({
        action: "representation.denied",
        tenantId,
        actor: { type: "system", id: null },
        details: details as never,
      });
    // A personal identity number, a name or an email has no field to go into.
    expect(
      refused({ clientId: "case-service", reason: "not_allowed", pin: "191212121212" }),
    ).toThrow(AuditCatalogueError);
    expect(refused({ clientId: "case-service", reason: "because" })).toThrow(AuditCatalogueError);
    expect(refused({ clientId: "Sven Medborgare", reason: "not_allowed" })).toThrow(
      AuditCatalogueError,
    );
    expect(
      refused({ clientId: "case-service", reason: "not_allowed", partyId: "556677-8899" }),
    ).toThrow(AuditCatalogueError);
    // The error names fields, never values.
    expect(refused({ clientId: "case-service", reason: "x", note: "secret-value" })).toThrow(
      /^(?!.*secret-value).*$/,
    );
  });
});

describe.skipIf(ts === undefined)("audit log", () => {
  const { repos, db, ownerDb } = ts!.db;

  const events = async (tenant: Tenant): Promise<AuditEvent[]> => {
    const all: AuditEvent[] = [];
    let cursor: string | undefined;
    for (;;) {
      const page = await repos.audit.query(
        { tenantId: tenant.id },
        {},
        { limit: 200, ...(cursor === undefined ? {} : { cursor }) },
      );
      all.push(...page.events);
      if (page.nextCursor === null) return all;
      cursor = page.nextCursor;
    }
  };

  it("forwards committed events to the sink; a failed write is logged, not thrown", async () => {
    const tenant = await createTenant(repos, "audit-sink");
    const forwarded: AuditEvent[][] = [];
    const sink: AuditSink = {
      forward: (batch) => {
        forwarded.push([...batch]);
        return Promise.resolve();
      },
    };
    const log = new AuditLog({ audit: repos.audit, logger: silent, sink });
    const stored = await log.record({
      action: "person.created",
      tenantId: tenant.id,
      actor: { type: "system", id: null },
      subject: { type: "person", id: "3f2b8c4e-91d7-4a3e-8b6f-2d4c9e1a7b55" },
      details: { loginMethodId: "0f1976f6-7f6c-4baf-a88c-2bc6f2e68ce7" },
    });
    await vi.waitFor(() => expect(forwarded).toEqual([[stored]]));

    // Inside a transaction: written with it, forwarded only once the caller says it committed.
    const inTx = await db.transaction(async (tx) =>
      log.recordIn(new AuditRepository(tx), {
        action: "login.groups_overage",
        tenantId: tenant.id,
        actor: { type: "system", id: null },
        details: { loginMethodId: "0f1976f6-7f6c-4baf-a88c-2bc6f2e68ce7" },
      }),
    );
    expect(forwarded).toHaveLength(1);
    log.forward([inTx]);
    await vi.waitFor(() => expect(forwarded).toHaveLength(2));

    const broken = await log.record({
      action: "person.created",
      tenantId: tenant.id,
      actor: { type: "system", id: null },
      details: { loginMethodId: "not-a-uuid" },
    });
    expect(broken).toBeUndefined();
    expect(forwarded).toHaveLength(2);
  });

  it("prunes old events only through the owner's retention function", async () => {
    const insertAt = (ago: string) =>
      ownerDb.query(
        `INSERT INTO audit_events (occurred_at, tenant_id, actor_type, action, details)
         VALUES (now() - $1::interval, NULL, 'system', 'retention.probe', '{}')`,
        [ago],
      );
    for (const ago of ["500 days", "450 days", "401 days", "100 days", "1 day"]) {
      await insertAt(ago);
    }
    const probes = async () =>
      (
        await ownerDb.query<{ n: number }>(
          "SELECT count(*)::int AS n FROM audit_events WHERE action = 'retention.probe'",
        )
      )[0]!.n;
    const denied = { code: "42501" };

    // The runtime role: no DELETE, no EXECUTE, and setting the cutoff itself does not help.
    await expect(
      db.query("DELETE FROM audit_events WHERE action = 'retention.probe'"),
    ).rejects.toMatchObject(denied);
    await expect(
      db.query("SELECT audit_events_prune(now() - interval '400 days', 10)"),
    ).rejects.toMatchObject(denied);
    await expect(
      db.transaction(async (tx) => {
        await tx.query("SELECT set_config('portvakt.audit_prune_before', now()::text, true)");
        await tx.query("DELETE FROM audit_events WHERE action = 'retention.probe'");
      }),
    ).rejects.toMatchObject(denied);
    await expect(assertRestrictedRuntimeRole(db)).resolves.toMatchObject({
      canChangeAuditEvents: false,
    });
    expect((await checkRuntimeRole(ownerDb)).canChangeAuditEvents).toBe(true);

    // The owner cannot delete directly either, nor prune younger than 90 days.
    await expect(
      ownerDb.query("DELETE FROM audit_events WHERE action = 'retention.probe'"),
    ).rejects.toThrow(/append-only/);
    await expect(
      ownerDb.query("SELECT audit_events_prune(now() - interval '10 days', 10)"),
    ).rejects.toThrow(/at least 90 days/);
    // Setting the cutoff by hand does not get around the 90 days either (the trigger checks it).
    const ownerDeleteWithCutoff = (cutoff: string, where: string) =>
      ownerDb.transaction(async (tx) => {
        await tx.query(
          "SELECT set_config('portvakt.audit_prune_before', (now() - $1::interval)::text, true)",
          [cutoff],
        );
        await tx.query(`DELETE FROM audit_events WHERE action = 'retention.probe' AND ${where}`);
      });
    await expect(ownerDeleteWithCutoff("0 days", "true")).rejects.toThrow(/append-only/);
    await expect(
      ownerDeleteWithCutoff("10 days", "occurred_at < now() - interval '400 days'"),
    ).rejects.toThrow(/append-only/);
    await expect(
      ownerDeleteWithCutoff("200 days", "occurred_at > now() - interval '150 days'"),
    ).rejects.toThrow(/append-only/);
    // The runtime role cannot create anything, not even temporary tables.
    await expect(db.query("CREATE TEMP TABLE scratch (x int)")).rejects.toMatchObject(denied);
    await expect(pruneAuditEvents(ownerDb, { retentionSeconds: 30 * DAY })).rejects.toThrow(
      RangeError,
    );
    expect(await probes()).toBe(5);

    const result = await pruneAuditEvents(ownerDb, { retentionSeconds: 400 * DAY, batchSize: 2 });
    expect(result.deleted).toBe(3);
    expect(await probes()).toBe(2);
    const [pruned] = (await repos.audit.query({ allTenants: true }, { actions: ["audit.pruned"] }))
      .events;
    expect(pruned).toMatchObject({
      tenantId: null,
      details: { deleted: 3, retentionDays: 400, before: result.before.toISOString() },
    });
    // Nothing older is left: a second run deletes nothing and writes no event.
    expect((await pruneAuditEvents(ownerDb, { retentionSeconds: 400 * DAY })).deleted).toBe(0);
    expect(
      (await repos.audit.query({ allTenants: true }, { actions: ["audit.pruned"] })).events,
    ).toHaveLength(1);
  });

  it("writes the expected events of real flows, with no personal data in them", async () => {
    const tenant = await createTenant(repos, "audit-pii");
    const entra = await createFederatedLoginMethod(ts!, idp!, tenant, "entra");
    const bankid = await createFederatedLoginMethod(ts!, idp!, tenant, "bankid", {
      sessionPolicy: { maxAgeSeconds: 3600, idleSeconds: 900, allowSso: true },
      trustPinForRepresentation: true,
    });
    const saml = await createSamlLoginMethod(ts!, idp!, tenant, "bankid");
    const testClient = await createTestClient(repos, tenant, {
      representationMode: "optional",
      postLogoutRedirectUris: ["https://app.example.test/signed-out"],
    });
    const config = await discoverWithSecret(ts!, tenant.slug, testClient);
    const redirectUri = testClient.application.redirectUris[0]!;
    const party = await repos.parties.create(tenant.id, {
      type: "person",
      identifier: "199001612382",
      displayName: "Samuel Samordning",
    });
    const org = await repos.parties.create(tenant.id, {
      type: "organisation",
      identifier: TEST_ORGNR,
      displayName: "Bygg AB",
    });
    const grant = await repos.grants.create(tenant.id, {
      agent: { pin: "191212121212" },
      partyId: party.id,
      allApplications: true,
    });
    await repos.grants.create(tenant.id, {
      agent: { pin: "191212121212" },
      partyId: org.id,
      allApplications: true,
    });

    const signIn = async (
      driver: FlowDriver,
      methodId: string,
      persona: string,
      params: Record<string, string> = {},
    ) => {
      const request = await authorizationRequest(config, redirectUri, params);
      let landing: Landing = await driver.follow(request.url.href);
      if (landing.kind === "login_ui" && landing.bootstrap.view === "login") {
        landing = await driver.chooseAndFollow(landing, { loginMethodId: methodId });
      }
      if (landing.kind === "idp_page") landing = await driver.persona(landing, persona);
      return { request, landing };
    };

    // An employee with name and email upstream.
    const employee = new FlowDriver(ts!, idp!);
    const anna = await signIn(employee, entra.id, "anna-handlaggare");
    await redeem(config, anna.request, anna.landing);

    // A cancelled upstream login.
    const cancelled = new FlowDriver(ts!, idp!);
    const cancel = await signIn(cancelled, bankid.id, "cancel");
    expect(cancel.landing).toMatchObject({ bootstrap: { error: "upstream_denied" } });

    // A citizen representing a person; a tampered choice first; then the right is revoked.
    const citizen = new FlowDriver(ts!, idp!);
    const sven = await signIn(citizen, bankid.id, "sven-medborgare");
    expect(
      (
        await citizen.chooseRepresentation(sven.landing, {
          partyId: "00000000-0000-4000-8000-000000000000",
        })
      ).status,
    ).toBe(403);
    const tokens = await redeem(
      config,
      sven.request,
      await citizen.chooseRepresentationAndFollow(sven.landing, { partyId: party.id }),
    );
    await repos.grants.revoke(tenant.id, grant.id, null);
    await expect(client.refreshTokenGrant(config, tokens.refresh_token!)).rejects.toThrow();

    // A step-up (fresher authentication) by another person.
    vi.useFakeTimers({ toFake: ["Date"], shouldAdvanceTime: true });
    try {
      vi.setSystemTime(Date.now() + 10_000);
      const mismatch = await signIn(citizen, bankid.id, "samuel-samordning", { max_age: "5" });
      expect(mismatch.landing).toMatchObject({ bootstrap: { error: "step_up_person_mismatch" } });
    } finally {
      vi.useRealTimers();
    }

    // SAML login and RP-initiated logout with single logout upstream.
    const samlDriver = new FlowDriver(ts!, idp!);
    const viaSaml = await signIn(samlDriver, saml.id, "saml-sven");
    const samlTokens = await redeem(
      config,
      viaSaml.request,
      viaSaml.landing.kind === "login_ui" && viaSaml.landing.bootstrap.view === "representation"
        ? await samlDriver.chooseRepresentationAndFollow(viaSaml.landing, { self: true })
        : viaSaml.landing,
    );
    const endSession = client.buildEndSessionUrl(config, {
      id_token_hint: samlTokens.id_token!,
      post_logout_redirect_uri: "https://app.example.test/signed-out",
    });
    const page = await (await samlDriver.browser.request(endSession.href)).text();
    const action = /<form id="op\.logoutForm" method="post" action="([^"]+)">/.exec(page)![1]!;
    const xsrf = /name="xsrf" value="([^"]+)"/.exec(page)![1]!;
    await samlDriver.follow(new URL(action, endSession).href, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ xsrf, logout: "yes" }).toString(),
    });

    const written = await events(tenant);
    const actions = new Set(written.map((event) => event.action));
    for (const action of [
      "login.success",
      "login.failure",
      "person.created",
      "representation.selected",
      "representation.denied",
      "token.refresh_denied",
      "grant.revoked",
      "step_up.person_mismatch",
      "session.logout",
    ]) {
      expect(actions, action).toContain(action);
    }
    expect(
      written
        .filter((event) => event.action === "session.logout")
        .map((event) => event.details.initiator)
        .sort(),
    ).toEqual(["rp", "slo"]);
    // Every event matches the catalogue (details strictly) ...
    for (const event of written) {
      expect(AUDIT_ACTIONS).toContain(event.action);
      const definition = AUDIT_EVENTS[event.action as keyof typeof AUDIT_EVENTS];
      expect(definition.details.safeParse(event.details).success, event.action).toBe(true);
      expect(event.outcome).toBe(definition.outcome);
    }

    // ... and no persona's personal data appears anywhere in an event.
    const personas = loadPersonas(DEFAULT_PERSONAS_PATH);
    const forbidden = new Set<string>(["Samuel Samordning", "Bygg AB", "5566778899"]);
    for (const employeePersona of personas.entra) {
      forbidden.add(employeePersona.name).add(employeePersona.email).add(employeePersona.oid);
    }
    for (const citizenPersona of personas.bankid) {
      forbidden
        .add(citizenPersona.pin)
        .add(citizenPersona.pin.slice(2))
        .add(`${citizenPersona.pin.slice(0, 8)}-${citizenPersona.pin.slice(8)}`)
        .add(citizenPersona.givenName)
        .add(citizenPersona.familyName)
        .add(citizenPersona.sub);
    }
    for (const samlPersona of [
      ...personas.saml.bankid,
      ...personas.saml.freja,
      ...personas.saml.siths,
    ]) {
      forbidden.add(samlPersona.nameId).add(samlPersona.givenName).add(samlPersona.sn);
      if (samlPersona.pin !== undefined) forbidden.add(samlPersona.pin);
      if (samlPersona.displayName !== undefined) forbidden.add(samlPersona.displayName);
    }
    const serialized = JSON.stringify(written);
    for (const value of forbidden) expect(serialized, value).not.toContain(value);
    // Nor tokens.
    expect(serialized).not.toContain(tokens.access_token.split(".")[1]!);
    expect(serialized).not.toMatch(/eyJ[A-Za-z0-9_-]{10,}/);
  });
});
