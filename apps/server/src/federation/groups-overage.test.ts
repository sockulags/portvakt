import { describe, expect, it } from "vitest";
import type { Tenant } from "../domain/tenant.js";
import { ValidationError } from "../repositories/errors.js";
import { createTenant } from "../testing/fixtures.js";
import {
  authorizationRequest,
  createFederatedLoginMethod,
  FlowDriver,
  redeem,
  startTestIdp,
  type Landing,
} from "../testing/federation.js";
import { createTestClient, discoverWithSecret } from "../testing/oidc-flow.js";
import { startTestServer } from "../testing/test-server.js";

/**
 * Entra ID groups overage resolved through Microsoft Graph (the mock IdP's `/entra/graph`):
 * the mock IdP starts first, so the server's GRAPH_API_URL can point at it.
 */
const idp = await startTestIdp();
const ts = await startTestServer({ env: { GRAPH_API_URL: `${idp.baseUrl}/entra/graph` } });

/** Mock persona with `groupsOverage` (apps/mock-idp/personas.json). */
const OLLE_OID = "c7b2e4a1-9f3d-4e6c-8a15-d4f7b2c9e061";

describe.skipIf(ts === undefined)("Entra ID groups overage through Microsoft Graph", () => {
  const { repos } = ts!.db;

  async function world(prefix: string, resolveGroupsOverage = true) {
    const tenant = await createTenant(repos, prefix);
    const app = await createTestClient(repos, tenant);
    const config = await discoverWithSecret(ts!, tenant.slug, app);
    const method = await createFederatedLoginMethod(ts!, idp, tenant, "entra", {
      resolveGroupsOverage,
    });
    await repos.access.createRule(tenant.id, {
      applicationId: app.application.id,
      loginMethodId: method.id,
      groupValue: "grp-handlaggare",
      role: "handlaggare",
    });
    return { tenant, app, config, method, redirectUri: app.application.redirectUris[0]! };
  }

  async function signIn(w: Awaited<ReturnType<typeof world>>, persona: string) {
    const driver = new FlowDriver(ts!, idp);
    const request = await authorizationRequest(w.config, w.redirectUri);
    let landing: Landing = await driver.follow(request.url.href);
    if (landing.kind === "idp_page") landing = await driver.persona(landing, persona);
    return { request, landing };
  }

  const auditOf = async (tenant: Tenant, action: string) =>
    (await repos.audit.query({ tenantId: tenant.id }, { actions: [action] })).events;

  it("reads the groups from Graph (every page, groups only) and audits the overage as resolved", async () => {
    const w = await world("overage-graph");
    const { request, landing } = await signIn(w, "olle-overage");
    const tokens = await redeem(w.config, request, landing);
    expect(tokens.claims()).toMatchObject({ name: "Olle Overage", roles: ["handlaggare"] });
    const identity = await repos.persons.findIdentity(w.tenant.id, w.method.id, OLLE_OID);
    expect(identity?.attributes.groups).toEqual([
      "grp-handlaggare",
      "grp-all-staff",
      "grp-overage-extra",
    ]);
    const events = await auditOf(w.tenant, "login.groups_overage");
    expect(events.map((event) => event.details)).toEqual([
      { loginMethodId: w.method.id, resolved: true },
    ]);
  });

  it("does not call Graph without an overage", async () => {
    const w = await world("overage-none");
    idp.idp.oidc("entra").failGraph(503);
    try {
      const { request, landing } = await signIn(w, "anna-handlaggare");
      const tokens = await redeem(w.config, request, landing);
      expect(tokens.claims()?.roles).toEqual(["handlaggare"]);
    } finally {
      idp.idp.oidc("entra").failGraph(undefined);
    }
    expect(await auditOf(w.tenant, "login.groups_overage")).toEqual([]);
  });

  it("fails the login closed when Graph fails, with an audited reason", async () => {
    const w = await world("overage-down");
    for (const [status, reason] of [
      [503, "upstream_unavailable"],
      [401, "upstream_error"],
    ] as const) {
      idp.idp.oidc("entra").failGraph(status);
      try {
        const { landing } = await signIn(w, "olle-overage");
        expect(landing.kind).toBe("login_ui");
        if (landing.kind === "login_ui") expect(landing.bootstrap).toMatchObject({ error: reason });
      } finally {
        idp.idp.oidc("entra").failGraph(undefined);
      }
    }
    const failures = await auditOf(w.tenant, "login.failure");
    expect(failures.map((event) => event.details)).toEqual([
      expect.objectContaining({ reason: "upstream_error", detail: "groups_overage_unresolved" }),
      expect.objectContaining({
        reason: "upstream_unavailable",
        detail: "groups_overage_unresolved",
      }),
    ]);
    // No person was provisioned and nothing claims the overage was handled.
    expect(await repos.persons.findIdentity(w.tenant.id, w.method.id, OLLE_OID)).toBeNull();
    expect(await auditOf(w.tenant, "login.groups_overage")).toEqual([]);
  });

  it("keeps treating an overage as no groups when the method does not resolve it", async () => {
    const w = await world("overage-off", false);
    const { request, landing } = await signIn(w, "olle-overage");
    const tokens = await redeem(w.config, request, landing);
    expect(tokens.claims()?.roles).toEqual([]);
    expect((await auditOf(w.tenant, "login.groups_overage")).map((e) => e.details)).toEqual([
      { loginMethodId: w.method.id },
    ]);
  });

  it("refuses resolveGroupsOverage without a groups claim mapping", async () => {
    const tenant = await createTenant(repos, "overage-rule");
    await expect(
      createFederatedLoginMethod(ts!, idp, tenant, "entra", {
        resolveGroupsOverage: true,
        claimMapping: { subject: "oid" },
      }),
    ).rejects.toBeInstanceOf(ValidationError);
  });
});
