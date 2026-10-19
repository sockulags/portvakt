import { beforeAll, describe, expect, it } from "vitest";
import {
  adminCall,
  adminToken,
  createAdmin,
  createAdminTenant,
  setupAdminWorld,
  type AdminTenant,
  type AdminWorld,
} from "../../testing/admin.js";
import { createApplication, createLoginMethod, login, TEST_ORGNR } from "../../testing/fixtures.js";
import { startTestServer } from "../../testing/test-server.js";
import { PLATFORM_ADMIN_ROLE, TENANT_ADMIN_ROLE } from "../constants.js";

/**
 * Privilege boundaries and lock-out guards of the admin API, live role checks, and the
 * operations that delete or detach (login methods, applications, identities, persons).
 */

const ts = await startTestServer();

type Json = Record<string, unknown>;
type Items = { items: Json[] };

describe.skipIf(ts === undefined)("admin API guards", () => {
  let world: AdminWorld;
  let x: AdminTenant;
  let platform: string;
  let platformId: string;
  let adminX: string;
  let adminXId: string;

  const call = <T = Json>(
    token: string,
    method: string,
    path: string,
    options?: Parameters<typeof adminCall>[4],
  ) => adminCall<T>(ts!, token, method, path, options);

  beforeAll(async () => {
    world = await setupAdminWorld(ts!);
    x = await createAdminTenant(world, "guards");
    platformId = await createAdmin(world, world.system, world.systemMethod, [PLATFORM_ADMIN_ROLE]);
    platform = await adminToken(world, world.system, world.systemMethod, platformId);
    adminXId = await createAdmin(world, x.tenant, x.method, [TENANT_ADMIN_ROLE]);
    adminX = await adminToken(world, x.tenant, x.method, adminXId);
  });

  describe("platform-admin can only come from the platform", () => {
    it("refuses tenant-admins of the system tenant everything but /me", async () => {
      const id = await createAdmin(world, world.system, world.systemMethod, [TENANT_ADMIN_ROLE]);
      const token = await adminToken(world, world.system, world.systemMethod, id);
      const base = `/tenants/${world.system.id}`;
      const assign = await call(token, "POST", `${base}/role-assignments`, {
        body: {
          applicationId: world.application.id,
          role: PLATFORM_ADMIN_ROLE,
          target: { personId: id },
        },
      });
      expect(assign.status).toBe(404);
      const rule = await call(token, "POST", `${base}/role-rules`, {
        body: {
          applicationId: world.application.id,
          loginMethodId: world.systemMethod.id,
          groupValue: "everyone",
          role: PLATFORM_ADMIN_ROLE,
        },
      });
      expect(rule.status).toBe(404);
      const method = await call(token, "POST", `${base}/login-methods`, {
        body: {
          protocol: "oidc",
          kind: "employee",
          displayName: "Own IdP",
          issuer: "http://127.0.0.1:9/own",
          clientId: "x",
          clientSecret: "s",
          claimMapping: {},
          assertedAcr: "urn:portvakt:acr:employee",
          sessionPolicy: { maxAgeSeconds: 3600, idleSeconds: 600, allowSso: true },
        },
      });
      expect(method.status).toBe(404);
      expect((await call(token, "GET", "/me")).status).toBe(200);
    });

    it("refuses platform-admin in another tenant: assignments, pending assignments and rules", async () => {
      const base = `/tenants/${x.tenant.id}`;
      const targets = [
        { personId: adminXId },
        { loginMethodId: x.method.id, subject: "someone-new" },
        { pin: "199001012385" },
      ];
      for (const token of [adminX, platform]) {
        for (const target of targets) {
          const response = await call(token, "POST", `${base}/role-assignments`, {
            body: { applicationId: world.application.id, role: PLATFORM_ADMIN_ROLE, target },
          });
          expect(response.status, JSON.stringify(target)).toBe(400);
          expect(response.body).toMatchObject({ errors: [{ field: "role" }] });
        }
        const rule = await call(token, "POST", `${base}/role-rules`, {
          body: {
            applicationId: world.application.id,
            loginMethodId: x.method.id,
            groupValue: "admins",
            role: PLATFORM_ADMIN_ROLE,
          },
        });
        expect(rule.body).toMatchObject({ errors: [{ field: "role" }] });
      }
      // tenant-admin stays assignable by the tenant's own administrator.
      const tenantAdmin = await call(adminX, "POST", `${base}/role-assignments`, {
        body: {
          applicationId: world.application.id,
          role: TENANT_ADMIN_ROLE,
          target: { loginMethodId: x.method.id, subject: "colleague" },
        },
      });
      expect(tenantAdmin.status).toBe(201);
    });

    it("lets platform administrators assign platform-admin in the system tenant", async () => {
      const response = await call(
        platform,
        "POST",
        `/tenants/${world.system.id}/role-assignments`,
        {
          body: {
            applicationId: world.application.id,
            role: PLATFORM_ADMIN_ROLE,
            target: { loginMethodId: world.systemMethod.id, subject: "second-platform-admin" },
          },
        },
      );
      expect(response.status).toBe(201);
      await call(
        platform,
        "DELETE",
        `/tenants/${world.system.id}/role-assignments/${(response.body as Items).items[0]!.id as string}`,
      );
    });
  });

  describe("live roles", () => {
    it("stops a removed role at the next request, not when the token expires", async () => {
      const id = await createAdmin(world, x.tenant, x.method, [TENANT_ADMIN_ROLE]);
      const token = await adminToken(world, x.tenant, x.method, id);
      expect((await call(token, "GET", `/tenants/${x.tenant.id}`)).status).toBe(200);
      await ts!.db.repos.access.unassignRole(x.tenant.id, {
        personId: id,
        applicationId: world.application.id,
        role: TENANT_ADMIN_ROLE,
      });
      expect((await call(token, "GET", `/tenants/${x.tenant.id}`)).status).toBe(403);
    });

    it("counts a role from a rule only while the stored groups still match", async () => {
      const { repos } = ts!.db;
      const { person } = await login(repos, x.tenant.id, x.method, "group-admin", {
        attributes: { groups: ["it-admins"] },
      });
      const rule = await repos.access.createRule(x.tenant.id, {
        applicationId: world.application.id,
        loginMethodId: x.method.id,
        groupValue: "it-admins",
        role: TENANT_ADMIN_ROLE,
      });
      const token = await adminToken(world, x.tenant, x.method, person.id);
      expect((await call(token, "GET", "/me")).status).toBe(200);
      await repos.access.deleteRule(x.tenant.id, rule.id);
      expect((await call(token, "GET", "/me")).status).toBe(403);
    });
  });

  describe("lock-out guards in the system tenant", () => {
    const system = () => `/tenants/${world.system.id}`;

    it("refuses removing the last platform-admin assignment", async () => {
      const list = await call<Items>(
        platform,
        "GET",
        `${system()}/role-assignments?applicationId=${world.application.id}`,
      );
      const own = list.body.items.find(
        (item) =>
          item.role === PLATFORM_ADMIN_ROLE &&
          (item.target as { personId?: string }).personId === platformId,
      )!;
      const response = await call(
        platform,
        "DELETE",
        `${system()}/role-assignments/${own.id as string}`,
      );
      expect(response.status).toBe(409);
      expect(response.body).toMatchObject({ code: "self_lockout" });
    });

    it("refuses disabling the last login method, or moving it to another issuer", async () => {
      const method = await call(
        platform,
        "GET",
        `${system()}/login-methods/${world.systemMethod.id}`,
      );
      const etag = method.body.etag as string;
      const disable = await call(
        platform,
        "PATCH",
        `${system()}/login-methods/${world.systemMethod.id}`,
        {
          body: { enabled: false },
          ifMatch: etag,
        },
      );
      expect(disable.body).toMatchObject({ code: "self_lockout" });
      const issuer = await call(
        platform,
        "PATCH",
        `${system()}/login-methods/${world.systemMethod.id}`,
        {
          body: { issuer: "http://127.0.0.1:9/elsewhere" },
          ifMatch: etag,
        },
      );
      expect(issuer.body).toMatchObject({ code: "self_lockout" });
      // The rename is fine.
      const rename = await call(
        platform,
        "PATCH",
        `${system()}/login-methods/${world.systemMethod.id}`,
        {
          body: { displayName: "System sign-in (renamed)" },
          ifMatch: etag,
        },
      );
      expect(rename.status).toBe(200);
    });

    it("allows the change once another way in exists (a rule), then refuses removing that", async () => {
      const second = await createLoginMethod(ts!.db.repos, world.system.id, {
        displayName: "Second system method",
      });
      const rule = await call(platform, "POST", `${system()}/role-rules`, {
        body: {
          applicationId: world.application.id,
          loginMethodId: second.id,
          groupValue: "platform-team",
          role: PLATFORM_ADMIN_ROLE,
        },
      });
      expect(rule.status).toBe(201);
      const method = await call(
        platform,
        "GET",
        `${system()}/login-methods/${world.systemMethod.id}`,
      );
      const moved = await call(
        platform,
        "PATCH",
        `${system()}/login-methods/${world.systemMethod.id}`,
        {
          body: { enabled: false },
          ifMatch: method.body.etag as string,
        },
      );
      expect(moved.status).toBe(200);
      const removeRule = await call(
        platform,
        "DELETE",
        `${system()}/role-rules/${rule.body.id as string}`,
      );
      expect(removeRule.body).toMatchObject({ code: "self_lockout" });
      // Restore for the other tests.
      await ts!.db.repos.loginMethods.update(world.system.id, world.systemMethod.id, {
        enabled: true,
      });
    });
  });

  describe("deleting and detaching", () => {
    it("deletes a login method without identities and refuses one with identities", async () => {
      const base = `/tenants/${x.tenant.id}/login-methods`;
      const unused = await createLoginMethod(ts!.db.repos, x.tenant.id, { displayName: "Unused" });
      const read = await call(adminX, "GET", `${base}/${unused.id}`);
      const missing = await call(adminX, "DELETE", `${base}/${unused.id}`);
      expect(missing.status).toBe(428);
      const deleted = await call(adminX, "DELETE", `${base}/${unused.id}`, {
        ifMatch: read.body.etag as string,
      });
      expect(deleted.status).toBe(204);
      expect((await call(adminX, "GET", `${base}/${unused.id}`)).status).toBe(404);
      const used = await call(adminX, "GET", `${base}/${x.method.id}`);
      const refused = await call(adminX, "DELETE", `${base}/${x.method.id}`, {
        ifMatch: used.body.etag as string,
      });
      expect(refused.status).toBe(409);
      expect(refused.body).toMatchObject({ code: "in_use" });
    });

    it("detaches an application with a typed confirmation, reporting what it removed", async () => {
      const { repos } = ts!.db;
      const app = await createApplication(repos);
      await repos.applications.enableForTenant(x.tenant.id, app.id);
      await repos.access.assignRole(x.tenant.id, {
        personId: adminXId,
        applicationId: app.id,
        role: "reader",
      });
      const base = `/tenants/${x.tenant.id}/applications/${app.id}`;
      const usage = await call(platform, "GET", `${base}/usage`);
      expect(usage.body).toMatchObject({ roleAssignments: 1, roleRules: 0 });
      expect((await call(adminX, "GET", `${base}/usage`)).status).toBe(403);
      const list = await call<Items>(platform, "GET", `/tenants/${x.tenant.id}/applications`);
      const entry = list.body.items.find((item) => item.applicationId === app.id)!;
      const wrong = await call(platform, "POST", `${base}/detach`, {
        body: { confirmClientId: "something-else" },
        ifMatch: entry.etag as string,
      });
      expect(wrong.body).toMatchObject({ errors: [{ field: "confirmClientId" }] });
      const detached = await call(platform, "POST", `${base}/detach`, {
        body: { confirmClientId: app.clientId },
        ifMatch: entry.etag as string,
      });
      expect(detached.body).toMatchObject({ roleAssignments: 1 });
      expect(await repos.access.listAssignments(x.tenant.id, { applicationId: app.id })).toEqual(
        [],
      );
      const events = await repos.audit.query(
        { tenantId: x.tenant.id },
        {
          actions: ["admin.tenant_application.detach"],
        },
      );
      expect(events.events[0]!.details).toMatchObject({ removed: { roleAssignments: 1 } });
    });

    it("unlinks an identity, refuses the last one, and deletes the person", async () => {
      const { repos } = ts!.db;
      const a = await createLoginMethod(repos, x.tenant.id, {
        displayName: "Link A",
        linkByPin: true,
      });
      const b = await createLoginMethod(repos, x.tenant.id, {
        displayName: "Link B",
        linkByPin: true,
      });
      const first = await login(repos, x.tenant.id, a, "subject-a", { pin: "199001012385" });
      const second = await login(repos, x.tenant.id, b, "subject-b", { pin: "199001012385" });
      expect(second.person.id).toBe(first.person.id);
      const base = `/tenants/${x.tenant.id}/persons/${first.person.id}`;
      const person = await call(adminX, "GET", base);
      const unlink = await call(adminX, "POST", `${base}/identities/${second.identity.id}/unlink`, {
        ifMatch: person.body.etag as string,
      });
      expect(unlink.status).toBe(200);
      expect((unlink.body.identities as Json[]).map((item) => item.id)).toEqual([
        first.identity.id,
      ]);
      const last = await call(adminX, "POST", `${base}/identities/${first.identity.id}/unlink`, {
        ifMatch: unlink.body.etag as string,
      });
      expect(last.status).toBe(409);
      expect(last.body).toMatchObject({ code: "last_identity" });
      await repos.access.assignRole(x.tenant.id, {
        personId: first.person.id,
        applicationId: world.application.id,
        role: TENANT_ADMIN_ROLE,
      });
      const deleted = await call(adminX, "DELETE", base, { ifMatch: unlink.body.etag as string });
      expect(deleted.status).toBe(204);
      expect((await call(adminX, "GET", base)).status).toBe(404);
      expect(
        await repos.access.listAssignments(x.tenant.id, { personId: first.person.id }),
      ).toEqual([]);
      const events = await repos.audit.query(
        { tenantId: x.tenant.id },
        {
          subjectId: first.person.id,
          actionPrefix: "admin.person",
        },
      );
      expect(events.events.map((event) => event.action)).toEqual([
        "admin.person.delete",
        "admin.person.identity_unlink",
      ]);
      expect(JSON.stringify(events.events)).not.toContain("subject-b");
    });
  });

  describe("editing applications, grants, tenants and parties", () => {
    it("reports what removing roles deletes, then removes them with the PATCH", async () => {
      const { repos } = ts!.db;
      const app = await createApplication(repos);
      await repos.applications.enableForTenant(x.tenant.id, app.id);
      await repos.access.assignRole(x.tenant.id, {
        personId: adminXId,
        applicationId: app.id,
        role: "reader",
      });
      const impact = await call(platform, "POST", `/applications/${app.id}/removal-impact`, {
        body: { roles: ["reader"], attributeKeys: [] },
      });
      expect(impact.body).toMatchObject({ roleAssignments: 1 });
      const current = await call(platform, "GET", `/applications/${app.id}`);
      const updated = await call(platform, "PATCH", `/applications/${app.id}`, {
        body: {
          name: "Renamed",
          redirectUris: ["https://app.example.test/t/{tenant}/callback"],
          roles: [{ role: "handlaggare" }, { role: "admin" }],
          representationMode: "optional",
          allowedExtraScopes: ["pin"],
        },
        ifMatch: current.body.etag as string,
      });
      expect(updated.status).toBe(200);
      expect(updated.body.application).toMatchObject({
        name: "Renamed",
        representationMode: "optional",
      });
      expect(await repos.access.listAssignments(x.tenant.id, { applicationId: app.id })).toEqual(
        [],
      );
    });

    it("changes a grant's applications and validity window", async () => {
      const { repos } = ts!.db;
      const app = await createApplication(repos);
      await repos.applications.enableForTenant(x.tenant.id, app.id);
      const party = await repos.parties.create(x.tenant.id, {
        type: "organisation",
        identifier: TEST_ORGNR,
        displayName: "Bygg AB",
      });
      const grant = await call(adminX, "POST", `/tenants/${x.tenant.id}/grants`, {
        body: { agent: { personId: adminXId }, partyId: party.id, allApplications: true },
      });
      const validTo = new Date(Date.now() + 30 * 86_400_000).toISOString();
      const patched = await call(
        adminX,
        "PATCH",
        `/tenants/${x.tenant.id}/grants/${grant.body.id as string}`,
        {
          body: { allApplications: false, applicationIds: [app.id], validTo },
          ifMatch: grant.body.etag as string,
        },
      );
      expect(patched.status).toBe(200);
      expect(patched.body).toMatchObject({
        allApplications: false,
        applicationIds: [app.id],
        validTo,
      });
      const invalid = await call(
        adminX,
        "PATCH",
        `/tenants/${x.tenant.id}/grants/${grant.body.id as string}`,
        {
          body: { validTo: new Date(Date.now() - 365 * 86_400_000).toISOString() },
          ifMatch: patched.body.etag as string,
        },
      );
      expect(invalid.body).toMatchObject({ errors: [{ field: "validTo" }] });
    });

    it("sets a tenant's representation sources (registered ones only)", async () => {
      const current = await call(platform, "GET", `/tenants/${x.tenant.id}`);
      const unknown = await call(platform, "PATCH", `/tenants/${x.tenant.id}`, {
        body: { representationSources: ["bolagsverket"] },
        ifMatch: current.body.etag as string,
      });
      expect(unknown.body).toMatchObject({ errors: [{ field: "representationSources.0" }] });
      const none = await call(platform, "PATCH", `/tenants/${x.tenant.id}`, {
        body: { representationSources: [] },
        ifMatch: current.body.etag as string,
      });
      expect(none.body).toMatchObject({ representationSources: [] });
      expect(
        (await call(adminX, "PATCH", `/tenants/${x.tenant.id}`, { body: { name: "x" } })).status,
      ).toBe(403);
    });

    it("sets, changes and removes attribute assignments, direct and pending, with etags", async () => {
      const { repos } = ts!.db;
      const app = await createApplication(repos, { attributeKeys: [{ key: "unit" }] });
      await repos.applications.enableForTenant(x.tenant.id, app.id);
      const base = `/tenants/${x.tenant.id}/attribute-assignments`;
      const undeclared = await call(adminX, "POST", base, {
        body: { applicationId: app.id, key: "other", value: "x", target: { personId: adminXId } },
      });
      expect(undeclared.status).toBe(400);
      const direct = await call<Items>(adminX, "POST", base, {
        body: {
          applicationId: app.id,
          key: "unit",
          value: "north",
          target: { personId: adminXId },
        },
      });
      const pending = await call<Items>(adminX, "POST", base, {
        body: {
          applicationId: app.id,
          key: "unit",
          value: "south",
          target: { loginMethodId: x.method.id, subject: "attr-later" },
        },
      });
      const list = await call<Items>(adminX, "GET", `${base}?applicationId=${app.id}`);
      expect(list.body.items.map((item) => [item.value, item.pending])).toEqual([
        ["north", false],
        ["south", true],
      ]);
      for (const created of [direct.body.items[0]!, pending.body.items[0]!]) {
        const path = `${base}/${created.id as string}`;
        expect((await call(adminX, "PATCH", path, { body: { value: "east" } })).status).toBe(428);
        const changed = await call(adminX, "PATCH", path, {
          body: { value: "east" },
          ifMatch: created.etag as string,
        });
        expect(changed.body).toMatchObject({ value: "east" });
        const stale = await call(adminX, "PATCH", path, {
          body: { value: "west" },
          ifMatch: created.etag as string,
        });
        expect(stale.status).toBe(412);
        expect((await call(adminX, "DELETE", path)).status).toBe(204);
      }
      expect(
        (await call<Items>(adminX, "GET", `${base}?applicationId=${app.id}`)).body.items,
      ).toEqual([]);
    });

    it("refuses unknown fields when creating a party", async () => {
      const response = await call(adminX, "POST", `/tenants/${x.tenant.id}/parties`, {
        body: { type: "organisation", identifier: TEST_ORGNR, displayName: "X", extra: true },
      });
      expect(response.body).toMatchObject({ errors: [{ field: "extra" }] });
    });
  });
});
