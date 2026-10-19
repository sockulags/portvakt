import { decodeJwt, importJWK, SignJWT, type JWK } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import type { Tenant } from "../../domain/tenant.js";
import {
  adminCall,
  adminServiceToken,
  adminToken,
  createAdmin,
  createAdminTenant,
  setupAdminWorld,
  type AdminTenant,
  type AdminWorld,
} from "../../testing/admin.js";
import { createApplication, login, TEST_ORGNR } from "../../testing/fixtures.js";
import { startTestServer } from "../../testing/test-server.js";
import { ADMIN_CLIENT_ID, PLATFORM_ADMIN_ROLE, TENANT_ADMIN_ROLE } from "../constants.js";
import { adminOpenApi, adminRoutes, type AdminDeps } from "./index.js";

const ts = await startTestServer();

type Json = Record<string, unknown>;
type Items = { items: Json[] };

describe.skipIf(ts === undefined)("admin API", () => {
  let world: AdminWorld;
  let x: AdminTenant;
  let y: AdminTenant;
  const tokens: Record<
    "platform" | "adminX" | "adminY" | "plain" | "service" | "systemTenantAdmin",
    string
  > = {} as never;
  let adminXId: string;

  beforeAll(async () => {
    world = await setupAdminWorld(ts!);
    x = await createAdminTenant(world, "x");
    y = await createAdminTenant(world, "y");
    const platformId = await createAdmin(world, world.system, world.systemMethod, [
      PLATFORM_ADMIN_ROLE,
    ]);
    adminXId = await createAdmin(world, x.tenant, x.method, [TENANT_ADMIN_ROLE]);
    const adminYId = await createAdmin(world, y.tenant, y.method, [TENANT_ADMIN_ROLE]);
    // platform-admin means nothing outside the system tenant.
    const plainId = await createAdmin(world, x.tenant, x.method, [PLATFORM_ADMIN_ROLE]);
    const systemTenantAdminId = await createAdmin(world, world.system, world.systemMethod, [
      TENANT_ADMIN_ROLE,
    ]);
    tokens.platform = await adminToken(world, world.system, world.systemMethod, platformId);
    tokens.adminX = await adminToken(world, x.tenant, x.method, adminXId);
    tokens.adminY = await adminToken(world, y.tenant, y.method, adminYId);
    tokens.plain = await adminToken(world, x.tenant, x.method, plainId);
    tokens.systemTenantAdmin = await adminToken(
      world,
      world.system,
      world.systemMethod,
      systemTenantAdminId,
    );
    tokens.service = await adminServiceToken(world, x.tenant);
  });

  const call = <T = Json>(
    token: string | undefined,
    method: string,
    path: string,
    options?: Parameters<typeof adminCall>[4],
  ) => adminCall<T>(ts!, token, method, path, options);

  /** A token signed with Portvakt's own key but with chosen claims (what a forger cannot do). */
  async function signed(claims: Json): Promise<string> {
    const key = ts!.portvakt.keyCache.current!.jwks.keys[0] as unknown as JWK;
    return new SignJWT(claims)
      .setProtectedHeader({ alg: "ES256", kid: key.kid!, typ: "at+jwt" })
      .sign(await importJWK(key, "ES256"));
  }

  describe("authentication", () => {
    it("answers problem+json 401 without or with a broken token", async () => {
      const none = await call(undefined, "GET", "/me");
      expect(none.status).toBe(401);
      expect(none.contentType).toContain("application/problem+json");
      expect(none.body).toMatchObject({
        code: "unauthorized",
        type: "urn:portvakt:problem:unauthorized",
      });
      expect((await call("not-a-jwt", "GET", "/me")).body).toMatchObject({ code: "invalid_token" });
    });

    it("derives the scope from the issuer's tenant and the roles", async () => {
      const platform = await call(tokens.platform, "GET", "/me");
      expect(platform.body).toMatchObject({ platform: true, tenant: { slug: "system" } });
      const tenant = await call(tokens.adminX, "GET", "/me");
      expect(tenant.body).toMatchObject({
        platform: false,
        personId: adminXId,
        tenant: { id: x.tenant.id },
      });
      // platform-admin outside system, or tenant-admin roles missing: no access.
      expect((await call(tokens.plain, "GET", "/me")).status).toBe(403);
    });

    it("refuses service tokens", async () => {
      const response = await call(tokens.service, "GET", "/me");
      expect(response.status).toBe(403);
      expect(response.body).toMatchObject({ code: "service_token_not_allowed" });
    });

    it("refuses a token whose tid names another tenant than its issuer", async () => {
      const claims = decodeJwt(tokens.adminY);
      const forged = await signed({ ...claims, tid: x.tenant.slug });
      expect((await call(forged, "GET", "/me")).body).toMatchObject({ code: "invalid_token" });
      // And a token of tenant Y's issuer never reaches tenant X's resources.
      const response = await call(tokens.adminY, "GET", `/tenants/${x.tenant.id}`);
      expect(response.status).toBe(404);
    });

    it("refuses tokens with rep, other audiences or unknown issuers", async () => {
      const claims = decodeJwt(tokens.adminX);
      const rep = await signed({
        ...claims,
        rep: { sub: crypto.randomUUID(), type: "organisation" },
      });
      expect((await call(rep, "GET", "/me")).body).toMatchObject({
        code: "representation_not_allowed",
      });
      const audience = await signed({ ...claims, aud: "service-a" });
      expect((await call(audience, "GET", "/me")).body).toMatchObject({ code: "invalid_token" });
      const issuer = await signed({ ...claims, iss: "https://evil.example/t/x" });
      expect((await call(issuer, "GET", "/me")).body).toMatchObject({ code: "invalid_token" });
    });
  });

  describe("scope matrix", () => {
    const deps = (): AdminDeps => ({}) as AdminDeps;
    const routes = () => adminRoutes(deps());

    const fill = (path: string, tenant: Tenant): string =>
      path.replace("{tenantId}", tenant.id).replace(/\{\w+\}/g, crypto.randomUUID());

    it("answers 404 to tenant administrators for every route of another tenant", async () => {
      for (const route of routes().filter((item) => item.path.includes("{tenantId}"))) {
        const method = route.method.toUpperCase();
        const options = route.body === undefined ? {} : { body: {} };
        const asX = await call(tokens.adminX, method, fill(route.path, y.tenant), options);
        expect(asX.status, `${method} ${route.path}`).toBe(route.platformOnly ? 403 : 404);
        const asY = await call(tokens.adminY, method, fill(route.path, x.tenant), options);
        expect(asY.status, `${method} ${route.path}`).toBe(route.platformOnly ? 403 : 404);
      }
    });

    it("refuses platform-only routes to tenant administrators", async () => {
      for (const route of routes().filter((item) => item.platformOnly)) {
        const method = route.method.toUpperCase();
        const options = route.body === undefined ? {} : { body: {} };
        const response = await call(tokens.adminX, method, fill(route.path, x.tenant), options);
        expect(response.status, `${method} ${route.path}`).toBe(403);
      }
    });

    it("shows tenant administrators of the system tenant nothing but themselves", async () => {
      expect((await call(tokens.systemTenantAdmin, "GET", "/me")).status).toBe(200);
      for (const route of routes().filter((item) => item.path !== "/me")) {
        const method = route.method.toUpperCase();
        const options = route.body === undefined ? {} : { body: {} };
        const response = await call(
          tokens.systemTenantAdmin,
          method,
          fill(route.path, world.system),
          options,
        );
        expect(response.status, `${method} ${route.path}`).toBe(404);
      }
    });

    it("refuses every route to service tokens and tokens without an admin role", async () => {
      for (const route of routes()) {
        const method = route.method.toUpperCase();
        for (const token of [tokens.service, tokens.plain]) {
          const response = await call(token, method, fill(route.path, x.tenant));
          expect(response.status, `${method} ${route.path}`).toBe(403);
        }
      }
    });

    it("lets tenant administrators read their own tenant and platform administrators any", async () => {
      const reads = routes().filter(
        (item) =>
          item.method === "get" &&
          !item.platformOnly &&
          item.path.match(/\{(\w+)\}/g)?.length === 1 &&
          item.path.includes("{tenantId}"),
      );
      expect(reads.length).toBeGreaterThan(8);
      for (const route of reads) {
        const own = await call(tokens.adminX, "GET", fill(route.path, x.tenant));
        expect(own.status, route.path).toBe(200);
        const platform = await call(tokens.platform, "GET", fill(route.path, y.tenant));
        expect(platform.status, route.path).toBe(200);
      }
      const list = await call<Items>(tokens.adminX, "GET", "/tenants");
      expect(list.body.items.map((item) => item.id)).toEqual([x.tenant.id]);
      const all = await call<Items>(tokens.platform, "GET", "/tenants");
      expect(all.body.items.map((item) => item.id)).toEqual(
        expect.arrayContaining([x.tenant.id, y.tenant.id, world.system.id]),
      );
      // An unknown tenant is 404 for the platform too.
      expect((await call(tokens.platform, "GET", `/tenants/${crypto.randomUUID()}`)).status).toBe(
        404,
      );
      expect((await call(tokens.platform, "GET", "/tenants/not-a-uuid")).status).toBe(404);
    });
  });

  describe("tenants and optimistic concurrency", () => {
    it("creates, renames with If-Match and keeps the slug immutable", async () => {
      const created = await call(tokens.platform, "POST", "/tenants", {
        body: { slug: `new-${Date.now()}`, name: "Ny kommun" },
      });
      expect(created.status).toBe(201);
      const id = created.body.id as string;
      const etag = created.body.etag as string;
      expect(created.etag).toBe(etag);

      const slug = await call(tokens.platform, "PATCH", `/tenants/${id}`, {
        body: { slug: "other" },
        ifMatch: etag,
      });
      expect(slug.status).toBe(400);
      expect(slug.body).toMatchObject({ code: "validation_failed", errors: [{ field: "slug" }] });

      const missing = await call(tokens.platform, "PATCH", `/tenants/${id}`, {
        body: { name: "A" },
      });
      expect(missing.status).toBe(428);
      expect(missing.body).toMatchObject({ code: "precondition_required" });

      const renamed = await call(tokens.platform, "PATCH", `/tenants/${id}`, {
        body: { name: "Nytt namn" },
        ifMatch: etag,
      });
      expect(renamed.status).toBe(200);
      expect(renamed.body.etag).not.toBe(etag);

      const stale = await call(tokens.platform, "PATCH", `/tenants/${id}`, {
        body: { name: "Tredje" },
        ifMatch: etag,
      });
      expect(stale.status).toBe(412);
      expect(stale.body).toMatchObject({ code: "precondition_failed" });

      const suspended = await call(tokens.platform, "POST", `/tenants/${id}/suspend`, {
        ifMatch: renamed.body.etag as string,
      });
      expect(suspended.body).toMatchObject({ status: "suspended" });

      const events = await ts!.db.repos.audit.query(
        { tenantId: id },
        { actionPrefix: "admin.tenant" },
      );
      expect(events.events.map((event) => event.action)).toEqual([
        "admin.tenant.suspend",
        "admin.tenant.update",
        "admin.tenant.create",
      ]);
      expect(events.events[1]!.details).toMatchObject({
        changes: { name: { from: "Ny kommun", to: "Nytt namn" } },
      });
    });

    it("refuses to suspend the system tenant and duplicate slugs", async () => {
      const system = await call(tokens.platform, "GET", `/tenants/${world.system.id}`);
      const response = await call(tokens.platform, "POST", `/tenants/${world.system.id}/suspend`, {
        ifMatch: system.body.etag as string,
      });
      expect(response.body).toMatchObject({ code: "self_lockout" });
      const duplicate = await call(tokens.platform, "POST", "/tenants", {
        body: { slug: x.tenant.slug, name: "Dup" },
      });
      expect(duplicate.status).toBe(409);
    });

    it("lists field errors and refuses non-JSON bodies", async () => {
      const invalid = await call(tokens.platform, "POST", "/tenants", {
        body: { slug: "Bad Slug", name: "" },
      });
      expect(invalid.status).toBe(400);
      expect(
        (invalid.body.errors as { field: string }[]).map((error) => error.field).sort(),
      ).toEqual(["name", "slug"]);
      const text = await call(tokens.platform, "POST", "/tenants", {
        headers: { "content-type": "text/plain" },
      });
      expect(text.status).toBe(415);
    });
  });

  describe("applications", () => {
    it("returns a generated secret once and never again", async () => {
      const created = await call(tokens.platform, "POST", "/applications", {
        body: {
          clientId: `app-${Date.now()}`,
          name: "Ny tjänst",
          clientAuth: { method: "client_secret_basic" },
          redirectUris: ["https://app.example.test/t/{tenant}/callback"],
          roles: [{ role: "reader" }],
        },
      });
      expect(created.status).toBe(201);
      const secret = created.body.clientSecret as string;
      expect(secret.length).toBeGreaterThanOrEqual(32);
      const application = created.body.application as Json;
      const read = await call(tokens.platform, "GET", `/applications/${application.id as string}`);
      expect(JSON.stringify(read.body)).not.toContain(secret);

      const rotated = await call(
        tokens.platform,
        "POST",
        `/applications/${application.id as string}/rotate-secret`,
        {
          ifMatch: read.body.etag as string,
        },
      );
      expect(rotated.status).toBe(200);
      expect(rotated.body.clientSecret).not.toBe(secret);
      const events = await ts!.db.repos.audit.query(
        { allTenants: true, tenantId: null },
        { subjectId: application.id as string },
      );
      const serialized = JSON.stringify(events.events);
      expect(serialized).not.toContain(secret);
      expect(serialized).not.toContain(rotated.body.clientSecret as string);
      expect(events.events.map((event) => event.action)).toEqual([
        "admin.application.secret_rotate",
        "admin.application.create",
      ]);
      expect(events.events[1]!.details.changes).toMatchObject({
        "clientAuth.clientSecret": { changed: true },
      });
    });

    it("sets serviceAudiences (default empty), validated and audited", async () => {
      const clientId = `svc-${Date.now()}`;
      const created = await call<{ application: Record<string, unknown> }>(
        tokens.platform,
        "POST",
        "/applications",
        {
          body: {
            clientId,
            name: "Service caller",
            clientAuth: { method: "client_secret_basic" },
            redirectUris: ["https://svc.example.test/cb"],
          },
        },
      );
      expect(created.status).toBe(201);
      const application = created.body.application;
      expect(application.serviceAudiences).toEqual([]);
      const changed = await call<{ application: Record<string, unknown> }>(
        tokens.platform,
        "PATCH",
        `/applications/${application.id as string}`,
        { body: { serviceAudiences: ["archive-service"] }, ifMatch: application.etag as string },
      );
      expect(changed.status).toBe(200);
      expect(changed.body.application.serviceAudiences).toEqual(["archive-service"]);
      const invalid = await call(
        tokens.platform,
        "PATCH",
        `/applications/${application.id as string}`,
        {
          body: { serviceAudiences: ["a b", "archive-service", "archive-service"] },
          ifMatch: changed.body.application.etag as string,
        },
      );
      expect(invalid.status).toBe(400);
      const [update] = (
        await ts!.db.repos.audit.query(
          { allTenants: true, tenantId: null },
          { subjectId: application.id as string, actions: ["admin.application.update"] },
        )
      ).events;
      expect(update?.details.changes).toMatchObject({
        serviceAudiences: { from: [], to: ["archive-service"] },
      });
    });

    it("validates redirect URIs and protects portvakt-admin", async () => {
      const bad = await call(tokens.platform, "POST", "/applications", {
        body: {
          clientId: `bad-${Date.now()}`,
          name: "Bad",
          clientAuth: { method: "client_secret_basic" },
          redirectUris: ["https://app.example.test/{other}/cb", "not a url"],
        },
      });
      expect(bad.status).toBe(400);
      expect((bad.body.errors as { field: string }[]).map((error) => error.field)).toEqual([
        "redirectUris.0",
        "redirectUris.1",
      ]);
      const admin = await call(tokens.platform, "GET", `/applications/${world.application.id}`);
      const disable = await call(
        tokens.platform,
        "PATCH",
        `/applications/${world.application.id}`,
        {
          body: { enabled: false },
          ifMatch: admin.body.etag as string,
        },
      );
      expect(disable.body).toMatchObject({ code: "self_lockout" });
      const list = await call<Items>(tokens.adminX, "GET", `/tenants/${x.tenant.id}/applications`);
      const own = list.body.items.find((item) => item.clientId === ADMIN_CLIENT_ID)!;
      const lockout = await call(
        tokens.adminX,
        "PATCH",
        `/tenants/${x.tenant.id}/applications/${world.application.id}`,
        {
          body: { enabled: false },
          ifMatch: own.etag as string,
        },
      );
      expect(lockout.body).toMatchObject({ code: "self_lockout" });
    });

    it("lets platform admins attach applications and tenant admins switch them", async () => {
      const app = await createApplication(ts!.db.repos);
      const attach = await call(
        tokens.platform,
        "PUT",
        `/tenants/${x.tenant.id}/applications/${app.id}`,
      );
      expect(attach.status).toBe(201);
      expect(
        (await call(tokens.adminX, "PUT", `/tenants/${x.tenant.id}/applications/${app.id}`)).status,
      ).toBe(403);
      const off = await call(
        tokens.adminX,
        "PATCH",
        `/tenants/${x.tenant.id}/applications/${app.id}`,
        {
          body: { enabled: false },
          ifMatch: attach.body.etag as string,
        },
      );
      expect(off.body).toMatchObject({ enabled: false });
    });
  });

  describe("login methods", () => {
    it("keeps secrets write-only, in responses and in audit diffs", async () => {
      const secret = "upstream-secret-must-never-leak-0123";
      const created = await call(tokens.adminX, "POST", `/tenants/${x.tenant.id}/login-methods`, {
        body: {
          protocol: "oidc",
          kind: "employee",
          displayName: "Entra",
          issuer: "http://127.0.0.1:9/entra",
          clientId: "portvakt",
          clientSecret: secret,
          claimMapping: { subject: "oid" },
          assertedAcr: "urn:portvakt:acr:employee",
          sessionPolicy: { maxAgeSeconds: 3600, idleSeconds: 600, allowSso: true },
          secretExpiresAt: new Date(Date.now() + 10 * 86_400_000).toISOString(),
        },
      });
      expect(created.status).toBe(201);
      expect(JSON.stringify(created.body)).not.toContain(secret);
      expect(created.body).toMatchObject({
        protocol: "oidc",
        oidc: { hasClientSecret: true },
        warnings: [{ code: "client_secret_expiring" }],
      });
      const id = created.body.id as string;
      const updated = await call(
        tokens.adminX,
        "PATCH",
        `/tenants/${x.tenant.id}/login-methods/${id}`,
        {
          body: { clientSecret: `${secret}-2`, displayName: "Entra ID" },
          ifMatch: created.body.etag as string,
        },
      );
      expect(updated.status).toBe(200);
      const policy = await call(
        tokens.adminX,
        "PUT",
        `/tenants/${x.tenant.id}/login-methods/${id}/session-policy`,
        {
          body: { maxAgeSeconds: 7200, idleSeconds: 900, allowSso: false },
          ifMatch: updated.body.etag as string,
        },
      );
      expect(policy.body).toMatchObject({
        sessionPolicy: { maxAgeSeconds: 7200, allowSso: false },
      });
      const wrongProtocol = await call(
        tokens.adminX,
        "PATCH",
        `/tenants/${x.tenant.id}/login-methods/${id}`,
        {
          body: { saml: { clockSkewSeconds: 30 } },
          ifMatch: policy.body.etag as string,
        },
      );
      expect(wrongProtocol.body).toMatchObject({ errors: [{ field: "saml" }] });

      const events = await ts!.db.repos.audit.query({ tenantId: x.tenant.id }, { subjectId: id });
      const serialized = JSON.stringify(events.events);
      expect(serialized).not.toContain(secret);
      expect(events.events.map((event) => event.action)).toEqual([
        "admin.login_method.update",
        "admin.login_method.update",
        "admin.login_method.create",
      ]);
      expect(events.events[1]!.details.changes).toEqual({
        clientSecret: { changed: true },
        displayName: { from: "Entra", to: "Entra ID" },
      });
      expect(events.events[0]!.details.changes).toMatchObject({
        "sessionPolicy.allowSso": { from: true, to: false },
      });
    });

    it("refuses an issuer the outbound guard refuses", async () => {
      const response = await call(tokens.adminX, "POST", `/tenants/${x.tenant.id}/login-methods`, {
        body: {
          protocol: "oidc",
          kind: "employee",
          displayName: "Metadata",
          issuer: "http://169.254.169.254/latest",
          clientId: "x",
          claimMapping: {},
          assertedAcr: "urn:portvakt:acr:employee",
          sessionPolicy: { maxAgeSeconds: 3600, idleSeconds: 600, allowSso: true },
        },
      });
      expect(response.body).toMatchObject({
        code: "validation_failed",
        errors: [{ field: "issuer" }],
      });
    });
  });

  describe("persons, assignments and representation", () => {
    it("searches by name prefix and by personal identity number, never listing numbers", async () => {
      const { repos } = ts!.db;
      const { person } = await login(repos, x.tenant.id, x.method, "subject-greta", {
        attributes: { name: "Greta Gransson", email: "greta@example.test" },
        pin: "191212121212",
      });
      const byName = await call<Items>(
        tokens.adminX,
        "POST",
        `/tenants/${x.tenant.id}/persons/search`,
        {
          body: { query: "gran" },
        },
      );
      expect(byName.body.items.map((item) => item.id)).toEqual([person.id]);
      const byPin = await call<Items>(
        tokens.adminX,
        "POST",
        `/tenants/${x.tenant.id}/persons/search`,
        {
          body: { pin: "19121212-1212" },
        },
      );
      expect(byPin.body.items.map((item) => item.id)).toEqual([person.id]);
      const detail = await call(
        tokens.adminX,
        "GET",
        `/tenants/${x.tenant.id}/persons/${person.id}`,
      );
      expect(detail.body).toMatchObject({
        displayName: "Greta Gransson",
        identities: [{ loginMethodId: x.method.id, subject: "subject-greta", hasPin: true }],
      });
      expect(JSON.stringify(detail.body)).not.toContain("191212121212");
      // Tenant Y's administrator finds nobody of tenant X.
      expect(
        (
          await call(tokens.adminY, "POST", `/tenants/${x.tenant.id}/persons/search`, {
            body: { query: "gran" },
          })
        ).status,
      ).toBe(404);
    });

    it("assigns roles pending to an identity reference and a personal identity number", async () => {
      const { repos } = ts!.db;
      const app = await createApplication(repos);
      await repos.applications.enableForTenant(x.tenant.id, app.id);
      const bySubject = await call<Items>(
        tokens.adminX,
        "POST",
        `/tenants/${x.tenant.id}/role-assignments`,
        {
          body: {
            applicationId: app.id,
            role: "reader",
            target: { loginMethodId: x.method.id, subject: "future-subject" },
          },
        },
      );
      expect(bySubject.status).toBe(201);
      expect(bySubject.body.items).toEqual([
        expect.objectContaining({
          pending: true,
          target: { kind: "identity", loginMethodId: x.method.id, subject: "future-subject" },
        }),
      ]);
      const byPin = await call<Items>(
        tokens.adminX,
        "POST",
        `/tenants/${x.tenant.id}/role-assignments`,
        {
          body: { applicationId: app.id, role: "admin", target: { pin: "199001012385" } },
        },
      );
      expect(byPin.body.items).toEqual([
        expect.objectContaining({ pending: true, target: { kind: "pin" } }),
      ]);
      const attribute = await call<Items>(
        tokens.adminX,
        "POST",
        `/tenants/${x.tenant.id}/attribute-assignments`,
        {
          body: {
            applicationId: app.id,
            key: "unit",
            value: "secret-unit-value",
            target: { loginMethodId: x.method.id, subject: "future-subject" },
          },
        },
      );
      expect(attribute.status).toBe(201);

      const { person, resolved } = await login(repos, x.tenant.id, x.method, "future-subject");
      expect(resolved.map((item) => item.kind).sort()).toEqual(["attribute", "role"]);
      const access = await repos.access.effectiveAccess(x.tenant.id, {
        personId: person.id,
        applicationId: app.id,
        loginMethodId: x.method.id,
        groups: [],
      });
      expect(access).toEqual({ roles: ["reader"], attributes: { unit: "secret-unit-value" } });
      const list = await call<Items>(
        tokens.adminX,
        "GET",
        `/tenants/${x.tenant.id}/role-assignments?applicationId=${app.id}`,
      );
      expect(list.body.items).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            pending: false,
            role: "reader",
            target: { kind: "person", personId: person.id },
          }),
          expect.objectContaining({ pending: true, role: "admin", target: { kind: "pin" } }),
        ]),
      );
      // The pin target only resolves through a method trusted for personal identity numbers.
      const untrusted = await login(repos, x.tenant.id, x.method, "pin-person", {
        pin: "199001012385",
      });
      expect(untrusted.resolved).toEqual([]);
      const events = await repos.audit.query(
        { tenantId: x.tenant.id },
        { actionPrefix: "admin.attribute_assignment" },
      );
      expect(JSON.stringify(events.events)).not.toContain("secret-unit-value");
      expect(JSON.stringify(events.events)).not.toContain("future-subject");
    });

    it("manages parties and grants without exposing personal identity numbers", async () => {
      const party = await call(tokens.adminX, "POST", `/tenants/${x.tenant.id}/parties`, {
        body: { type: "organisation", identifier: TEST_ORGNR, displayName: "Bygg AB" },
      });
      expect(party.status).toBe(201);
      const person = await call(tokens.adminX, "POST", `/tenants/${x.tenant.id}/parties`, {
        body: { type: "person", identifier: "199001012385", displayName: "Pelle Person" },
      });
      expect(person.body).toMatchObject({ identifier: "19900101-****" });
      const grant = await call(tokens.adminX, "POST", `/tenants/${x.tenant.id}/grants`, {
        body: { agent: { pin: "191212121212" }, partyId: party.body.id, allApplications: true },
      });
      expect(grant.status).toBe(201);
      expect(grant.body).toMatchObject({ agent: { kind: "pin" }, status: "active" });
      expect(JSON.stringify(grant.body)).not.toContain("191212121212");
      const revoked = await call(
        tokens.adminX,
        "POST",
        `/tenants/${x.tenant.id}/grants/${grant.body.id as string}/revoke`,
        {
          ifMatch: grant.body.etag as string,
        },
      );
      expect(revoked.body).toMatchObject({ status: "revoked", revokedBy: adminXId });
      const events = await ts!.db.repos.audit.query(
        { tenantId: x.tenant.id },
        { actionPrefix: "admin.party" },
      );
      const serialized = JSON.stringify(events.events);
      expect(serialized).not.toContain("Pelle");
      expect(serialized).not.toContain("199001012385");
      expect(serialized).not.toContain("Bygg");
    });
  });

  describe("signing keys, audit and dashboard", () => {
    it("rotates (platform only) with a reason free of personal data", async () => {
      const keys = await call(tokens.adminX, "GET", "/signing-keys");
      const etag = keys.body.etag as string;
      const refused = await call(tokens.adminX, "POST", "/signing-keys/rotate", {
        body: { reason: "tenant admin" },
        ifMatch: etag,
      });
      expect(refused.status).toBe(403);
      const pii = await call(tokens.platform, "POST", "/signing-keys/rotate", {
        body: { reason: "for 19121212-1212" },
        ifMatch: etag,
      });
      expect(pii.body).toMatchObject({ errors: [{ field: "reason" }] });
      // Concurrent rotations with the same tag: the tag is checked under the rotation's lock.
      const attempts = await Promise.all(
        [1, 2, 3].map((n) =>
          call(tokens.platform, "POST", "/signing-keys/rotate", {
            body: { reason: `parallel rotation ${n}` },
            ifMatch: etag,
          }),
        ),
      );
      expect(attempts.map((attempt) => attempt.status).sort()).toEqual([200, 412, 412]);
      const rotated = attempts.find((attempt) => attempt.status === 200)!;
      // Published ahead: the new key is in the key set and becomes active later.
      expect(rotated.body).toMatchObject({
        status: "scheduled",
        activatedKid: null,
        retiringKid: null,
        retiredKids: [],
      });
      const nextKid = rotated.body.nextKid as string;
      const activatesAt = Date.parse(rotated.body.activatesAt as string);
      expect(activatesAt - Date.now()).toBeGreaterThan(
        (ts!.config.keyRotation.manualPublishAheadSeconds - 5) * 1000,
      );
      const listed = await call<{ keys: Json[]; etag: string }>(
        tokens.platform,
        "GET",
        "/signing-keys",
      );
      expect(listed.body.keys).toContainEqual(
        expect.objectContaining({
          kid: nextKid,
          state: "next",
          activateAt: rotated.body.activatesAt,
        }),
      );
      const events = await ts!.db.repos.audit.query(
        { allTenants: true, tenantId: null },
        { actions: ["admin.signing_key.rotate", "key.rotate"] },
      );
      expect(events.events.map((event) => event.action).sort()).toEqual([
        "admin.signing_key.rotate",
        "key.rotate",
      ]);
      expect(
        events.events.find((event) => event.action === "admin.signing_key.rotate")?.details,
      ).toMatchObject({ emergency: false, activatedKid: null, scheduledKid: nextKid });
      // The key that signed the callers' tokens still signs.
      expect((await call(tokens.adminX, "GET", "/me")).status).toBe(200);
      // (Emergency rotation retires the key these tokens carry: keys/rotation.test.ts.)
    });

    it("pages audit events with a keyset cursor; system-wide only for the platform", async () => {
      const first = await call<{ items: Json[]; nextCursor: string | null }>(
        tokens.adminX,
        "GET",
        `/tenants/${x.tenant.id}/audit-events?limit=2&actionPrefix=admin`,
      );
      expect(first.body.items).toHaveLength(2);
      expect(first.body.nextCursor).not.toBeNull();
      const second = await call<{ items: Json[] }>(
        tokens.adminX,
        "GET",
        `/tenants/${x.tenant.id}/audit-events?limit=2&actionPrefix=admin&cursor=${first.body.nextCursor!}`,
      );
      expect(Number(second.body.items[0]!.seq)).toBeLessThan(Number(first.body.items[1]!.seq));
      expect((await call(tokens.adminX, "GET", "/audit-events")).status).toBe(403);
      const platform = await call<Items>(
        tokens.platform,
        "GET",
        "/audit-events?tenantId=platform&action=admin.signing_key.rotate",
      );
      expect(platform.body.items).toHaveLength(1);
      const bad = await call(
        tokens.adminX,
        "GET",
        `/tenants/${x.tenant.id}/audit-events?limit=1000`,
      );
      expect(bad.body).toMatchObject({ errors: [{ field: "query.limit" }] });
    });

    it("summarises logins, warnings and key status", async () => {
      await ts!.db.repos.audit.append({
        tenantId: x.tenant.id,
        actor: { type: "person", id: adminXId },
        action: "login.success",
        details: {},
      });
      const dashboard = await call(tokens.adminX, "GET", `/tenants/${x.tenant.id}/dashboard`);
      expect(dashboard.status).toBe(200);
      expect(dashboard.body).toMatchObject({
        logins: { last24h: 1, last7d: 1 },
        warnings: expect.arrayContaining([
          expect.objectContaining({ code: "client_secret_expiring" }),
        ]) as unknown,
        keys: { activeKid: expect.any(String) as unknown },
      });
    });
  });

  describe("OpenAPI", () => {
    it("serves a valid OpenAPI 3.1 document that documents every route", async () => {
      const response = await fetch(`${ts!.baseUrl}/admin/api/v1/openapi.json`);
      expect(response.status).toBe(200);
      const document = (await response.json()) as Json;
      validateOpenApi(document);
      const paths = document.paths as Record<string, Record<string, Json>>;
      const deps = { config: ts!.config } as AdminDeps;
      const routes = adminRoutes(deps);
      const documented = Object.entries(paths).flatMap(([path, operations]) =>
        Object.keys(operations).map((method) => `${method} ${path}`),
      );
      expect(documented.sort()).toEqual(
        routes.map((route) => `${route.method} ${route.path}`).sort(),
      );
      expect(adminOpenApi(deps)).toEqual(document);
    });
  });
});

/**
 * Structural validation of an OpenAPI 3.1 document (the parts this API uses): version, info,
 * unique operation ids, declared path parameters, responses, and every `$ref` resolvable.
 */
function validateOpenApi(document: Json): void {
  expect(document.openapi).toMatch(/^3\.1\.\d+$/);
  expect(document.info).toMatchObject({
    title: expect.any(String) as unknown,
    version: expect.any(String) as unknown,
  });
  const components = document.components as { schemas: Json; securitySchemes: Json };
  const ids = new Set<string>();
  const refs: string[] = [];
  const collect = (value: unknown): void => {
    if (Array.isArray(value)) value.forEach(collect);
    else if (value !== null && typeof value === "object") {
      for (const [key, item] of Object.entries(value)) {
        if (key === "$ref") refs.push(item as string);
        else collect(item);
      }
    }
  };
  for (const [path, operations] of Object.entries(
    document.paths as Record<string, Record<string, Json>>,
  )) {
    expect(path.startsWith("/")).toBe(true);
    const templated = [...path.matchAll(/\{(\w+)\}/g)].map((match) => match[1]);
    for (const [method, operation] of Object.entries(operations)) {
      expect(["get", "post", "put", "patch", "delete"]).toContain(method);
      const id = operation.operationId as string;
      expect(ids.has(id), id).toBe(false);
      ids.add(id);
      const parameters = (operation.parameters ?? []) as {
        name: string;
        in: string;
        required?: boolean;
        schema: unknown;
      }[];
      for (const name of templated) {
        expect(
          parameters.some((p) => p.in === "path" && p.name === name && p.required === true),
          `${id} ${name}`,
        ).toBe(true);
      }
      for (const parameter of parameters) {
        expect(["path", "query", "header"]).toContain(parameter.in);
        expect(parameter.schema).toBeTypeOf("object");
      }
      const responses = operation.responses as Record<string, Json>;
      expect(Object.keys(responses).length).toBeGreaterThan(0);
      for (const [status, response] of Object.entries(responses)) {
        expect(status).toMatch(/^[1-5]\d\d$/);
        expect(response.description).toBeTypeOf("string");
      }
    }
  }
  collect(document.paths);
  collect(components.schemas);
  for (const ref of refs) {
    const name = /^#\/components\/schemas\/(.+)$/.exec(ref)?.[1];
    expect(name, ref).toBeDefined();
    expect(components.schemas[name!], ref).toBeDefined();
  }
  expect(components.securitySchemes).toHaveProperty("bearerAuth");
}
