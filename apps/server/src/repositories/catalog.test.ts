import { describe, expect, it } from "vitest";
import { generateClientSecret } from "../crypto/secrets.js";
import {
  createApplication,
  createLoginMethod,
  createTenant,
  createTenantWithApp,
  login,
  uniqueSuffix,
} from "../testing/fixtures.js";
import { setupTestDatabase } from "../testing/test-database.js";
import { ConflictError, InvalidIdError, InvalidReferenceError, ValidationError } from "./errors.js";

const testDb = await setupTestDatabase();

describe.skipIf(testDb === undefined)("tenants, applications and login methods", () => {
  const { repos, db } = testDb!;

  describe("tenants", () => {
    it("creates, finds, updates and refuses duplicate or invalid slugs", async () => {
      const tenant = await createTenant(repos, "kommun");
      expect(await repos.tenants.findBySlug(tenant.slug)).toEqual(tenant);
      await expect(repos.tenants.create({ slug: tenant.slug, name: "Dup" })).rejects.toBeInstanceOf(
        ConflictError,
      );
      await expect(repos.tenants.create({ slug: "Bad Slug", name: "x" })).rejects.toBeInstanceOf(
        ValidationError,
      );
      const suspended = await repos.tenants.update(tenant.id, { status: "suspended" });
      expect(suspended.status).toBe("suspended");
      expect(suspended.updatedAt.getTime()).toBeGreaterThanOrEqual(tenant.updatedAt.getTime());
      expect(await repos.tenants.findActiveBySlug(tenant.slug)).toBeNull();
    });
  });

  describe("applications", () => {
    it("stores client auth, URIs, declared roles and attribute keys", async () => {
      const secret = generateClientSecret();
      const app = await createApplication(repos, {
        clientAuth: { method: "client_secret_post", clientSecret: secret },
        postLogoutRedirectUris: ["https://svc.example.test/logged-out"],
        allowedExtraScopes: ["pin"],
      });
      expect(app.clientAuth).toEqual({ method: "client_secret_post" });
      expect(JSON.stringify(app)).not.toContain(secret);
      expect(await repos.applications.getClientSecret(app.id)).toBe(secret);
      const [raw] = await db.query<{ client_secret_encrypted: string }>(
        "SELECT client_secret_encrypted FROM applications WHERE id = $1",
        [app.id],
      );
      expect(raw?.client_secret_encrypted.startsWith("pv1.")).toBe(true);
      expect(raw?.client_secret_encrypted).not.toContain(secret);
      expect(app.roles.map((r) => r.role)).toEqual(["admin", "handlaggare", "reader"]);
      expect(app.attributeKeys).toEqual([{ key: "unit", description: null }]);
      expect(app.allowedExtraScopes).toEqual(["pin"]);
      expect(await repos.applications.findByClientId(app.clientId)).toEqual(app);
    });

    it("supports private_key_jwt with a JWKS URI or inline public JWKS", async () => {
      const byUri = await createApplication(repos, {
        clientAuth: { method: "private_key_jwt", jwksUri: "https://svc.example.test/jwks" },
      });
      expect(byUri.clientAuth).toEqual({
        method: "private_key_jwt",
        jwksUri: "https://svc.example.test/jwks",
      });
      const jwks = { keys: [{ kty: "EC", crv: "P-256", x: "abc", y: "def", kid: "k1" }] };
      const inline = await createApplication(repos, {
        clientAuth: { method: "private_key_jwt", jwks },
      });
      expect(inline.clientAuth).toEqual({ method: "private_key_jwt", jwks });
      await expect(
        createApplication(repos, {
          clientAuth: {
            method: "private_key_jwt",
            jwks: { keys: [{ ...jwks.keys[0], kty: "EC", d: "private" }] },
          },
        }),
      ).rejects.toBeInstanceOf(ValidationError);
    });

    it("rejects invalid redirect URIs, short secrets and malformed ids", async () => {
      await expect(
        createApplication(repos, { redirectUris: ["https://svc.example.test/cb#fragment"] }),
      ).rejects.toBeInstanceOf(ValidationError);
      await expect(
        createApplication(repos, {
          clientAuth: { method: "client_secret_basic", clientSecret: "password123" },
        }),
      ).rejects.toBeInstanceOf(ValidationError);
      await expect(repos.applications.findById("1")).rejects.toBeInstanceOf(InvalidIdError);
      await expect(repos.tenants.update("1", { name: "x" })).rejects.toBeInstanceOf(InvalidIdError);
      await expect(
        repos.loginMethods.getClientSecret(crypto.randomUUID(), "1"),
      ).rejects.toBeInstanceOf(InvalidIdError);
    });

    it("finds an application by client_id only when enabled for the tenant", async () => {
      const tenant = await createTenant(repos);
      const app = await createApplication(repos);
      expect(await repos.applications.findEnabledByClientId(tenant.id, app.clientId)).toBeNull();

      await repos.applications.enableForTenant(tenant.id, app.id);
      expect((await repos.applications.findEnabledByClientId(tenant.id, app.clientId))?.id).toBe(
        app.id,
      );
      expect((await repos.applications.listEnabledForTenant(tenant.id)).map((a) => a.id)).toEqual([
        app.id,
      ]);

      await repos.applications.disableForTenant(tenant.id, app.id);
      expect(await repos.applications.findEnabledByClientId(tenant.id, app.clientId)).toBeNull();
      expect((await repos.applications.listForTenant(tenant.id))[0]?.enabled).toBe(false);

      await repos.applications.enableForTenant(tenant.id, app.id);
      await repos.applications.update(app.id, { enabled: false });
      expect(await repos.applications.findEnabledByClientId(tenant.id, app.clientId)).toBeNull();

      await repos.applications.update(app.id, { enabled: true });
      await repos.tenants.update(tenant.id, { status: "suspended" });
      expect(await repos.applications.findEnabledByClientId(tenant.id, app.clientId)).toBeNull();
    });

    it("updates client auth atomically", async () => {
      const app = await createApplication(repos);
      const updated = await repos.applications.update(app.id, {
        clientAuth: { method: "private_key_jwt", jwksUri: "https://svc.example.test/jwks" },
        redirectUris: ["https://new.example.test/cb"],
      });
      expect(updated.clientAuth).toEqual({
        method: "private_key_jwt",
        jwksUri: "https://svc.example.test/jwks",
      });
      expect(updated.redirectUris).toEqual(["https://new.example.test/cb"]);
      expect(updated.name).toBe(app.name);
    });
  });

  describe("login methods", () => {
    it("stores the upstream secret encrypted and returns it only on request", async () => {
      const tenant = await createTenant(repos);
      const method = await createLoginMethod(repos, tenant.id, { clientSecret: "s3cret-upstream" });
      expect(method.hasClientSecret).toBe(true);
      expect(JSON.stringify(method)).not.toContain("s3cret-upstream");

      const [raw] = await db.query<{ client_secret_encrypted: string }>(
        "SELECT client_secret_encrypted FROM login_methods WHERE id = $1",
        [method.id],
      );
      expect(raw?.client_secret_encrypted.startsWith("pv1.")).toBe(true);
      expect(raw?.client_secret_encrypted).not.toContain("s3cret-upstream");
      expect(await repos.loginMethods.getClientSecret(tenant.id, method.id)).toBe(
        "s3cret-upstream",
      );

      // A ciphertext copied to another login method does not decrypt there.
      const other = await createLoginMethod(repos, tenant.id, { clientSecret: "other" });
      await db.query("UPDATE login_methods SET client_secret_encrypted = $1 WHERE id = $2", [
        raw?.client_secret_encrypted,
        other.id,
      ]);
      await expect(repos.loginMethods.getClientSecret(tenant.id, other.id)).rejects.toThrow(
        /authentication failed/,
      );

      const cleared = await repos.loginMethods.update(tenant.id, method.id, { clientSecret: null });
      expect(cleared.hasClientSecret).toBe(false);
      expect(await repos.loginMethods.getClientSecret(tenant.id, method.id)).toBeNull();
    });

    it("keeps claim mapping, session policy and other settings", async () => {
      const tenant = await createTenant(repos);
      const expires = new Date(Date.now() + 10 * 86_400_000);
      const method = await createLoginMethod(repos, tenant.id, {
        kind: "citizen",
        claimMapping: { pin: "personal_identity_number", protectedIdentity: "protected" },
        assertedAcr: "urn:portvakt:acr:loa3",
        secretExpiresAt: expires,
        sessionPolicy: { maxAgeSeconds: 900, idleSeconds: 300, allowSso: false },
      });
      expect(method).toMatchObject({
        kind: "citizen",
        claimMapping: {
          subject: "sub",
          pin: "personal_identity_number",
          protectedIdentity: "protected",
        },
        assertedAcr: "urn:portvakt:acr:loa3",
        secretExpiresAt: expires,
        sessionPolicy: { maxAgeSeconds: 900, idleSeconds: 300, allowSso: false },
      });
      const soon = await repos.loginMethods.listSecretsExpiringBefore(
        tenant.id,
        new Date(Date.now() + 30 * 86_400_000),
      );
      expect(soon.map((m) => m.id)).toEqual([method.id]);

      await expect(
        createLoginMethod(repos, tenant.id, {
          sessionPolicy: { maxAgeSeconds: 60, idleSeconds: 120, allowSso: true },
        }),
      ).rejects.toBeInstanceOf(ValidationError);
      await expect(
        createLoginMethod(repos, tenant.id, { claimMapping: { unknownKey: "x" } as never }),
      ).rejects.toBeInstanceOf(ValidationError);
      await expect(
        createLoginMethod(repos, tenant.id, { scopes: ["profile"] }),
      ).rejects.toBeInstanceOf(ValidationError);
    });

    it("lists enabled methods and resolves home realm domains", async () => {
      const tenant = await createTenant(repos);
      const employees = await createLoginMethod(repos, tenant.id, {
        displayName: "A Employees",
        homeRealmDomains: ["Example.ORG", "corp.example.org"],
      });
      const citizens = await createLoginMethod(repos, tenant.id, {
        displayName: "B Citizens",
        kind: "citizen",
      });
      const disabled = await createLoginMethod(repos, tenant.id, {
        displayName: "C Disabled",
        enabled: false,
        homeRealmDomains: ["disabled.example.org"],
      });
      expect(employees.homeRealmDomains).toEqual(["corp.example.org", "example.org"]);
      expect((await repos.loginMethods.listEnabled(tenant.id)).map((m) => m.id)).toEqual([
        employees.id,
        citizens.id,
      ]);
      expect((await repos.loginMethods.list(tenant.id)).map((m) => m.id)).toContain(disabled.id);

      expect(
        (await repos.loginMethods.findEnabledByHomeRealm(tenant.id, "anna@EXAMPLE.org"))?.id,
      ).toBe(employees.id);
      expect(
        (await repos.loginMethods.findEnabledByHomeRealm(tenant.id, "corp.example.org"))?.id,
      ).toBe(employees.id);
      expect(
        await repos.loginMethods.findEnabledByHomeRealm(tenant.id, "x@disabled.example.org"),
      ).toBeNull();
      expect(
        await repos.loginMethods.findEnabledByHomeRealm(tenant.id, "x@unknown.org"),
      ).toBeNull();
      expect(await repos.loginMethods.findEnabledByHomeRealm(tenant.id, "not an email")).toBeNull();

      // A domain belongs to one login method per tenant.
      await expect(
        createLoginMethod(repos, tenant.id, { homeRealmDomains: ["example.org"] }),
      ).rejects.toBeInstanceOf(ConflictError);
      const moved = await repos.loginMethods.update(tenant.id, employees.id, {
        homeRealmDomains: ["example.org"],
      });
      expect(moved.homeRealmDomains).toEqual(["example.org"]);
    });

    it("refuses to delete a login method that has identities", async () => {
      const { tenant, loginMethod } = await createTenantWithApp(repos);
      await login(repos, tenant.id, loginMethod, `s-${uniqueSuffix()}`);
      await expect(repos.loginMethods.delete(tenant.id, loginMethod.id)).rejects.toBeInstanceOf(
        InvalidReferenceError,
      );
      const disabled = await repos.loginMethods.update(tenant.id, loginMethod.id, {
        enabled: false,
      });
      expect(disabled.enabled).toBe(false);
    });
  });

  it("deletes a tenant with everything it owns", async () => {
    const { tenant, application, loginMethod } = await createTenantWithApp(repos);
    const { person } = await login(repos, tenant.id, loginMethod, "to-delete");
    await repos.access.assignRole(tenant.id, {
      personId: person.id,
      applicationId: application.id,
      role: "reader",
    });
    expect(await repos.tenants.delete(tenant.id)).toBe(true);
    expect(await repos.persons.findById(tenant.id, person.id)).toBeNull();
    // The global application survives.
    expect(await repos.applications.findById(application.id)).not.toBeNull();
  });
});
