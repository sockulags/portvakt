import { describe, expect, it } from "vitest";
import {
  createApplication,
  createLoginMethod,
  createTenantWithApp,
  login,
  uniqueSuffix,
} from "../testing/fixtures.js";
import { setupTestDatabase } from "../testing/test-database.js";
import {
  ApplicationNotInTenantError,
  InvalidReferenceError,
  UndeclaredAttributeKeyError,
  InvalidIdError,
  UndeclaredRoleError,
  ValidationError,
} from "./errors.js";

const testDb = await setupTestDatabase();

describe.skipIf(testDb === undefined)("AccessRepository", () => {
  const { repos, db } = testDb!;

  async function setup() {
    const base = await createTenantWithApp(repos);
    const { person } = await login(
      repos,
      base.tenant.id,
      base.loginMethod,
      `sub-${uniqueSuffix()}`,
    );
    return { ...base, person };
  }

  describe("effective roles", () => {
    it("combines direct assignments with matching group rules", async () => {
      const { tenant, application, loginMethod, person } = await setup();
      await repos.access.assignRole(tenant.id, {
        personId: person.id,
        applicationId: application.id,
        role: "reader",
      });
      await repos.access.createRule(tenant.id, {
        applicationId: application.id,
        loginMethodId: loginMethod.id,
        groupValue: "grp-handlaggare",
        role: "handlaggare",
      });
      await repos.access.createRule(tenant.id, {
        applicationId: application.id,
        loginMethodId: loginMethod.id,
        groupValue: "grp-admins",
        role: "admin",
      });
      // Same role from both an assignment and a rule is reported once.
      await repos.access.createRule(tenant.id, {
        applicationId: application.id,
        loginMethodId: loginMethod.id,
        groupValue: "grp-handlaggare",
        role: "reader",
      });

      const access = await repos.access.effectiveAccess(tenant.id, {
        personId: person.id,
        applicationId: application.id,
        loginMethodId: loginMethod.id,
        groups: ["grp-handlaggare", "unrelated"],
      });
      expect(access.roles).toEqual(["handlaggare", "reader"]);

      const noGroups = await repos.access.effectiveAccess(tenant.id, {
        personId: person.id,
        applicationId: application.id,
        loginMethodId: loginMethod.id,
        groups: [],
      });
      expect(noGroups.roles).toEqual(["reader"]);
    });

    it("applies a rule scoped to a login method only for that login method", async () => {
      const { tenant, application, loginMethod, person } = await setup();
      const citizenMethod = await createLoginMethod(repos, tenant.id, {
        kind: "citizen",
        displayName: "Mock BankID",
      });
      await repos.access.createRule(tenant.id, {
        applicationId: application.id,
        loginMethodId: loginMethod.id,
        groupValue: "staff",
        role: "handlaggare",
      });

      const viaScoped = await repos.access.effectiveAccess(tenant.id, {
        personId: person.id,
        applicationId: application.id,
        loginMethodId: loginMethod.id,
        groups: ["staff"],
      });
      const viaOther = await repos.access.effectiveAccess(tenant.id, {
        personId: person.id,
        applicationId: application.id,
        loginMethodId: citizenMethod.id,
        groups: ["staff"],
      });
      expect(viaScoped.roles).toEqual(["handlaggare"]);
      expect(viaOther.roles).toEqual([]);
    });

    it("returns roles for the requested application only", async () => {
      const { tenant, application, loginMethod, person } = await setup();
      const other = await createApplication(repos);
      await repos.applications.enableForTenant(tenant.id, other.id);
      await repos.access.assignRole(tenant.id, {
        personId: person.id,
        applicationId: other.id,
        role: "admin",
      });
      await repos.access.createRule(tenant.id, {
        applicationId: other.id,
        loginMethodId: loginMethod.id,
        groupValue: "g",
        role: "reader",
      });
      const access = await repos.access.effectiveAccess(tenant.id, {
        personId: person.id,
        applicationId: application.id,
        loginMethodId: loginMethod.id,
        groups: ["g"],
      });
      expect(access.roles).toEqual([]);
    });

    it("returns attributes for the application", async () => {
      const { tenant, application, loginMethod, person } = await setup();
      await repos.access.setAttribute(tenant.id, {
        personId: person.id,
        applicationId: application.id,
        key: "unit",
        value: "north",
      });
      await repos.access.setAttribute(tenant.id, {
        personId: person.id,
        applicationId: application.id,
        key: "unit",
        value: "south",
      });
      const access = await repos.access.effectiveAccess(tenant.id, {
        personId: person.id,
        applicationId: application.id,
        loginMethodId: loginMethod.id,
        groups: [],
      });
      expect(access.attributes).toEqual({ unit: "south" });
    });

    it("drops assignments and rules when the application stops declaring the role", async () => {
      const { tenant, application, loginMethod, person } = await setup();
      await repos.access.assignRole(tenant.id, {
        personId: person.id,
        applicationId: application.id,
        role: "admin",
      });
      await repos.access.createRule(tenant.id, {
        applicationId: application.id,
        loginMethodId: loginMethod.id,
        groupValue: "g",
        role: "admin",
      });
      expect(await repos.applications.removeRole(application.id, "admin")).toBe(true);
      const access = await repos.access.effectiveAccess(tenant.id, {
        personId: person.id,
        applicationId: application.id,
        loginMethodId: loginMethod.id,
        groups: ["g"],
      });
      expect(access.roles).toEqual([]);
      expect(await repos.access.listRules(tenant.id, { applicationId: application.id })).toEqual(
        [],
      );
    });
  });

  describe("declared-role enforcement", () => {
    it("refuses to assign or rule an undeclared role", async () => {
      const { tenant, application, loginMethod, person } = await setup();
      await expect(
        repos.access.assignRole(tenant.id, {
          personId: person.id,
          applicationId: application.id,
          role: "superuser",
        }),
      ).rejects.toBeInstanceOf(UndeclaredRoleError);
      await expect(
        repos.access.createRule(tenant.id, {
          applicationId: application.id,
          loginMethodId: loginMethod.id,
          groupValue: "g",
          role: "superuser",
        }),
      ).rejects.toBeInstanceOf(UndeclaredRoleError);
    });

    it("accepts a role once the application declares it", async () => {
      const { tenant, application, person } = await setup();
      await repos.applications.declareRole(application.id, "auditor", "Read-only audit access");
      const assignment = await repos.access.assignRole(tenant.id, {
        personId: person.id,
        applicationId: application.id,
        role: "auditor",
      });
      expect(assignment.role).toBe("auditor");
      // Idempotent.
      const again = await repos.access.assignRole(tenant.id, {
        personId: person.id,
        applicationId: application.id,
        role: "auditor",
      });
      expect(again.id).toBe(assignment.id);
    });

    it("enforces declared roles in SQL as well", async () => {
      const { tenant, application, loginMethod, person } = await setup();
      await expect(
        db.query(
          `INSERT INTO role_assignments (tenant_id, person_id, application_id, role)
           VALUES ($1, $2, $3, 'superuser')`,
          [tenant.id, person.id, application.id],
        ),
      ).rejects.toMatchObject({ code: "23503" });
      await expect(
        db.query(
          `INSERT INTO role_rules (tenant_id, application_id, login_method_id, group_value, role)
           VALUES ($1, $2, $3, 'g', 'superuser')`,
          [tenant.id, application.id, loginMethod.id],
        ),
      ).rejects.toMatchObject({ code: "23503" });
    });

    it("requires every rule to name its login method", async () => {
      const { tenant, application } = await setup();
      await expect(
        repos.access.createRule(tenant.id, {
          applicationId: application.id,
          groupValue: "g",
          role: "reader",
        } as never),
      ).rejects.toBeInstanceOf(ValidationError);
      await expect(
        db.query(
          `INSERT INTO role_rules (tenant_id, application_id, group_value, role)
           VALUES ($1, $2, 'g', 'reader')`,
          [tenant.id, application.id],
        ),
      ).rejects.toMatchObject({ code: "23502" });
    });

    it("refuses an undeclared attribute key", async () => {
      const { tenant, application, person } = await setup();
      await expect(
        repos.access.setAttribute(tenant.id, {
          personId: person.id,
          applicationId: application.id,
          key: "undeclared",
          value: "x",
        }),
      ).rejects.toBeInstanceOf(UndeclaredAttributeKeyError);
    });

    it("refuses an application that is not attached to the tenant", async () => {
      const { tenant, person } = await setup();
      const detached = await createApplication(repos);
      await expect(
        repos.access.assignRole(tenant.id, {
          personId: person.id,
          applicationId: detached.id,
          role: "reader",
        }),
      ).rejects.toBeInstanceOf(ApplicationNotInTenantError);
    });

    it("refuses a person or login method from another tenant", async () => {
      const { tenant, application, person } = await setup();
      const other = await setup();
      await repos.applications.enableForTenant(other.tenant.id, application.id);
      await expect(
        repos.access.assignRole(other.tenant.id, {
          personId: person.id,
          applicationId: application.id,
          role: "reader",
        }),
      ).rejects.toBeInstanceOf(InvalidReferenceError);
      await expect(
        repos.access.createRule(tenant.id, {
          applicationId: application.id,
          loginMethodId: other.loginMethod.id,
          groupValue: "g",
          role: "reader",
        }),
      ).rejects.toBeInstanceOf(InvalidReferenceError);
    });
  });

  describe("enablement", () => {
    async function withAccess() {
      const base = await setup();
      await repos.access.assignRole(base.tenant.id, {
        personId: base.person.id,
        applicationId: base.application.id,
        role: "admin",
      });
      await repos.access.setAttribute(base.tenant.id, {
        personId: base.person.id,
        applicationId: base.application.id,
        key: "unit",
        value: "north",
      });
      const query = {
        personId: base.person.id,
        applicationId: base.application.id,
        loginMethodId: base.loginMethod.id,
        groups: [],
      };
      expect((await repos.access.effectiveAccess(base.tenant.id, query)).roles).toEqual(["admin"]);
      return { ...base, query };
    }
    const nothing = { roles: [], attributes: {} };

    it("returns nothing while the application is disabled for the tenant", async () => {
      const { tenant, application, query } = await withAccess();
      await repos.applications.disableForTenant(tenant.id, application.id);
      expect(await repos.access.effectiveAccess(tenant.id, query)).toEqual(nothing);
      expect(await repos.applications.listEnabledForTenant(tenant.id)).toEqual([]);
      await repos.applications.enableForTenant(tenant.id, application.id);
      expect((await repos.access.effectiveAccess(tenant.id, query)).roles).toEqual(["admin"]);
    });

    it("returns nothing while the application is disabled globally", async () => {
      const { tenant, application, query } = await withAccess();
      await repos.applications.update(application.id, { enabled: false });
      expect(await repos.access.effectiveAccess(tenant.id, query)).toEqual(nothing);
      expect(await repos.applications.listEnabledForTenant(tenant.id)).toEqual([]);
    });

    it("returns nothing while the tenant is suspended", async () => {
      const { tenant, query } = await withAccess();
      await repos.tenants.update(tenant.id, { status: "suspended" });
      expect(await repos.access.effectiveAccess(tenant.id, query)).toEqual(nothing);
      expect(await repos.applications.listEnabledForTenant(tenant.id)).toEqual([]);
    });
  });

  describe("cascades", () => {
    async function withEverything() {
      const base = await setup();
      const ids = { personId: base.person.id, applicationId: base.application.id };
      await repos.access.assignRole(base.tenant.id, { ...ids, role: "admin" });
      await repos.access.createRule(base.tenant.id, {
        applicationId: base.application.id,
        loginMethodId: base.loginMethod.id,
        groupValue: "g",
        role: "reader",
      });
      await repos.access.setAttribute(base.tenant.id, { ...ids, key: "unit", value: "x" });
      return base;
    }

    async function remaining(tenantId: string) {
      return {
        assignments: (await repos.access.listAssignments(tenantId)).length,
        rules: (await repos.access.listRules(tenantId)).length,
        attributes: (await repos.access.listAttributes(tenantId)).length,
      };
    }

    it("removeFromTenant deletes the tenant's assignments, rules and attributes", async () => {
      const { tenant, application } = await withEverything();
      expect(await remaining(tenant.id)).toEqual({ assignments: 1, rules: 1, attributes: 1 });
      expect(await repos.applications.removeFromTenant(tenant.id, application.id)).toBe(true);
      expect(await remaining(tenant.id)).toEqual({ assignments: 0, rules: 0, attributes: 0 });
      expect(await repos.applications.findById(application.id)).not.toBeNull();
    });

    it("disableForTenant keeps them for re-enabling", async () => {
      const { tenant, application } = await withEverything();
      await repos.applications.disableForTenant(tenant.id, application.id);
      expect(await remaining(tenant.id)).toEqual({ assignments: 1, rules: 1, attributes: 1 });
    });

    it("deleting the application deletes them in every tenant", async () => {
      const { tenant, application } = await withEverything();
      expect(await repos.applications.delete(application.id)).toBe(true);
      expect(await remaining(tenant.id)).toEqual({ assignments: 0, rules: 0, attributes: 0 });
    });
  });

  it("validates ids", async () => {
    const { tenant } = await setup();
    await expect(repos.access.listAssignments("x")).rejects.toBeInstanceOf(InvalidIdError);
    await expect(repos.access.deleteRule(tenant.id, "x")).rejects.toBeInstanceOf(InvalidIdError);
    await expect(repos.access.listAttributes(tenant.id, { personId: "x" })).rejects.toBeInstanceOf(
      InvalidIdError,
    );
  });
});
