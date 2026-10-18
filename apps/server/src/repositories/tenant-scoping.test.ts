import { describe, expect, it } from "vitest";
import {
  createTenantWithApp,
  login,
  TEST_ORGNR,
  TEST_PINS,
  uniqueSuffix,
} from "../testing/fixtures.js";
import { setupTestDatabase } from "../testing/test-database.js";
import { NotFoundError } from "./errors.js";

const testDb = await setupTestDatabase();

/**
 * Tenant B holds a full set of data; every tenant-scoped query run with tenant A's id must come
 * back empty, even when given B's row ids directly.
 */
describe.skipIf(testDb === undefined)("tenant scoping", () => {
  const { repos } = testDb!;

  async function populate(prefix: string) {
    const base = await createTenantWithApp(repos, prefix);
    const { tenant, application, loginMethod } = base;
    await repos.loginMethods.update(tenant.id, loginMethod.id, {
      homeRealmDomains: [`${prefix}-${uniqueSuffix()}.example.org`],
    });
    const { person, identity } = await login(
      repos,
      tenant.id,
      loginMethod,
      "same-subject-in-both-tenants",
      { attributes: { groups: ["staff"] }, pin: TEST_PINS[0] },
    );
    await repos.access.assignRole(tenant.id, {
      personId: person.id,
      applicationId: application.id,
      role: "admin",
    });
    const rule = await repos.access.createRule(tenant.id, {
      applicationId: application.id,
      loginMethodId: loginMethod.id,
      groupValue: "staff",
      role: "handlaggare",
    });
    await repos.access.setAttribute(tenant.id, {
      personId: person.id,
      applicationId: application.id,
      key: "unit",
      value: prefix,
    });
    const party = await repos.parties.create(tenant.id, {
      type: "organisation",
      identifier: TEST_ORGNR,
      displayName: `${prefix} AB`,
    });
    const grant = await repos.grants.create(tenant.id, {
      agent: { personId: person.id },
      partyId: party.id,
      allApplications: true,
    });
    const pinGrant = await repos.grants.create(tenant.id, {
      agent: { pin: TEST_PINS[0] },
      partyId: party.id,
      allApplications: true,
    });
    await repos.audit.append({
      tenantId: tenant.id,
      actor: { type: "system" },
      action: "login.success",
    });
    return { ...base, person, identity, rule, party, grant, pinGrant };
  }

  it("never returns tenant B rows to a query scoped to tenant A", async () => {
    const a = await populate("a");
    const b = await populate("b");
    const A = a.tenant.id;

    // Applications: B's app is not enabled in A.
    expect(await repos.applications.findEnabledByClientId(A, b.application.clientId)).toBeNull();
    expect((await repos.applications.listEnabledForTenant(A)).map((x) => x.id)).toEqual([
      a.application.id,
    ]);
    expect((await repos.applications.listForTenant(A)).map((x) => x.application.id)).toEqual([
      a.application.id,
    ]);

    // Login methods.
    expect(await repos.loginMethods.findById(A, b.loginMethod.id)).toBeNull();
    expect((await repos.loginMethods.list(A)).map((x) => x.id)).toEqual([a.loginMethod.id]);
    expect((await repos.loginMethods.listEnabled(A)).map((x) => x.id)).toEqual([a.loginMethod.id]);
    const bDomain = (await repos.loginMethods.findById(b.tenant.id, b.loginMethod.id))
      ?.homeRealmDomains[0];
    expect(await repos.loginMethods.findEnabledByHomeRealm(A, `x@${bDomain}`)).toBeNull();
    await expect(repos.loginMethods.getClientSecret(A, b.loginMethod.id)).rejects.toBeInstanceOf(
      NotFoundError,
    );
    await expect(
      repos.loginMethods.update(A, b.loginMethod.id, { displayName: "hijack" }),
    ).rejects.toBeInstanceOf(NotFoundError);
    expect(await repos.loginMethods.delete(A, b.loginMethod.id)).toBe(false);

    // Persons and identities: same upstream subject, different persons.
    expect(a.person.id).not.toBe(b.person.id);
    expect(await repos.persons.findById(A, b.person.id)).toBeNull();
    expect(await repos.persons.listIdentities(A, b.person.id)).toEqual([]);
    expect(
      await repos.persons.findIdentity(A, b.loginMethod.id, "same-subject-in-both-tenants"),
    ).toBeNull();

    // Roles, rules, attributes.
    expect(await repos.access.listAssignments(A, { personId: b.person.id })).toEqual([]);
    expect((await repos.access.listAssignments(A)).every((x) => x.tenantId === A)).toBe(true);
    expect((await repos.access.listRules(A)).map((x) => x.id)).toEqual([a.rule.id]);
    expect(await repos.access.listAttributes(A, { personId: b.person.id })).toEqual([]);
    expect(await repos.access.deleteRule(A, b.rule.id)).toBe(false);
    const leaked = await repos.access.effectiveAccess(A, {
      personId: b.person.id,
      applicationId: b.application.id,
      loginMethodId: b.loginMethod.id,
      groups: ["staff"],
    });
    expect(leaked).toEqual({ roles: [], attributes: {} });

    // Parties and grants.
    expect(await repos.parties.findById(A, b.party.id)).toBeNull();
    expect((await repos.parties.list(A)).map((x) => x.id)).toEqual([a.party.id]);
    expect(await repos.parties.findByIdentifier(A, "organisation", TEST_ORGNR)).toEqual(a.party);
    expect(await repos.grants.findById(A, b.grant.id)).toBeNull();
    // Same personal identity number in both tenants: blind indexes match, tenant scoping holds.
    expect(a.identity.pinIndex).toBe(b.identity.pinIndex);
    expect(await repos.grants.findById(A, b.pinGrant.id)).toBeNull();
    // B's person id finds nothing in A; the shared pin index only finds A's own pin grant.
    expect(
      (await repos.grants.listForAgent(A, b.person.id, b.identity.pinIndex)).map((g) => g.id),
    ).toEqual([a.pinGrant.id]);
    expect(
      (await repos.grants.listForAgent(A, a.person.id, a.identity.pinIndex))
        .map((g) => g.id)
        .sort(),
    ).toEqual([a.grant.id, a.pinGrant.id].sort());
    expect(
      await repos.grants.listValidForAgent(A, b.person.id, b.identity.pinIndex, b.application.id),
    ).toEqual([]);
    expect(
      (
        await repos.grants.listValidForAgent(A, a.person.id, a.identity.pinIndex, b.application.id)
      ).map((g) => g.id),
    ).toEqual([]);
    expect(
      await repos.grants.findValid(A, b.grant.id, b.person.id, null, b.application.id),
    ).toBeNull();
    await expect(repos.grants.revoke(A, b.grant.id, null)).rejects.toBeInstanceOf(NotFoundError);
    expect((await repos.grants.findById(b.tenant.id, b.grant.id))?.revokedAt).toBeNull();

    // Audit.
    const events = await repos.audit.query({ tenantId: A });
    expect(events.events.length).toBeGreaterThan(0);
    expect(events.events.every((event) => event.tenantId === A)).toBe(true);
  });
});
