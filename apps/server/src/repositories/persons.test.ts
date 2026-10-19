import { describe, expect, it } from "vitest";
import {
  createLoginMethod,
  createTenant,
  createTenantWithApp,
  login,
  TEST_PINS,
} from "../testing/fixtures.js";
import { setupTestDatabase } from "../testing/test-database.js";
import { InvalidIdError, InvalidReferenceError, ValidationError } from "./errors.js";

const testDb = await setupTestDatabase();

const CITIZEN_ACR = "http://id.elegnamnden.se/loa/1.0/loa3";

describe.skipIf(testDb === undefined)("PersonRepository JIT upsert", () => {
  const { repos, db } = testDb!;

  it("creates the person and identity at first login", async () => {
    const { tenant, loginMethod } = await createTenantWithApp(repos);
    const result = await login(repos, tenant.id, loginMethod, "oid-1", {
      attributes: { name: "Anna Andersson", email: "anna@example.test", groups: ["g1"] },
    });

    expect(result.created).toBe(true);
    expect(result.linked).toBe(false);
    expect(result.person.tenantId).toBe(tenant.id);
    expect(result.person.lastLoginAt).toBeInstanceOf(Date);
    expect(result.identity).toMatchObject({
      tenantId: tenant.id,
      personId: result.person.id,
      loginMethodId: loginMethod.id,
      subject: "oid-1",
      pinIndex: null,
      attributes: {
        name: "Anna Andersson",
        email: "anna@example.test",
        groups: ["g1"],
        protectedIdentity: false,
      },
    });
    expect(await repos.persons.findById(tenant.id, result.person.id)).toEqual(result.person);
  });

  it("finds the same person at the next login and refreshes the attributes", async () => {
    const { tenant, loginMethod } = await createTenantWithApp(repos);
    const first = await login(repos, tenant.id, loginMethod, "oid-2", {
      attributes: { name: "Old Name", groups: ["a"] },
    });
    const second = await login(repos, tenant.id, loginMethod, "oid-2", {
      attributes: { name: "New Name", groups: ["b"] },
    });

    expect(second.created).toBe(false);
    expect(second.person.id).toBe(first.person.id);
    expect(second.identity.id).toBe(first.identity.id);
    expect(second.identity.attributes).toEqual({
      name: "New Name",
      groups: ["b"],
      protectedIdentity: false,
    });
    expect(second.identity.lastLoginAt.getTime()).toBeGreaterThanOrEqual(
      first.identity.lastLoginAt.getTime(),
    );
    expect(await repos.persons.listIdentities(tenant.id, first.person.id)).toHaveLength(1);
  });

  it("stores no name or email for a protected identity", async () => {
    const { tenant, loginMethod } = await createTenantWithApp(repos);
    await login(repos, tenant.id, loginMethod, "protected", {
      attributes: { name: "Known Name", email: "known@example.test", groups: ["g"] },
    });
    const result = await login(repos, tenant.id, loginMethod, "protected", {
      attributes: {
        name: "Secret Name",
        email: "secret@example.test",
        groups: ["g"],
        protectedIdentity: true,
      },
    });
    expect(result.identity.attributes).toEqual({ groups: ["g"], protectedIdentity: true });
    const [raw] = await db.query<{ attributes: object }>(
      "SELECT attributes FROM identities WHERE id = $1",
      [result.identity.id],
    );
    expect(JSON.stringify(raw?.attributes)).not.toMatch(/Name|example\.test/);
  });

  it("stores the personal identity number encrypted with a blind index", async () => {
    const { tenant, loginMethod } = await createTenantWithApp(repos);
    const result = await login(repos, tenant.id, loginMethod, "with-pin", { pin: TEST_PINS[0] });
    expect(result.identity.pinIndex).toBe(testDb!.keys.index.compute("pin", "191212121212").index);
    expect(await repos.persons.getPin(tenant.id, result.identity.id)).toBe("191212121212");

    const [raw] = await db.query<{ pin_encrypted: string; attributes: object }>(
      "SELECT pin_encrypted, attributes FROM identities WHERE id = $1",
      [result.identity.id],
    );
    expect(raw?.pin_encrypted.startsWith("pv1.")).toBe(true);
    expect(JSON.stringify(raw)).not.toContain("191212121212");
    expect(JSON.stringify(raw)).not.toContain("121212");

    await expect(
      login(repos, tenant.id, loginMethod, "bad-pin", { pin: "19121212-1213" }),
    ).rejects.toBeInstanceOf(ValidationError);
  });

  it("treats the same subject from another login method as another person", async () => {
    const { tenant, loginMethod } = await createTenantWithApp(repos);
    const other = await createLoginMethod(repos, tenant.id, { displayName: "Other IdP" });
    const a = await login(repos, tenant.id, loginMethod, "shared-sub");
    const b = await login(repos, tenant.id, other, "shared-sub");
    expect(b.created).toBe(true);
    expect(b.person.id).not.toBe(a.person.id);
  });

  describe("linking by personal identity number", () => {
    async function citizenMethods(linkByPin: [boolean, boolean]) {
      const tenant = await createTenant(repos);
      const options = (name: string, link: boolean) => ({
        kind: "citizen" as const,
        displayName: name,
        assertedAcr: CITIZEN_ACR,
        claimMapping: { subject: "sub", pin: "pin", acr: "acr" },
        linkByPin: link,
      });
      const bankid = await createLoginMethod(repos, tenant.id, options("BankID", linkByPin[0]));
      const freja = await createLoginMethod(repos, tenant.id, options("Freja", linkByPin[1]));
      return { tenant, bankid, freja };
    }

    it("links a new identity to the person another linking method already knows", async () => {
      const { tenant, bankid, freja } = await citizenMethods([true, true]);
      const first = await login(repos, tenant.id, bankid, "bankid-sub", { pin: TEST_PINS[1] });
      const second = await login(repos, tenant.id, freja, "freja-sub", { pin: "900101-2385" });
      expect(second).toMatchObject({ created: false, linked: true });
      expect(second.person.id).toBe(first.person.id);
      expect(await repos.persons.listIdentities(tenant.id, first.person.id)).toHaveLength(2);
      // Later logins are plain refreshes.
      const again = await login(repos, tenant.id, freja, "freja-sub", { pin: TEST_PINS[1] });
      expect(again).toMatchObject({ created: false, linked: false });
      expect(again.person.id).toBe(first.person.id);
    });

    it("does not link when either method does not link by pin", async () => {
      const { tenant, bankid, freja } = await citizenMethods([true, false]);
      const first = await login(repos, tenant.id, bankid, "bankid-sub", { pin: TEST_PINS[1] });
      const second = await login(repos, tenant.id, freja, "freja-sub", { pin: TEST_PINS[1] });
      expect(second).toMatchObject({ created: true, linked: false });
      expect(second.person.id).not.toBe(first.person.id);

      const reverse = await citizenMethods([false, true]);
      const a = await login(repos, reverse.tenant.id, reverse.bankid, "a", { pin: TEST_PINS[1] });
      const b = await login(repos, reverse.tenant.id, reverse.freja, "b", { pin: TEST_PINS[1] });
      expect(b.person.id).not.toBe(a.person.id);
    });

    it("does not link when the login did not reach the method's asserted acr", async () => {
      const { tenant, bankid, freja } = await citizenMethods([true, true]);
      const first = await login(repos, tenant.id, bankid, "bankid-sub", { pin: TEST_PINS[1] });
      const weak = await login(repos, tenant.id, freja, "freja-sub", {
        pin: TEST_PINS[1],
        acr: "urn:portvakt:acr:loa2",
      });
      expect(weak).toMatchObject({ created: true, linked: false });
      expect(weak.person.id).not.toBe(first.person.id);
    });

    it("refuses linkByPin at save without a pin mapping or below loa3, unranked included", async () => {
      const tenant = await createTenant(repos);
      const base = { kind: "citizen" as const, displayName: "Self-asserted", linkByPin: true };
      // The probe: an unranked, self-asserted acr needs no upstream acr mapping, so it proves
      // nothing about who signed in, and must never link into a BankID person.
      await expect(
        createLoginMethod(repos, tenant.id, {
          ...base,
          assertedAcr: "urn:example:self-asserted",
          claimMapping: { subject: "sub", pin: "pin" },
        }),
      ).rejects.toThrow(/linkByPin: the method must assert at least loa3/);
      await expect(
        createLoginMethod(repos, tenant.id, {
          ...base,
          assertedAcr: "http://id.elegnamnden.se/loa/1.0/loa2",
          claimMapping: { subject: "sub", pin: "pin", acr: "acr" },
        }),
      ).rejects.toThrow(/linkByPin: the method must assert at least loa3/);
      await expect(
        createLoginMethod(repos, tenant.id, {
          ...base,
          assertedAcr: CITIZEN_ACR,
          claimMapping: { subject: "sub", acr: "acr" },
        }),
      ).rejects.toThrow(/linkByPin: the method must map a personal identity number/);
      const plain = await createLoginMethod(repos, tenant.id, {
        ...base,
        linkByPin: false,
        assertedAcr: "urn:example:self-asserted",
        claimMapping: { subject: "sub", pin: "pin" },
      });
      await expect(
        repos.loginMethods.update(tenant.id, plain.id, { linkByPin: true }),
      ).rejects.toThrow(/linkByPin: the method must assert at least loa3/);
    });

    it("does not link through or into a method below loa3 saved before the rule", async () => {
      const { tenant, bankid, freja } = await citizenMethods([true, true]);
      // An older row: linkByPin on a self-asserted, unranked method (the save rule is newer).
      const selfAsserted = "urn:example:self-asserted";
      await db.query("UPDATE login_methods SET asserted_acr = $2 WHERE id = $1", [
        freja.id,
        selfAsserted,
      ]);
      const victim = await login(repos, tenant.id, bankid, "bankid-sub", { pin: TEST_PINS[1] });
      const intruder = await login(repos, tenant.id, freja, "self-sub", {
        pin: TEST_PINS[1],
        acr: selfAsserted,
      });
      expect(intruder).toMatchObject({ created: true, linked: false });
      expect(intruder.person.id).not.toBe(victim.person.id);

      // The other direction: a person known only to the weak method is never joined either.
      const other = await citizenMethods([true, true]);
      await db.query("UPDATE login_methods SET asserted_acr = $2 WHERE id = $1", [
        other.freja.id,
        selfAsserted,
      ]);
      const weakFirst = await login(repos, other.tenant.id, other.freja, "self-sub", {
        pin: TEST_PINS[2],
        acr: selfAsserted,
      });
      const strong = await login(repos, other.tenant.id, other.bankid, "bankid-sub", {
        pin: TEST_PINS[2],
      });
      expect(strong).toMatchObject({ created: true, linked: false });
      expect(strong.person.id).not.toBe(weakFirst.person.id);
    });

    it("does not link without a pin, with another pin, or across tenants", async () => {
      const { tenant, bankid, freja } = await citizenMethods([true, true]);
      const first = await login(repos, tenant.id, bankid, "bankid-sub", { pin: TEST_PINS[1] });
      const noPin = await login(repos, tenant.id, freja, "no-pin");
      const otherPin = await login(repos, tenant.id, freja, "other-pin", { pin: TEST_PINS[2] });
      expect(noPin.person.id).not.toBe(first.person.id);
      expect(otherPin.person.id).not.toBe(first.person.id);

      const elsewhere = await citizenMethods([true, true]);
      const foreign = await login(repos, elsewhere.tenant.id, elsewhere.freja, "x", {
        pin: TEST_PINS[1],
      });
      expect(foreign).toMatchObject({ created: true, linked: false });
    });
  });

  it("creates exactly one person under concurrent first logins", async () => {
    const { tenant, loginMethod } = await createTenantWithApp(repos);
    const results = await Promise.all(
      Array.from({ length: 5 }, () => login(repos, tenant.id, loginMethod, "racer")),
    );
    expect(new Set(results.map((result) => result.person.id)).size).toBe(1);
    expect(results.filter((result) => result.created)).toHaveLength(1);
    const [row] = await db.query<{ count: number }>(
      "SELECT count(*)::int AS count FROM persons WHERE tenant_id = $1",
      [tenant.id],
    );
    expect(row?.count).toBe(1);
  });

  it("refuses a login method of another tenant and leaves nothing behind", async () => {
    const { loginMethod } = await createTenantWithApp(repos, "owner");
    const intruder = await createTenant(repos, "intruder");
    await expect(login(repos, intruder.id, loginMethod, "x")).rejects.toBeInstanceOf(
      InvalidReferenceError,
    );
    const rows = await db.query("SELECT 1 FROM persons WHERE tenant_id = $1", [intruder.id]);
    expect(rows).toHaveLength(0);
  });

  it("validates mapped attributes and ids", async () => {
    const { tenant, loginMethod } = await createTenantWithApp(repos);
    await expect(
      login(repos, tenant.id, loginMethod, "", {
        attributes: { groups: "not-an-array" as unknown as string[] },
      }),
    ).rejects.toBeInstanceOf(ValidationError);
    await expect(repos.persons.findById(tenant.id, "not-a-uuid")).rejects.toBeInstanceOf(
      InvalidIdError,
    );
    await expect(repos.persons.listIdentities("nope", tenant.id)).rejects.toBeInstanceOf(
      InvalidIdError,
    );
  });
});
