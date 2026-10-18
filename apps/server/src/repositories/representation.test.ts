import { describe, expect, it } from "vitest";
import {
  createApplication,
  createTenantWithApp,
  login,
  TEST_ORGNR,
  TEST_PINS,
  uniqueSuffix,
} from "../testing/fixtures.js";
import { setupTestDatabase } from "../testing/test-database.js";
import { ConflictError, InvalidIdError, InvalidReferenceError, ValidationError } from "./errors.js";

const testDb = await setupTestDatabase();

const HOUR = 3600 * 1000;

describe.skipIf(testDb === undefined)("representation grants", () => {
  const { repos, db } = testDb!;

  async function setup() {
    const base = await createTenantWithApp(repos);
    const { person: agent, identity } = await login(
      repos,
      base.tenant.id,
      base.loginMethod,
      `agent-${uniqueSuffix()}`,
    );
    const organisation = await repos.parties.create(base.tenant.id, {
      type: "organisation",
      identifier: TEST_ORGNR,
      displayName: "Exempel AB",
    });
    const valid = (applicationId = base.application.id, at?: Date) =>
      repos.grants.listValidForAgent(
        base.tenant.id,
        agent.id,
        identity.pinIndex,
        applicationId,
        at,
      );
    return { ...base, agent, identity, organisation, valid };
  }

  it("lists a grant inside its window with its party", async () => {
    const { tenant, application, agent, organisation, valid } = await setup();
    const grant = await repos.grants.create(tenant.id, {
      agent: { personId: agent.id },
      partyId: organisation.id,
      allApplications: true,
      validFrom: new Date(Date.now() - HOUR),
      validTo: new Date(Date.now() + HOUR),
    });
    const grants = await valid();
    expect(grants.map((g) => g.id)).toEqual([grant.id]);
    expect(grants[0]?.party).toEqual(organisation);
    expect(grants[0]?.party.identifier).toBe("5566778899");
    expect(grants[0]).toMatchObject({
      agent: { type: "person", personId: agent.id },
      allApplications: true,
      applicationIds: [],
    });
    expect(
      await repos.grants.findValid(tenant.id, grant.id, agent.id, null, application.id),
    ).not.toBeNull();
  });

  it("excludes expired and not yet valid grants; valid_from is inclusive, valid_to exclusive", async () => {
    const { tenant, application, agent, organisation, valid } = await setup();
    const expired = await repos.grants.create(tenant.id, {
      agent: { personId: agent.id },
      partyId: organisation.id,
      allApplications: true,
      validFrom: new Date(Date.now() - 2 * HOUR),
      validTo: new Date(Date.now() - HOUR),
    });
    const future = await repos.grants.create(tenant.id, {
      agent: { personId: agent.id },
      partyId: organisation.id,
      allApplications: true,
      validFrom: new Date(Date.now() + HOUR),
    });
    expect(await valid()).toEqual([]);
    const findAt = (grantId: string, at?: Date) =>
      repos.grants.findValid(tenant.id, grantId, agent.id, null, application.id, at);
    expect(await findAt(expired.id)).toBeNull();
    expect(await findAt(future.id)).toBeNull();

    expect(
      (await valid(application.id, new Date(Date.now() - 1.5 * HOUR))).map((g) => g.id),
    ).toEqual([expired.id]);
    expect(await findAt(expired.id, expired.validFrom)).not.toBeNull();
    expect(await findAt(expired.id, new Date(expired.validFrom.getTime() - 1))).toBeNull();
    expect(await findAt(expired.id, expired.validTo!)).toBeNull();
    expect(await findAt(future.id, future.validFrom)).not.toBeNull();
  });

  it("excludes revoked grants and keeps the first revocation", async () => {
    const { tenant, application, agent, organisation, valid } = await setup();
    const grant = await repos.grants.create(tenant.id, {
      agent: { personId: agent.id },
      partyId: organisation.id,
      allApplications: true,
    });
    const admin = crypto.randomUUID();
    const revoked = await repos.grants.revoke(tenant.id, grant.id, admin);
    expect(revoked.revokedAt).toBeInstanceOf(Date);
    expect(revoked.revokedBy).toBe(admin);
    const again = await repos.grants.revoke(tenant.id, grant.id, crypto.randomUUID());
    expect(again.revokedAt).toEqual(revoked.revokedAt);
    expect(again.revokedBy).toBe(admin);

    expect(await valid()).toEqual([]);
    expect(
      await repos.grants.findValid(tenant.id, grant.id, agent.id, null, application.id),
    ).toBeNull();
    expect(await repos.grants.listForAgent(tenant.id, agent.id, null)).toHaveLength(1);
  });

  it("honours an application limit", async () => {
    const { tenant, agent, organisation, valid } = await setup();
    const other = await createApplication(repos);
    await repos.applications.enableForTenant(tenant.id, other.id);
    const limited = await repos.grants.create(tenant.id, {
      agent: { personId: agent.id },
      partyId: organisation.id,
      allApplications: false,
      applicationIds: [other.id, other.id],
    });
    expect(limited).toMatchObject({ allApplications: false, applicationIds: [other.id] });
    expect(await valid()).toEqual([]);
    expect((await valid(other.id)).map((g) => g.id)).toEqual([limited.id]);
  });

  it("a limited grant stays limited when its only application is removed from the tenant", async () => {
    const { tenant, application, agent, organisation, valid } = await setup();
    const x = await createApplication(repos);
    await repos.applications.enableForTenant(tenant.id, x.id);
    const grant = await repos.grants.create(tenant.id, {
      agent: { personId: agent.id },
      partyId: organisation.id,
      allApplications: false,
      applicationIds: [x.id],
    });
    expect(await repos.applications.removeFromTenant(tenant.id, x.id)).toBe(true);

    const after = await repos.grants.findById(tenant.id, grant.id);
    expect(after).toMatchObject({ allApplications: false, applicationIds: [] });
    expect(await valid(application.id)).toEqual([]);
    expect(
      await repos.grants.findValid(tenant.id, grant.id, agent.id, null, application.id),
    ).toBeNull();
    // Even re-attaching X does not resurrect the limit.
    await repos.applications.enableForTenant(tenant.id, x.id);
    expect(await valid(x.id)).toEqual([]);
  });

  it("requires an explicit choice between all applications and a list", async () => {
    const { tenant, application, agent, organisation } = await setup();
    const base = { agent: { personId: agent.id }, partyId: organisation.id };
    await expect(
      repos.grants.create(tenant.id, { ...base, allApplications: false }),
    ).rejects.toBeInstanceOf(ValidationError);
    await expect(
      repos.grants.create(tenant.id, {
        ...base,
        allApplications: true,
        applicationIds: [application.id],
      }),
    ).rejects.toBeInstanceOf(ValidationError);
  });

  it("matches a grant made out to a personal identity number at the agent's first login", async () => {
    const { tenant, application, loginMethod, organisation } = await setup();
    const grant = await repos.grants.create(tenant.id, {
      agent: { pin: TEST_PINS[2] },
      partyId: organisation.id,
      allApplications: true,
    });
    expect(grant.agent.type).toBe("pin");
    const [raw] = await db.query<Record<string, unknown>>(
      "SELECT * FROM representation_grants WHERE id = $1",
      [grant.id],
    );
    expect(JSON.stringify(raw)).not.toContain("200001010008");

    const { person, identity } = await login(repos, tenant.id, loginMethod, "newcomer", {
      pin: "000101-0008",
    });
    const found = await repos.grants.listValidForAgent(
      tenant.id,
      person.id,
      identity.pinIndex,
      application.id,
    );
    expect(found.map((g) => g.id)).toEqual([grant.id]);
    expect(
      await repos.grants.findValid(
        tenant.id,
        grant.id,
        person.id,
        identity.pinIndex,
        application.id,
      ),
    ).not.toBeNull();
    expect(await repos.grants.listForAgent(tenant.id, person.id, identity.pinIndex)).toHaveLength(
      1,
    );

    // Someone else, with another or no pin, does not get it.
    const { person: other, identity: otherIdentity } = await login(
      repos,
      tenant.id,
      loginMethod,
      "someone-else",
      { pin: TEST_PINS[0] },
    );
    expect(
      await repos.grants.listValidForAgent(
        tenant.id,
        other.id,
        otherIdentity.pinIndex,
        application.id,
      ),
    ).toEqual([]);
    expect(await repos.grants.listValidForAgent(tenant.id, other.id, null, application.id)).toEqual(
      [],
    );
  });

  it("only lists grants of the given agent", async () => {
    const { tenant, application, loginMethod, agent, organisation } = await setup();
    const { person: someoneElse } = await login(
      repos,
      tenant.id,
      loginMethod,
      `o-${uniqueSuffix()}`,
    );
    const grant = await repos.grants.create(tenant.id, {
      agent: { personId: agent.id },
      partyId: organisation.id,
      allApplications: true,
    });
    expect(
      await repos.grants.listValidForAgent(tenant.id, someoneElse.id, null, application.id),
    ).toEqual([]);
    expect(
      await repos.grants.findValid(tenant.id, grant.id, someoneElse.id, null, application.id),
    ).toBeNull();
  });

  it("validates the window, references and ids", async () => {
    const { tenant, application, agent, organisation } = await setup();
    const other = await setup();
    await expect(
      repos.grants.create(tenant.id, {
        agent: { personId: agent.id },
        partyId: organisation.id,
        allApplications: true,
        validFrom: new Date(),
        validTo: new Date(Date.now() - HOUR),
      }),
    ).rejects.toBeInstanceOf(ValidationError);
    await expect(
      repos.grants.create(tenant.id, {
        agent: { personId: agent.id },
        partyId: other.organisation.id,
        allApplications: true,
      }),
    ).rejects.toBeInstanceOf(InvalidReferenceError);
    const detached = await createApplication(repos);
    await expect(
      repos.grants.create(tenant.id, {
        agent: { personId: agent.id },
        partyId: organisation.id,
        allApplications: false,
        applicationIds: [detached.id],
      }),
    ).rejects.toBeInstanceOf(InvalidReferenceError);
    await expect(
      repos.grants.create(tenant.id, {
        agent: { pin: "19121212-1213" },
        partyId: organisation.id,
        allApplications: true,
      }),
    ).rejects.toBeInstanceOf(ValidationError);
    await expect(
      repos.grants.findValid(tenant.id, "bad", agent.id, null, application.id),
    ).rejects.toBeInstanceOf(InvalidIdError);
  });

  describe("parties", () => {
    it("validates, encrypts and indexes identifiers; unique per tenant and type", async () => {
      const { tenant, organisation } = await setup();
      const [raw] = await db.query<Record<string, unknown>>("SELECT * FROM parties WHERE id = $1", [
        organisation.id,
      ]);
      expect(JSON.stringify(raw)).not.toContain("5566778899");

      await expect(
        repos.parties.create(tenant.id, {
          type: "organisation",
          identifier: "5566778899",
          displayName: "Duplicate in another format",
        }),
      ).rejects.toBeInstanceOf(ConflictError);
      await expect(
        repos.parties.create(tenant.id, {
          type: "organisation",
          identifier: TEST_PINS[0],
          displayName: "A personnummer is not an organisation",
        }),
      ).rejects.toBeInstanceOf(ValidationError);
      await expect(
        repos.parties.create(tenant.id, {
          type: "person",
          identifier: "not a number",
          displayName: "x",
        }),
      ).rejects.toBeInstanceOf(ValidationError);

      const person = await repos.parties.create(tenant.id, {
        type: "person",
        identifier: "121212+1212",
        displayName: "Tolvan",
      });
      expect(person.identifier).toBe("191212121212");
      expect(await repos.parties.findByIdentifier(tenant.id, "person", "19121212-1212")).toEqual(
        person,
      );
      expect(
        await repos.parties.findByIdentifier(tenant.id, "organisation", "556677-8899"),
      ).toEqual(organisation);
      expect(await repos.parties.findByIdentifier(tenant.id, "organisation", "garbage")).toBeNull();
    });
  });
});
