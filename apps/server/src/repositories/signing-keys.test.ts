import { describe, expect, it } from "vitest";
import { generateSigningKey } from "../crypto/jwk.js";
import { createKeyRing } from "../crypto/keyring.js";
import { generateClientSecret } from "../crypto/secrets.js";
import {
  createApplication,
  createLoginMethod,
  createTenant,
  login,
  TEST_ORGNR,
  TEST_PINS,
} from "../testing/fixtures.js";
import { setupTestDatabase, testMasterKeys } from "../testing/test-database.js";
import {
  ConflictError,
  InvalidStateTransitionError,
  NotFoundError,
  TransitionNotDueError,
  ValidationError,
} from "./errors.js";
import { createRepositories, rewrapAllSecrets } from "./index.js";

const testDb = await setupTestDatabase();

const PUBLISH_AHEAD = { publishAheadSeconds: 2 * 86_400 };
const RETIRE_AFTER = { retireAfterSeconds: 2 * 86_400 };
const forced = (reason: string) =>
  ({ force: true, actor: { type: "person", id: "admin-person" }, reason }) as const;

// Signing keys are global, so the cases in this file run in order on one shared state.
describe.skipIf(testDb === undefined)("SigningKeyRepository", () => {
  const { repos, db } = testDb!;
  const first = generateSigningKey();
  const second = generateSigningKey();
  const third = generateSigningKey();

  /** Pretends the key was created (and, if retiring, demoted) `seconds` ago. */
  async function age(kid: string, seconds: number): Promise<void> {
    await db.query(
      `UPDATE signing_keys
          SET created_at = created_at - make_interval(secs => $2),
              retiring_at = retiring_at - make_interval(secs => $2)
        WHERE kid = $1`,
      [kid, seconds],
    );
  }

  it("stores a new key as next, published but not active, with the private part encrypted", async () => {
    const key = await repos.signingKeys.createNext(first);
    expect(key).toMatchObject({ kid: first.kid, alg: "ES256", state: "next", activatedAt: null });
    expect(key.publicJwk).toEqual(first.publicJwk);
    expect((await repos.signingKeys.listPublished()).map((k) => k.kid)).toEqual([first.kid]);

    const [raw] = await db.query<{ private_jwk_encrypted: string; public_jwk: object }>(
      "SELECT private_jwk_encrypted, public_jwk FROM signing_keys WHERE kid = $1",
      [first.kid],
    );
    expect(raw?.private_jwk_encrypted.startsWith("pv1.")).toBe(true);
    expect(raw?.private_jwk_encrypted).not.toContain(first.privateJwk.d);
    expect(raw?.public_jwk).not.toHaveProperty("d");
  });

  it("allows only one next key", async () => {
    await expect(repos.signingKeys.createNext(second)).rejects.toBeInstanceOf(ConflictError);
  });

  it("does not activate a next key before it has been published for KEY_PUBLISH_AHEAD", async () => {
    await expect(repos.signingKeys.activate(first.kid, PUBLISH_AHEAD)).rejects.toBeInstanceOf(
      TransitionNotDueError,
    );
    await age(first.kid, PUBLISH_AHEAD.publishAheadSeconds - 60);
    await expect(repos.signingKeys.activate(first.kid, PUBLISH_AHEAD)).rejects.toBeInstanceOf(
      TransitionNotDueError,
    );
    expect((await repos.signingKeys.findByKid(first.kid))?.state).toBe("next");
  });

  it("activates the first key once due, without a previous active key", async () => {
    await age(first.kid, 120);
    const result = await repos.signingKeys.activate(first.kid, PUBLISH_AHEAD);
    expect(result.activated.state).toBe("active");
    expect(result.activated.activatedAt).toBeInstanceOf(Date);
    expect(result.retiring).toBeNull();
  });

  it("refuses transitions that skip a state, and invalid policies", async () => {
    await expect(
      repos.signingKeys.activate(first.kid, { publishAheadSeconds: 0 }),
    ).rejects.toBeInstanceOf(InvalidStateTransitionError);
    await expect(
      repos.signingKeys.retire(first.kid, { retireAfterSeconds: 0 }),
    ).rejects.toBeInstanceOf(InvalidStateTransitionError);
    await expect(repos.signingKeys.discardNext(first.kid)).rejects.toBeInstanceOf(
      InvalidStateTransitionError,
    );
    await expect(
      repos.signingKeys.activate("unknown-kid", { publishAheadSeconds: 0 }),
    ).rejects.toBeInstanceOf(NotFoundError);
    await expect(
      repos.signingKeys.activate(first.kid, { publishAheadSeconds: -1 }),
    ).rejects.toBeInstanceOf(ValidationError);
    await expect(
      repos.signingKeys.activate(first.kid, { ...forced(""), reason: "" }),
    ).rejects.toBeInstanceOf(ValidationError);
  });

  it("rotates: next becomes active and the old active key becomes retiring", async () => {
    await repos.signingKeys.createNext(second);
    await age(second.kid, PUBLISH_AHEAD.publishAheadSeconds);
    const result = await repos.signingKeys.activate(second.kid, PUBLISH_AHEAD);
    expect(result.activated.kid).toBe(second.kid);
    expect(result.retiring?.kid).toBe(first.kid);
    expect(result.retiring?.state).toBe("retiring");
    expect(result.retiring?.retiringAt).toBeInstanceOf(Date);

    const published = await repos.signingKeys.listPublished();
    expect(published.map((k) => [k.kid, k.state])).toEqual([
      [second.kid, "active"],
      [first.kid, "retiring"],
    ]);

    const material = await repos.signingKeys.loadMaterial();
    expect(material.map((k) => k.kid)).toEqual([second.kid, first.kid]);
    expect(material[0]?.privateJwk).toEqual(second.privateJwk);
  });

  it("does not retire a key before it has been retiring for KEY_RETIRE_AFTER", async () => {
    await expect(repos.signingKeys.retire(first.kid, RETIRE_AFTER)).rejects.toBeInstanceOf(
      TransitionNotDueError,
    );
    expect((await repos.signingKeys.findByKid(first.kid))?.state).toBe("retiring");
  });

  it("serialises concurrent activations: exactly one succeeds", async () => {
    await repos.signingKeys.createNext(third);
    await age(third.kid, PUBLISH_AHEAD.publishAheadSeconds);
    const results = await Promise.allSettled([
      repos.signingKeys.activate(third.kid, PUBLISH_AHEAD),
      repos.signingKeys.activate(third.kid, PUBLISH_AHEAD),
    ]);
    expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
    const rejected = results.find((r) => r.status === "rejected");
    expect(rejected?.reason).toBeInstanceOf(InvalidStateTransitionError);
    expect((await repos.signingKeys.list(["active"])).map((k) => k.kid)).toEqual([third.kid]);
    expect((await repos.signingKeys.list(["retiring"])).map((k) => k.kid).sort()).toEqual(
      [first.kid, second.kid].sort(),
    );
  });

  it("retires a retiring key once due and erases its private part", async () => {
    await age(first.kid, RETIRE_AFTER.retireAfterSeconds);
    const retired = await repos.signingKeys.retire(first.kid, RETIRE_AFTER);
    expect(retired.state).toBe("retired");
    expect(retired.retiredAt).toBeInstanceOf(Date);
    expect(retired.publicJwk).toEqual(first.publicJwk);
    const [raw] = await db.query<{ private_jwk_encrypted: string | null }>(
      "SELECT private_jwk_encrypted FROM signing_keys WHERE kid = $1",
      [first.kid],
    );
    expect(raw?.private_jwk_encrypted).toBeNull();
    expect((await repos.signingKeys.listPublished()).map((k) => k.kid)).not.toContain(first.kid);
  });

  it("emergency rotation: forced activation and retirement skip the wait and are audited", async () => {
    const replacement = generateSigningKey();
    await repos.signingKeys.createNext(replacement);
    const result = await repos.signingKeys.activate(replacement.kid, forced("third key leaked"));
    expect(result.retiring?.kid).toBe(third.kid);
    const retired = await repos.signingKeys.retire(third.kid, forced("third key leaked"));
    expect(retired.state).toBe("retired");
    expect(retired.publicJwk).toEqual(third.publicJwk);
    expect(await repos.signingKeys.findByKid(third.kid)).not.toBeNull();

    const audit = await repos.audit.query(
      { allTenants: true, tenantId: null },
      { actionPrefix: "key" },
    );
    expect(
      audit.events.map((event) => [event.action, event.subject?.id, event.details.reason]),
    ).toEqual([
      ["key.retire_forced", third.kid, "third key leaked"],
      ["key.activate_forced", replacement.kid, "third key leaked"],
    ]);
    expect(audit.events[1]?.details.retiringKid).toBe(third.kid);
    expect(audit.events[0]?.actor).toEqual({ type: "person", id: "admin-person" });
  });

  it("discards an unused next key", async () => {
    const unused = generateSigningKey();
    await repos.signingKeys.createNext(unused);
    expect((await repos.signingKeys.discardNext(unused.kid)).state).toBe("retired");
  });

  it("enforces one active key and consistent timestamps in SQL", async () => {
    await expect(
      db.query("UPDATE signing_keys SET state = 'active', retiring_at = NULL WHERE kid = $1", [
        second.kid,
      ]),
    ).rejects.toMatchObject({ code: "23505" });
    await expect(
      db.query("UPDATE signing_keys SET state = 'retired' WHERE kid = $1", [second.kid]),
    ).rejects.toMatchObject({ code: "23514" });
  });

  it("re-wraps secrets and re-indexes identifiers after a master key rotation", async () => {
    const tenant = await createTenant(repos);
    const method = await createLoginMethod(repos, tenant.id, { clientSecret: "rotate-me" });
    const appSecret = generateClientSecret();
    const app = await createApplication(repos, {
      clientAuth: { method: "client_secret_basic", clientSecret: appSecret },
    });
    const { identity } = await login(repos, tenant.id, method, "pin-holder", { pin: TEST_PINS[0] });
    const party = await repos.parties.create(tenant.id, {
      type: "organisation",
      identifier: TEST_ORGNR,
      displayName: "Rotated AB",
    });
    const grant = await repos.grants.create(tenant.id, {
      agent: { pin: TEST_PINS[1] },
      partyId: party.id,
      allApplications: true,
    });

    // New master key; the old current key becomes a previous key.
    const newKey = Buffer.from("test-master-key-rotated-32-bytes", "utf8");
    const rotated = createKeyRing({ current: newKey, previous: [testMasterKeys.current] });
    const result = await rewrapAllSecrets(db, rotated);
    expect(result).toMatchObject({
      identityPins: 1,
      partyIdentifiers: 1,
      grantAgentIdentifiers: 1,
    });
    expect(result.loginMethodSecrets).toBeGreaterThanOrEqual(1);
    expect(result.applicationSecrets).toBeGreaterThanOrEqual(1);
    expect(result.signingKeys).toBe(2); // second and the replacement still hold private keys

    // Only the new key is needed afterwards.
    const newOnly = createRepositories(db, createKeyRing({ current: newKey, previous: [] }));
    expect(await newOnly.loginMethods.getClientSecret(tenant.id, method.id)).toBe("rotate-me");
    expect(await newOnly.applications.getClientSecret(app.id)).toBe(appSecret);
    expect(await newOnly.persons.getPin(tenant.id, identity.id)).toBe("191212121212");
    expect((await newOnly.signingKeys.loadMaterial()).map((k) => k.privateJwk.d)).toContain(
      second.privateJwk.d,
    );
    // Blind-index lookups work with the new key alone.
    expect(
      (await newOnly.parties.findByIdentifier(tenant.id, "organisation", TEST_ORGNR))?.id,
    ).toBe(party.id);
    const relogin = await login(newOnly, tenant.id, method, "pin-holder", { pin: TEST_PINS[0] });
    expect(relogin.identity.pinIndex).toBe(rotated.index.compute("pin", "191212121212").index);
    const { person: agent, identity: agentIdentity } = await login(
      newOnly,
      tenant.id,
      method,
      "agent",
      { pin: TEST_PINS[1] },
    );
    expect(
      (
        await newOnly.grants.listValidForAgent(tenant.id, agent.id, agentIdentity.pinIndex, app.id)
      ).map((g) => g.id),
    ).toEqual([]); // app not attached to this tenant
    await newOnly.applications.enableForTenant(tenant.id, app.id);
    expect(
      (
        await newOnly.grants.listValidForAgent(tenant.id, agent.id, agentIdentity.pinIndex, app.id)
      ).map((g) => g.id),
    ).toEqual([grant.id]);

    expect(await rewrapAllSecrets(db, rotated)).toEqual({
      applicationSecrets: 0,
      loginMethodSecrets: 0,
      signingKeys: 0,
      identityPins: 0,
      partyIdentifiers: 0,
      grantAgentIdentifiers: 0,
    });
  });
});
