import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { createKeyRing } from "../crypto/keyring.js";
import { createLoginMethod, createTenant } from "../testing/fixtures.js";
import { setupTestDatabase, testMasterKeys } from "../testing/test-database.js";
import { ConflictError, NotFoundError, ValidationError } from "./errors.js";
import { createRepositories, rewrapAllSecrets } from "./index.js";

const testDb = await setupTestDatabase();

describe.skipIf(testDb === undefined)("login method client key rotation", () => {
  const { repos, db } = testDb!;

  it("prepares a next key, promotes it and keeps the former key published for the overlap", async () => {
    const tenant = await createTenant(repos, "client-keys");
    const method = await createLoginMethod(repos, tenant.id, {
      clientAuthMethod: "private_key_jwt",
    });
    const active = method.clientKeyKid!;
    expect(
      (await repos.loginMethods.listClientKeys(tenant.id, method.id))?.map((k) => k.state),
    ).toEqual(["active"]);
    // Nothing to promote yet.
    expect(await repos.loginMethods.rotateClientKey(tenant.id, method.id)).toBeNull();

    const next = await repos.loginMethods.prepareClientKeyRotation(tenant.id, method.id);
    expect(next).not.toBe(active);
    await expect(
      repos.loginMethods.prepareClientKeyRotation(tenant.id, method.id),
    ).rejects.toBeInstanceOf(ConflictError);
    const prepared = await repos.loginMethods.listClientKeys(tenant.id, method.id);
    expect(prepared?.map((k) => `${k.kid}:${k.state}`)).toEqual([
      `${active}:active`,
      `${next}:next`,
    ]);
    expect(prepared?.every((k) => !("d" in k.publicJwk))).toBe(true);
    // The next key does not sign yet.
    expect((await repos.loginMethods.getClientKey(tenant.id, method.id))?.kid).toBe(active);

    const [{ envelope } = { envelope: "" }] = await db.query<{ envelope: string }>(
      "SELECT client_next_private_jwk_encrypted AS envelope FROM login_methods WHERE id = $1",
      [method.id],
    );
    expect(envelope.startsWith("pv1.")).toBe(true);

    expect(await repos.loginMethods.rotateClientKey(tenant.id, method.id, 600)).toEqual({
      activeKid: next,
      retiringKid: active,
    });
    expect((await repos.loginMethods.getClientKey(tenant.id, method.id))?.kid).toBe(next);
    const rotated = await repos.loginMethods.listClientKeys(tenant.id, method.id);
    expect(rotated?.map((k) => `${k.kid}:${k.state}`)).toEqual([
      `${next}:active`,
      `${active}:retiring`,
    ]);
    const retiresAt = rotated?.[1]?.retiresAt;
    expect(retiresAt).toBeInstanceOf(Date);
    // The retiring key keeps no private part.
    const [row] = await db.query<{ retiring: object; private: string | null }>(
      `SELECT client_retiring_public_jwk AS retiring, client_next_private_jwk_encrypted AS private
         FROM login_methods WHERE id = $1`,
      [method.id],
    );
    expect(row?.retiring).not.toHaveProperty("d");
    expect(row?.private).toBeNull();

    // Once the overlap has passed (app clock), only the active key is published.
    const later = new Date(retiresAt!.getTime() + 1000);
    expect(
      (await repos.loginMethods.listClientKeys(tenant.id, method.id, later))?.map((k) => k.kid),
    ).toEqual([next]);
  });

  it("refuses a method of another tenant, an unknown one and a negative overlap", async () => {
    const tenant = await createTenant(repos, "client-keys-refused");
    const method = await createLoginMethod(repos, tenant.id);
    const other = await createTenant(repos, "client-keys-other");
    expect(await repos.loginMethods.listClientKeys(other.id, method.id)).toBeNull();
    await expect(
      repos.loginMethods.prepareClientKeyRotation(other.id, method.id),
    ).rejects.toBeInstanceOf(NotFoundError);
    expect(await repos.loginMethods.rotateClientKey(other.id, method.id)).toBeNull();
    expect(await repos.loginMethods.listClientKeys(tenant.id, randomUUID())).toBeNull();
    await expect(
      repos.loginMethods.prepareClientKeyRotation(tenant.id, randomUUID()),
    ).rejects.toBeInstanceOf(NotFoundError);
    await expect(
      repos.loginMethods.rotateClientKey(tenant.id, method.id, -1),
    ).rejects.toBeInstanceOf(ValidationError);
  });

  it("re-wraps a prepared next key under a new master key", async () => {
    const tenant = await createTenant(repos, "client-keys-rewrap");
    const method = await createLoginMethod(repos, tenant.id, {
      clientAuthMethod: "private_key_jwt",
    });
    const next = await repos.loginMethods.prepareClientKeyRotation(tenant.id, method.id);
    const newKey = Buffer.from("test-master-key-rotated-32-bytes", "utf8");
    const rotatedRing = createKeyRing({ current: newKey, previous: [testMasterKeys.current] });
    const result = await rewrapAllSecrets(db, rotatedRing);
    // The method's secret, its active key and its next key.
    expect(result.loginMethodSecrets).toBeGreaterThanOrEqual(3);
    const newOnly = createRepositories(db, createKeyRing({ current: newKey, previous: [] }));
    await newOnly.loginMethods.rotateClientKey(tenant.id, method.id);
    const key = await newOnly.loginMethods.getClientKey(tenant.id, method.id);
    expect(key?.kid).toBe(next);
    expect(key?.privateJwk.d).toEqual(expect.any(String));
  });
});
