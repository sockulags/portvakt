import { describe, expect, it } from "vitest";
import { METRICS } from "../../metrics/registry.js";
import { ValidationError } from "../../repositories/errors.js";
import { createTenant } from "../../testing/fixtures.js";
import {
  authorizationRequest,
  FlowDriver,
  LOA3,
  redeem,
  startTestIdp,
} from "../../testing/federation.js";
import { createTestClient, discoverWithSecret } from "../../testing/oidc-flow.js";
import { createSamlLoginMethod, spEntityId } from "../../testing/saml.js";
import { startTestServer } from "../../testing/test-server.js";

const ts = await startTestServer();
const idp = ts === undefined ? undefined : await startTestIdp();

describe.skipIf(ts === undefined)("SAML login method administration", () => {
  const { repos } = ts!.db;
  const db = ts!.db.db;
  const admin = () => ts!.portvakt.samlAdmin;
  const bankid = () => idp!.idp.saml("bankid");

  async function world(prefix: string) {
    const tenant = await createTenant(repos, prefix);
    const app = await createTestClient(repos, tenant, { allowedExtraScopes: ["pin"] });
    const config = await discoverWithSecret(ts!, tenant.slug, app);
    return { tenant, config, redirectUri: app.application.redirectUris[0]! };
  }

  async function signIn(w: Awaited<ReturnType<typeof world>>, persona = "saml-sven") {
    const driver = new FlowDriver(ts!, idp!);
    const request = await authorizationRequest(w.config, w.redirectUri, { scope: "openid pin" });
    let landing = await driver.follow(request.url.href);
    if (landing.kind === "idp_page") landing = await driver.persona(landing, persona);
    return {
      landing,
      tokens: landing.kind === "app" ? await redeem(w.config, request, landing) : undefined,
    };
  }

  const issuesOf = async (promise: Promise<unknown>): Promise<readonly string[]> => {
    const error = await promise.catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(ValidationError);
    return (error as ValidationError).issues;
  };

  describe("creating and updating", () => {
    it("validates the IdP: metadata signature, entityID, certificates and LoA URIs", async () => {
      const tenant = await createTenant(repos, "saml-validate");
      bankid().setMetadataMode("tampered");
      try {
        expect(await issuesOf(createSamlLoginMethod(ts!, idp!, tenant, "bankid"))).toEqual([
          "saml.metadata: signature_invalid",
        ]);
      } finally {
        bankid().setMetadataMode("signed");
      }
      expect(
        await issuesOf(
          createSamlLoginMethod(ts!, idp!, tenant, "bankid", {
            saml: { idpEntityId: "https://idp.unknown.example/saml" },
          }),
        ),
      ).toEqual(["saml.metadata: entity_not_found"]);
      // Signed by another key than the configured metadata signing certificate.
      expect(
        await issuesOf(
          createSamlLoginMethod(ts!, idp!, tenant, "bankid", {
            saml: { metadataSigningCertificate: bankid().signingCertificate },
          }),
        ),
      ).toEqual(["saml.metadata: signature_invalid"]);
      expect(
        await issuesOf(
          createSamlLoginMethod(ts!, idp!, tenant, "bankid", {
            saml: {
              metadataSigningCertificate:
                "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----",
            },
          }),
        ),
      ).toEqual(["saml.metadataSigningCertificate: not a valid certificate"]);
      const custom = "https://idp.example/loa/custom-high";
      expect(
        await issuesOf(
          createSamlLoginMethod(ts!, idp!, tenant, "bankid", {
            assertedAcr: custom,
            saml: { requestedLoa: [custom] },
          }),
        ),
      ).toContain(
        "saml.requestedLoa: unknown LoA URI (not in the Swedish eID registry or ACR_RANKING); set allowCustomLoa to use it",
      );
      const allowed = await createSamlLoginMethod(ts!, idp!, tenant, "bankid", {
        assertedAcr: custom,
        saml: { requestedLoa: [custom], allowCustomLoa: true },
      });
      expect(allowed.saml.requestedLoa).toEqual([custom]);
      // The asserted acr must be reachable by a requested level.
      expect(
        await issuesOf(
          createSamlLoginMethod(ts!, idp!, tenant, "bankid", {
            assertedAcr: "http://id.elegnamnden.se/loa/1.0/loa4",
          }),
        ),
      ).toContain("assertedAcr: no requested LoA meets the login method's asserted acr");
    });

    it("accepts inline metadata, and re-checks the IdP when its source changes", async () => {
      const w = await world("saml-inline");
      const xml = await (await fetch(bankid().metadataUrl)).text();
      const method = await createSamlLoginMethod(ts!, idp!, w.tenant, "bankid", {
        saml: { metadataUrl: null, metadataXml: xml, metadataSigningCertificate: null },
      });
      expect(method.saml.metadataXml).toBe(xml);
      expect((await signIn(w)).tokens?.claims()).toMatchObject({ acr: LOA3, pin: "191212121212" });

      const freja = idp!.idp.saml("freja");
      await expect(
        admin().update(w.tenant.id, method.id, { saml: { idpEntityId: freja.entityId } }),
      ).rejects.toThrow(/entity_not_found/);
      const moved = await admin().update(w.tenant.id, method.id, {
        displayName: "Moved to Freja",
        saml: {
          idpEntityId: freja.entityId,
          metadataXml: null,
          metadataUrl: freja.metadataUrl,
          metadataSigningCertificate: freja.metadataSigningCertificate,
        },
      });
      expect(moved.saml.idpEntityId).toBe(freja.entityId);
      const cache = await repos.saml.metadataCache(w.tenant.id, method.id);
      expect(cache.metadata?.entityId).toBe(freja.entityId);
      expect((await signIn(w, "freja-frida")).tokens?.claims()).toMatchObject({
        pin: "198507099805",
      });
    });
  });

  describe("metadata refresh", () => {
    const failures = (reason: string) =>
      ts!.portvakt.metrics
        .counters()
        .find((counter) => counter.name === METRICS.samlMetadataRefresh)
        ?.get({ outcome: "failure", reason }) ?? 0;

    it("keeps the last good metadata on failure and a bad signature, and never fetches during a login", async () => {
      const w = await world("saml-refresh");
      const method = await createSamlLoginMethod(ts!, idp!, w.tenant, "bankid");
      const due = () =>
        db.query(
          `UPDATE login_method_saml SET metadata_checked_at = now() - interval '2 days'
            WHERE login_method_id = $1`,
          [method.id],
        );
      const good = (await repos.saml.metadataCache(w.tenant.id, method.id)).metadata;
      expect(good?.signingCertificates).toEqual([bankid().signingCertificate]);
      try {
        bankid().setMetadataMode("unavailable");
        await due();
        const before = failures("http_status");
        expect(await ts!.portvakt.jobs.refreshSamlMetadata()).toBeGreaterThanOrEqual(1);
        expect(failures("http_status")).toBe(before + 1);
        let cache = await repos.saml.metadataCache(w.tenant.id, method.id);
        expect(cache.error).toBe("http_status");
        expect(cache.metadata).toEqual(good);
        // Logins use the cached copy while the metadata URL fails.
        expect((await signIn(w)).tokens?.claims()).toMatchObject({ pin: "191212121212" });

        bankid().setMetadataMode("tampered");
        await due();
        await ts!.portvakt.jobs.refreshSamlMetadata();
        cache = await repos.saml.metadataCache(w.tenant.id, method.id);
        expect(cache.error).toBe("signature_invalid");
        expect(cache.metadata).toEqual(good);

        // Not due again yet: a failing method is retried after a few minutes, not every tick.
        expect(await repos.saml.listMetadataDue(100, 300)).not.toContainEqual(
          expect.objectContaining({ loginMethodId: method.id }),
        );
      } finally {
        bankid().setMetadataMode("signed");
      }
      await due();
      await ts!.portvakt.jobs.refreshSamlMetadata();
      const cache = await repos.saml.metadataCache(w.tenant.id, method.id);
      expect(cache.error).toBeNull();
      expect(cache.metadata?.slo.redirect?.location).toBe(`${bankid().entityId}/slo`);
    });
  });

  describe("SP keys", () => {
    async function metadataOf(entity: string): Promise<string> {
      return (await fetch(`${entity}/metadata`)).text();
    }
    const count = (xml: string, use: string) =>
      (xml.match(new RegExp(`<md:KeyDescriptor use="${use}">`, "g")) ?? []).length;

    it("rotates with an overlap: both certificates published, an IdP encrypting to either works", async () => {
      const w = await world("saml-rotate");
      const method = await createSamlLoginMethod(ts!, idp!, w.tenant, "bankid", {
        sessionPolicy: { maxAgeSeconds: 3600, idleSeconds: 900, allowSso: true },
      });
      const entity = spEntityId(ts!, w.tenant, method);
      const before = await metadataOf(entity);
      expect([count(before, "signing"), count(before, "encryption")]).toEqual([1, 1]);
      const oldKeys = await repos.saml.listSpKeys(w.tenant.id, method.id);

      const next = await admin().prepareSpKeyRotation(w.tenant.id, method.id);
      expect(next.map((key) => [key.purpose, key.state])).toEqual([
        ["signing", "next"],
        ["encryption", "next"],
      ]);
      const overlap = await metadataOf(entity);
      expect([count(overlap, "signing"), count(overlap, "encryption")]).toEqual([2, 2]);
      await expect(admin().prepareSpKeyRotation(w.tenant.id, method.id)).rejects.toThrow(
        /next SP key/,
      );

      // The IdP picks up the overlap metadata and encrypts to the old (still active) certificate…
      await bankid().registerSp(entity, { metadataXml: overlap, encryptionCertificateIndex: 0 });
      expect((await signIn(w)).tokens?.claims()).toMatchObject({ pin: "191212121212" });
      // …or already to the new one.
      await bankid().registerSp(entity, { metadataXml: overlap, encryptionCertificateIndex: 1 });
      expect((await signIn(w)).tokens?.claims()).toMatchObject({ pin: "191212121212" });

      expect(await admin().rotateSpKeys(w.tenant.id, method.id)).toEqual(["signing", "encryption"]);
      const after = await metadataOf(entity);
      expect([count(after, "signing"), count(after, "encryption")]).toEqual([1, 1]);
      const oldEncryption = oldKeys.find((key) => key.purpose === "encryption")!;
      expect(after).not.toContain(oldEncryption.certificate.split("\n")[1]);
      const states = (await repos.saml.listSpKeys(w.tenant.id, method.id)).map((key) => [
        key.purpose,
        key.state,
      ]);
      expect(states).toEqual([
        ["encryption", "active"],
        ["encryption", "previous"],
        ["signing", "active"],
        ["signing", "previous"],
      ]);

      // An IdP still encrypting to the old certificate (its cached overlap metadata) keeps
      // working; requests are now signed with the new key, which that metadata lists too.
      await bankid().registerSp(entity, { metadataXml: overlap, encryptionCertificateIndex: 0 });
      expect((await signIn(w)).tokens?.claims()).toMatchObject({ pin: "191212121212" });

      // After the previous key is dropped, the old certificate no longer decrypts.
      await repos.saml.deletePreviousSpKey(w.tenant.id, method.id, "encryption");
      const refused = await signIn(w);
      expect(refused.landing.kind).toBe("login_ui");
      bankid().forgetSp(entity);
    });

    it("reports SP certificates that expire soon", async () => {
      const w = await world("saml-expiry");
      const method = await createSamlLoginMethod(ts!, idp!, w.tenant, "bankid");
      expect(await admin().expiringSpCertificates(w.tenant.id)).toEqual([]);
      const keys = await repos.saml.listSpKeys(w.tenant.id, method.id);
      const notAfter = keys[0]!.notAfter;
      const soon = new Date(notAfter.getTime() - 10 * 24 * 3600 * 1000);
      const expiring = await admin().expiringSpCertificates(w.tenant.id, undefined, soon);
      expect(expiring.map((entry) => [entry.loginMethodId, entry.purpose, entry.state])).toEqual(
        expect.arrayContaining([
          [method.id, "signing", "active"],
          [method.id, "encryption", "active"],
        ]),
      );
    });

    it("stores SP private keys only as SecretBox envelopes", async () => {
      const w = await world("saml-rewrap");
      const method = await createSamlLoginMethod(ts!, idp!, w.tenant, "bankid");
      const [row] = await db.query<{ private_key_encrypted: string }>(
        "SELECT private_key_encrypted FROM saml_sp_keys WHERE login_method_id = $1 LIMIT 1",
        [method.id],
      );
      expect(row?.private_key_encrypted).toMatch(/^pv1\./);
      expect(row?.private_key_encrypted).not.toContain("PRIVATE");
      const pairs = await repos.saml.spKeyPairs(w.tenant.id, method.id, "signing");
      expect(pairs[0]?.privateKey).toContain("BEGIN PRIVATE KEY");
    });
  });

  it("remembers assertion IDs once until they expire; the cleanup job removes expired ones", async () => {
    const tenant = await createTenant(repos, "saml-replay-cache");
    const method = await createSamlLoginMethod(ts!, idp!, tenant, "bankid");
    const other = await createSamlLoginMethod(ts!, idp!, tenant, "freja");
    const future = new Date(Date.now() + 600_000);
    expect(await repos.saml.rememberAssertion(tenant.id, method.id, "_a1", future)).toBe(true);
    expect(await repos.saml.rememberAssertion(tenant.id, method.id, "_a1", future)).toBe(false);
    // Scoped by login method: the same ID at another SP is another assertion.
    expect(await repos.saml.rememberAssertion(tenant.id, other.id, "_a1", future)).toBe(true);
    const parallel = await Promise.all(
      Array.from({ length: 5 }, () =>
        repos.saml.rememberAssertion(tenant.id, method.id, "_a2", future),
      ),
    );
    expect(parallel.filter(Boolean)).toHaveLength(1);

    await repos.saml.rememberAssertion(tenant.id, method.id, "_old", new Date(Date.now() - 1000));
    await db.query(
      "UPDATE saml_replay_cache SET expires_at = now() - interval '1 minute' WHERE login_method_id = $1 AND expires_at < now() + interval '1 minute'",
      [method.id],
    );
    expect(await ts!.portvakt.jobs.cleanupExpired()).toBeGreaterThanOrEqual(1);
    const [left] = await db.query<{ count: number }>(
      "SELECT count(*)::int AS count FROM saml_replay_cache WHERE login_method_id = $1",
      [method.id],
    );
    expect(left?.count).toBe(2);
    // An expired ID may be seen again (its responses expired long ago).
    expect(await repos.saml.rememberAssertion(tenant.id, method.id, "_old", future)).toBe(true);
  });

  it("keeps OIDC and SAML updates apart", async () => {
    const tenant = await createTenant(repos, "saml-protocol");
    const method = await createSamlLoginMethod(ts!, idp!, tenant, "bankid");
    await expect(
      repos.loginMethods.update(tenant.id, method.id, { displayName: "x" }),
    ).rejects.toThrow(/not an OIDC login method/);
    expect(await repos.loginMethods.ensureClientPublicJwk(tenant.id, method.id)).toBeNull();
    const found = await repos.loginMethods.findById(tenant.id, method.id);
    expect(found?.protocol).toBe("saml");
  });
});
