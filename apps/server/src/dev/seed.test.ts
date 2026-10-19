import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { startTestIdp } from "../testing/federation.js";
import { startTestServer } from "../testing/test-server.js";
import { DEMO_TENANT_SLUG, seedDev, type DevSeedOptions } from "./seed.js";

const ts = await startTestServer();

/** A public P-256 JWK (the private part is not needed here). */
const SERVICE_D_JWK = {
  kty: "EC",
  crv: "P-256",
  kid: "service-d-1",
  x: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
  y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
};
const idp = ts === undefined ? undefined : await startTestIdp();

describe("seed:dev CLI", () => {
  it("refuses NODE_ENV=production before touching anything", () => {
    const cli = fileURLToPath(new URL("./seed-cli.ts", import.meta.url));
    const result = spawnSync(process.execPath, ["--import", "tsx", cli], {
      cwd: fileURLToPath(new URL("../..", import.meta.url)),
      // A database URL that would fail loudly if the CLI got as far as connecting.
      env: {
        ...process.env,
        NODE_ENV: "production",
        DATABASE_URL: "postgres://nobody@127.0.0.1:9/x",
      },
      encoding: "utf8",
      timeout: 60_000,
    });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("refuses NODE_ENV=production");
  });
});

describe.skipIf(ts === undefined)("seed:dev", () => {
  const options = (secretA?: string): DevSeedOptions => ({
    mockIdpUrl: idp!.baseUrl,
    services: [
      {
        clientId: "service-a",
        name: "Tjänst A",
        url: "http://localhost:3100",
        secret: secretA,
        enabled: true,
      },
      { clientId: "service-b", name: "Tjänst B", url: "http://localhost:3200", enabled: false },
      { clientId: "service-c", name: "Tjänst C", url: "http://localhost:3300", enabled: true },
      {
        clientId: "service-d",
        name: "Tjänst D",
        url: "http://localhost:3301",
        jwks: { keys: [SERVICE_D_JWK] },
        enabled: true,
      },
    ],
    isolationTenant: { slug: "demo-isolation", name: "Isoleringstest", clientIds: ["service-c"] },
    entraClient: { clientId: "portvakt-dev", secret: "dev-only-entra-client-secret" },
    bankidClient: { clientId: "portvakt-dev", secret: "dev-only-bankid-client-secret" },
    admin: {
      publicUrl: "http://localhost:3400",
      clientSecret: "dev-only-admin-client-secret-0123456789abcdef",
    },
  });

  it("creates the demo tenant and converges on the same state when run again", async () => {
    const { repos } = ts!.db;
    const target = { repos, samlAdmin: ts!.portvakt.samlAdmin };
    const first = await seedDev(target, options());
    expect(first.tenant.slug).toBe(DEMO_TENANT_SLUG);
    expect(Object.keys(first.generatedSecrets).sort()).toEqual([
      "service-a",
      "service-b",
      "service-c",
    ]);
    const tenantId = first.tenant.id;

    expect(await repos.applications.findEnabledByClientId(tenantId, "service-a")).not.toBeNull();
    // Service B is attached but disabled: its sign-ins are refused until it is enabled.
    expect(await repos.applications.findEnabledByClientId(tenantId, "service-b")).toBeNull();
    const attached = await repos.applications.listForTenant(tenantId);
    expect(attached.map((entry) => [entry.application.clientId, entry.enabled]).sort()).toEqual([
      ["portvakt-admin", true],
      ["service-a", true],
      ["service-b", false],
      ["service-c", true],
      ["service-d", true],
    ]);
    // service-d authenticates with private_key_jwt (no generated secret).
    const serviceD = (await repos.applications.findByClientId("service-d"))!;
    expect(serviceD.clientAuth.method).toBe("private_key_jwt");
    // The Java demo (sdk-java) on :3300, enabled in the demo tenant and the isolation tenant.
    const serviceC = (await repos.applications.findByClientId("service-c"))!;
    expect(serviceC.redirectUris).toEqual(["http://localhost:3300/auth/callback"]);
    expect(serviceC.postLogoutRedirectUris).toEqual(["http://localhost:3300/"]);
    const isolation = (await repos.tenants.findBySlug("demo-isolation"))!;
    expect(
      await repos.applications.findEnabledByClientId(isolation.id, "service-c"),
    ).not.toBeNull();
    expect(await repos.applications.findEnabledByClientId(isolation.id, "service-a")).toBeNull();
    expect(await repos.loginMethods.list(isolation.id)).toEqual([]);
    const serviceA = (await repos.applications.findByClientId("service-a"))!;
    expect(serviceA.redirectUris).toEqual(["http://localhost:3100/auth/callback"]);
    expect(serviceA.representationMode).toBe("optional");

    const methods = await repos.loginMethods.list(tenantId);
    expect(methods.map((method) => `${method.protocol}:${method.kind}`).sort()).toEqual([
      "oidc:citizen",
      "oidc:citizen",
      "oidc:employee",
      "saml:citizen",
      "saml:employee",
    ]);
    const entra = methods.find((method) => method.displayName === "Mock Entra (anställda)")!;
    expect(entra.homeRealmDomains).toEqual(["kommun.example"]);
    const bankid = methods.find((method) => method.displayName === "Mock BankID (SAML)")!;
    expect(bankid).toMatchObject({ linkByPin: true, trustPinForRepresentation: true });
    expect((await repos.access.listRules(tenantId, { applicationId: serviceA.id })).length).toBe(3);
    const parties = await repos.parties.list(tenantId);
    expect(parties.map((party) => party.type).sort()).toEqual(["organisation", "person"]);
    for (const party of parties) {
      expect((await repos.grants.listForParty(tenantId, party.id)).length).toBe(1);
    }

    // The admin portal: system tenant, Erik platform admin and Anna tenant admin (pending).
    const system = (await repos.tenants.findBySlug("system"))!;
    const admin = (await repos.applications.findByClientId("portvakt-admin"))!;
    expect(admin.redirectUris).toEqual(["http://localhost:3400/t/{tenant}/auth/callback"]);
    expect(
      await repos.applications.findEnabledByClientId(system.id, "portvakt-admin"),
    ).not.toBeNull();
    expect((await repos.pending.listRoles(system.id)).map((item) => item.role)).toEqual([
      "platform-admin",
    ]);
    expect((await repos.pending.listRoles(tenantId)).map((item) => item.role)).toEqual([
      "tenant-admin",
    ]);
    expect((await repos.loginMethods.list(system.id)).map((method) => method.displayName)).toEqual([
      "Mock Entra (administratörer)",
    ]);

    // Run again (after a mock IdP restart the SAML metadata is fetched again): no changes.
    const second = await seedDev(target, options());
    expect(second.changes).toEqual([]);
    expect(second.generatedSecrets).toEqual({});
    expect(second.loginMethods).toEqual(first.loginMethods);
    expect((await repos.loginMethods.list(tenantId)).length).toBe(5);

    // A configured secret replaces the generated one; B is disabled again by the seed.
    const serviceB = attached.find((entry) => entry.application.clientId === "service-b")!;
    await repos.applications.enableForTenant(tenantId, serviceB.application.id);
    const third = await seedDev(target, options("service-a-secret-from-env-0123456789ab"));
    expect(await repos.applications.getClientSecret(serviceA.id)).toBe(
      "service-a-secret-from-env-0123456789ab",
    );
    expect(third.changes).toContain(`application service-b disabled in ${DEMO_TENANT_SLUG}`);
  });
});
