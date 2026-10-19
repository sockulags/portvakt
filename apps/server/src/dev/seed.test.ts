import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { startTestIdp } from "../testing/federation.js";
import { startTestServer } from "../testing/test-server.js";
import { DEMO_TENANT_SLUG, seedDev, type DevSeedOptions } from "./seed.js";

const ts = await startTestServer();
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
    ],
    entraClient: { clientId: "portvakt-dev", secret: "dev-only-entra-client-secret" },
    bankidClient: { clientId: "portvakt-dev", secret: "dev-only-bankid-client-secret" },
  });

  it("creates the demo tenant and converges on the same state when run again", async () => {
    const { repos } = ts!.db;
    const target = { repos, samlAdmin: ts!.portvakt.samlAdmin };
    const first = await seedDev(target, options());
    expect(first.tenant.slug).toBe(DEMO_TENANT_SLUG);
    expect(Object.keys(first.generatedSecrets).sort()).toEqual(["service-a", "service-b"]);
    const tenantId = first.tenant.id;

    expect(await repos.applications.findEnabledByClientId(tenantId, "service-a")).not.toBeNull();
    // Service B is attached but disabled: its sign-ins are refused until it is enabled.
    expect(await repos.applications.findEnabledByClientId(tenantId, "service-b")).toBeNull();
    const attached = await repos.applications.listForTenant(tenantId);
    expect(attached.map((entry) => [entry.application.clientId, entry.enabled]).sort()).toEqual([
      ["service-a", true],
      ["service-b", false],
    ]);
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

    // Run again (after a mock IdP restart the SAML metadata is fetched again): no changes.
    const second = await seedDev(target, options());
    expect(second.changes).toEqual([]);
    expect(second.generatedSecrets).toEqual({});
    expect(second.loginMethods).toEqual(first.loginMethods);
    expect((await repos.loginMethods.list(tenantId)).length).toBe(5);

    // A configured secret replaces the generated one; B is disabled again by the seed.
    await repos.applications.enableForTenant(tenantId, attached[1]!.application.id);
    const third = await seedDev(target, options("service-a-secret-from-env-0123456789ab"));
    expect(await repos.applications.getClientSecret(serviceA.id)).toBe(
      "service-a-secret-from-env-0123456789ab",
    );
    expect(third.changes).toContain(`application service-b disabled in ${DEMO_TENANT_SLUG}`);
  });
});
