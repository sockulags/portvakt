import { describe, expect, it, vi } from "vitest";
import { createTenant, uniqueSuffix } from "../testing/fixtures.js";
import { startTestServer } from "../testing/test-server.js";

const ts = await startTestServer();

describe.skipIf(ts === undefined)("discovery and JWKS per tenant", () => {
  const { db, portvakt, baseUrl } = ts!;
  const { repos } = db;

  async function getJson(path: string): Promise<{ status: number; body: Record<string, unknown> }> {
    const response = await fetch(`${baseUrl}${path}`);
    return { status: response.status, body: (await response.json()) as Record<string, unknown> };
  }

  it("remembers a slug no tenant has briefly, and finds a tenant created with it at once", async () => {
    const slug = `ghost-${uniqueSuffix()}`;
    const lookups = vi.spyOn(portvakt.repos.tenants, "findActiveBySlug");
    try {
      const path = `/t/${slug}/.well-known/openid-configuration`;
      for (let i = 0; i < 5; i += 1) expect((await getJson(path)).status).toBe(404);
      for (let i = 0; i < 3; i += 1) {
        expect((await fetch(`${baseUrl}/t/${slug}/jwks`)).status).toBe(404);
      }
      // One database lookup for all eight requests.
      expect(lookups.mock.calls.filter(([value]) => value === slug)).toHaveLength(1);
      // Creating the tenant invalidates the negative cache (change event).
      await repos.tenants.create({ slug, name: "Ghost" });
      await expect.poll(async () => (await getJson(path)).status).toBe(200);
    } finally {
      lookups.mockRestore();
    }
  });

  it("does not remember a suspended tenant as unknown: reactivating it works at once", async () => {
    const tenant = await createTenant(repos, "napping");
    await repos.tenants.update(tenant.id, { status: "suspended" });
    const path = `/t/${tenant.slug}/.well-known/openid-configuration`;
    await expect.poll(async () => (await getJson(path)).status).toBe(404);
    await repos.tenants.update(tenant.id, { status: "active" });
    await expect.poll(async () => (await getJson(path)).status).toBe(200);
  });

  it("publishes one issuer per tenant, each with its own endpoints", async () => {
    const a = await createTenant(repos, "acme");
    const b = await createTenant(repos, "beta");
    const discoveryA = await getJson(`/t/${a.slug}/.well-known/openid-configuration`);
    const discoveryB = await getJson(`/t/${b.slug}/.well-known/openid-configuration`);
    expect(discoveryA.status).toBe(200);
    expect(discoveryA.body.issuer).toBe(`${baseUrl}/t/${a.slug}`);
    expect(discoveryB.body.issuer).toBe(`${baseUrl}/t/${b.slug}`);
    expect(discoveryA.body.issuer).not.toBe(discoveryB.body.issuer);
    expect(discoveryA.body).toMatchObject({
      authorization_endpoint: `${baseUrl}/t/${a.slug}/auth`,
      token_endpoint: `${baseUrl}/t/${a.slug}/token`,
      jwks_uri: `${baseUrl}/t/${a.slug}/jwks`,
      end_session_endpoint: `${baseUrl}/t/${a.slug}/session/end`,
      revocation_endpoint: `${baseUrl}/t/${a.slug}/token/revocation`,
      introspection_endpoint: `${baseUrl}/t/${a.slug}/token/introspection`,
      response_types_supported: ["code"],
      grant_types_supported: expect.arrayContaining([
        "authorization_code",
        "refresh_token",
        "client_credentials",
      ]) as unknown,
      code_challenge_methods_supported: ["S256"],
      id_token_signing_alg_values_supported: ["ES256"],
      token_endpoint_auth_methods_supported: [
        "client_secret_basic",
        "client_secret_post",
        "private_key_jwt",
      ],
      claims_parameter_supported: false,
    });
    expect(discoveryA.body).not.toHaveProperty("userinfo_endpoint");
    expect(discoveryA.body).not.toHaveProperty("request_object_signing_alg_values_supported");
    expect(discoveryA.body.claims_supported).toEqual(
      expect.arrayContaining(["sub", "tid", "roles", "attrs", "name", "email"]),
    );
  });

  it("serves the endpoints right for a slug that starts with a route name", async () => {
    const tenant = await repos.tenants.create({ slug: `authority-${uniqueSuffix()}`, name: "A" });
    const discovery = await getJson(`/t/${tenant.slug}/.well-known/openid-configuration`);
    expect(discovery.body.authorization_endpoint).toBe(`${baseUrl}/t/${tenant.slug}/auth`);
    expect(discovery.body.token_endpoint).toBe(`${baseUrl}/t/${tenant.slug}/token`);
    expect((await getJson(`/t/${tenant.slug}/jwks`)).status).toBe(200);
  });

  it("publishes the next, active and retiring public keys, never a private part", async () => {
    const tenant = await createTenant(repos, "keys");
    const jwks = await getJson(`/t/${tenant.slug}/jwks`);
    const keys = jwks.body.keys as Record<string, unknown>[];
    const loaded = portvakt.keyCache.current!;
    expect(keys.map((key) => key.kid)).toEqual(loaded.kids.map((key) => key.kid));
    for (const key of keys) {
      expect(key).toMatchObject({ kty: "EC", crv: "P-256", alg: "ES256", use: "sig" });
      expect(key).not.toHaveProperty("d");
    }
  });

  it("answers 404 for an unknown or suspended tenant without building a provider", async () => {
    expect(
      (await fetch(`${baseUrl}/t/no-such-tenant/.well-known/openid-configuration`)).status,
    ).toBe(404);
    expect((await fetch(`${baseUrl}/t/NOT_A_SLUG/jwks`)).status).toBe(404);
    const suspended = await repos.tenants.create({
      slug: `suspended-${uniqueSuffix()}`,
      name: "Suspended",
      status: "suspended",
    });
    expect((await fetch(`${baseUrl}/t/${suspended.slug}/jwks`)).status).toBe(404);
    for (const slug of ["no-such-tenant", "NOT_A_SLUG", suspended.slug]) {
      expect(portvakt.registry.peek(slug)).toBeUndefined();
    }
  });

  it("stops serving a tenant once it is suspended", async () => {
    const tenant = await createTenant(repos, "soon-suspended");
    expect((await fetch(`${baseUrl}/t/${tenant.slug}/jwks`)).status).toBe(200);
    await repos.tenants.update(tenant.id, { status: "suspended" });
    await expect
      .poll(async () => (await fetch(`${baseUrl}/t/${tenant.slug}/jwks`)).status)
      .toBe(404);
  });
});
