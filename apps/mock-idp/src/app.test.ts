import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createMockIdp } from "./app.js";
import { DEV_CLIENTS, parseClients } from "./clients.js";
import { acrFor } from "./issuer.js";
import { MemoryStore } from "./memory-adapter.js";
import { renderLoginPage } from "./page.js";
import {
  DEFAULT_PERSONAS_PATH,
  LOA_RANKING,
  loadPersonas,
  luhnValid,
  personasSchema,
} from "./personas.js";

const [loa2, loa3, loa4] = LOA_RANKING;
const idp = await createMockIdp({ publicUrl: "http://idp.test", clients: DEV_CLIENTS });

describe("mock IdP", () => {
  it("refuses to start with NODE_ENV=production", async () => {
    vi.stubEnv("NODE_ENV", "production");
    try {
      await expect(createMockIdp({ publicUrl: "http://idp.test" })).rejects.toThrow(/production/);
    } finally {
      vi.unstubAllEnvs();
    }
  });

  it("reports health", async () => {
    const res = await request(idp.app).get("/healthz");
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ status: "ok" });
  });

  it("publishes two issuers with their own metadata and keys", async () => {
    const entra = await request(idp.app).get("/entra/.well-known/openid-configuration");
    const bankid = await request(idp.app).get("/bankid/.well-known/openid-configuration");
    expect(entra.body).toMatchObject({
      issuer: "http://idp.test/entra",
      code_challenge_methods_supported: ["S256"],
    });
    expect(
      (entra.body as { token_endpoint_auth_methods_supported: string[] })
        .token_endpoint_auth_methods_supported,
    ).toEqual(
      expect.arrayContaining(["client_secret_basic", "client_secret_post", "private_key_jwt"]),
    );
    expect(bankid.body).toMatchObject({
      issuer: "http://idp.test/bankid",
      acr_values_supported: [...LOA_RANKING],
    });
    const jwks = (await request(idp.app).get("/bankid/jwks")).body as { keys: object[] };
    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0]).toMatchObject({ kty: "EC", alg: "ES256" });
    expect(jwks.keys[0]).not.toHaveProperty("d");
  });

  it("serves a multi-tenant issuer whose discovery reports a {tenantid} template", async () => {
    expect(idp.issuer("entra-mt")).toBe("http://idp.test/entra-mt/organizations/v2.0");
    const alias = await request(idp.app)
      .get("/entra-mt/organizations/v2.0/.well-known/openid-configuration")
      .set("Host", "idp.test");
    const body = alias.body as { issuer: string; token_endpoint: string };
    expect(body.issuer).toBe("http://idp.test/entra-mt/{tenantid}/v2.0");
    expect(body.token_endpoint).toBe("http://idp.test/entra-mt/organizations/v2.0/token");
  });

  it("revokes only grant-bound models with a grant", async () => {
    const store = new MemoryStore();
    await store.adapterFor("AccessToken").upsert("at", { grantId: "g1" }, 60);
    await store.adapterFor("Interaction").upsert("i1", { grantId: "g1" }, 60);
    await store.adapterFor("AccessToken").revokeByGrantId("g1");
    expect(await store.adapterFor("AccessToken").find("at")).toBeUndefined();
    expect(await store.adapterFor("Interaction").find("i1")).toEqual({ grantId: "g1" });
  });

  it("ships default personas covering the test scenarios, all with Luhn-valid numbers", () => {
    const personas = loadPersonas(DEFAULT_PERSONAS_PATH);
    expect(personas.entra.length).toBeGreaterThanOrEqual(2);
    expect(new Set(personas.entra.map((p) => p.groups.join(","))).size).toBeGreaterThan(1);
    expect(personas.bankid.length).toBeGreaterThanOrEqual(3);
    expect(personas.bankid.some((p) => Number(p.pin.slice(6, 8)) > 60)).toBe(true);
    expect(personas.bankid.some((p) => p.protectedIdentity)).toBe(true);
    for (const citizen of personas.bankid) expect(luhnValid(citizen.pin.slice(2))).toBe(true);
  });

  it("refuses personas with a wrong check digit or duplicate ids", () => {
    const valid = loadPersonas(DEFAULT_PERSONAS_PATH);
    const broken = structuredClone(valid);
    broken.bankid[0]!.pin = "191212121213";
    expect(personasSchema.safeParse(broken).success).toBe(false);
    const duplicate = structuredClone(valid);
    duplicate.bankid[0]!.id = duplicate.entra[0]!.id;
    expect(personasSchema.safeParse(duplicate).success).toBe(false);
  });

  it("honours a persona's highest acr and refuses levels it cannot reach", () => {
    expect(acrFor({ maxAcr: loa3 }, [])).toBe(loa3);
    expect(acrFor({ maxAcr: loa4 }, [loa3])).toBe(loa3);
    expect(acrFor({ maxAcr: loa2 }, [loa3, loa4])).toBeNull();
    expect(acrFor({ maxAcr: undefined }, [])).toBeUndefined();
    expect(acrFor({ maxAcr: undefined }, [loa2])).toBeUndefined();
  });

  it("renders persona buttons with stable test ids and escapes values", () => {
    const html = renderLoginPage({
      kind: "bankid",
      action: "/bankid/interaction/abc",
      personas: [{ id: "sven", label: "Sven <b>", detail: "loa3" }],
    });
    expect(html).toContain('data-testid="persona-sven"');
    expect(html).toContain('data-testid="cancel"');
    expect(html).toContain("Sven &lt;b&gt;");
  });

  it("publishes signed SAML IdP metadata per flavour, with the SITHS organisation's scope", async () => {
    for (const flavour of ["bankid", "freja", "siths"] as const) {
      const res = await request(idp.app).get(`/saml/${flavour}/metadata`);
      expect(res.status).toBe(200);
      expect(res.text).toContain(`entityID="http://idp.test/saml/${flavour}"`);
      expect(res.text).toContain("SignatureValue>");
      expect(res.text).toContain("SingleSignOnService");
    }
    const siths = await request(idp.app).get("/saml/siths/metadata");
    expect(siths.text).toContain(">2321000016</shibmd:Scope>");
    expect(idp.saml("siths").personas.map((persona) => persona.id)).toContain("siths-sara");
  });

  it("renders SAML test switches with stable test ids", () => {
    const html = renderLoginPage({
      title: "Mock BankID (SAML)",
      action: "/saml/bankid/sso/abc",
      personas: [{ id: "saml-sven", label: "Sven", detail: "loa3" }],
      switches: ["cancel", "expired"],
    });
    expect(html).toContain('data-testid="switch"');
    expect(html).toContain('data-testid="switch-expired"');
    expect(html).toContain('data-testid="persona-saml-sven"');
  });

  it("refuses an unsigned AuthnRequest", async () => {
    const res = await request(idp.app).get("/saml/bankid/sso").query({ SAMLRequest: "AAAA" });
    expect(res.status).toBe(400);
  });

  it("parses clients from inline JSON and validates them", () => {
    expect(
      parseClients(
        JSON.stringify([
          {
            issuer: "entra",
            client_id: "c",
            client_secret: "s",
            redirect_uris: ["http://localhost:3000/t/x/federation/y/callback"],
          },
        ]),
      )[0],
    ).toMatchObject({ client_id: "c", token_endpoint_auth_method: "client_secret_basic" });
    expect(() => parseClients('[{"issuer":"entra","client_id":"c","redirect_uris":[]}]')).toThrow();
    expect(parseClients(undefined)).toHaveLength(2);
  });
});
