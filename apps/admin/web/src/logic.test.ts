import { describe, expect, it, vi } from "vitest";
import { ApiError, createApi } from "./api";
import {
  createBody,
  draftFieldOf,
  draftFromMethod,
  emptyDraft,
  updateBody,
  validateDraft,
  validateTenant,
  type OidcDraft,
  type SamlDraft,
} from "./forms";
import { format, MESSAGES, pickLocale } from "./i18n";
import { auditQuery } from "./pages/Audit";
import { looksLikePin } from "./pages/Persons";
import { hrefOf, parseLocation } from "./router";
import type { LoginMethod } from "./types";

/** Every leaf of a message tree, with its path. */
function leaves(value: unknown, path = ""): [string, unknown][] {
  if (value !== null && typeof value === "object") {
    return Object.entries(value).flatMap(([key, item]) =>
      leaves(item, path === "" ? key : `${path}.${key}`),
    );
  }
  return [[path, value]];
}

describe("i18n", () => {
  it("has the same non-empty messages in Swedish and English", () => {
    const sv = leaves(MESSAGES.sv);
    const en = leaves(MESSAGES.en);
    expect(en.map(([path]) => path)).toEqual(sv.map(([path]) => path));
    for (const [path, text] of [...sv, ...en]) {
      expect(typeof text, path).toBe("string");
      expect((text as string).trim().length, path).toBeGreaterThan(0);
    }
    // Placeholders match between the languages.
    const placeholders = (text: unknown) =>
      [...String(text).matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort();
    for (let index = 0; index < sv.length; index += 1) {
      expect(placeholders(en[index]![1]), sv[index]![0]).toEqual(placeholders(sv[index]![1]));
    }
  });

  it("defaults to Swedish; English only by a stored choice", () => {
    expect(pickLocale(null)).toBe("sv");
    expect(pickLocale("en")).toBe("en");
    expect(pickLocale("sv")).toBe("sv");
    expect(pickLocale("xx")).toBe("sv");
  });

  it("formats placeholders", () => {
    expect(format("{count} varningar", { count: 3 })).toBe("3 varningar");
    expect(format("{a} {b}", { a: "x" })).toBe("x {b}");
  });
});

describe("router", () => {
  it("parses and builds portal URLs", () => {
    const tenant = "8a41c2d0-5e3b-4f7a-9c18-6b2e0d4f3a91";
    const location = parseLocation(`/t/system/login-methods/${tenant}`, `?tenant=${tenant}`);
    expect(location).toEqual({ slug: "system", page: "login-methods", id: tenant, tenant });
    expect(hrefOf(location!)).toBe(`/t/system/login-methods/${tenant}?tenant=${tenant}`);
    expect(hrefOf(parseLocation("/t/demo/", "")!)).toBe("/t/demo/");
    expect(parseLocation("/t/demo/unknown", "")?.page).toBe("overview");
    expect(parseLocation("/t/Bad Slug/", "")).toBeUndefined();
    expect(parseLocation("/t/demo/persons/<script>", "?tenant=x")).toMatchObject({
      id: undefined,
      tenant: undefined,
    });
  });
});

describe("login method form", () => {
  it("validates an OIDC draft", () => {
    const draft = emptyDraft("oidc") as OidcDraft;
    expect(validateDraft(draft, true)).toMatchObject({
      displayName: "required",
      issuer: "required",
      clientId: "required",
      clientSecret: "required",
    });
    const filled: OidcDraft = {
      ...draft,
      displayName: "Entra",
      issuer: "https://login.example.org/v2.0",
      clientId: "portvakt",
      clientSecret: "s3cret",
      scopes: "profile email",
      idleMinutes: "600",
      maxAgeMinutes: "60",
      homeRealmDomains: "kommun.example, bad domain",
    };
    expect(validateDraft(filled, true)).toEqual({
      scopes: "openid",
      idleMinutes: "idle_exceeds_max",
      homeRealmDomains: "domain",
    });
    // Editing: the secret may stay empty (the stored one is kept).
    expect(
      validateDraft(
        { ...filled, scopes: "openid", idleMinutes: "30", homeRealmDomains: "", clientSecret: "" },
        false,
      ),
    ).toEqual({});
  });

  it("validates a SAML draft", () => {
    const draft = emptyDraft("saml") as SamlDraft;
    expect(validateDraft(draft, true)).toMatchObject({
      displayName: "required",
      idpEntityId: "required",
      metadataUrl: "required",
    });
    expect(
      validateDraft(
        {
          ...draft,
          displayName: "BankID",
          idpEntityId: "https://idp.example.org",
          metadataUrl: "https://idp.example.org/metadata",
          metadataSigningCertificate: "not a pem",
          logoUrl: "http://insecure.example/logo.png",
          logoWidth: "x",
          logoHeight: "40",
        },
        true,
      ),
    ).toEqual({ metadataSigningCertificate: "certificate", logoUrl: "https", logoWidth: "number" });
  });

  it("builds request bodies with the secret only when typed", () => {
    const draft: OidcDraft = {
      ...(emptyDraft("oidc") as OidcDraft),
      displayName: " Entra ",
      issuer: "https://login.example.org/v2.0",
      clientId: "portvakt",
      groupsClaim: "groups",
      maxAgeMinutes: "120",
      idleMinutes: "30",
      secretExpiresAt: "2027-01-31",
    };
    expect(createBody(draft)).toMatchObject({
      protocol: "oidc",
      displayName: "Entra",
      sessionPolicy: { maxAgeSeconds: 7200, idleSeconds: 1800, allowSso: true },
      claimMapping: { subject: "sub", name: "name", email: "email", groups: "groups" },
      secretExpiresAt: "2027-01-31T00:00:00.000Z",
    });
    expect(createBody(draft)).not.toHaveProperty("clientSecret");
    expect(updateBody({ ...draft, clientSecret: "new" })).toMatchObject({ clientSecret: "new" });
    const saml = createBody({
      ...(emptyDraft("saml") as SamlDraft),
      displayName: "BankID",
      idpEntityId: "https://idp.example.org",
      metadataUrl: "https://idp.example.org/metadata",
      allowUnsignedMetadata: true,
      requestedLoa: "http://id.elegnamnden.se/loa/1.0/loa3\n\n",
    });
    expect(saml).toMatchObject({
      protocol: "saml",
      saml: {
        metadataUrl: "https://idp.example.org/metadata",
        allowUnsignedMetadata: true,
        requestedLoa: ["http://id.elegnamnden.se/loa/1.0/loa3"],
      },
    });
  });

  it("round-trips a stored method and maps server fields to form fields", () => {
    const method = {
      id: "1",
      tenantId: "t",
      protocol: "oidc",
      kind: "employee",
      displayName: "Entra",
      assertedAcr: "urn:portvakt:acr:employee",
      homeRealmDomains: ["kommun.example"],
      secretExpiresAt: "2027-01-31T00:00:00.000Z",
      sessionPolicy: { maxAgeSeconds: 3600, idleSeconds: 600, allowSso: false },
      linkByPin: false,
      trustPinForRepresentation: false,
      enabled: true,
      oidc: {
        issuer: "https://login.example.org",
        clientId: "c",
        hasClientSecret: true,
        clientAuthMethod: "client_secret_basic",
        useUserinfo: false,
        clientAssertionAudience: "token_endpoint",
        allowedUpstreamTenants: [],
        trustUpstreamEmail: true,
        pinLoginHint: false,
        scopes: ["openid", "profile"],
        claimMapping: { subject: "oid" },
        redirectUri: "https://p/cb",
        jwksUri: "https://p/jwks",
      },
      warnings: [],
      etag: '"x"',
    } satisfies LoginMethod;
    const draft = draftFromMethod(method) as OidcDraft;
    expect(draft).toMatchObject({
      subjectClaim: "oid",
      maxAgeMinutes: "60",
      idleMinutes: "10",
      secretExpiresAt: "2027-01-31",
      clientSecret: "",
    });
    expect(updateBody(draft)).toMatchObject({
      homeRealmDomains: ["kommun.example"],
      sessionPolicy: { allowSso: false },
    });
    expect(draftFieldOf("sessionPolicy.idleSeconds")).toBe("idleMinutes");
    expect(draftFieldOf("saml.metadataUrl")).toBe("metadataUrl");
    expect(draftFieldOf("saml.uiInfo.logos.0.url")).toBe("logoUrl");
    expect(draftFieldOf("issuer")).toBe("issuer");
  });

  it("validates tenants", () => {
    expect(validateTenant("", "")).toEqual({ slug: "required", name: "required" });
    expect(validateTenant("Bad", "Kommun")).toEqual({ slug: "slug" });
    expect(validateTenant("ny-kommun", "Ny kommun")).toEqual({});
  });
});

describe("pages' helpers", () => {
  it("recognises personal identity numbers for an exact search", () => {
    expect(looksLikePin("19121212-1212")).toBe(true);
    expect(looksLikePin("121212-1212")).toBe(true);
    expect(looksLikePin("anna")).toBe(false);
  });

  it("builds audit queries with an exclusive end date", () => {
    const query = new URLSearchParams(
      auditQuery(
        {
          actionPrefix: " Login ",
          actorId: "",
          subjectId: "",
          from: "",
          to: "2026-10-19",
          scope: "tenant",
        },
        "42",
        20,
      ),
    );
    expect(query.get("actionPrefix")).toBe("login");
    expect(query.get("cursor")).toBe("42");
    expect(new Date(query.get("to")!).getDate()).toBe(20);
  });
});

describe("api client", () => {
  it("sends the CSRF token on mutations, retries a stale one once and parses problems", async () => {
    const calls: { url: string; init: RequestInit }[] = [];
    let token = "first";
    const fetcher = vi.fn((url: string, init: RequestInit = {}) => {
      calls.push({ url, init });
      if (url.endsWith("/auth/session")) {
        const body = { authenticated: true, csrfToken: token };
        token = "second";
        return new Response(JSON.stringify(body), { status: 200 });
      }
      const headers = new Headers(init.headers);
      if (headers.get("x-csrf-token") === "first") {
        return new Response(JSON.stringify({ code: "csrf_failed" }), { status: 403 });
      }
      return new Response(
        JSON.stringify({ code: "precondition_failed", errors: [{ field: "name", message: "x" }] }),
        { status: 412 },
      );
    });
    const api = createApi("demo", fetcher as unknown as typeof fetch);
    const failure = await api
      .send("PATCH", "/tenants/1", { body: { name: "a" }, etag: '"e"' })
      .catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(ApiError);
    expect((failure as ApiError).isConflict).toBe(true);
    expect((failure as ApiError).fieldErrors()).toEqual({ name: "x" });
    const patches = calls.filter((call) => call.url === "/t/demo/api/tenants/1");
    expect(patches.map((call) => new Headers(call.init.headers).get("x-csrf-token"))).toEqual([
      "first",
      "second",
    ]);
    expect(new Headers(patches[1]!.init.headers).get("if-match")).toBe('"e"');
  });
});
