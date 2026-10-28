import { describe, expect, it } from "vitest";
import { createKeyRing } from "../../crypto/keyring.js";
import { certificateInfo, generateSelfSignedKeyPair, pemBody } from "../../crypto/x509.js";
import { SAML_ATTRIBUTES, samlAttributeMappingSchema } from "../../domain/saml.js";
import { mapSamlAttributes, NAMEID_FORMATS } from "./attributes.js";
import { MetadataError, parseIdpMetadata, restrictToHttps } from "./metadata.js";
import {
  nameIdIndexCandidates,
  sealUpstreamSession,
  sessionIndexCandidates,
  unsealUpstreamSession,
} from "./upstream-session.js";
import { signEnveloped } from "./xml.js";

const pair = await generateSelfSignedKeyPair("unit test", 3600);

const IDP = "https://idp.example.test/saml";

function entity(entityId: string, extra = ""): string {
  return `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="${entityId}" ID="_${entityId.length}x"${extra}>
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:Extensions><shibmd:Scope xmlns:shibmd="urn:mace:shibboleth:metadata:1.0" regexp="false">5562265719</shibmd:Scope></md:Extensions>
    <md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>${pemBody(pair.certificate)}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
    <md:KeyDescriptor use="encryption"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>${pemBody(pair.certificate)}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="${entityId}/slo"/>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="${entityId}/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>`;
}

const options = (overrides: Partial<Parameters<typeof parseIdpMetadata>[1]> = {}) => ({
  entityId: IDP,
  signingCertificate: null,
  now: new Date(),
  ...overrides,
});

const reasonOf = async (promise: Promise<unknown>): Promise<string | undefined> => {
  const error = await promise.catch((caught: unknown) => caught);
  return error instanceof MetadataError ? error.reason : undefined;
};

describe("IdP metadata", () => {
  it("reads endpoints, signing certificates and scopes of an entity", async () => {
    const metadata = await parseIdpMetadata(entity(IDP), options());
    expect(metadata).toMatchObject({
      entityId: IDP,
      sso: { redirect: `${IDP}/sso`, post: null },
      slo: { redirect: { location: `${IDP}/slo`, responseLocation: `${IDP}/slo` }, post: null },
      scopes: ["5562265719"],
    });
    // Only the signing KeyDescriptor counts as a signing certificate.
    expect(metadata.signingCertificates).toHaveLength(1);
  });

  it("finds the entity in a federation aggregate and honours every validUntil", async () => {
    const aggregate = `<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" validUntil="2999-01-01T00:00:00Z">${entity("https://other.example/idp")}${entity(IDP, ' validUntil="2998-01-01T00:00:00Z"')}</md:EntitiesDescriptor>`;
    const metadata = await parseIdpMetadata(aggregate, options());
    expect(metadata.validUntil).toBe(Date.parse("2998-01-01T00:00:00Z"));
    expect(
      await reasonOf(parseIdpMetadata(aggregate, options({ now: new Date("2998-06-01") }))),
    ).toBe("expired");
    expect(
      await reasonOf(parseIdpMetadata(aggregate, options({ entityId: "https://x.example" }))),
    ).toBe("entity_not_found");
    const twice = `<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">${entity(IDP)}${entity(IDP)}</md:EntitiesDescriptor>`;
    expect(await reasonOf(parseIdpMetadata(twice, options()))).toBe("duplicate_entity");
  });

  it("refuses DTDs, non-metadata and unsigned or wrongly signed metadata when a certificate is set", async () => {
    expect(
      await reasonOf(parseIdpMetadata(`<!DOCTYPE x [<!ENTITY a "b">]>${entity(IDP)}`, options())),
    ).toBe("dtd_not_allowed");
    expect(await reasonOf(parseIdpMetadata("<html/>", options()))).toBe("not_metadata");
    expect(await reasonOf(parseIdpMetadata("not xml <", options()))).toBe("malformed");
    const withCert = options({ signingCertificate: pair.certificate });
    expect(await reasonOf(parseIdpMetadata(entity(IDP), withCert))).toBe("signature_invalid");
    const signed = signEnveloped(
      entity(IDP),
      "/*[local-name(.)='EntityDescriptor']",
      pair.privateKey,
      pair.certificate,
    );
    expect((await parseIdpMetadata(signed, withCert)).entityId).toBe(IDP);
    const tampered = signed.replace(`${IDP}/sso`, "https://evil.example/sso");
    expect(await reasonOf(parseIdpMetadata(tampered, withCert))).toBe("signature_invalid");
  });

  it("requires an SSO endpoint and a signing certificate", async () => {
    const noSso = entity(IDP).replace(/<md:SingleSignOnService[^>]*\/>/, "");
    expect(await reasonOf(parseIdpMetadata(noSso, options()))).toBe("no_sso_endpoint");
    const noKeys = entity(IDP).replace(
      /<md:KeyDescriptor use="signing">[\s\S]*?<\/md:KeyDescriptor>/,
      "",
    );
    expect(await reasonOf(parseIdpMetadata(noKeys, options()))).toBe("no_signing_certificate");
  });

  it("keeps only https endpoints when https is required (production)", async () => {
    const httpIdp = "http://idp.example.test/saml";
    const httpOnly = entity(IDP).replaceAll(`${IDP}/`, `${httpIdp}/`);
    // Outside production plain http endpoints are used (local mocks).
    expect((await parseIdpMetadata(httpOnly, options())).sso.redirect).toBe(`${httpIdp}/sso`);
    expect(await reasonOf(parseIdpMetadata(httpOnly, options({ requireHttps: true })))).toBe(
      "insecure_endpoint",
    );

    // An https SSO endpoint with an http SLO endpoint: the SLO endpoint counts as absent.
    const mixed = entity(IDP).replace(`${IDP}/slo`, `${httpIdp}/slo`);
    const secure = await parseIdpMetadata(mixed, options({ requireHttps: true }));
    expect(secure.sso.redirect).toBe(`${IDP}/sso`);
    expect(secure.slo).toEqual({ redirect: null, post: null });
    expect(
      (await parseIdpMetadata(entity(IDP), options({ requireHttps: true }))).slo.redirect,
    ).not.toBeNull();
  });

  it("restricts cached metadata to https endpoints", async () => {
    const metadata = await parseIdpMetadata(entity(IDP), options());
    const httpPost = {
      ...metadata,
      sso: { redirect: metadata.sso.redirect, post: "http://x.example/sso" },
    };
    expect(restrictToHttps(httpPost)?.sso).toEqual({ redirect: `${IDP}/sso`, post: null });
    const onlyHttp = { ...metadata, sso: { redirect: "http://x.example/sso", post: null } };
    expect(restrictToHttps(onlyHttp)).toBeNull();
    const httpResponse = {
      ...metadata,
      slo: {
        redirect: { location: `${IDP}/slo`, responseLocation: "http://x.example/slo" },
        post: null,
      },
    };
    expect(restrictToHttps(httpResponse)?.slo.redirect).toBeNull();
  });
});

describe("SAML attribute mapping", () => {
  const settings = (overrides: Partial<Parameters<typeof mapSamlAttributes>[0]> = {}) => ({
    attributeMapping: samlAttributeMappingSchema.parse({}),
    subjectSource: "personalIdentityNumber" as const,
    trustEmail: false,
    ...overrides,
  });
  const subject = (
    attributes: Record<string, string[]>,
    nameIdFormat: string = NAMEID_FORMATS.persistent,
  ) => ({
    nameId: "pseudonym-1",
    nameIdFormat,
    attributes,
    loa: "http://id.elegnamnden.se/loa/1.0/loa3",
  });

  it("maps the framework attributes and canonicalises the personal identity number", () => {
    const result = mapSamlAttributes(
      settings(),
      subject({
        [SAML_ATTRIBUTES.personalIdentityNumber]: ["191212121212"],
        [SAML_ATTRIBUTES.givenName]: ["Sven"],
        [SAML_ATTRIBUTES.sn]: ["Medborgare"],
      }),
      [],
    );
    if (typeof result === "string") throw new Error(result);
    expect(result.subjectFromPin).toBe(true);
    expect(result.mapped.pin).toBe("191212121212");
    // No displayName: givenName and sn joined.
    expect(result.mapped.attributes).toMatchObject({
      name: "Sven Medborgare",
      protectedIdentity: false,
    });
    expect(result.mapped.attributes.upstreamAcr).toBe("http://id.elegnamnden.se/loa/1.0/loa3");
  });

  it("refuses invalid, missing and ambiguous identifiers and transient NameIDs as subjects", () => {
    expect(
      mapSamlAttributes(
        settings(),
        subject({ [SAML_ATTRIBUTES.personalIdentityNumber]: ["191212121213"] }),
        [],
      ),
    ).toBe("invalid_pin");
    expect(mapSamlAttributes(settings(), subject({}), [])).toBe("missing_subject");
    expect(
      mapSamlAttributes(
        settings({ subjectSource: "employeeHsaId" }),
        subject({ [SAML_ATTRIBUTES.employeeHsaId]: ["SE1", "SE2"] }),
        [],
      ),
    ).toBe("ambiguous_attribute");
    expect(
      mapSamlAttributes(
        settings({ subjectSource: "nameId" }),
        subject({}, NAMEID_FORMATS.transient),
        [],
      ),
    ).toBe("transient_nameid");
    const byNameId = mapSamlAttributes(settings({ subjectSource: "nameId" }), subject({}), []);
    expect(typeof byNameId === "string" ? byNameId : byNameId.mapped.subject).toBe("pseudonym-1");
  });

  it("accepts orgAffiliation only within the IdP's scopes and flags protected identity by configuration", () => {
    const result = mapSamlAttributes(
      settings({
        subjectSource: "employeeHsaId",
        attributeMapping: samlAttributeMappingSchema.parse({
          protectedIdentity: { attribute: "urn:x:protected", values: ["1", "true"] },
        }),
      }),
      subject({
        [SAML_ATTRIBUTES.employeeHsaId]: ["SE2321000016-1003"],
        [SAML_ATTRIBUTES.orgAffiliation]: ["a@5562265719", "b@1111111111", "no-scope"],
        "urn:x:protected": ["1"],
      }),
      ["5562265719"],
    );
    if (typeof result === "string") throw new Error(result);
    expect(result.mapped.attributes.groups).toEqual(["a@5562265719"]);
    expect(result.droppedAffiliations).toBe(2);
    expect(result.mapped.attributes.protectedIdentity).toBe(true);
  });
});

describe("SP certificates", () => {
  it("generates RSA 3072 key pairs with self-signed certificates", () => {
    const info = certificateInfo(pair.certificate);
    expect(info.keyType).toBe("rsa");
    expect(info.notAfter.getTime()).toBeGreaterThan(Date.now());
    expect(pair.privateKey).toContain("BEGIN PRIVATE KEY");
  });
});

describe("upstream SAML sessions", () => {
  const keys = createKeyRing({ current: Buffer.alloc(32, 7), previous: [] });
  const methodId = "7d0b5a52-6a43-4f4e-9b8a-0f1d2c3b4a59";

  it("seals a session whose optional values are empty attributes as if they were absent", () => {
    // IdPs may send NameQualifier="" or SessionIndex="": the login must not fail on it.
    const session = sealUpstreamSession(keys, methodId, {
      nameId: "pseudonym-1",
      nameIdFormat: "",
      nameQualifier: "",
      spNameQualifier: "",
      sessionIndex: "",
    });
    expect(session.sessionIndexIndex).toBeUndefined();
    expect(session.nameIdIndex).toBe(nameIdIndexCandidates(keys, methodId, "pseudonym-1")[0]);
    expect(unsealUpstreamSession(keys, methodId, session)).toEqual({
      nameId: "pseudonym-1",
      nameIdFormat: undefined,
      nameQualifier: undefined,
      spNameQualifier: undefined,
      sessionIndex: undefined,
    });
  });

  it("keeps the values that are present, sealed to the login method", () => {
    const session = sealUpstreamSession(keys, methodId, {
      nameId: "pseudonym-2",
      nameIdFormat: NAMEID_FORMATS.persistent,
      nameQualifier: IDP,
      spNameQualifier: undefined,
      sessionIndex: "s-1",
    });
    expect(session.sealed).not.toContain("pseudonym-2");
    expect(session.sessionIndexIndex).toBe(sessionIndexCandidates(keys, methodId, "s-1")[0]);
    expect(unsealUpstreamSession(keys, methodId, session)).toMatchObject({
      nameId: "pseudonym-2",
      nameQualifier: IDP,
      sessionIndex: "s-1",
    });
    expect(() =>
      unsealUpstreamSession(keys, "8d0b5a52-6a43-4f4e-9b8a-0f1d2c3b4a59", session),
    ).toThrow();
  });
});
