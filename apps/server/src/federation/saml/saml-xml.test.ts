import { describe, expect, it } from "vitest";
import { generateSelfSignedKeyPair } from "../../crypto/x509.js";
import { decryptAssertion, DecryptionError, MAX_ENCRYPTED_KEYS } from "./decrypt.js";
import type { IdpMetadata } from "./metadata.js";
import { readResponse, ResponseRejected, validateResponse } from "./protocol.js";
import {
  checkSignature,
  LOGOUT_LIMITS,
  NS,
  parseXml,
  RESPONSE_LIMITS,
  rootOf,
  signEnveloped,
  XmlError,
} from "./xml.js";

/**
 * Unit tests of the signature and parsing rules: each case is built so that it only fails at
 * the check it names (the refusal reason is asserted), so removing that check fails the test.
 */

const idp = await generateSelfSignedKeyPair("unit idp", 3600);
const IDP = "https://idp.example.test/saml";
const SP = "https://sp.example.test/t/x/saml/1";
const ACS = `${SP}/acs`;

const metadata: IdpMetadata = {
  entityId: IDP,
  validUntil: null,
  sso: { redirect: `${IDP}/sso`, post: null },
  slo: { redirect: null, post: null },
  signingCertificates: [idp.certificate],
  scopes: [],
  principalSelection: [],
  entityCategories: [],
};

const sign = (xml: string, xpath: string, location?: "first") =>
  signEnveloped(xml, xpath, idp.privateKey, idp.certificate, { afterIssuer: location !== "first" });

const reasonOf = async (promise: Promise<unknown>): Promise<string> => {
  const error = await promise.catch((caught: unknown) => caught);
  if (error instanceof XmlError || error instanceof ResponseRejected) return error.reason;
  if (error instanceof DecryptionError) return error.reason;
  return `unexpected: ${String(error)}`;
};

describe("bounded parsing (F1)", () => {
  it("refuses a flood of empty elements and deep nesting quickly", async () => {
    const flood = `<a>${"<b/>".repeat(120_000)}</a>`;
    let started = performance.now();
    expect(await reasonOf(parseXml(flood))).toBe("too_many_elements");
    expect(performance.now() - started).toBeLessThan(1000);
    const deep = `${"<a>".repeat(5000)}${"</a>".repeat(5000)}`;
    started = performance.now();
    expect(await reasonOf(parseXml(deep))).toBe("too_deep");
    expect(performance.now() - started).toBeLessThan(1000);
    expect(await reasonOf(parseXml(`<a>${"x".repeat(70 * 1024)}</a>`, LOGOUT_LIMITS))).toBe(
      "too_large",
    );
  });

  it("answers the ~900k-character, ~170k-element SAML message in well under a second", async () => {
    const bomb = `<samlp:Response xmlns:samlp="${NS.samlp}" ID="_r">${"<x/>".repeat(170_000)}</samlp:Response>`;
    const started = performance.now();
    expect(await reasonOf(readResponse(Buffer.from(bomb).toString("base64"), metadata))).toBe(
      "too_large",
    );
    // Within the size cap (the element cap is what stops it).
    const dense = `<samlp:Response xmlns:samlp="${NS.samlp}" ID="_r">${"<x/>".repeat(RESPONSE_LIMITS.maxElements + 1)}</samlp:Response>`;
    expect(await reasonOf(readResponse(Buffer.from(dense).toString("base64"), metadata))).toBe(
      "too_many_elements",
    );
    expect(performance.now() - started).toBeLessThan(1000);
  });
});

describe("checkSignature (F4)", () => {
  const doc = (inner = "") =>
    `<root><a ID="_a"><Issuer>i</Issuer><v>signed</v></a><b ID="_b"><Issuer>i</Issuer><v>other</v></b>${inner}</root>`;
  const signA = () => sign(doc(), "//*[@ID='_a']");
  const element = async (xml: string, id: string) => {
    const root = rootOf(await parseXml(xml));
    const found = [...Array(root.childNodes.length).keys()]
      .map((index) => root.childNodes[index])
      .find((node) => node?.nodeType === 1 && (node as Element).getAttribute("ID") === id);
    return found as Element;
  };

  it("accepts a valid enveloped signature and returns only the signed bytes", async () => {
    // Content inside the Signature (a ds:Object) is not covered by the digest: it must not be
    // part of what is returned.
    const xml = signA().replace(
      "</SignatureValue>",
      "</SignatureValue><Object><v>injected</v></Object>",
    );
    const result = checkSignature(xml, await element(xml, "_a"), [idp.certificate]);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.signed).toContain("<v>signed</v>");
    expect(result.signed).not.toContain("injected");
    expect((await element(xml, "_a")).toString()).toContain("injected");
  });

  it("refuses a signature that references a sibling element", async () => {
    // b is signed, but its signature sits in a: valid crypto, wrong element.
    const xml = signEnveloped(doc(), "//*[@ID='_b']", idp.privateKey, idp.certificate, {});
    const moved = xml.replace(/<b ID="_b">(<Signature[\s\S]*<\/Signature>)/, '<b ID="_b">');
    const signature = /<Signature[\s\S]*<\/Signature>/.exec(xml)![0];
    const placed = moved.replace('<a ID="_a">', `<a ID="_a">${signature}`);
    expect(checkSignature(placed, await element(placed, "_a"), [idp.certificate])).toEqual({
      ok: false,
      reason: "reference_mismatch",
    });
  });

  it("refuses an ID that another element also carries (Id, id or a namespaced ID)", async () => {
    for (const copy of ['<c Id="_a"/>', '<c id="_a"/>', '<c xmlns:x="urn:x" x:ID="_a"/>']) {
      const xml = signA().replace("</root>", `${copy}</root>`);
      expect(checkSignature(xml, await element(xml, "_a"), [idp.certificate]), copy).toEqual({
        ok: false,
        reason: "duplicate_id",
      });
    }
  });

  it("refuses two Signature elements", async () => {
    const xml = signA();
    const signature = /<Signature[\s\S]*<\/Signature>/.exec(xml)![0];
    const twice = xml.replace(
      signature,
      signature + signature.replace(/<SignatureValue>[^<]+/, "<SignatureValue>AAAA"),
    );
    expect(checkSignature(twice, await element(twice, "_a"), [idp.certificate])).toEqual({
      ok: false,
      reason: "signature_count",
    });
  });

  it("refuses a signature by another key and SHA-1", async () => {
    const other = await generateSelfSignedKeyPair("other", 3600);
    const xml = signA();
    expect(checkSignature(xml, await element(xml, "_a"), [other.certificate])).toEqual({
      ok: false,
      reason: "invalid",
    });
  });
});

describe("validateResponse reads only the signed assertion (F4)", () => {
  const now = Date.now();
  const iso = (ms: number) => new Date(ms).toISOString();
  const assertion = (id: string, pin: string) =>
    `<saml:Assertion xmlns:saml="${NS.saml}" ID="${id}" IssueInstant="${iso(now)}" Version="2.0"><saml:Issuer>${IDP}</saml:Issuer><saml:Subject><saml:NameID>n</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="_req" NotOnOrAfter="${iso(now + 300_000)}" Recipient="${ACS}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="${iso(now - 1000)}" NotOnOrAfter="${iso(now + 300_000)}"><saml:AudienceRestriction><saml:Audience>${SP}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="${iso(now)}"><saml:AuthnContext><saml:AuthnContextClassRef>http://id.elegnamnden.se/loa/1.0/loa3</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name="urn:oid:1.2.752.29.4.13"><saml:AttributeValue>${pin}</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion>`;
  const response = (inner: string) =>
    `<samlp:Response xmlns:samlp="${NS.samlp}" xmlns:saml="${NS.saml}" ID="_resp" Version="2.0" IssueInstant="${iso(now)}" InResponseTo="_req"><saml:Issuer>${IDP}</saml:Issuer>${inner}<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status></samlp:Response>`;
  const signedAssertion = sign(assertion("_good", "191212121212"), "/*[local-name(.)='Assertion']");
  const run = async (xml: string) =>
    validateResponse(
      { entityId: SP, acsUrl: ACS, sloUrl: `${SP}/slo` },
      metadata,
      await readResponse(Buffer.from(xml).toString("base64"), metadata),
      {
        requireSignedResponse: false,
        decryptionKeys: [],
        requireGcm: false,
        clockSkewSeconds: 60,
        now,
      },
    );

  it("ignores a modified copy elsewhere in the document", async () => {
    const copy = `<samlp:Extensions>${assertion("_copy", "200001010008")}</samlp:Extensions>`;
    const result = await run(response(`${copy}${signedAssertion}`));
    expect(result.attributes["urn:oid:1.2.752.29.4.13"]).toEqual(["191212121212"]);
    expect(result.id).toBe("_good");
  });

  it("refuses a copy that reuses the signed assertion's ID", async () => {
    const copy = `<samlp:Extensions>${assertion("_good", "200001010008")}</samlp:Extensions>`;
    expect(await reasonOf(run(response(`${copy}${signedAssertion}`)))).toBe("signature_invalid");
  });

  it("refuses an unsigned assertion", async () => {
    expect(await reasonOf(run(response(assertion("_u", "191212121212"))))).toBe(
      "signature_invalid",
    );
  });
});

describe("decryption bounds (F2)", () => {
  it("refuses more than four EncryptedKey candidates before any RSA operation", async () => {
    const key = `<xenc:EncryptedKey xmlns:xenc="${NS.xenc}"><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/><xenc:CipherData><xenc:CipherValue>AAAA</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey>`;
    const encrypted = (count: number) =>
      `<saml:EncryptedAssertion xmlns:saml="${NS.saml}"><xenc:EncryptedData xmlns:xenc="${NS.xenc}"><xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm"/><xenc:CipherData><xenc:CipherValue>AAAA</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>${key.repeat(count)}</saml:EncryptedAssertion>`;
    const decrypt = async (count: number) =>
      decryptAssertion(rootOf(await parseXml(encrypted(count))), [idp.privateKey], {
        requireGcm: false,
        limits: RESPONSE_LIMITS,
      });
    expect(await reasonOf(decrypt(MAX_ENCRYPTED_KEYS + 1))).toBe("too_many_keys");
    expect(await reasonOf(decrypt(MAX_ENCRYPTED_KEYS))).toBe("decryption_failed");
  });
});
