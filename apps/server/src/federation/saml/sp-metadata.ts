import { ENTITY_CATEGORY_ATTRIBUTE, type SamlSettings } from "../../domain/saml.js";
import { pemBody } from "../../crypto/x509.js";
import type { SpKey } from "../../repositories/saml.js";
import { NAMEID_FORMATS } from "./attributes.js";
import type { SpEndpoints, SpSigner } from "./protocol.js";
import { DIGEST_ALGORITHMS, SIGNATURE_ALGORITHMS } from "./algorithms.js";
import { newSamlId } from "./protocol.js";
import { BINDINGS, buildXml, NS, signEnveloped } from "./xml.js";

const ATTRNAME_FORMAT_URI = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri";

const GCM = [
  "http://www.w3.org/2009/xmlenc11#aes256-gcm",
  "http://www.w3.org/2009/xmlenc11#aes192-gcm",
  "http://www.w3.org/2009/xmlenc11#aes128-gcm",
] as const;
const CBC = [
  "http://www.w3.org/2001/04/xmlenc#aes256-cbc",
  "http://www.w3.org/2001/04/xmlenc#aes192-cbc",
  "http://www.w3.org/2001/04/xmlenc#aes128-cbc",
] as const;

/**
 * Exactly the encryption algorithms `decrypt.ts` accepts, advertised so IdPs pick one of them
 * (Deployment Profile 2.1.3): AES-GCM (and AES-CBC unless the method requires GCM or does not
 * require a signed Response), and RSA-OAEP
 * key transport (`rsa-oaep-mgf1p` with SHA-1; `xmlenc11#rsa-oaep` with SHA-256 and MGF1-SHA256).
 */
export function spEncryptionMethods(requireGcm: boolean): Record<string, unknown>[] {
  return [
    ...[...GCM, ...(requireGcm ? [] : CBC)].map((algorithm) => ({ "@Algorithm": algorithm })),
    {
      "@Algorithm": "http://www.w3.org/2009/xmlenc11#rsa-oaep",
      "ds:DigestMethod": { "@Algorithm": "http://www.w3.org/2001/04/xmlenc#sha256" },
      "xenc11:MGF": {
        "@xmlns:xenc11": "http://www.w3.org/2009/xmlenc11#",
        "@Algorithm": "http://www.w3.org/2009/xmlenc11#mgf1sha256",
      },
    },
    { "@Algorithm": "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p" },
  ];
}

/** Signature and digest algorithms accepted from IdPs (`algorithms.ts`), advertised. */
const SIGNING_METHODS = Object.keys(SIGNATURE_ALGORITHMS);
const DIGEST_METHODS = Object.keys(DIGEST_ALGORITHMS);

export interface SpMetadataInput {
  readonly sp: SpEndpoints;
  readonly settings: SamlSettings;
  readonly displayName: string;
  readonly organization: { readonly name: string; readonly url: string };
  /** Active and next keys (previous keys are not published). */
  readonly keys: readonly SpKey[];
  /** Signs the metadata (enveloped) when the login method asks for signed metadata. */
  readonly signer: SpSigner | undefined;
}

const keyDescriptor = (use: "signing" | "encryption", key: SpKey, requireGcm: boolean) => ({
  "@use": use,
  "ds:KeyInfo": {
    "ds:X509Data": { "ds:X509Certificate": { "#text": pemBody(key.certificate) } },
  },
  ...(use === "encryption"
    ? {
        "md:EncryptionMethod": spEncryptionMethods(requireGcm),
      }
    : {}),
});

const localized = (value: string) => [
  { "@xml:lang": "sv", "#text": value },
  { "@xml:lang": "en", "#text": value },
];

const localizedPair = (value: { readonly sv: string; readonly en?: string | undefined }) => [
  { "@xml:lang": "sv", "#text": value.sv },
  ...(value.en === undefined ? [] : [{ "@xml:lang": "en", "#text": value.en }]),
];

/**
 * The SP metadata of a SAML login method (what the tenant registers with the federation or the
 * IdP): signing and encryption certificates (active and, during a rotation overlap, next), the
 * HTTP-POST AssertionConsumerService, SingleLogoutService (HTTP-Redirect and HTTP-POST), entity
 * categories (`http://macedir.org/entity-category`), UIInfo and Organization, requested
 * attributes beyond the entity categories, and the supported algorithms.
 */
export function buildSpMetadata(input: SpMetadataInput): string {
  const { sp, settings } = input;
  // CBC only inside a required Response signature (decrypt.ts via protocol.ts).
  const gcmOnly = settings.requireGcm || !settings.requireSignedResponse;
  const published = input.keys.filter((key) => key.state === "active" || key.state === "next");
  const signing = published.filter((key) => key.purpose === "signing");
  const encryption = published.filter((key) => key.purpose === "encryption");
  const entityExtensions: Record<string, unknown> = {
    "alg:DigestMethod": DIGEST_METHODS.map((algorithm) => ({
      "@xmlns:alg": NS.alg,
      "@Algorithm": algorithm,
    })),
    "alg:SigningMethod": SIGNING_METHODS.map((algorithm) => ({
      "@xmlns:alg": NS.alg,
      "@Algorithm": algorithm,
    })),
  };
  if (settings.entityCategories.length > 0) {
    entityExtensions["mdattr:EntityAttributes"] = {
      "@xmlns:mdattr": NS.mdattr,
      "saml:Attribute": {
        "@xmlns:saml": NS.saml,
        "@Name": ENTITY_CATEGORY_ATTRIBUTE,
        "@NameFormat": ATTRNAME_FORMAT_URI,
        "saml:AttributeValue": settings.entityCategories.map((category) => ({ "#text": category })),
      },
    };
  }
  const descriptor: Record<string, unknown> = {
    "@protocolSupportEnumeration": "urn:oasis:names:tc:SAML:2.0:protocol",
    "@AuthnRequestsSigned": "true",
    "@WantAssertionsSigned": "true",
    "md:Extensions": {
      "mdui:UIInfo": {
        "@xmlns:mdui": NS.mdui,
        "mdui:DisplayName":
          settings.uiInfo.displayName === undefined
            ? localized(input.displayName)
            : localizedPair(settings.uiInfo.displayName),
        ...(settings.uiInfo.description === undefined
          ? {}
          : { "mdui:Description": localizedPair(settings.uiInfo.description) }),
        ...(settings.uiInfo.logos.length === 0
          ? {}
          : {
              "mdui:Logo": settings.uiInfo.logos.map((logo) => ({
                "@width": String(logo.width),
                "@height": String(logo.height),
                ...(logo.lang === undefined ? {} : { "@xml:lang": logo.lang }),
                "#text": logo.url,
              })),
            }),
      },
    },
    "md:KeyDescriptor": [
      ...signing.map((key) => keyDescriptor("signing", key, gcmOnly)),
      ...encryption.map((key) => keyDescriptor("encryption", key, gcmOnly)),
    ],
    "md:SingleLogoutService": [
      { "@Binding": BINDINGS.redirect, "@Location": sp.sloUrl },
      { "@Binding": BINDINGS.post, "@Location": sp.sloUrl },
    ],
    "md:NameIDFormat": [
      { "#text": NAMEID_FORMATS.persistent },
      { "#text": NAMEID_FORMATS.transient },
    ],
    "md:AssertionConsumerService": {
      "@Binding": BINDINGS.post,
      "@Location": sp.acsUrl,
      "@index": "0",
      "@isDefault": "true",
    },
  };
  if (settings.requestedAttributes.length > 0) {
    descriptor["md:AttributeConsumingService"] = {
      "@index": "0",
      "@isDefault": "true",
      "md:ServiceName": localized(input.displayName),
      "md:RequestedAttribute": settings.requestedAttributes.map((attribute) => ({
        "@Name": attribute.name,
        "@NameFormat": ATTRNAME_FORMAT_URI,
        "@isRequired": attribute.required ? "true" : "false",
      })),
    };
  }
  const xml = buildXml({
    "md:EntityDescriptor": {
      "@xmlns:md": NS.md,
      "@xmlns:ds": NS.ds,
      "@entityID": sp.entityId,
      "@ID": newSamlId(),
      "md:Extensions": entityExtensions,
      "md:SPSSODescriptor": descriptor,
      "md:Organization": {
        "md:OrganizationName": localized(input.organization.name),
        "md:OrganizationDisplayName": localized(input.organization.name),
        "md:OrganizationURL": localized(input.organization.url),
      },
    },
  });
  if (!settings.signMetadata || input.signer === undefined) return xml;
  return signEnveloped(
    xml,
    "/*[local-name(.)='EntityDescriptor']",
    input.signer.privateKey,
    input.signer.certificate,
  );
}
