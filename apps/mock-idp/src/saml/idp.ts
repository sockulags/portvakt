import { createVerify, randomBytes } from "node:crypto";
import querystring from "node:querystring";
import { deflateRawSync, inflateRawSync } from "node:zlib";
import express, { Router, type Request, type Response } from "express";
import { renderLoginPage } from "../page.js";
import {
  LOA_RANKING,
  MOCK_PROTECTED_IDENTITY_ATTRIBUTE,
  type SamlFlavour,
  type SamlPersona,
} from "../personas.js";
import {
  encryptAssertion,
  signElement,
  signRedirect,
  SIGNATURE_URIS,
  type ContentChoice,
  type DigestChoice,
  type KeyTransportChoice,
  type SignatureChoice,
  type SigningKey,
} from "./crypto.js";
import { generateSelfSignedKeyPair } from "./x509.js";
import {
  attr,
  BINDING,
  children,
  descendants,
  el,
  escapeXml,
  NS,
  parse,
  RSA_SHA256,
  signatureValid,
  text,
  textOf,
} from "./xml.js";

/**
 * A mock SAML 2.0 IdP following the Swedish eID Framework (development and tests only): signed
 * metadata, signed responses and assertions (RSA, or ECDSA for an `ec` IdP), assertions encrypted
 * to the SP's encryption certificate from its metadata, ForceAuthn and RequestedAuthnContext
 * honoured (NoAuthnContext when a persona cannot meet the request), PrincipalSelection, single
 * logout in both directions and both bindings, and test switches that produce broken or hostile
 * responses.
 */

/** Behaviours a test (or a developer on the persona page) can ask for. */
export const SAML_SWITCHES = [
  "cancel",
  "authn-failed",
  "wrong-audience",
  "expired",
  "unsigned",
  "tampered-signature",
  "wrong-in-response-to",
  "wrong-subject-in-response-to",
  "replay",
  "reuse-assertion-id",
  "lower-loa",
  "wrapped",
  "multiple-assertions",
  "unencrypted",
  "stale-authn",
  "sha1-signature",
  "sha1-digest",
  "rsa-1_5",
  "3des",
  "oaep-sha256",
  "aes-cbc",
  "aes192-cbc",
  "sibling-key",
  "wrong-recipient",
  "wrong-destination",
  "no-destination",
  "old-issue-instant",
  "wrong-assertion-issuer",
  "unsolicited",
  "forged-keyinfo",
  "dtd",
  "comment-in-nameid",
  "long-nameid",
  "hostile-attributes",
] as const;
export type SamlSwitch = (typeof SAML_SWITCHES)[number];
const isSwitch = (value: unknown): value is SamlSwitch =>
  typeof value === "string" && (SAML_SWITCHES as readonly string[]).includes(value);

const STATUS = {
  success: "urn:oasis:names:tc:SAML:2.0:status:Success",
  requester: "urn:oasis:names:tc:SAML:2.0:status:Requester",
  responder: "urn:oasis:names:tc:SAML:2.0:status:Responder",
  authnFailed: "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed",
  noAuthnContext: "urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext",
  unknownPrincipal: "urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal",
  cancel: "http://id.elegnamnden.se/status/1.0/cancel",
} as const;

const ATTR = {
  personalIdentityNumber: "urn:oid:1.2.752.29.4.13",
  givenName: "urn:oid:2.5.4.42",
  sn: "urn:oid:2.5.4.4",
  displayName: "urn:oid:2.16.840.1.113730.3.1.241",
  prid: "urn:oid:1.2.752.201.3.4",
  pridPersistence: "urn:oid:1.2.752.201.3.5",
  orgAffiliation: "urn:oid:1.2.752.201.3.1",
  employeeHsaId: "urn:oid:1.2.752.29.6.2.1",
  mail: "urn:oid:0.9.2342.19200300.100.1.3",
} as const;

const PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";

const TITLES: Record<SamlFlavour, string> = {
  bankid: "Mock BankID (SAML)",
  freja: "Mock Freja eID (SAML)",
  siths: "Mock SITHS (SAML)",
};

const ENTITY_CATEGORIES: Record<SamlFlavour, readonly string[]> = {
  bankid: ["http://id.elegnamnden.se/ec/1.0/loa3-pnr"],
  freja: ["http://id.elegnamnden.se/ec/1.0/loa3-pnr", "http://id.elegnamnden.se/ec/1.0/loa2-pnr"],
  siths: ["http://id.swedenconnect.se/ec/1.0/loa3-hsaid"],
};

/** orgAffiliation scopes (`shibmd:Scope`) per flavour: the SITHS mock's organisation. */
const SCOPES: Record<SamlFlavour, readonly string[]> = {
  bankid: [],
  freja: [],
  siths: ["2321000016"],
};

/** What the mock knows about an SP (from its metadata). */
interface SpInfo {
  readonly entityId: string;
  readonly acsUrl: string;
  readonly sloRedirect: string | undefined;
  readonly sloPost: string | undefined;
  readonly signingCertificates: readonly string[];
  readonly encryptionCertificates: readonly string[];
}

interface SpRegistration {
  readonly info: SpInfo;
  /** Registered by a test with fixed metadata (else fetched from `{entityID}/metadata`). */
  readonly pinned: boolean;
  /** Encrypt assertions (to the certificate at `encryptionCertificateIndex`). */
  readonly encrypt: boolean;
  readonly encryptionCertificateIndex: number;
}

/** An AuthnRequest the mock received (tests assert on it). */
export interface ReceivedAuthnRequest {
  readonly spEntityId: string;
  readonly requestId: string;
  readonly binding: "redirect" | "post";
  readonly forceAuthn: boolean;
  readonly requestedLoa: readonly string[];
  readonly comparison: string;
  readonly principalPin: string | undefined;
  readonly relayState: string | undefined;
}

interface PendingRequest extends ReceivedAuthnRequest {
  readonly sp: SpInfo;
}

interface IdpSession {
  readonly personaId: string;
  readonly authnInstant: Date;
  readonly sessionIndex: string;
}

export interface PreparedLogin {
  /** Persona to sign in without the persona page. */
  readonly persona?: string;
  readonly switch?: SamlSwitch;
}

export type MetadataMode = "signed" | "unsigned" | "tampered" | "unavailable" | "without-entity";

/** A LogoutRequest the mock received from an SP (SP-initiated logout). */
export interface ReceivedLogoutRequest {
  readonly spEntityId: string;
  readonly binding: "redirect" | "post";
  readonly nameId: string;
  readonly sessionIndex: string | undefined;
}

/** An auto-submitting form (HTTP-POST binding). */
export interface MockAutoPost {
  readonly action: string;
  readonly fields: Readonly<Record<string, string>>;
}

export interface MockSamlIdp {
  readonly flavour: SamlFlavour;
  /** Path segment below `/saml/` (the flavour, or another name such as `ecdsa`). */
  readonly name: string;
  readonly keyType: "rsa" | "ec";
  readonly entityId: string;
  readonly metadataUrl: string;
  readonly router: Router;
  /** Certificate the IdP signs responses and assertions with. */
  readonly signingCertificate: string;
  /** Certificate the IdP's metadata is signed with (a separate key, like a federation's). */
  readonly metadataSigningCertificate: string;
  readonly personas: readonly SamlPersona[];
  /**
   * Registers an SP with fixed metadata (or fetches it now), instead of fetching
   * `{entityID}/metadata` on its first request. `encrypt: false` sends plain assertions.
   */
  registerSp(
    entityId: string,
    options?: {
      readonly metadataXml?: string;
      readonly encrypt?: boolean;
      readonly encryptionCertificateIndex?: number;
    },
  ): Promise<void>;
  /** Forgets an SP: its metadata is fetched again on its next request. */
  forgetSp(entityId: string): void;
  /** Queues what the next AuthnRequest from the SP gets (auto-login and/or a switch). */
  prepare(entityId: string, next: PreparedLogin): void;
  /** Every AuthnRequest received, oldest first. */
  requests(): readonly ReceivedAuthnRequest[];
  setMetadataMode(mode: MetadataMode): void;
  /** SLO bindings the metadata lists (default both). */
  setSloBindings(bindings: readonly ("redirect" | "post")[]): void;
  /** SP-initiated LogoutRequests received, oldest first. */
  logoutRequests(): readonly ReceivedLogoutRequest[];
  /** LogoutResponses received from SPs (to IdP-initiated logouts), oldest first. */
  logoutResponses(): readonly {
    readonly binding: "redirect" | "post";
    readonly inResponseTo: string | undefined;
    readonly status: string | undefined;
  }[];
  /**
   * An IdP-initiated logout over HTTP-Redirect: the URL (signed LogoutRequest) the browser is
   * sent to. `dtd` adds a DTD to the message (Portvakt must refuse it).
   */
  initiateLogout(
    entityId: string,
    subject: { readonly nameId: string; readonly sessionIndex?: string },
    options?: { readonly dtd?: boolean; readonly destination?: string },
  ): Promise<string>;
  /** An IdP-initiated logout over HTTP-POST: the form the browser posts. */
  initiateLogoutPost(
    entityId: string,
    subject: { readonly nameId: string; readonly sessionIndex?: string },
  ): Promise<MockAutoPost>;
  /** Ends the IdP's own SSO sessions (as if the person signed out at the IdP). */
  clearSessions(): void;
}

const newId = (): string => `_${randomBytes(16).toString("hex")}`;
const iso = (date: Date): string => date.toISOString().replace(/\.\d{3}Z$/, "Z");
const pemBody = (pem: string): string =>
  pem.replace(/-----(BEGIN|END) CERTIFICATE-----/g, "").replace(/\s+/g, "");
const toPem = (base64: string): string =>
  `-----BEGIN CERTIFICATE-----\n${(base64.replace(/\s+/g, "").match(/.{1,64}/g) ?? []).join("\n")}\n-----END CERTIFICATE-----\n`;

const rank = (loa: string): number => (LOA_RANKING as readonly string[]).indexOf(loa);
const DTD = '<!DOCTYPE x [<!ENTITY a "b">]>';

/** The raw (still encoded) `key=value` tokens of a query string. */
function rawTokens(req: Request): Map<string, string> {
  const query = req.originalUrl.includes("?")
    ? req.originalUrl.slice(req.originalUrl.indexOf("?") + 1)
    : "";
  const tokens = new Map<string, string>();
  for (const token of query.split("&")) {
    const eq = token.indexOf("=");
    if (eq > 0) tokens.set(token.slice(0, eq), token);
  }
  return tokens;
}

/** Verifies an HTTP-Redirect binding signature (RSA-SHA256) over the raw query. */
function redirectSignatureValid(
  req: Request,
  param: string,
  certificates: readonly string[],
): boolean {
  const tokens = rawTokens(req);
  const message = tokens.get(param);
  const sigAlg = tokens.get("SigAlg");
  const signature = typeof req.query.Signature === "string" ? req.query.Signature : undefined;
  if (message === undefined || sigAlg === undefined || signature === undefined) return false;
  if (req.query.SigAlg !== RSA_SHA256) return false;
  const relay = tokens.get("RelayState");
  const signed = [message, ...(relay === undefined ? [] : [relay]), sigAlg].join("&");
  return certificates.some((certificate) => {
    try {
      return createVerify("RSA-SHA256").update(signed).verify(certificate, signature, "base64");
    } catch {
      return false;
    }
  });
}

function autoPostPage(action: string, fields: Readonly<Record<string, string>>): string {
  const inputs = Object.entries(fields)
    .map(
      ([name, value]) =>
        `<input type="hidden" name="${escapeXml(name)}" value="${escapeXml(value)}">`,
    )
    .join("\n");
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Mock IdP (development)</title></head>
<body onload="document.forms[0].submit()">
<form method="post" action="${escapeXml(action)}" data-testid="saml-post-form">
${inputs}
<noscript><button type="submit">Continue</button></noscript>
</form>
</body></html>`;
}

async function parseSpMetadata(entityId: string, xml: string): Promise<SpInfo> {
  const root = await parse(xml);
  if (attr(root, "entityID") !== entityId) throw new Error("SP metadata for another entityID");
  const descriptor = children(root, NS.md, "SPSSODescriptor")[0];
  if (descriptor === undefined) throw new Error("SP metadata without SPSSODescriptor");
  const certs = (use: string) =>
    children(descriptor, NS.md, "KeyDescriptor")
      .filter((key) => attr(key, "use") === use || attr(key, "use") === undefined)
      .flatMap((key) =>
        descendants(key, NS.ds, "X509Certificate").map((cert) => toPem(textOf(cert))),
      );
  const acs = children(descriptor, NS.md, "AssertionConsumerService").find(
    (service) => attr(service, "Binding") === BINDING.post,
  );
  const slo = (binding: string) =>
    attr(
      children(descriptor, NS.md, "SingleLogoutService").find(
        (service) => attr(service, "Binding") === binding,
      ),
      "Location",
    );
  const acsUrl = attr(acs, "Location");
  if (acsUrl === undefined) throw new Error("SP metadata without an HTTP-POST ACS");
  return {
    entityId,
    acsUrl,
    sloRedirect: slo(BINDING.redirect),
    sloPost: slo(BINDING.post),
    signingCertificates: certs("signing"),
    encryptionCertificates: certs("encryption"),
  };
}

export interface MockSamlIdpOptions {
  readonly flavour: SamlFlavour;
  /** Path segment below `/saml/` (default: the flavour). */
  readonly name?: string;
  /** Key type of the signing keys (default RSA; `ec` signs with ECDSA P-256). */
  readonly keyType?: "rsa" | "ec";
  /** Origin of the mock IdP app; the IdP lives at `{publicUrl}/saml/{name}`. */
  readonly publicUrl: string;
  readonly personas: readonly SamlPersona[];
}

export async function createMockSamlIdp(options: MockSamlIdpOptions): Promise<MockSamlIdp> {
  const { flavour, personas } = options;
  const name = options.name ?? flavour;
  const keyType = options.keyType ?? "rsa";
  const base = `${options.publicUrl}/saml/${name}`;
  const entityId = base;
  const ssoUrl = `${base}/sso`;
  const sloUrl = `${base}/slo`;
  const year = 365 * 24 * 3600;
  const signing = await generateSelfSignedKeyPair(
    `Mock ${name} IdP signing`,
    year,
    new Date(),
    keyType,
  );
  const metadataKey = await generateSelfSignedKeyPair(
    `Mock ${name} metadata`,
    year,
    new Date(),
    keyType,
  );
  // An attacker's key: signs with its own certificate in KeyInfo (forged-keyinfo).
  const attacker = await generateSelfSignedKeyPair(`Not ${name}`, year, new Date(), keyType);
  const cookieName = `mock_saml_${name}`;
  const signature: SignatureChoice = keyType === "ec" ? "ecdsa-sha256" : "rsa-sha256";

  const sps = new Map<string, SpRegistration>();
  const pending = new Map<string, PendingRequest>();
  const sessions = new Map<string, IdpSession>();
  const prepared = new Map<string, PreparedLogin[]>();
  const received: ReceivedAuthnRequest[] = [];
  const logoutRequests: ReceivedLogoutRequest[] = [];
  const logoutResponses: {
    binding: "redirect" | "post";
    inResponseTo: string | undefined;
    status: string | undefined;
  }[] = [];
  const lastResponse = new Map<string, { readonly xml: string; readonly assertionId: string }>();
  let metadataMode: MetadataMode = "signed";
  let sloBindings: readonly ("redirect" | "post")[] = ["redirect", "post"];

  const sign = (
    xml: string,
    elementXPath: string,
    overrides: {
      readonly key?: SigningKey;
      readonly signature?: SignatureChoice;
      readonly digest?: DigestChoice;
      readonly placement?: "afterIssuer" | "first";
    } = {},
  ): string =>
    signElement(xml, elementXPath, overrides.key ?? signing, {
      signature: overrides.signature ?? signature,
      digest: overrides.digest ?? "sha256",
      placement: overrides.placement ?? "afterIssuer",
    });

  const redirectUrl = (
    location: string,
    param: "SAMLRequest" | "SAMLResponse",
    xml: string,
    relayState: string | undefined,
  ): string => {
    const message: Record<string, string> = {
      [param]: deflateRawSync(Buffer.from(xml, "utf8")).toString("base64"),
    };
    if (relayState !== undefined) message.RelayState = relayState;
    message.SigAlg = SIGNATURE_URIS[signature];
    const signed = querystring.stringify(message);
    const value = signRedirect(signed, signing.privateKey, keyType);
    return `${location}${location.includes("?") ? "&" : "?"}${signed}&Signature=${encodeURIComponent(value)}`;
  };

  async function register(
    spEntityId: string,
    registration: {
      readonly metadataXml?: string;
      readonly encrypt?: boolean;
      readonly encryptionCertificateIndex?: number;
      readonly pinned?: boolean;
    } = {},
  ): Promise<SpRegistration> {
    let xml = registration.metadataXml;
    if (xml === undefined) {
      const response = await fetch(`${spEntityId}/metadata`);
      if (!response.ok) throw new Error(`SP metadata not available (${response.status})`);
      xml = await response.text();
    }
    const info = await parseSpMetadata(spEntityId, xml);
    const entry: SpRegistration = {
      info,
      pinned: registration.pinned ?? registration.metadataXml !== undefined,
      encrypt: registration.encrypt ?? info.encryptionCertificates.length > 0,
      encryptionCertificateIndex: registration.encryptionCertificateIndex ?? 0,
    };
    sps.set(spEntityId, entry);
    return entry;
  }

  const spOf = async (spEntityId: string): Promise<SpRegistration> =>
    sps.get(spEntityId) ?? register(spEntityId, { pinned: false });

  function metadataXml(): string {
    const scopes = SCOPES[flavour].map((scope) => text("shibmd:Scope", { regexp: "false" }, scope));
    const entity = el(
      "md:EntityDescriptor",
      {
        "xmlns:md": NS.md,
        "xmlns:ds": NS.ds,
        entityID: entityId,
        ID: newId(),
        validUntil: iso(new Date(Date.now() + 7 * 24 * 3600 * 1000)),
      },
      el(
        "md:Extensions",
        {},
        el(
          "mdattr:EntityAttributes",
          { "xmlns:mdattr": NS.mdattr },
          el(
            "saml:Attribute",
            {
              "xmlns:saml": NS.saml,
              Name: "http://macedir.org/entity-category",
              NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
            },
            ...ENTITY_CATEGORIES[flavour].map((category) =>
              text("saml:AttributeValue", {}, category),
            ),
          ),
        ),
      ),
      el(
        "md:IDPSSODescriptor",
        {
          protocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
          WantAuthnRequestsSigned: "true",
        },
        el(
          "md:Extensions",
          { "xmlns:shibmd": NS.shibmd, "xmlns:psc": NS.psc },
          ...scopes,
          el(
            "psc:RequestedPrincipalSelection",
            {},
            el("psc:MatchValue", { Name: ATTR.personalIdentityNumber }),
          ),
        ),
        el(
          "md:KeyDescriptor",
          { use: "signing" },
          el(
            "ds:KeyInfo",
            {},
            el("ds:X509Data", {}, text("ds:X509Certificate", {}, pemBody(signing.certificate))),
          ),
        ),
        ...(sloBindings.includes("redirect")
          ? [el("md:SingleLogoutService", { Binding: BINDING.redirect, Location: sloUrl })]
          : []),
        ...(sloBindings.includes("post")
          ? [el("md:SingleLogoutService", { Binding: BINDING.post, Location: sloUrl })]
          : []),
        text("md:NameIDFormat", {}, PERSISTENT),
        el("md:SingleSignOnService", { Binding: BINDING.redirect, Location: ssoUrl }),
        el("md:SingleSignOnService", { Binding: BINDING.post, Location: ssoUrl }),
      ),
    );
    // A signed aggregate no longer listing this IdP (another entity only).
    const xml =
      metadataMode === "without-entity"
        ? el(
            "md:EntitiesDescriptor",
            { "xmlns:md": NS.md, ID: newId() },
            el("md:EntityDescriptor", { entityID: `${base}-other` }),
          )
        : entity;
    if (metadataMode === "unsigned") return xml;
    const root = metadataMode === "without-entity" ? "EntitiesDescriptor" : "EntityDescriptor";
    const signed = sign(xml, `/*[local-name(.)='${root}']`, {
      key: metadataKey,
      placement: "first",
    });
    // A changed endpoint after signing: the signature no longer matches.
    return metadataMode === "tampered" ? signed.replaceAll(`${base}/slo`, `${base}/sl0`) : signed;
  }

  /** The level to assert for a request, or `null` when the persona cannot meet it. */
  function chooseLoa(persona: SamlPersona, request: ReceivedAuthnRequest): string | null {
    if (request.requestedLoa.length === 0) return persona.loa[0] ?? null;
    if (request.comparison === "minimum") {
      const lowest = Math.min(...request.requestedLoa.map(rank).filter((value) => value >= 0));
      return persona.loa.find((loa) => rank(loa) >= lowest) ?? null;
    }
    return persona.loa.find((loa) => request.requestedLoa.includes(loa)) ?? null;
  }

  function attributes(persona: SamlPersona): string {
    const values: [string, readonly string[]][] = [
      [ATTR.givenName, [persona.givenName]],
      [ATTR.sn, [persona.sn]],
      [ATTR.displayName, persona.displayName === undefined ? [] : [persona.displayName]],
      [ATTR.personalIdentityNumber, persona.pin === undefined ? [] : [persona.pin]],
      [ATTR.prid, persona.prid === undefined ? [] : [persona.prid]],
      [
        ATTR.pridPersistence,
        persona.pridPersistence === undefined ? [] : [persona.pridPersistence],
      ],
      [ATTR.employeeHsaId, persona.employeeHsaId === undefined ? [] : [persona.employeeHsaId]],
      [ATTR.orgAffiliation, persona.orgAffiliation],
      [ATTR.mail, persona.mail === undefined ? [] : [persona.mail]],
      [MOCK_PROTECTED_IDENTITY_ATTRIBUTE, persona.protectedIdentity ? ["true"] : []],
    ];
    return el(
      "saml2:AttributeStatement",
      {},
      ...values
        .filter(([, list]) => list.length > 0)
        .map(([attributeName, list]) =>
          el(
            "saml2:Attribute",
            { Name: attributeName, NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri" },
            ...list.map((value) =>
              text("saml2:AttributeValue", { "xsi:type": "xs:string" }, value),
            ),
          ),
        ),
    );
  }

  interface AssertionInput {
    readonly id: string;
    readonly persona: SamlPersona;
    readonly request: PendingRequest;
    readonly loa: string;
    readonly authnInstant: Date;
    readonly sessionIndex: string;
    readonly now: Date;
    readonly switch: SamlSwitch | undefined;
  }

  function assertionXml(input: AssertionInput): string {
    const { persona, request, now } = input;
    const sw = input.switch;
    const expired = sw === "expired";
    const issued = expired
      ? new Date(now.getTime() - 20 * 60_000)
      : sw === "old-issue-instant"
        ? new Date(now.getTime() - 10 * 60_000)
        : now;
    const notOnOrAfter = expired
      ? new Date(now.getTime() - 10 * 60_000)
      : new Date(now.getTime() + 5 * 60_000);
    const audience =
      sw === "wrong-audience" ? "https://sp.wrong.example/saml" : request.sp.entityId;
    const inResponseTo =
      sw === "unsolicited"
        ? undefined
        : sw === "wrong-in-response-to" || sw === "wrong-subject-in-response-to"
          ? newId()
          : request.requestId;
    return el(
      "saml2:Assertion",
      {
        "xmlns:saml2": NS.saml,
        "xmlns:xs": NS.xs,
        "xmlns:xsi": NS.xsi,
        ID: input.id,
        IssueInstant: iso(issued),
        Version: "2.0",
      },
      text(
        "saml2:Issuer",
        {},
        sw === "wrong-assertion-issuer" ? "https://other-idp.example/saml" : entityId,
      ),
      el(
        "saml2:Subject",
        {},
        text(
          "saml2:NameID",
          { Format: PERSISTENT, NameQualifier: entityId, SPNameQualifier: request.sp.entityId },
          sw === "long-nameid" ? "n".repeat(2000) : persona.nameId,
        ),
        el(
          "saml2:SubjectConfirmation",
          { Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer" },
          el("saml2:SubjectConfirmationData", {
            InResponseTo: inResponseTo,
            NotOnOrAfter: iso(notOnOrAfter),
            Recipient:
              sw === "wrong-recipient" ? `${request.sp.entityId}/elsewhere` : request.sp.acsUrl,
          }),
        ),
      ),
      el(
        "saml2:Conditions",
        { NotBefore: iso(new Date(issued.getTime() - 1000)), NotOnOrAfter: iso(notOnOrAfter) },
        el("saml2:AudienceRestriction", {}, text("saml2:Audience", {}, audience)),
      ),
      el(
        "saml2:AuthnStatement",
        { AuthnInstant: iso(input.authnInstant), SessionIndex: input.sessionIndex },
        el("saml2:AuthnContext", {}, text("saml2:AuthnContextClassRef", {}, input.loa)),
      ),
      sw === "hostile-attributes"
        ? attributes(persona).replace(
            "</saml2:AttributeStatement>",
            `${["__proto__", "constructor", "toString"]
              .map((attributeName) =>
                el(
                  "saml2:Attribute",
                  { Name: attributeName },
                  text("saml2:AttributeValue", {}, "x"),
                ),
              )
              .join("")}</saml2:AttributeStatement>`,
          )
        : attributes(persona),
    );
  }

  /** Signs an assertion with the algorithms a switch asks for. */
  function signAssertion(xml: string, sw: SamlSwitch | undefined): string {
    return sign(xml, "/*[local-name(.)='Assertion']", {
      ...(sw === "sha1-signature" && keyType === "rsa" ? { signature: "rsa-sha1" as const } : {}),
      ...(sw === "sha1-digest" ? { digest: "sha1" as const } : {}),
      ...(sw === "forged-keyinfo" ? { key: attacker } : {}),
    });
  }

  function responseXml(
    request: PendingRequest,
    inner: string,
    status: { readonly code: string; readonly subCode?: string },
    sw: SamlSwitch | undefined,
  ): string {
    const statusXml = el(
      "saml2p:Status",
      {},
      el(
        "saml2p:StatusCode",
        { Value: status.code },
        ...(status.subCode === undefined
          ? []
          : [el("saml2p:StatusCode", { Value: status.subCode })]),
      ),
    );
    const destination =
      sw === "no-destination"
        ? undefined
        : sw === "wrong-destination"
          ? `${request.sp.entityId}/elsewhere`
          : request.sp.acsUrl;
    const xml = el(
      "saml2p:Response",
      {
        "xmlns:saml2p": NS.samlp,
        "xmlns:saml2": NS.saml,
        ID: newId(),
        Version: "2.0",
        IssueInstant: iso(new Date()),
        Destination: destination,
        InResponseTo:
          sw === "unsolicited"
            ? undefined
            : sw === "wrong-in-response-to"
              ? newId()
              : request.requestId,
      },
      text("saml2:Issuer", {}, entityId),
      statusXml,
      inner,
    );
    if (sw === "unsigned" || sw === "wrapped") return xml;
    const signed = sign(xml, "/*[local-name(.)='Response']", {
      ...(sw === "forged-keyinfo" ? { key: attacker } : {}),
    });
    return sw === "dtd" ? `${DTD}${signed}` : signed;
  }

  async function respond(
    res: Response,
    request: PendingRequest,
    persona: SamlPersona | undefined,
    sw: SamlSwitch | undefined,
    session: IdpSession | undefined,
  ): Promise<void> {
    const registration = await spOf(request.sp.entityId);
    const send = (xml: string): void => {
      res
        .status(200)
        .set({ "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" })
        .send(
          autoPostPage(request.sp.acsUrl, {
            SAMLResponse: Buffer.from(xml, "utf8").toString("base64"),
            ...(request.relayState === undefined ? {} : { RelayState: request.relayState }),
          }),
        );
    };
    const failure = (code: string, subCode: string): void => {
      send(responseXml(request, "", { code, subCode }, sw));
    };

    if (sw === "replay") {
      const previous = lastResponse.get(request.sp.entityId);
      if (previous !== undefined) {
        send(previous.xml);
        return;
      }
    }
    if (persona === undefined || sw === "cancel") {
      failure(STATUS.responder, STATUS.cancel);
      return;
    }
    if (sw === "authn-failed") {
      failure(STATUS.responder, STATUS.authnFailed);
      return;
    }
    if (request.principalPin !== undefined && request.principalPin !== persona.pin) {
      failure(STATUS.requester, STATUS.unknownPrincipal);
      return;
    }
    let loa = chooseLoa(persona, request);
    if (sw === "lower-loa") loa = "http://id.elegnamnden.se/loa/1.0/loa2";
    if (loa === null) {
      failure(STATUS.requester, STATUS.noAuthnContext);
      return;
    }
    const now = new Date();
    const reuse = sw === "reuse-assertion-id" ? lastResponse.get(request.sp.entityId) : undefined;
    const assertionId = reuse?.assertionId ?? newId();
    const authnInstant =
      sw === "stale-authn" ? new Date(now.getTime() - 3600_000) : (session?.authnInstant ?? now);
    const sessionIndex = session?.sessionIndex ?? newId();
    const input: AssertionInput = {
      id: assertionId,
      persona,
      request,
      loa,
      authnInstant,
      sessionIndex,
      now,
      switch: sw,
    };
    let assertion =
      sw === "unsigned" ? assertionXml(input) : signAssertion(assertionXml(input), sw);
    if (sw === "tampered-signature") {
      // A signed value changed after signing: the assertion's digest no longer matches.
      assertion = assertion.replace(
        `>${escapeXml(persona.givenName)}<`,
        `>${escapeXml(persona.givenName)}x<`,
      );
    }
    if (sw === "comment-in-nameid") {
      // A comment inside the signed NameID (canonicalization drops comments, so the signature
      // still holds): the SP must read the whole value.
      const half = Math.floor(persona.nameId.length / 2);
      assertion = assertion.replace(
        `>${escapeXml(persona.nameId)}<`,
        `>${escapeXml(persona.nameId.slice(0, half))}<!-- a comment -->${escapeXml(persona.nameId.slice(half))}<`,
      );
    }
    let inner: string;
    if (sw === "wrapped") {
      // Signature wrapping: an unsigned evil assertion carries the legitimate signature and the
      // signed assertion is hidden in its Advice.
      const evilId = newId();
      const signatureXml = /<(ds:)?Signature[\s\S]*<\/(ds:)?Signature>/.exec(assertion)?.[0] ?? "";
      const evil = assertionXml({
        ...input,
        id: evilId,
        persona: { ...persona, nameId: "evil-nameid", pin: "191212121212" },
      })
        .replace(`</saml2:Issuer>`, `</saml2:Issuer>${signatureXml}`)
        .replace(
          `<saml2:AttributeStatement>`,
          `<saml2:Advice>${assertion}</saml2:Advice><saml2:AttributeStatement>`,
        );
      inner = evil;
    } else if (sw === "multiple-assertions") {
      inner = assertion + signAssertion(assertionXml({ ...input, id: newId() }), undefined);
    } else if (registration.encrypt && sw !== "unencrypted") {
      const certificate =
        registration.info.encryptionCertificates[registration.encryptionCertificateIndex] ??
        registration.info.encryptionCertificates[0];
      if (certificate === undefined) throw new Error("SP has no encryption certificate");
      const content: ContentChoice =
        sw === "3des"
          ? "3des"
          : sw === "aes-cbc"
            ? "aes128-cbc"
            : sw === "aes192-cbc"
              ? "aes192-cbc"
              : "aes256-gcm";
      const keyTransport: KeyTransportChoice =
        sw === "rsa-1_5" ? "rsa-1_5" : sw === "oaep-sha256" ? "oaep-sha256" : "oaep-mgf1p";
      inner = encryptAssertion(assertion, certificate, {
        content,
        keyTransport,
        siblingKey: sw === "sibling-key",
      });
    } else {
      inner = assertion;
    }
    const xml = responseXml(request, inner, { code: STATUS.success }, sw);
    if (sw !== "replay") lastResponse.set(request.sp.entityId, { xml, assertionId });
    send(xml);
  }

  const router = Router();
  router.use(express.urlencoded({ extended: false, limit: "1mb" }));

  router.get("/metadata", (_req, res) => {
    if (metadataMode === "unavailable") {
      res.status(503).send("metadata unavailable");
      return;
    }
    res
      .set({ "Content-Type": "application/samlmetadata+xml", "Cache-Control": "no-store" })
      .send(metadataXml());
  });

  /** Reads and verifies an AuthnRequest (HTTP-Redirect or HTTP-POST) from a known SP. */
  async function readAuthnRequest(
    req: Request,
    binding: "redirect" | "post",
  ): Promise<PendingRequest> {
    const source = (binding === "redirect" ? req.query : req.body) as Record<string, unknown>;
    const message = source.SAMLRequest;
    if (typeof message !== "string") throw new Error("no SAMLRequest");
    const bytes = Buffer.from(message, "base64");
    const xml =
      binding === "redirect" ? inflateRawSync(bytes).toString("utf8") : bytes.toString("utf8");
    const root = await parse(xml);
    if (root.localName !== "AuthnRequest") throw new Error("not an AuthnRequest");
    const spEntityId = textOf(children(root, NS.saml, "Issuer")[0]);
    let registration = await spOf(spEntityId);
    const verified = (certs: readonly string[]) =>
      binding === "redirect"
        ? redirectSignatureValid(req, "SAMLRequest", certs)
        : signatureValid(xml, root, certs);
    if (!verified(registration.info.signingCertificates) && !registration.pinned) {
      // The SP may have rotated its keys: fetch its metadata again once.
      registration = await register(spEntityId, { pinned: false });
    }
    if (!verified(registration.info.signingCertificates)) {
      throw new Error("AuthnRequest signature invalid");
    }
    if (attr(root, "Destination") !== ssoUrl) throw new Error("AuthnRequest Destination mismatch");
    const acs = attr(root, "AssertionConsumerServiceURL");
    if (acs !== undefined && acs !== registration.info.acsUrl) throw new Error("unknown ACS URL");
    const requested = children(root, NS.samlp, "RequestedAuthnContext")[0];
    const principal = descendants(root, NS.psc, "MatchValue").find(
      (match) => attr(match, "Name") === ATTR.personalIdentityNumber,
    );
    const relayState = typeof source.RelayState === "string" ? source.RelayState : undefined;
    const request: PendingRequest = {
      sp: registration.info,
      spEntityId,
      requestId: attr(root, "ID") ?? "",
      binding,
      forceAuthn: attr(root, "ForceAuthn") === "true",
      requestedLoa:
        requested === undefined
          ? []
          : children(requested, NS.saml, "AuthnContextClassRef").map(textOf),
      comparison: attr(requested, "Comparison") ?? "exact",
      principalPin: principal === undefined ? undefined : textOf(principal),
      relayState,
    };
    received.push({
      spEntityId,
      requestId: request.requestId,
      binding,
      forceAuthn: request.forceAuthn,
      requestedLoa: request.requestedLoa,
      comparison: request.comparison,
      principalPin: request.principalPin,
      relayState,
    });
    return request;
  }

  const cookieOf = (req: Request): string | undefined => {
    const header = req.headers.cookie ?? "";
    for (const part of header.split(";")) {
      const [cookie, value] = part.trim().split("=");
      if (cookie === cookieName && value !== undefined) return value;
    }
    return undefined;
  };

  async function signIn(
    res: Response,
    request: PendingRequest,
    persona: SamlPersona,
    sw: SamlSwitch | undefined,
  ): Promise<void> {
    const session: IdpSession = {
      personaId: persona.id,
      authnInstant: new Date(),
      sessionIndex: newId(),
    };
    const cookie = randomBytes(16).toString("hex");
    sessions.set(cookie, session);
    res.cookie(cookieName, cookie, {
      httpOnly: true,
      path: `/saml/${name}`,
      sameSite: "none",
      secure: false,
    });
    await respond(res, request, persona, sw, session);
  }

  async function handleSso(
    req: Request,
    res: Response,
    binding: "redirect" | "post",
  ): Promise<void> {
    let request: PendingRequest;
    try {
      request = await readAuthnRequest(req, binding);
    } catch (error) {
      res
        .status(400)
        .type("text/plain")
        .send(`invalid AuthnRequest: ${error instanceof Error ? error.message : "error"}`);
      return;
    }
    const queue = prepared.get(request.spEntityId);
    const next = queue?.shift();
    if (next !== undefined) {
      const persona = personas.find((candidate) => candidate.id === next.persona);
      if (next.persona !== undefined && persona === undefined) {
        res.status(400).type("text/plain").send("unknown prepared persona");
        return;
      }
      if (persona === undefined) await respond(res, request, undefined, next.switch, undefined);
      else await signIn(res, request, persona, next.switch);
      return;
    }
    // An IdP SSO session answers without asking, unless the SP forces authentication.
    const existing = sessions.get(cookieOf(req) ?? "");
    const persona = personas.find((candidate) => candidate.id === existing?.personaId);
    if (existing !== undefined && persona !== undefined && !request.forceAuthn) {
      await respond(res, request, persona, undefined, existing);
      return;
    }
    const key = randomBytes(12).toString("hex");
    pending.set(key, request);
    res.redirect(303, `${ssoUrl}/${key}`);
  }

  router.get("/sso", (req, res, next) => {
    handleSso(req, res, "redirect").catch(next);
  });
  router.post("/sso", (req, res, next) => {
    handleSso(req, res, "post").catch(next);
  });

  router.get("/sso/:key", (req, res) => {
    if (!pending.has(req.params.key)) {
      res.status(404).type("text/plain").send("unknown or used request");
      return;
    }
    res.set({ "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" }).send(
      renderLoginPage({
        title: name === flavour ? TITLES[flavour] : `${TITLES[flavour]} (${name})`,
        action: `${ssoUrl}/${req.params.key}`,
        personas: personas.map((persona) => ({
          id: persona.id,
          label: persona.displayName ?? `${persona.givenName} ${persona.sn}`,
          detail: [
            persona.pin === undefined
              ? undefined
              : `${persona.pin.slice(0, 8)}-${persona.pin.slice(8)}`,
            persona.employeeHsaId,
            persona.prid,
            persona.loa.map((loa) => loa.split("/").at(-1)).join(", "),
            persona.protectedIdentity ? "protected identity" : undefined,
          ]
            .filter(Boolean)
            .join(" · "),
        })),
        switches: SAML_SWITCHES,
      }),
    );
  });

  router.post("/sso/:key/login", (req, res, next) => {
    const request = pending.get(req.params.key);
    pending.delete(req.params.key);
    const body = req.body as Record<string, unknown>;
    const persona = personas.find((candidate) => candidate.id === body.persona);
    if (request === undefined || persona === undefined) {
      res.status(400).type("text/plain").send("unknown request or persona");
      return;
    }
    signIn(res, request, persona, isSwitch(body.switch) ? body.switch : undefined).catch(next);
  });

  router.post("/sso/:key/cancel", (req, res, next) => {
    const request = pending.get(req.params.key);
    pending.delete(req.params.key);
    if (request === undefined) {
      res.status(400).type("text/plain").send("unknown request");
      return;
    }
    respond(res, request, undefined, "cancel", undefined).catch(next);
  });

  /** Handles a logout message from an SP (either binding). */
  async function handleSlo(
    req: Request,
    res: Response,
    binding: "redirect" | "post",
  ): Promise<void> {
    const source = (binding === "redirect" ? req.query : req.body) as Record<string, unknown>;
    const isRequest = typeof source.SAMLRequest === "string";
    const param = isRequest ? "SAMLRequest" : "SAMLResponse";
    const message = source[param];
    if (typeof message !== "string") {
      res.status(400).type("text/plain").send("no SAML message");
      return;
    }
    const bytes = Buffer.from(message, "base64");
    const xml =
      binding === "redirect" ? inflateRawSync(bytes).toString("utf8") : bytes.toString("utf8");
    const root = await parse(xml);
    const spEntityId = textOf(children(root, NS.saml, "Issuer")[0]);
    const registration = await spOf(spEntityId);
    const valid =
      binding === "redirect"
        ? redirectSignatureValid(req, param, registration.info.signingCertificates)
        : signatureValid(xml, root, registration.info.signingCertificates);
    if (!valid) {
      res.status(400).type("text/plain").send("invalid signature");
      return;
    }
    if (!isRequest) {
      const status = descendants(root, NS.samlp, "StatusCode")[0];
      logoutResponses.push({
        binding,
        inResponseTo: attr(root, "InResponseTo"),
        status: attr(status, "Value"),
      });
      res
        .type("text/html")
        .send(
          '<!doctype html><title>Signed out</title><p data-testid="idp-logged-out">Signed out.</p>',
        );
      return;
    }
    const nameId = textOf(children(root, NS.saml, "NameID")[0]);
    const sessionIndex = textOf(children(root, NS.samlp, "SessionIndex")[0]) || undefined;
    logoutRequests.push({ spEntityId, binding, nameId, sessionIndex });
    for (const [cookie, session] of sessions) {
      const persona = personas.find((candidate) => candidate.id === session.personaId);
      if (persona?.nameId === nameId) sessions.delete(cookie);
    }
    const relayState = typeof source.RelayState === "string" ? source.RelayState : undefined;
    const viaPost = binding === "post" || registration.info.sloRedirect === undefined;
    const location = viaPost ? registration.info.sloPost : registration.info.sloRedirect;
    if (location === undefined) {
      res.status(400).type("text/plain").send("SP has no SLO endpoint");
      return;
    }
    const response = el(
      "saml2p:LogoutResponse",
      {
        "xmlns:saml2p": NS.samlp,
        "xmlns:saml2": NS.saml,
        ID: newId(),
        Version: "2.0",
        IssueInstant: iso(new Date()),
        Destination: location,
        InResponseTo: attr(root, "ID"),
      },
      text("saml2:Issuer", {}, entityId),
      el("saml2p:Status", {}, el("saml2p:StatusCode", { Value: STATUS.success })),
    );
    if (!viaPost) {
      res.redirect(303, redirectUrl(location, "SAMLResponse", response, relayState));
      return;
    }
    const signed = sign(response, "/*[local-name(.)='LogoutResponse']");
    res
      .status(200)
      .type("text/html")
      .send(
        autoPostPage(location, {
          SAMLResponse: Buffer.from(signed, "utf8").toString("base64"),
          ...(relayState === undefined ? {} : { RelayState: relayState }),
        }),
      );
  }

  router.get("/slo", (req, res, next) => {
    handleSlo(req, res, "redirect").catch(next);
  });
  router.post("/slo", (req, res, next) => {
    handleSlo(req, res, "post").catch(next);
  });

  const logoutRequestXml = (
    spEntityId: string,
    location: string,
    subject: { readonly nameId: string; readonly sessionIndex?: string },
  ): string =>
    el(
      "saml2p:LogoutRequest",
      {
        "xmlns:saml2p": NS.samlp,
        "xmlns:saml2": NS.saml,
        ID: newId(),
        Version: "2.0",
        IssueInstant: iso(new Date()),
        Destination: location,
        NotOnOrAfter: iso(new Date(Date.now() + 5 * 60_000)),
      },
      text("saml2:Issuer", {}, entityId),
      text(
        "saml2:NameID",
        { Format: PERSISTENT, NameQualifier: entityId, SPNameQualifier: spEntityId },
        subject.nameId,
      ),
      ...(subject.sessionIndex === undefined
        ? []
        : [text("saml2p:SessionIndex", {}, subject.sessionIndex)]),
    );

  return {
    flavour,
    name,
    keyType,
    entityId,
    metadataUrl: `${base}/metadata`,
    router,
    signingCertificate: signing.certificate,
    metadataSigningCertificate: metadataKey.certificate,
    personas,
    async registerSp(spEntityId, registration = {}) {
      await register(spEntityId, {
        ...registration,
        pinned: registration.metadataXml !== undefined,
      });
    },
    forgetSp(spEntityId) {
      sps.delete(spEntityId);
    },
    prepare(spEntityId, next) {
      const queue = prepared.get(spEntityId) ?? [];
      queue.push(next);
      prepared.set(spEntityId, queue);
    },
    requests: () => [...received],
    setMetadataMode(mode) {
      metadataMode = mode;
    },
    setSloBindings(bindings) {
      sloBindings = [...bindings];
    },
    logoutRequests: () => [...logoutRequests],
    logoutResponses: () => [...logoutResponses],
    async initiateLogout(spEntityId, subject, options = {}) {
      const registration = await spOf(spEntityId);
      const location = registration.info.sloRedirect;
      if (location === undefined) throw new Error("SP has no HTTP-Redirect SLO endpoint");
      const xml = logoutRequestXml(spEntityId, options.destination ?? location, subject);
      return redirectUrl(
        location,
        "SAMLRequest",
        options.dtd === true ? `${DTD}${xml}` : xml,
        randomBytes(8).toString("hex"),
      );
    },
    async initiateLogoutPost(spEntityId, subject) {
      const registration = await spOf(spEntityId);
      const location = registration.info.sloPost;
      if (location === undefined) throw new Error("SP has no HTTP-POST SLO endpoint");
      const signed = sign(
        logoutRequestXml(spEntityId, location, subject),
        "/*[local-name(.)='LogoutRequest']",
      );
      return {
        action: location,
        fields: {
          SAMLRequest: Buffer.from(signed, "utf8").toString("base64"),
          RelayState: randomBytes(8).toString("hex"),
        },
      };
    },
    clearSessions() {
      sessions.clear();
    },
  };
}
