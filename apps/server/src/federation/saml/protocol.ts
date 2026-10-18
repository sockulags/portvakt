import { randomBytes } from "node:crypto";
import { SAML, ValidateInResponseTo, type SamlConfig } from "@node-saml/node-saml";
import {
  PRINCIPAL_SELECTION_NS,
  SAML_ATTRIBUTES,
  SAML_STATUS,
  type SamlComparison,
} from "../../domain/saml.js";
import { decryptAssertion, DecryptionError } from "./decrypt.js";
import type { IdpMetadata } from "./metadata.js";
import { parseRedirectBinding, RedirectBindingError, redirectSignatureValid } from "./redirect.js";
import {
  attribute,
  buildXml,
  LOGOUT_LIMITS,
  RESPONSE_LIMITS,
  child,
  children,
  NS,
  parseXml,
  rootOf,
  signEnveloped,
  textOf,
  verifiedXml,
  XmlError,
  type XmlLimits,
} from "./xml.js";

/**
 * SAML 2.0 Web Browser SSO and single logout messages. Outgoing requests are built and signed by
 * node-saml (AuthnRequest over HTTP-Redirect with SigAlg or HTTP-POST with an enveloped
 * signature; LogoutRequest and LogoutResponse over HTTP-Redirect), HTTP-POST logout messages
 * with node-saml's signing helper. Incoming messages are verified with xml-crypto and the
 * allowlisted algorithms (`xml.ts`, `algorithms.ts`), decrypted with `decrypt.ts`, and read only
 * from the signed bytes. The pending request lives in `federation_states` (single use, per
 * tenant and login method) and is checked by the caller against the values returned here.
 */

export interface SpEndpoints {
  /** SP entityID: `{PUBLIC_URL}/t/{slug}/saml/{loginMethodId}`. */
  readonly entityId: string;
  readonly acsUrl: string;
  readonly sloUrl: string;
}

/** The SP's active signing key pair. */
export interface SpSigner {
  readonly privateKey: string;
  readonly certificate: string;
}

/** A fresh SAML ID (xs:ID: must not start with a digit). */
export const newSamlId = (): string => `_${randomBytes(20).toString("hex")}`;

/** RelayState: an opaque reference to the pending request (80 characters at most per binding). */
export const newRelayState = (): string => randomBytes(32).toString("base64url");

const iso = (time: number): string => new Date(time).toISOString().replace(/\.\d{3}Z$/, "Z");

/** Limits on values read from IdP messages (longer ones refuse the message). */
const LIMITS = {
  id: 256,
  nameId: 1024,
  qualifier: 1024,
  format: 255,
  sessionIndex: 1024,
  classRef: 1024,
  attributeName: 255,
  attributeValue: 2048,
  attributeValues: 100,
  attributes: 200,
} as const;

/** Why a message was refused; the reason is a fixed code, safe to log and audit. */
export class ResponseRejected extends Error {
  readonly reason: string;

  constructor(reason: string, message: string) {
    super(message);
    this.name = "ResponseRejected";
    this.reason = reason;
  }
}

const bounded = (value: string | undefined, max: number): string | undefined => {
  if (value !== undefined && value.length > max) {
    throw new ResponseRejected("value_too_long", "a value in the message is too long");
  }
  return value;
};

const baseConfig = (
  sp: SpEndpoints,
  idp: IdpMetadata,
  signer: SpSigner,
): Omit<SamlConfig, "entryPoint"> => ({
  issuer: sp.entityId,
  callbackUrl: sp.acsUrl,
  audience: sp.entityId,
  idpCert: [...idp.signingCertificates],
  idpIssuer: idp.entityId,
  privateKey: signer.privateKey,
  publicCert: signer.certificate,
  signatureAlgorithm: "sha256",
  digestAlgorithm: "sha256",
  // No NameIDPolicy Format: the IdP's default (persistent per the Deployment Profile).
  identifierFormat: null,
  validateInResponseTo: ValidateInResponseTo.never,
  wantAssertionsSigned: true,
});

export interface AuthnRequestInput {
  readonly requestId: string;
  readonly relayState: string;
  readonly binding: "redirect" | "post";
  readonly forceAuthn: boolean;
  readonly requestedLoa: readonly string[];
  readonly comparison: SamlComparison;
  /** PrincipalSelection: the personal identity number of the person expected to sign in. */
  readonly principalPin: string | undefined;
}

export type OutgoingMessage =
  | { readonly binding: "redirect"; readonly url: string }
  | {
      readonly binding: "post";
      readonly url: string;
      readonly fields: Readonly<Record<string, string>>;
    };

/** Builds the signed AuthnRequest of a pending request for the IdP's SSO endpoint. */
export async function buildAuthnRequest(
  sp: SpEndpoints,
  idp: IdpMetadata,
  signer: SpSigner,
  input: AuthnRequestInput,
): Promise<OutgoingMessage> {
  const entryPoint = input.binding === "post" ? idp.sso.post : idp.sso.redirect;
  if (entryPoint === null) throw new Error("IdP has no SSO endpoint for this binding");
  if (input.principalPin !== undefined && input.binding !== "post") {
    // A personal identity number never goes into a URL.
    throw new Error("PrincipalSelection needs the HTTP-POST binding");
  }
  const saml = new SAML({
    ...baseConfig(sp, idp, signer),
    entryPoint,
    generateUniqueId: () => input.requestId,
    forceAuthn: input.forceAuthn,
    authnContext: [...input.requestedLoa],
    racComparison: input.comparison,
    authnRequestBinding: input.binding === "post" ? "HTTP-POST" : "HTTP-Redirect",
    // HTTP-POST carries the request base64 without DEFLATE (bindings 3.5.4).
    skipRequestCompression: input.binding === "post",
    ...(input.principalPin === undefined
      ? {}
      : {
          samlAuthnRequestExtensions: {
            "psc:PrincipalSelection": {
              "@xmlns:psc": PRINCIPAL_SELECTION_NS,
              "psc:MatchValue": {
                "@Name": SAML_ATTRIBUTES.personalIdentityNumber,
                "#text": input.principalPin,
              },
            },
          },
        }),
  });
  if (input.binding === "redirect") {
    return {
      binding: "redirect",
      url: await saml.getAuthorizeUrlAsync(input.relayState, undefined, {}),
    };
  }
  const message = await saml.getAuthorizeMessageAsync(input.relayState, undefined, {});
  const fields: Record<string, string> = {};
  for (const [key, value] of Object.entries(message)) {
    if (typeof value === "string") fields[key] = value;
  }
  return { binding: "post", url: entryPoint, fields };
}

/** Status of a SAML response or logout response: top-level and second-level codes. */
export interface SamlStatus {
  readonly code: string;
  readonly subCode: string | undefined;
}

function statusOf(element: Element): SamlStatus | undefined {
  const status = child(element, NS.samlp, "Status");
  if (status === undefined) return undefined;
  const top = child(status, NS.samlp, "StatusCode");
  if (top === undefined) return undefined;
  const sub = child(top, NS.samlp, "StatusCode");
  return {
    code: attribute(top, "Value") ?? "",
    subCode: sub === undefined ? undefined : attribute(sub, "Value"),
  };
}

/**
 * A posted Response before the assertion is validated. When the Response is signed, every value
 * here comes from its signed bytes; otherwise from the received XML (and is then only used for
 * pre-checks that refuse, never to accept).
 */
export interface ResponseEnvelope {
  readonly xml: string;
  /** The signed bytes of the Response (its signature verified), `null` when not signed. */
  readonly signedXml: string | null;
  readonly status: SamlStatus | undefined;
  readonly inResponseTo: string | undefined;
  readonly destination: string | undefined;
  readonly issuer: string | undefined;
  readonly hasEncryptedAssertion: boolean;
  readonly hasPlainAssertion: boolean;
  /** Assertions plus encrypted assertions directly in the Response. */
  readonly assertionCount: number;
  readonly responseSigned: boolean;
}

/** Decodes, parses and checks the signature of a posted SAMLResponse. */
export async function readResponse(
  samlResponse: string,
  idp: IdpMetadata,
  limits: XmlLimits = RESPONSE_LIMITS,
): Promise<ResponseEnvelope> {
  if (samlResponse.length > Math.ceil((limits.maxBytes * 4) / 3) + 8) {
    throw new XmlError("too_large", "SAML response too large");
  }
  if (!/^[A-Za-z0-9+/=\s]+$/.test(samlResponse)) throw new XmlError("malformed", "not base64");
  const xml = Buffer.from(samlResponse, "base64").toString("utf8");
  const received = rootOf(await parseXml(xml, limits));
  if (received.localName !== "Response" || received.namespaceURI !== NS.samlp) {
    throw new XmlError("not_a_response", "not a SAML Response");
  }
  const signedXml = verifiedXml(xml, received, idp.signingCertificates);
  const root = signedXml === null ? received : rootOf(await parseXml(signedXml, limits));
  const plain = children(root, NS.saml, "Assertion").length;
  const encrypted = children(root, NS.saml, "EncryptedAssertion").length;
  const issuer = child(root, NS.saml, "Issuer");
  return {
    xml,
    signedXml,
    status: statusOf(root),
    inResponseTo: attribute(root, "InResponseTo"),
    destination: attribute(root, "Destination"),
    issuer: issuer === undefined ? undefined : textOf(issuer),
    hasEncryptedAssertion: encrypted > 0,
    hasPlainAssertion: plain > 0,
    assertionCount: plain + encrypted,
    responseSigned: signedXml !== null,
  };
}

/** A validated assertion: everything below comes from the signed (decrypted) assertion. */
export interface ValidatedAssertion {
  readonly id: string;
  readonly issuer: string;
  readonly issueInstant: number;
  readonly nameId: string | undefined;
  readonly nameIdFormat: string | undefined;
  readonly nameQualifier: string | undefined;
  readonly spNameQualifier: string | undefined;
  readonly sessionIndex: string | undefined;
  /** Epoch milliseconds. */
  readonly authnInstant: number;
  readonly authnContextClassRef: string;
  /** Bearer SubjectConfirmationData values. */
  readonly confirmation: {
    readonly inResponseTo: string | undefined;
    readonly recipient: string | undefined;
    readonly notOnOrAfter: number | undefined;
    readonly notBefore: number | undefined;
  };
  /** Latest NotOnOrAfter of the assertion (Conditions, SubjectConfirmationData). */
  readonly notOnOrAfter: number;
  readonly attributes: Readonly<Record<string, readonly string[]>>;
}

const BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

function epochOf(value: string | undefined): number | undefined {
  if (value === undefined) return undefined;
  const time = Date.parse(value);
  return Number.isFinite(time) ? time : Number.NaN;
}

/**
 * Validates the assertion of a Response: the Response's signature when required, exactly one
 * Assertion or EncryptedAssertion, decryption with the SP's keys (`decryptionKeys`, active
 * first), the assertion's own signature (always required), Conditions NotBefore/NotOnOrAfter
 * with the skew and every AudienceRestriction naming the SP. Returns the values of the signed
 * assertion. Throws {@link ResponseRejected}.
 */
export async function validateResponse(
  sp: SpEndpoints,
  idp: IdpMetadata,
  envelope: ResponseEnvelope,
  options: {
    readonly requireSignedResponse: boolean;
    readonly decryptionKeys: readonly string[];
    readonly requireGcm: boolean;
    readonly clockSkewSeconds: number;
    readonly now: number;
    readonly limits?: XmlLimits;
  },
): Promise<ValidatedAssertion> {
  const limits = options.limits ?? RESPONSE_LIMITS;
  if (options.requireSignedResponse && envelope.signedXml === null) {
    throw new ResponseRejected("response_not_signed", "the Response is not signed");
  }
  const base = envelope.signedXml ?? envelope.xml;
  const response = rootOf(await parseXml(base, limits));
  const plain = children(response, NS.saml, "Assertion");
  const encrypted = children(response, NS.saml, "EncryptedAssertion");
  if (plain.length + encrypted.length !== 1) {
    throw new ResponseRejected("assertion_count", "not exactly one assertion");
  }

  let signed: string | null;
  if (encrypted[0] !== undefined) {
    let assertionXml: string;
    try {
      assertionXml = await decryptAssertion(encrypted[0], options.decryptionKeys, {
        // AES-CBC (no integrity of its own) only inside a required, verified Response signature.
        requireGcm:
          options.requireGcm || !(options.requireSignedResponse && envelope.signedXml !== null),
        limits,
      });
    } catch (error) {
      if (error instanceof DecryptionError || error instanceof XmlError) {
        throw new ResponseRejected(error.reason, "the assertion could not be decrypted");
      }
      throw error;
    }
    signed = verifiedXml(
      assertionXml,
      rootOf(await parseXml(assertionXml, limits)),
      idp.signingCertificates,
    );
  } else {
    signed = verifiedXml(base, plain[0]!, idp.signingCertificates);
  }
  if (signed === null) throw new ResponseRejected("signature_invalid", "assertion not signed");

  // Only the signed (and decrypted) assertion bytes are read from here on.
  const assertion = rootOf(await parseXml(signed, limits));
  if (assertion.localName !== "Assertion" || assertion.namespaceURI !== NS.saml) {
    throw new ResponseRejected("no_assertion", "signed content is not an assertion");
  }
  const id = bounded(attribute(assertion, "ID"), LIMITS.id);
  const issuerElement = child(assertion, NS.saml, "Issuer");
  const issueInstant = epochOf(attribute(assertion, "IssueInstant"));
  if (id === undefined || issuerElement === undefined || issueInstant === undefined) {
    throw new ResponseRejected("response_invalid", "assertion without ID, Issuer or IssueInstant");
  }

  const skew = options.clockSkewSeconds * 1000;
  const conditions = child(assertion, NS.saml, "Conditions");
  if (conditions === undefined) throw new ResponseRejected("response_invalid", "no Conditions");
  const notBefore = epochOf(attribute(conditions, "NotBefore"));
  const conditionsEnd = epochOf(attribute(conditions, "NotOnOrAfter"));
  if (
    Number.isNaN(notBefore ?? 0) ||
    Number.isNaN(conditionsEnd ?? 0) ||
    (notBefore !== undefined && options.now + skew < notBefore) ||
    (conditionsEnd !== undefined && options.now - skew >= conditionsEnd)
  ) {
    throw new ResponseRejected("assertion_expired", "outside the assertion's Conditions");
  }
  const restrictions = children(conditions, NS.saml, "AudienceRestriction");
  if (
    restrictions.length === 0 ||
    !restrictions.every((restriction) =>
      children(restriction, NS.saml, "Audience").some(
        (audience) => textOf(audience) === sp.entityId,
      ),
    )
  ) {
    throw new ResponseRejected("audience_mismatch", "the SP is not the assertion's audience");
  }

  const subject = child(assertion, NS.saml, "Subject");
  if (subject === undefined) throw new ResponseRejected("response_invalid", "no Subject");
  const nameIdElement = child(subject, NS.saml, "NameID");
  if (child(subject, NS.saml, "EncryptedID") !== undefined) {
    // The Deployment Profile forbids EncryptedID (the assertion itself is encrypted).
    throw new ResponseRejected("response_invalid", "EncryptedID is not supported");
  }
  const confirmations = children(subject, NS.saml, "SubjectConfirmation").filter(
    (confirmation) => attribute(confirmation, "Method") === BEARER,
  );
  if (confirmations.length !== 1) {
    throw new ResponseRejected("response_invalid", "not exactly one bearer SubjectConfirmation");
  }
  const data = child(confirmations[0]!, NS.saml, "SubjectConfirmationData");
  if (data === undefined) {
    throw new ResponseRejected("response_invalid", "no SubjectConfirmationData");
  }

  const statements = children(assertion, NS.saml, "AuthnStatement");
  if (statements.length !== 1) {
    throw new ResponseRejected("response_invalid", "not exactly one AuthnStatement");
  }
  const statement = statements[0]!;
  const authnInstant = epochOf(attribute(statement, "AuthnInstant"));
  const context = child(statement, NS.saml, "AuthnContext");
  const classRef =
    context === undefined ? undefined : child(context, NS.saml, "AuthnContextClassRef");
  if (authnInstant === undefined || Number.isNaN(authnInstant) || classRef === undefined) {
    throw new ResponseRejected("response_invalid", "AuthnStatement without instant or context");
  }

  const confirmation = {
    inResponseTo: bounded(attribute(data, "InResponseTo"), LIMITS.id),
    recipient: attribute(data, "Recipient"),
    notOnOrAfter: epochOf(attribute(data, "NotOnOrAfter")),
    notBefore: epochOf(attribute(data, "NotBefore")),
  };
  const ends = [confirmation.notOnOrAfter, conditionsEnd].filter(
    (value): value is number => value !== undefined,
  );
  if (
    ends.length === 0 ||
    ends.some(Number.isNaN) ||
    Number.isNaN(issueInstant) ||
    Number.isNaN(confirmation.notBefore ?? 0)
  ) {
    throw new ResponseRejected("response_invalid", "assertion without a valid NotOnOrAfter");
  }

  // No prototype: attribute names come from the IdP (`__proto__`, `constructor`).
  const attributes = Object.create(null) as Record<string, string[]>;
  let count = 0;
  for (const statementElement of children(assertion, NS.saml, "AttributeStatement")) {
    for (const attr of children(statementElement, NS.saml, "Attribute")) {
      count += 1;
      const name = bounded(attribute(attr, "Name"), LIMITS.attributeName);
      if (name === undefined) continue;
      const values = children(attr, NS.saml, "AttributeValue")
        // Complex values (elements) are not used by the framework attributes Portvakt maps.
        .filter((value) => children(value, NS.saml, "NameID").length === 0)
        .map((value) => bounded(textOf(value), LIMITS.attributeValue) ?? "")
        .filter((value) => value.length > 0);
      const merged = [...(attributes[name] ?? []), ...values];
      if (merged.length > LIMITS.attributeValues || count > LIMITS.attributes) {
        throw new ResponseRejected("value_too_long", "too many attribute values");
      }
      attributes[name] = merged;
    }
  }

  const nameId =
    nameIdElement === undefined ? undefined : bounded(textOf(nameIdElement), LIMITS.nameId);
  return {
    id,
    issuer: bounded(textOf(issuerElement), LIMITS.qualifier) ?? "",
    issueInstant,
    nameId: nameId === "" ? undefined : nameId,
    nameIdFormat:
      nameIdElement === undefined
        ? undefined
        : bounded(attribute(nameIdElement, "Format"), LIMITS.format),
    nameQualifier:
      nameIdElement === undefined
        ? undefined
        : bounded(attribute(nameIdElement, "NameQualifier"), LIMITS.qualifier),
    spNameQualifier:
      nameIdElement === undefined
        ? undefined
        : bounded(attribute(nameIdElement, "SPNameQualifier"), LIMITS.qualifier),
    sessionIndex: bounded(attribute(statement, "SessionIndex"), LIMITS.sessionIndex),
    authnInstant,
    authnContextClassRef: bounded(textOf(classRef), LIMITS.classRef) ?? "",
    confirmation,
    notOnOrAfter: Math.max(...ends),
    attributes,
  };
}

/** Whether a status says the person cancelled (framework second-level code). */
export const isCancel = (status: SamlStatus): boolean => status.subCode === SAML_STATUS.cancel;

// --- Single logout ------------------------------------------------------------------------

/** The upstream session a logout request names (from the login's assertion). */
export interface LogoutSubject {
  readonly nameId: string;
  readonly nameIdFormat: string | undefined;
  readonly nameQualifier: string | undefined;
  readonly spNameQualifier: string | undefined;
  readonly sessionIndex: string | undefined;
}

const PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";

/**
 * SP-initiated LogoutRequest to the IdP's SLO endpoint: HTTP-Redirect (signed query) when the
 * IdP offers it, else HTTP-POST (enveloped signature) as auto-submitted form fields.
 */
export async function buildLogoutRequest(
  sp: SpEndpoints,
  idp: IdpMetadata,
  signer: SpSigner,
  input: {
    readonly requestId: string;
    readonly relayState: string;
    readonly subject: LogoutSubject;
  },
): Promise<OutgoingMessage> {
  const { subject } = input;
  const redirect = idp.slo.redirect;
  if (redirect !== null) {
    const saml = new SAML({
      ...baseConfig(sp, idp, signer),
      entryPoint: redirect.location,
      logoutUrl: redirect.location,
      generateUniqueId: () => input.requestId,
    });
    const url = await saml.getLogoutUrlAsync(
      {
        issuer: idp.entityId,
        nameID: subject.nameId,
        nameIDFormat: subject.nameIdFormat ?? PERSISTENT,
        ...(subject.nameQualifier === undefined ? {} : { nameQualifier: subject.nameQualifier }),
        ...(subject.spNameQualifier === undefined
          ? {}
          : { spNameQualifier: subject.spNameQualifier }),
        ...(subject.sessionIndex === undefined ? {} : { sessionIndex: subject.sessionIndex }),
      },
      input.relayState,
      {},
    );
    return { binding: "redirect", url };
  }
  const post = idp.slo.post;
  if (post === null) throw new Error("IdP has no SLO endpoint");
  const xml = buildXml({
    "samlp:LogoutRequest": {
      "@xmlns:samlp": NS.samlp,
      "@xmlns:saml": NS.saml,
      "@ID": input.requestId,
      "@Version": "2.0",
      "@IssueInstant": iso(Date.now()),
      "@Destination": post.location,
      "saml:Issuer": { "#text": sp.entityId },
      "saml:NameID": {
        "@Format": subject.nameIdFormat ?? PERSISTENT,
        ...(subject.nameQualifier === undefined ? {} : { "@NameQualifier": subject.nameQualifier }),
        ...(subject.spNameQualifier === undefined
          ? {}
          : { "@SPNameQualifier": subject.spNameQualifier }),
        "#text": subject.nameId,
      },
      ...(subject.sessionIndex === undefined
        ? {}
        : { "samlp:SessionIndex": { "#text": subject.sessionIndex } }),
    },
  });
  const signed = signEnveloped(
    xml,
    "/*[local-name(.)='LogoutRequest']",
    signer.privateKey,
    signer.certificate,
    {
      afterIssuer: true,
    },
  );
  return {
    binding: "post",
    url: post.location,
    fields: {
      SAMLRequest: Buffer.from(signed, "utf8").toString("base64"),
      RelayState: input.relayState,
    },
  };
}

/** A logout message received at the SLO endpoint, after its signature was verified. */
export type IncomingLogout =
  | {
      readonly kind: "request";
      readonly id: string;
      readonly issuer: string;
      readonly nameId: string;
      readonly sessionIndexes: readonly string[];
      readonly issueInstant: number;
      readonly relayState: string | undefined;
      readonly binding: "redirect" | "post";
    }
  | {
      readonly kind: "response";
      /**
       * The signature was verified. A logout response only ever ends Portvakt's own redirect
       * chain, so an unverified one is logged and the logout continues.
       */
      readonly verified: boolean;
      readonly issuer: string | undefined;
      readonly inResponseTo: string | undefined;
      readonly status: SamlStatus | undefined;
      readonly relayState: string | undefined;
    };

/** Raw parameters of an SLO request: query (HTTP-Redirect) or form fields (HTTP-POST). */
export interface SloParameters {
  readonly binding: "redirect" | "post";
  readonly fields: Readonly<Record<string, string>>;
  /** HTTP-Redirect: the raw query string (the signature covers its exact encoding). */
  readonly rawQuery: string;
}

/** How far a LogoutRequest's IssueInstant may lie in the past (beyond the clock skew). */
const LOGOUT_REQUEST_MAX_AGE_MS = 5 * 60_000;

/**
 * Verifies and reads a LogoutRequest or LogoutResponse from the IdP. HTTP-Redirect messages are
 * parsed from the raw query (`redirect.ts`), HTTP-POST ones read from their signed bytes. A
 * LogoutRequest must be signed, be issued by the IdP, name the SP's SLO URL as Destination and
 * have a recent IssueInstant. Throws {@link ResponseRejected}.
 */
export async function readLogoutMessage(
  sp: SpEndpoints,
  idp: IdpMetadata,
  params: SloParameters,
  options: { readonly clockSkewSeconds: number; readonly now: number },
): Promise<IncomingLogout> {
  let xml: string;
  let isRequest: boolean;
  let relayState: string | undefined;
  let verified: boolean;
  let root: Element;
  if (params.binding === "redirect") {
    let message;
    try {
      message = parseRedirectBinding(params.rawQuery);
    } catch (error) {
      if (error instanceof RedirectBindingError) {
        throw new ResponseRejected(error.reason, "redirect binding message refused");
      }
      throw error;
    }
    xml = message.xml;
    isRequest = message.kind === "SAMLRequest";
    relayState = message.relayState;
    verified = redirectSignatureValid(message, idp.signingCertificates);
    if (isRequest && !verified) {
      throw new ResponseRejected(
        message.signature === undefined ? "signature_missing" : "signature_invalid",
        "logout request not signed by the IdP",
      );
    }
    root = rootOf(await parseXml(xml, LOGOUT_LIMITS));
  } else {
    const fields = params.fields;
    isRequest = typeof fields.SAMLRequest === "string";
    const message = isRequest ? fields.SAMLRequest : fields.SAMLResponse;
    if (
      typeof message !== "string" ||
      message.length === 0 ||
      message.length > Math.ceil((LOGOUT_LIMITS.maxBytes * 4) / 3) + 8
    ) {
      throw new ResponseRejected("malformed", "no SAML message");
    }
    if ((typeof fields.SAMLRequest === "string") === (typeof fields.SAMLResponse === "string")) {
      throw new ResponseRejected("message_count", "not exactly one SAML message");
    }
    relayState = typeof fields.RelayState === "string" ? fields.RelayState : undefined;
    xml = Buffer.from(message, "base64").toString("utf8");
    const received = rootOf(await parseXml(xml, LOGOUT_LIMITS));
    const signed = verifiedXml(xml, received, idp.signingCertificates);
    verified = signed !== null;
    if (isRequest && !verified) {
      throw new ResponseRejected("signature_invalid", "logout request not signed by the IdP");
    }
    // HTTP-POST: read the message from the signed bytes only.
    root = signed === null ? received : rootOf(await parseXml(signed, LOGOUT_LIMITS));
  }

  const issuerElement = child(root, NS.saml, "Issuer");
  const issuer = issuerElement === undefined ? undefined : textOf(issuerElement);
  if (isRequest) {
    if (root.localName !== "LogoutRequest" || root.namespaceURI !== NS.samlp) {
      throw new ResponseRejected("malformed", "not a LogoutRequest");
    }
    const id = bounded(attribute(root, "ID"), LIMITS.id);
    const nameId = child(root, NS.saml, "NameID");
    if (id === undefined || nameId === undefined || issuer !== idp.entityId) {
      throw new ResponseRejected("response_invalid", "LogoutRequest without ID, NameID or issuer");
    }
    if (attribute(root, "Destination") !== sp.sloUrl) {
      throw new ResponseRejected("destination_mismatch", "LogoutRequest for another endpoint");
    }
    const skew = options.clockSkewSeconds * 1000;
    const issueInstant = epochOf(attribute(root, "IssueInstant"));
    if (
      issueInstant === undefined ||
      Number.isNaN(issueInstant) ||
      issueInstant > options.now + skew ||
      options.now - issueInstant > LOGOUT_REQUEST_MAX_AGE_MS + skew
    ) {
      throw new ResponseRejected("assertion_expired", "LogoutRequest IssueInstant out of range");
    }
    const notOnOrAfter = epochOf(attribute(root, "NotOnOrAfter"));
    if (notOnOrAfter !== undefined && !(notOnOrAfter > options.now - skew)) {
      throw new ResponseRejected("assertion_expired", "LogoutRequest expired");
    }
    return {
      kind: "request",
      id,
      issuer,
      nameId: bounded(textOf(nameId), LIMITS.nameId) ?? "",
      sessionIndexes: children(root, NS.samlp, "SessionIndex")
        .map((index) => bounded(textOf(index), LIMITS.sessionIndex) ?? "")
        .slice(0, 20),
      issueInstant,
      relayState,
      binding: params.binding,
    };
  }
  if (root.localName !== "LogoutResponse" || root.namespaceURI !== NS.samlp) {
    throw new ResponseRejected("malformed", "not a LogoutResponse");
  }
  return {
    kind: "response",
    verified,
    issuer,
    inResponseTo: attribute(root, "InResponseTo"),
    status: statusOf(root),
    relayState,
  };
}

/**
 * The SP's signed LogoutResponse to an IdP-initiated LogoutRequest: HTTP-Redirect when the IdP
 * offers it, else HTTP-POST.
 */
export async function buildLogoutResponse(
  sp: SpEndpoints,
  idp: IdpMetadata,
  signer: SpSigner,
  request: { readonly id: string; readonly relayState: string | undefined },
  success: boolean,
): Promise<OutgoingMessage> {
  const redirect = idp.slo.redirect;
  if (redirect !== null) {
    const saml = new SAML({
      ...baseConfig(sp, idp, signer),
      entryPoint: redirect.responseLocation,
      logoutUrl: redirect.responseLocation,
    });
    const url = await saml.getLogoutResponseUrlAsync(
      { ID: request.id, issuer: idp.entityId, nameID: "", nameIDFormat: "" },
      request.relayState ?? "",
      {},
      success,
    );
    return { binding: "redirect", url };
  }
  const post = idp.slo.post;
  if (post === null) throw new Error("IdP has no SLO endpoint");
  const xml = buildXml({
    "samlp:LogoutResponse": {
      "@xmlns:samlp": NS.samlp,
      "@xmlns:saml": NS.saml,
      "@ID": newSamlId(),
      "@Version": "2.0",
      "@IssueInstant": iso(Date.now()),
      "@Destination": post.responseLocation,
      "@InResponseTo": request.id,
      "saml:Issuer": { "#text": sp.entityId },
      "samlp:Status": {
        "samlp:StatusCode": {
          "@Value": success ? SAML_STATUS.success : SAML_STATUS.responder,
        },
      },
    },
  });
  const signed = signEnveloped(
    xml,
    "/*[local-name(.)='LogoutResponse']",
    signer.privateKey,
    signer.certificate,
    {
      afterIssuer: true,
    },
  );
  return {
    binding: "post",
    url: post.responseLocation,
    fields: {
      SAMLResponse: Buffer.from(signed, "utf8").toString("base64"),
      ...(request.relayState === undefined ? {} : { RelayState: request.relayState }),
    },
  };
}
