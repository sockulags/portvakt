import type { LoginMethod } from "./types";

/**
 * Form logic of the login method editor, kept free of React so it can be tested: drafts (what
 * the form fields hold, as strings and booleans), client-side validation (the server validates
 * again and its field errors are mapped back to the form), and the request bodies.
 */

export type ValidationCode =
  | "required"
  | "url"
  | "https"
  | "number"
  | "idle_exceeds_max"
  | "domain"
  | "slug"
  | "certificate"
  | "openid"
  | "date";

/** Field errors: a {@link ValidationCode}, or a message of the server. */
export type Errors<F extends string = string> = Partial<Record<F, string>>;

interface CommonDraft {
  displayName: string;
  kind: "employee" | "citizen";
  assertedAcr: string;
  homeRealmDomains: string;
  maxAgeMinutes: string;
  idleMinutes: string;
  allowSso: boolean;
  linkByPin: boolean;
  trustPinForRepresentation: boolean;
  enabled: boolean;
}

export interface OidcDraft extends CommonDraft {
  protocol: "oidc";
  issuer: string;
  clientId: string;
  /** Write-only: empty keeps the stored secret. */
  clientSecret: string;
  clientAuthMethod: "client_secret_basic" | "client_secret_post" | "private_key_jwt";
  scopes: string;
  subjectClaim: string;
  nameClaim: string;
  emailClaim: string;
  pinClaim: string;
  groupsClaim: string;
  acrClaim: string;
  trustUpstreamEmail: boolean;
  /** `YYYY-MM-DD` or empty. */
  secretExpiresAt: string;
}

export interface SamlDraft extends CommonDraft {
  protocol: "saml";
  idpEntityId: string;
  metadataSource: "url" | "xml";
  metadataUrl: string;
  /** Inline metadata; empty keeps the stored document. */
  metadataXml: string;
  metadataSigningCertificate: string;
  allowUnsignedMetadata: boolean;
  requestedLoa: string;
  subjectSource: "personalIdentityNumber" | "prid" | "employeeHsaId" | "nameId";
  entityCategories: string;
  uiDisplayName: string;
  uiDescription: string;
  logoUrl: string;
  logoWidth: string;
  logoHeight: string;
  requireEncryptedAssertions: boolean;
  requireSignedResponse: boolean;
  trustEmail: boolean;
}

export type LoginMethodDraft = OidcDraft | SamlDraft;

export const EMPLOYEE_ACR = "urn:portvakt:acr:employee";
export const LOA3 = "http://id.elegnamnden.se/loa/1.0/loa3";

const common = (kind: "employee" | "citizen"): CommonDraft => ({
  displayName: "",
  kind,
  assertedAcr: kind === "employee" ? EMPLOYEE_ACR : LOA3,
  homeRealmDomains: "",
  maxAgeMinutes: kind === "employee" ? "480" : "60",
  idleMinutes: kind === "employee" ? "60" : "15",
  allowSso: true,
  linkByPin: kind === "citizen",
  trustPinForRepresentation: false,
  enabled: true,
});

export function emptyDraft(protocol: "oidc" | "saml"): LoginMethodDraft {
  if (protocol === "oidc") {
    return {
      ...common("employee"),
      protocol,
      issuer: "",
      clientId: "",
      clientSecret: "",
      clientAuthMethod: "client_secret_basic",
      scopes: "openid profile email",
      subjectClaim: "sub",
      nameClaim: "name",
      emailClaim: "email",
      pinClaim: "",
      groupsClaim: "",
      acrClaim: "",
      trustUpstreamEmail: false,
      secretExpiresAt: "",
    };
  }
  return {
    ...common("citizen"),
    protocol,
    idpEntityId: "",
    metadataSource: "url",
    metadataUrl: "",
    metadataXml: "",
    metadataSigningCertificate: "",
    allowUnsignedMetadata: false,
    requestedLoa: LOA3,
    subjectSource: "personalIdentityNumber",
    entityCategories: "",
    uiDisplayName: "",
    uiDescription: "",
    logoUrl: "",
    logoWidth: "",
    logoHeight: "",
    requireEncryptedAssertions: true,
    requireSignedResponse: true,
    trustEmail: false,
  };
}

const minutes = (seconds: number): string => String(Math.round(seconds / 60));

export function draftFromMethod(method: LoginMethod): LoginMethodDraft {
  const base: CommonDraft = {
    displayName: method.displayName,
    kind: method.kind,
    assertedAcr: method.assertedAcr,
    homeRealmDomains: method.homeRealmDomains.join(", "),
    maxAgeMinutes: minutes(method.sessionPolicy.maxAgeSeconds),
    idleMinutes: minutes(method.sessionPolicy.idleSeconds),
    allowSso: method.sessionPolicy.allowSso,
    linkByPin: method.linkByPin,
    trustPinForRepresentation: method.trustPinForRepresentation,
    enabled: method.enabled,
  };
  if (method.protocol === "oidc" && method.oidc !== undefined) {
    const oidc = method.oidc;
    return {
      ...base,
      protocol: "oidc",
      issuer: oidc.issuer,
      clientId: oidc.clientId,
      clientSecret: "",
      clientAuthMethod: oidc.clientAuthMethod,
      scopes: oidc.scopes.join(" "),
      subjectClaim: oidc.claimMapping.subject ?? "sub",
      nameClaim: oidc.claimMapping.name ?? "",
      emailClaim: oidc.claimMapping.email ?? "",
      pinClaim: oidc.claimMapping.pin ?? "",
      groupsClaim: oidc.claimMapping.groups ?? "",
      acrClaim: oidc.claimMapping.acr ?? "",
      trustUpstreamEmail: oidc.trustUpstreamEmail,
      secretExpiresAt: method.secretExpiresAt?.slice(0, 10) ?? "",
    };
  }
  const saml = method.saml!;
  const logo = saml.uiInfo.logos?.[0];
  return {
    ...base,
    protocol: "saml",
    idpEntityId: saml.idpEntityId,
    metadataSource: saml.hasInlineMetadata ? "xml" : "url",
    metadataUrl: saml.metadataUrl ?? "",
    metadataXml: "",
    metadataSigningCertificate: saml.metadataSigningCertificate ?? "",
    allowUnsignedMetadata: saml.allowUnsignedMetadata,
    requestedLoa: saml.requestedLoa.join("\n"),
    subjectSource: saml.subjectSource,
    entityCategories: saml.entityCategories.join("\n"),
    uiDisplayName: saml.uiInfo.displayName?.sv ?? "",
    uiDescription: saml.uiInfo.description?.sv ?? "",
    logoUrl: logo?.url ?? "",
    logoWidth: logo === undefined ? "" : String(logo.width),
    logoHeight: logo === undefined ? "" : String(logo.height),
    requireEncryptedAssertions: saml.requireEncryptedAssertions,
    requireSignedResponse: saml.requireSignedResponse,
    trustEmail: saml.trustEmail,
  };
}

const words = (value: string): string[] => value.split(/[\s,]+/).filter((item) => item !== "");
const lines = (value: string): string[] =>
  value
    .split(/\r?\n/)
    .map((item) => item.trim())
    .filter((item) => item !== "");

export function isHttpUrl(value: string): boolean {
  if (!URL.canParse(value)) return false;
  const url = new URL(value);
  return (url.protocol === "https:" || url.protocol === "http:") && url.hash === "";
}

const DOMAIN = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/;
const POSITIVE = /^[1-9]\d{0,6}$/;
export const SLUG = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

/** Client-side validation: the field names are the draft's, the values validation codes. */
export function validateDraft(draft: LoginMethodDraft, creating: boolean): Errors {
  const errors: Errors = {};
  if (draft.displayName.trim() === "") errors.displayName = "required";
  if (draft.assertedAcr.trim() === "") errors.assertedAcr = "required";
  for (const domain of words(draft.homeRealmDomains)) {
    if (!DOMAIN.test(domain.toLowerCase())) errors.homeRealmDomains = "domain";
  }
  if (!POSITIVE.test(draft.maxAgeMinutes)) errors.maxAgeMinutes = "number";
  if (!POSITIVE.test(draft.idleMinutes)) errors.idleMinutes = "number";
  else if (
    POSITIVE.test(draft.maxAgeMinutes) &&
    Number(draft.idleMinutes) > Number(draft.maxAgeMinutes)
  ) {
    errors.idleMinutes = "idle_exceeds_max";
  }
  if (draft.protocol === "oidc") {
    if (!isHttpUrl(draft.issuer)) errors.issuer = draft.issuer === "" ? "required" : "url";
    if (draft.clientId.trim() === "") errors.clientId = "required";
    if (!words(draft.scopes).includes("openid")) errors.scopes = "openid";
    if (draft.subjectClaim.trim() === "") errors.subjectClaim = "required";
    if (draft.secretExpiresAt !== "" && !/^\d{4}-\d{2}-\d{2}$/.test(draft.secretExpiresAt)) {
      errors.secretExpiresAt = "date";
    }
    if (creating && draft.clientAuthMethod !== "private_key_jwt" && draft.clientSecret === "") {
      errors.clientSecret = "required";
    }
    return errors;
  }
  if (draft.idpEntityId.trim() === "") errors.idpEntityId = "required";
  if (draft.metadataSource === "url") {
    if (!isHttpUrl(draft.metadataUrl))
      errors.metadataUrl = draft.metadataUrl === "" ? "required" : "url";
  } else if (creating && draft.metadataXml.trim() === "") {
    errors.metadataXml = "required";
  }
  const certificate = draft.metadataSigningCertificate.trim();
  if (
    certificate !== "" &&
    !/^-----BEGIN CERTIFICATE-----[\s\S]+-----END CERTIFICATE-----$/.test(certificate)
  ) {
    errors.metadataSigningCertificate = "certificate";
  }
  if (lines(draft.requestedLoa).length === 0) errors.requestedLoa = "required";
  if (draft.logoUrl !== "") {
    if (!draft.logoUrl.startsWith("https://") || !isHttpUrl(draft.logoUrl))
      errors.logoUrl = "https";
    if (!POSITIVE.test(draft.logoWidth)) errors.logoWidth = "number";
    if (!POSITIVE.test(draft.logoHeight)) errors.logoHeight = "number";
  }
  return errors;
}

const optional = (value: string): string | undefined =>
  value.trim() === "" ? undefined : value.trim();

function commonBody(draft: LoginMethodDraft) {
  return {
    kind: draft.kind,
    displayName: draft.displayName.trim(),
    assertedAcr: draft.assertedAcr.trim(),
    homeRealmDomains: words(draft.homeRealmDomains).map((domain) => domain.toLowerCase()),
    sessionPolicy: {
      maxAgeSeconds: Number(draft.maxAgeMinutes) * 60,
      idleSeconds: Number(draft.idleMinutes) * 60,
      allowSso: draft.allowSso,
    },
    linkByPin: draft.linkByPin,
    trustPinForRepresentation: draft.trustPinForRepresentation,
    enabled: draft.enabled,
  };
}

function oidcBody(draft: OidcDraft) {
  const claimMapping: Record<string, string> = { subject: draft.subjectClaim.trim() };
  for (const [key, value] of [
    ["name", draft.nameClaim],
    ["email", draft.emailClaim],
    ["pin", draft.pinClaim],
    ["groups", draft.groupsClaim],
    ["acr", draft.acrClaim],
  ] as const) {
    const claim = optional(value);
    if (claim !== undefined) claimMapping[key] = claim;
  }
  return {
    issuer: draft.issuer.trim(),
    clientId: draft.clientId.trim(),
    clientAuthMethod: draft.clientAuthMethod,
    scopes: words(draft.scopes),
    claimMapping,
    trustUpstreamEmail: draft.trustUpstreamEmail,
    secretExpiresAt:
      draft.secretExpiresAt === ""
        ? null
        : new Date(`${draft.secretExpiresAt}T00:00:00Z`).toISOString(),
  };
}

function samlBody(draft: SamlDraft, creating: boolean) {
  const uiDescription = optional(draft.uiDescription);
  const uiDisplayName = optional(draft.uiDisplayName);
  return {
    idpEntityId: draft.idpEntityId.trim(),
    ...(draft.metadataSource === "url"
      ? { metadataUrl: draft.metadataUrl.trim(), ...(creating ? {} : { metadataXml: null }) }
      : draft.metadataXml.trim() === ""
        ? {}
        : { metadataXml: draft.metadataXml, ...(creating ? {} : { metadataUrl: null }) }),
    metadataSigningCertificate: optional(draft.metadataSigningCertificate) ?? null,
    allowUnsignedMetadata:
      draft.metadataSource === "url" &&
      draft.metadataSigningCertificate.trim() === "" &&
      draft.allowUnsignedMetadata,
    requestedLoa: lines(draft.requestedLoa),
    subjectSource: draft.subjectSource,
    entityCategories: lines(draft.entityCategories),
    requireEncryptedAssertions: draft.requireEncryptedAssertions,
    requireSignedResponse: draft.requireSignedResponse,
    trustEmail: draft.trustEmail,
    uiInfo: {
      ...(uiDisplayName === undefined ? {} : { displayName: { sv: uiDisplayName } }),
      ...(uiDescription === undefined ? {} : { description: { sv: uiDescription } }),
      logos:
        draft.logoUrl === ""
          ? []
          : [
              {
                url: draft.logoUrl.trim(),
                width: Number(draft.logoWidth),
                height: Number(draft.logoHeight),
              },
            ],
    },
  };
}

/** The body of `POST /tenants/{id}/login-methods`. */
export function createBody(draft: LoginMethodDraft): Record<string, unknown> {
  if (draft.protocol === "oidc") {
    return {
      protocol: "oidc",
      ...commonBody(draft),
      ...oidcBody(draft),
      ...(draft.clientSecret === "" ? {} : { clientSecret: draft.clientSecret }),
    };
  }
  return { protocol: "saml", ...commonBody(draft), saml: samlBody(draft, true) };
}

/** The body of `PATCH .../login-methods/{id}`: the whole configuration, the secret only if typed. */
export function updateBody(draft: LoginMethodDraft): Record<string, unknown> {
  if (draft.protocol === "oidc") {
    return {
      ...commonBody(draft),
      ...oidcBody(draft),
      ...(draft.clientSecret === "" ? {} : { clientSecret: draft.clientSecret }),
    };
  }
  return { ...commonBody(draft), saml: samlBody(draft, false) };
}

/** The draft field a server field error belongs to (`saml.metadataUrl` -> `metadataUrl`). */
export function draftFieldOf(serverField: string): string {
  const map: Record<string, string> = {
    "sessionPolicy.maxAgeSeconds": "maxAgeMinutes",
    "sessionPolicy.idleSeconds": "idleMinutes",
    "claimMapping.subject": "subjectClaim",
    "claimMapping.acr": "acrClaim",
    "claimMapping.pin": "pinClaim",
    "saml.uiInfo.logos": "logoUrl",
    "saml.metadata": "metadataUrl",
  };
  if (map[serverField] !== undefined) return map[serverField];
  const prefix = Object.keys(map).find((key) => serverField.startsWith(`${key}.`));
  if (prefix !== undefined) return map[prefix]!;
  const parts = serverField.split(".");
  if (parts[0] === "saml" && parts[1] !== undefined) return parts[1];
  return parts[0] ?? serverField;
}

/** Validation of the tenant form (slug and name). */
export function validateTenant(slug: string, name: string): Errors<"slug" | "name"> {
  const errors: Errors<"slug" | "name"> = {};
  if (!SLUG.test(slug) || slug.length < 2) errors.slug = slug === "" ? "required" : "slug";
  if (name.trim() === "") errors.name = "required";
  return errors;
}
