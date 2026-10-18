import { z } from "zod";

/**
 * Identifiers of the Swedish eID Framework (Sweden Connect technical framework, DIGG), as used
 * by SAML login methods. Sources (docs.swedenconnect.se/technical-framework/latest):
 *
 * - Attribute Specification for the Swedish eID Framework, version 1.8 (2024-12-04);
 * - Registry for identifiers, version 1.8 (2024-12-04);
 * - Deployment Profile for the Swedish eID Framework, version 1.8 (2024-12-04);
 * - Entity Categories for the Swedish eID Framework, version 1.9 (2024-12-04);
 * - Principal Selection in SAML Authentication Requests, version 1.0 (2020-01-17).
 */

/** Attribute names (`NameFormat` uri) of the Attribute Specification. */
export const SAML_ATTRIBUTES = {
  personalIdentityNumber: "urn:oid:1.2.752.29.4.13",
  givenName: "urn:oid:2.5.4.42",
  sn: "urn:oid:2.5.4.4",
  displayName: "urn:oid:2.16.840.1.113730.3.1.241",
  mail: "urn:oid:0.9.2342.19200300.100.1.3",
  dateOfBirth: "urn:oid:1.3.6.1.5.5.7.9.1",
  prid: "urn:oid:1.2.752.201.3.4",
  pridPersistence: "urn:oid:1.2.752.201.3.5",
  personalIdentityNumberBinding: "urn:oid:1.2.752.201.3.6",
  orgAffiliation: "urn:oid:1.2.752.201.3.1",
  organizationIdentifier: "urn:oid:2.5.4.97",
  organizationName: "urn:oid:2.5.4.10",
  transactionIdentifier: "urn:oid:1.2.752.201.3.2",
  employeeHsaId: "urn:oid:1.2.752.29.6.2.1",
} as const;

/** Levels of assurance (Registry for identifiers, section "Level of Assurance"). */
export const SWEDISH_EID_LOA = [
  "http://id.elegnamnden.se/loa/1.0/loa1",
  "http://id.elegnamnden.se/loa/1.0/loa2",
  "http://id.elegnamnden.se/loa/1.0/loa3",
  "http://id.elegnamnden.se/loa/1.0/loa4",
  "http://id.elegnamnden.se/loa/1.0/eidas-low",
  "http://id.elegnamnden.se/loa/1.0/eidas-sub",
  "http://id.elegnamnden.se/loa/1.0/eidas-high",
  "http://id.elegnamnden.se/loa/1.0/eidas-nf-low",
  "http://id.elegnamnden.se/loa/1.0/eidas-nf-sub",
  "http://id.elegnamnden.se/loa/1.0/eidas-nf-high",
  "http://id.swedenconnect.se/loa/1.0/loa2-nonresident",
  "http://id.swedenconnect.se/loa/1.0/loa3-nonresident",
  "http://id.swedenconnect.se/loa/1.0/loa4-nonresident",
  "http://id.swedenconnect.se/loa/1.0/uncertified-loa2",
  "http://id.swedenconnect.se/loa/1.0/uncertified-loa3",
  "http://id.swedenconnect.se/loa/1.0/uncertified-eidas-low",
  "http://id.swedenconnect.se/loa/1.0/uncertified-eidas-sub",
  "http://id.swedenconnect.se/loa/1.0/uncertified-eidas-high",
] as const;

/** Service entity categories, service property and service type categories (Entity Categories). */
export const SWEDISH_EID_ENTITY_CATEGORIES = [
  "http://id.elegnamnden.se/ec/1.0/loa2-pnr",
  "http://id.elegnamnden.se/ec/1.0/loa3-pnr",
  "http://id.elegnamnden.se/ec/1.0/loa4-pnr",
  "http://id.elegnamnden.se/ec/1.0/eidas-naturalperson",
  "http://id.elegnamnden.se/ec/1.0/eidas-pnr-delivery",
  "http://id.swedenconnect.se/ec/1.0/loa2-orgid",
  "http://id.swedenconnect.se/ec/1.0/loa3-orgid",
  "http://id.swedenconnect.se/ec/1.0/loa4-orgid",
  "http://id.swedenconnect.se/ec/1.0/loa2-name",
  "http://id.swedenconnect.se/ec/1.0/loa3-name",
  "http://id.swedenconnect.se/ec/1.0/loa4-name",
  // Listed by the Registry 1.8; Entity Categories 1.9 leaves it to the federation operator.
  "http://id.swedenconnect.se/ec/1.0/loa3-hsaid",
  "http://id.swedenconnect.se/ec/sc/uncertified-loa3-pnr",
  "http://id.swedenconnect.se/ec/sc/uncertified-loa3-hsaid",
  "http://id.elegnamnden.se/sprop/1.0/mobile-auth",
  "http://id.elegnamnden.se/st/1.0/public-sector-sp",
  "http://id.elegnamnden.se/st/1.0/private-sector-sp",
  "http://id.swedenconnect.se/general-ec/1.0/secure-authenticator-binding",
  "http://id.swedenconnect.se/general-ec/1.0/accepts-coordination-number",
  "http://id.swedenconnect.se/general-ec/1.0/supports-user-message",
] as const;

/** Name of the metadata attribute carrying entity categories (Deployment Profile 2.1.3). */
export const ENTITY_CATEGORY_ATTRIBUTE = "http://macedir.org/entity-category";

/** Status codes: SAML core plus the framework's second-level codes (Registry, "Status Codes"). */
export const SAML_STATUS = {
  success: "urn:oasis:names:tc:SAML:2.0:status:Success",
  requester: "urn:oasis:names:tc:SAML:2.0:status:Requester",
  responder: "urn:oasis:names:tc:SAML:2.0:status:Responder",
  authnFailed: "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed",
  noAuthnContext: "urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext",
  requestDenied: "urn:oasis:names:tc:SAML:2.0:status:RequestDenied",
  unknownPrincipal: "urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal",
  noPassive: "urn:oasis:names:tc:SAML:2.0:status:NoPassive",
  partialLogout: "urn:oasis:names:tc:SAML:2.0:status:PartialLogout",
  cancel: "http://id.elegnamnden.se/status/1.0/cancel",
  fraud: "http://id.elegnamnden.se/status/1.0/fraud",
  possibleFraud: "http://id.elegnamnden.se/status/1.0/possibleFraud",
} as const;

/** Namespace of the PrincipalSelection extension (Principal Selection 1.0). */
export const PRINCIPAL_SELECTION_NS = "http://id.swedenconnect.se/authn/1.0/principal-selection/ns";

/** What identifies the person for identity linking (`identities.subject`). */
export const SAML_SUBJECT_SOURCES = [
  "personalIdentityNumber",
  "prid",
  "employeeHsaId",
  "nameId",
] as const;
export type SamlSubjectSource = (typeof SAML_SUBJECT_SOURCES)[number];

export const SAML_BINDINGS = ["redirect", "post"] as const;
export type SamlBinding = (typeof SAML_BINDINGS)[number];

/**
 * RequestedAuthnContext comparison. The Deployment Profile allows only `exact` (or none); a
 * returned AuthnContextClassRef must then be one of the requested URIs. `minimum` is for IdPs
 * outside the framework: the returned level must rank at least as high as the lowest requested.
 */
export const SAML_COMPARISONS = ["exact", "minimum"] as const;
export type SamlComparison = (typeof SAML_COMPARISONS)[number];

/** Attribute name: a URI or `urn:oid:` name as in the Attribute Specification. */
export const samlAttributeNameSchema = z
  .string()
  .min(1)
  .max(255)
  .regex(/^[A-Za-z][A-Za-z0-9+.-]*:[\x21-\x7E]+$/, "must be an attribute name URI");

const uriSchema = z
  .string()
  .min(1)
  .max(1024)
  .regex(/^[A-Za-z][A-Za-z0-9+.-]*:[\x21-\x7E]+$/, "must be a URI");

/**
 * Which SAML attributes feed which Portvakt attribute. Defaults follow the Attribute
 * Specification; every entry can be overridden per login method. `name` is displayName, and
 * when that is absent givenName and sn joined.
 */
export const samlAttributeMappingSchema = z
  .object({
    personalIdentityNumber: samlAttributeNameSchema.default(SAML_ATTRIBUTES.personalIdentityNumber),
    displayName: samlAttributeNameSchema.default(SAML_ATTRIBUTES.displayName),
    givenName: samlAttributeNameSchema.default(SAML_ATTRIBUTES.givenName),
    surname: samlAttributeNameSchema.default(SAML_ATTRIBUTES.sn),
    prid: samlAttributeNameSchema.default(SAML_ATTRIBUTES.prid),
    pridPersistence: samlAttributeNameSchema.default(SAML_ATTRIBUTES.pridPersistence),
    employeeHsaId: samlAttributeNameSchema.default(SAML_ATTRIBUTES.employeeHsaId),
    /** Mapped only with `trustEmail` (the framework IdPs do not verify addresses for Portvakt). */
    email: samlAttributeNameSchema.optional(),
    /** Group values for role rules (default: orgAffiliation, `uid@orgnr`, scope-checked). */
    groups: z.array(samlAttributeNameSchema).max(10).default([SAML_ATTRIBUTES.orgAffiliation]),
    /**
     * Protected identity (skyddad identitet): the framework defines no attribute or status for
     * it, so it is configurable: the attribute and the values that flag a protected identity.
     */
    protectedIdentity: z
      .object({
        attribute: samlAttributeNameSchema,
        values: z.array(z.string().min(1).max(255)).min(1).max(10),
      })
      .strict()
      .optional(),
  })
  .strict();
export type SamlAttributeMapping = z.output<typeof samlAttributeMappingSchema>;
export type SamlAttributeMappingInput = z.input<typeof samlAttributeMappingSchema>;

/** An attribute requested in SP metadata (`md:RequestedAttribute`) beyond the entity categories. */
export const requestedAttributeSchema = z
  .object({ name: samlAttributeNameSchema, required: z.boolean().default(false) })
  .strict();
export type RequestedAttribute = z.output<typeof requestedAttributeSchema>;

const pemCertificateSchema = z
  .string()
  .max(16384)
  .regex(
    /^\s*-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----\s*$/,
    "must be one PEM certificate",
  )
  .transform((pem) => pem.trim());

const httpUrlSchema = z
  .url({ protocol: /^https?$/ })
  .max(2048)
  .refine((value) => !value.includes("#"), "must not contain a fragment");

/** Inline metadata: one XML document. */
const metadataXmlSchema = z
  .string()
  .min(1)
  .max(10 * 1024 * 1024);

const localizedSchema = (max: number) =>
  z
    .object({
      sv: z.string().trim().min(1).max(max),
      en: z.string().trim().min(1).max(max).optional(),
    })
    .strict();

/**
 * mdui:UIInfo of the SP metadata. The Deployment Profile requires a DisplayName in Swedish and at
 * least one Logo, and recommends a Description in Swedish. DisplayName defaults to the login
 * method's display name; production refuses to save a method without a logo.
 */
export const uiInfoSchema = z
  .object({
    displayName: localizedSchema(200).optional(),
    description: localizedSchema(1000).optional(),
    logos: z
      .array(
        z
          .object({
            url: z.url({ protocol: /^https$/ }).max(2048),
            width: z.number().int().min(1).max(4096),
            height: z.number().int().min(1).max(4096),
            lang: z.enum(["sv", "en"]).optional(),
          })
          .strict(),
      )
      .max(5)
      .default([]),
  })
  .strict();
export type UiInfo = z.output<typeof uiInfoSchema>;

/** An organisation number (10 digits), the scope of orgAffiliation values. */
const orgScopeSchema = z.string().regex(/^\d{10}$/, "must be a 10-digit organisation number");

/** The SAML part of a login method (stored in `login_method_saml`). */
export interface SamlSettings {
  readonly idpEntityId: string;
  readonly metadataUrl: string | null;
  /** Inline metadata (instead of a URL). */
  readonly metadataXml: string | null;
  /** Verify the metadata's signature with this certificate (PEM) when set. */
  readonly metadataSigningCertificate: string | null;
  readonly metadataRefreshSeconds: number;
  /** AuthnContextClassRef values requested, in order. */
  readonly requestedLoa: readonly string[];
  readonly authnContextComparison: SamlComparison;
  readonly entityCategories: readonly string[];
  readonly requestedAttributes: readonly RequestedAttribute[];
  readonly subjectSource: SamlSubjectSource;
  readonly attributeMapping: SamlAttributeMapping;
  readonly authnRequestBinding: SamlBinding;
  /** The framework requires EncryptedAssertion; false accepts plain (signed) assertions too. */
  readonly requireEncryptedAssertions: boolean;
  /** The Deployment Profile requires a signed Response (the assertion is always signed). */
  readonly requireSignedResponse: boolean;
  readonly signMetadata: boolean;
  readonly clockSkewSeconds: number;
  /** Map the email attribute (the IdP verifies addresses itself). */
  readonly trustEmail: boolean;
  /**
   * Use a metadata URL without a metadata signing certificate: an explicit decision (production
   * refuses unsigned metadata URLs otherwise), audited when saved.
   */
  readonly allowUnsignedMetadata: boolean;
  /** Refuse AES-CBC content encryption (accept AES-GCM only). */
  readonly requireGcm: boolean;
  readonly uiInfo: UiInfo;
  /** orgAffiliation scopes accepted besides the IdP metadata's `shibmd:Scope` values. */
  readonly orgAffiliationScopes: readonly string[];
}

const loaListSchema = z
  .array(uriSchema)
  .min(1)
  .max(20)
  .refine((values) => new Set(values).size === values.length, "values must be unique");

const uriListSchema = z
  .array(uriSchema)
  .max(50)
  .transform((values) => [...new Set(values)]);

export const samlSettingsInputSchema = z
  .object({
    idpEntityId: uriSchema,
    metadataUrl: httpUrlSchema.nullable().default(null),
    metadataXml: metadataXmlSchema.nullable().default(null),
    metadataSigningCertificate: pemCertificateSchema.nullable().default(null),
    metadataRefreshSeconds: z
      .number()
      .int()
      .min(300)
      .max(7 * 24 * 3600)
      .default(3600),
    requestedLoa: loaListSchema,
    authnContextComparison: z.enum(SAML_COMPARISONS).default("exact"),
    entityCategories: uriListSchema.default([]),
    requestedAttributes: z.array(requestedAttributeSchema).max(50).default([]),
    subjectSource: z.enum(SAML_SUBJECT_SOURCES),
    attributeMapping: samlAttributeMappingSchema.prefault({}),
    authnRequestBinding: z.enum(SAML_BINDINGS).default("redirect"),
    requireEncryptedAssertions: z.boolean().default(true),
    requireSignedResponse: z.boolean().default(true),
    signMetadata: z.boolean().default(false),
    clockSkewSeconds: z.number().int().min(0).max(300).default(60),
    trustEmail: z.boolean().default(false),
    allowUnsignedMetadata: z.boolean().default(false),
    requireGcm: z.boolean().default(false),
    uiInfo: uiInfoSchema.prefault({}),
    orgAffiliationScopes: z
      .array(orgScopeSchema)
      .max(50)
      .transform((values) => [...new Set(values)])
      .default([]),
    /**
     * Accept requested LoA URIs outside the framework's registry and ACR_RANKING (an explicit
     * decision for IdPs with their own levels). Not stored.
     */
    allowCustomLoa: z.boolean().default(false),
  })
  .strict()
  .refine((settings) => (settings.metadataUrl === null) !== (settings.metadataXml === null), {
    message: "exactly one of metadataUrl and metadataXml is required",
    path: ["metadataUrl"],
  })
  .refine(
    (settings) =>
      !settings.allowUnsignedMetadata ||
      (settings.metadataUrl !== null && settings.metadataSigningCertificate === null),
    {
      message: "allowUnsignedMetadata applies only to a metadata URL without a signing certificate",
      path: ["allowUnsignedMetadata"],
    },
  );
export type SamlSettingsInput = z.input<typeof samlSettingsInputSchema>;
export type ParsedSamlSettings = z.output<typeof samlSettingsInputSchema>;

/** A partial update of the SAML settings (the merged result is validated as a whole). */
export const samlSettingsPatchSchema = z
  .object({
    idpEntityId: uriSchema,
    metadataUrl: httpUrlSchema.nullable(),
    metadataXml: metadataXmlSchema.nullable(),
    metadataSigningCertificate: pemCertificateSchema.nullable(),
    metadataRefreshSeconds: z
      .number()
      .int()
      .min(300)
      .max(7 * 24 * 3600),
    requestedLoa: loaListSchema,
    authnContextComparison: z.enum(SAML_COMPARISONS),
    entityCategories: uriListSchema,
    requestedAttributes: z.array(requestedAttributeSchema).max(50),
    subjectSource: z.enum(SAML_SUBJECT_SOURCES),
    attributeMapping: samlAttributeMappingSchema,
    authnRequestBinding: z.enum(SAML_BINDINGS),
    requireEncryptedAssertions: z.boolean(),
    requireSignedResponse: z.boolean(),
    signMetadata: z.boolean(),
    clockSkewSeconds: z.number().int().min(0).max(300),
    trustEmail: z.boolean(),
    allowUnsignedMetadata: z.boolean(),
    requireGcm: z.boolean(),
    uiInfo: uiInfoSchema,
    orgAffiliationScopes: z.array(orgScopeSchema).max(50),
    allowCustomLoa: z.boolean(),
  })
  .partial()
  .strict();
export type SamlSettingsPatch = z.input<typeof samlSettingsPatchSchema>;

/** Rules over SAML settings as messages for a validation error. `acrRanking`: ACR_RANKING. */
export function samlSettingsViolations(
  settings: Pick<SamlSettings, "requestedLoa" | "authnContextComparison"> & {
    readonly allowCustomLoa: boolean;
  },
  assertedAcr: string,
  acrRanking: readonly string[],
): string[] {
  const issues: string[] = [];
  const known = new Set<string>([...SWEDISH_EID_LOA, ...acrRanking]);
  const unknown = settings.requestedLoa.filter((loa) => !known.has(loa));
  if (unknown.length > 0 && !settings.allowCustomLoa) {
    issues.push(
      "saml.requestedLoa: unknown LoA URI (not in the Swedish eID registry or ACR_RANKING); set allowCustomLoa to use it",
    );
  }
  if (settings.authnContextComparison === "minimum") {
    if (settings.requestedLoa.some((loa) => !acrRanking.includes(loa))) {
      issues.push("saml.requestedLoa: comparison minimum needs levels in ACR_RANKING");
    }
  }
  // The login method's acr must be reachable: a returned level must meet it.
  const meets = (loa: string): boolean => {
    if (loa === assertedAcr) return true;
    const have = acrRanking.indexOf(loa);
    const need = acrRanking.indexOf(assertedAcr);
    return have >= 0 && need >= 0 && have >= need;
  };
  if (!settings.requestedLoa.some(meets)) {
    issues.push("assertedAcr: no requested LoA meets the login method's asserted acr");
  }
  return issues;
}
