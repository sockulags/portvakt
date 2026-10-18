import type { ClaimMapping } from "../../domain/login-method.js";
import { SAML_ATTRIBUTES, type SamlSettings } from "../../domain/saml.js";
import { mapUpstreamClaims, type MappedIdentity, type MappingFailure } from "../claim-mapping.js";

/** NameID formats (SAML core 8.3). */
export const NAMEID_FORMATS = {
  persistent: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
  transient: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
} as const;

/** What a validated assertion says about the person (values are personal data: never log). */
export interface SamlSubjectData {
  readonly nameId: string | undefined;
  readonly nameIdFormat: string | undefined;
  /** Attribute name (`Name`) to its string values. */
  readonly attributes: Readonly<Record<string, readonly string[]>>;
  /** The AuthnContextClassRef the IdP returned. */
  readonly loa: string;
}

export type SamlMappingFailure =
  | MappingFailure
  /** An attribute that must be single-valued (subject, personal identity number) was not. */
  | "ambiguous_attribute"
  /** NameID as subject needs a persistent NameID (a transient one changes every login). */
  | "transient_nameid";

export interface SamlMappedIdentity {
  readonly mapped: MappedIdentity;
  /**
   * The subject is the personal identity number: the identity is keyed by its blind index, never
   * by the number itself (personal identity numbers are only stored encrypted).
   */
  readonly subjectFromPin: boolean;
  /** orgAffiliation values dropped because their scope is not one the IdP's metadata lists. */
  readonly droppedAffiliations: number;
}

// Synthetic claim names: the SAML attributes are mapped through the same code as OIDC claims.
const CLAIM = {
  subject: "saml:subject",
  name: "saml:name",
  email: "saml:email",
  pin: "saml:pin",
  groups: "saml:groups",
  acr: "saml:acr",
  protectedIdentity: "saml:protected_identity",
} as const;

const MAPPING: ClaimMapping = {
  subject: CLAIM.subject,
  name: CLAIM.name,
  email: CLAIM.email,
  pin: CLAIM.pin,
  groups: CLAIM.groups,
  acr: CLAIM.acr,
  protectedIdentity: CLAIM.protectedIdentity,
};

/** `uid@orgnr` (Attribute Specification): the scope is the part after the last `@`. */
function affiliationScope(value: string): string | undefined {
  const at = value.lastIndexOf("@");
  return at > 0 && at < value.length - 1 ? value.slice(at + 1) : undefined;
}

/**
 * Maps the attributes of a validated SAML assertion to a Portvakt identity, through the login
 * method's attribute mapping (defaults per the Attribute Specification) and subject source:
 *
 * - `personalIdentityNumber`: validated and canonicalised by the personnummer module; the
 *   identity is keyed by its blind index;
 * - `prid` / `employeeHsaId`: the attribute's value;
 * - `nameId`: the persistent NameID (unique per IdP and SP).
 *
 * `name` is displayName, else givenName and sn joined. orgAffiliation values (default group
 * source, for role rules) are only accepted when their scope is listed as a `shibmd:Scope` of
 * the IdP or one of the login method's `orgAffiliationScopes` (Attribute Specification: the SP
 * must not accept a value that fails this check). employeeHsaId and the accepted orgAffiliation
 * values are also kept on the identity for the `hsa` scope's claims.
 */
export function mapSamlAttributes(
  settings: Pick<SamlSettings, "attributeMapping" | "subjectSource" | "trustEmail">,
  subject: SamlSubjectData,
  idpScopes: readonly string[],
): SamlMappedIdentity | SamlMappingFailure {
  const mapping = settings.attributeMapping;
  const values = (name: string | undefined): readonly string[] =>
    name === undefined || !Object.hasOwn(subject.attributes, name)
      ? []
      : (subject.attributes[name] ?? []);
  let ambiguous = false;
  const single = (name: string | undefined): string | undefined => {
    const found = values(name);
    if (found.length > 1) ambiguous = true;
    return found.length === 1 ? found[0] : undefined;
  };

  const pin = single(mapping.personalIdentityNumber);
  let subjectValue: string | undefined;
  switch (settings.subjectSource) {
    case "personalIdentityNumber":
      subjectValue = pin;
      break;
    case "prid":
      subjectValue = single(mapping.prid);
      break;
    case "employeeHsaId":
      subjectValue = single(mapping.employeeHsaId);
      break;
    case "nameId":
      if (subject.nameIdFormat === NAMEID_FORMATS.transient) return "transient_nameid";
      subjectValue = subject.nameId;
      break;
  }
  if (ambiguous) return "ambiguous_attribute";

  const displayName = values(mapping.displayName)[0];
  const given = values(mapping.givenName)[0];
  const surname = values(mapping.surname)[0];
  const name =
    displayName ?? ([given, surname].filter((part) => part !== undefined).join(" ") || undefined);

  const inScope = (value: string): boolean => {
    const scope = affiliationScope(value);
    return scope !== undefined && idpScopes.includes(scope);
  };
  const affiliations = values(SAML_ATTRIBUTES.orgAffiliation);
  const acceptedAffiliations = affiliations.filter(inScope).slice(0, 10);
  const droppedAffiliations = affiliations.length - affiliations.filter(inScope).length;
  const groups: string[] = [];
  for (const attribute of mapping.groups) {
    for (const value of values(attribute)) {
      if (attribute === SAML_ATTRIBUTES.orgAffiliation && !inScope(value)) continue;
      groups.push(value);
    }
  }
  const hsaId = single(mapping.employeeHsaId);
  if (ambiguous) return "ambiguous_attribute";

  const flagged =
    mapping.protectedIdentity !== undefined &&
    values(mapping.protectedIdentity.attribute).some((value) =>
      mapping.protectedIdentity?.values.includes(value),
    );

  const claims: Record<string, unknown> = {
    [CLAIM.subject]: subjectValue,
    [CLAIM.groups]: groups,
    [CLAIM.acr]: subject.loa,
    [CLAIM.protectedIdentity]: flagged,
    ...(name === undefined ? {} : { [CLAIM.name]: name }),
    ...(pin === undefined ? {} : { [CLAIM.pin]: pin }),
    ...(mapping.email === undefined ? {} : { [CLAIM.email]: values(mapping.email)[0] }),
  };
  const mapped = mapUpstreamClaims(MAPPING, claims, { trustEmail: settings.trustEmail });
  if (typeof mapped === "string") return mapped;
  return {
    mapped: {
      ...mapped,
      attributes: {
        ...mapped.attributes,
        ...(hsaId === undefined || hsaId.length > 64 ? {} : { hsaId }),
        ...(acceptedAffiliations.length === 0 ? {} : { orgAffiliation: acceptedAffiliations }),
      },
    },
    subjectFromPin: settings.subjectSource === "personalIdentityNumber",
    droppedAffiliations,
  };
}
