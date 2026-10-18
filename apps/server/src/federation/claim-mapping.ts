import type { ClaimMapping } from "../domain/login-method.js";
import type { IdentityAttributesInput } from "../domain/person.js";
import { parsePersonnummer } from "../domain/personnummer.js";

/**
 * Maps upstream claims (ID token, merged with userinfo when the login method asks for it) to a
 * Portvakt identity through the login method's claim mapping. Values are personal data: the
 * result and every error are never logged; errors carry a reason code only.
 */

export type MappingFailure =
  /** No usable subject claim. */
  | "missing_subject"
  /** The personal identity number claim is present but not a valid personnummer. */
  | "invalid_pin";

export interface MappedIdentity {
  readonly subject: string;
  readonly attributes: IdentityAttributesInput;
  /** Canonical 12-digit personnummer or samordningsnummer, when mapped. */
  readonly pin: string | undefined;
  readonly upstreamAcr: string | undefined;
  /**
   * Entra ID groups overage: the token names a source for the groups claim instead of carrying
   * it (`_claim_names` / `_claim_sources`). The groups are then treated as empty.
   */
  readonly groupsOverage: boolean;
  readonly amr: string[];
}

const MAX_GROUPS = 1000;
const AMR_VALUE = /^[A-Za-z0-9_.:-]{1,64}$/;
/** `amr` when the upstream reports none: authenticated by a federated IdP. */
export const FEDERATED_AMR = "fed";

/**
 * Reads a claim by name; a name that is not a top-level claim is read as a dotted path into
 * nested objects (`realm_access.roles`). Claim names that contain dots themselves (URIs such as
 * `https://id.oidc.se/claim/personalIdentityNumber`) are found as top-level claims first.
 */
export function readClaim(claims: Readonly<Record<string, unknown>>, name: string): unknown {
  if (Object.hasOwn(claims, name)) return claims[name];
  let current: unknown = claims;
  for (const part of name.split(".")) {
    if (typeof current !== "object" || current === null || Array.isArray(current)) {
      return undefined;
    }
    if (!Object.hasOwn(current, part)) return undefined;
    current = (current as Record<string, unknown>)[part];
  }
  return current;
}

function text(value: unknown, max: number): string | undefined {
  if (typeof value === "number" && Number.isFinite(value)) value = String(value);
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 && trimmed.length <= max ? trimmed : undefined;
}

function groupsOf(value: unknown): string[] {
  const values = Array.isArray(value) ? value : value === undefined ? [] : [value];
  const groups = new Set<string>();
  for (const item of values) {
    const group = text(item, 512);
    if (group !== undefined) groups.add(group);
    if (groups.size >= MAX_GROUPS) break;
  }
  return [...groups];
}

function isOverage(claims: Readonly<Record<string, unknown>>, groupsClaim: string): boolean {
  const names = claims._claim_names;
  return (
    typeof names === "object" &&
    names !== null &&
    Object.hasOwn(names, groupsClaim) &&
    readClaim(claims, groupsClaim) === undefined
  );
}

/** Values that flag a protected identity; anything else does not. */
const PROTECTED_VALUES: readonly unknown[] = [true, "true", 1, "1"];

export interface MappingOptions {
  /**
   * The upstream verifies email addresses itself (Entra ID work accounts): map the email claim
   * without `email_verified`. Otherwise only an email with `email_verified: true` is mapped.
   */
  readonly trustEmail: boolean;
}

export function mapUpstreamClaims(
  mapping: ClaimMapping,
  claims: Readonly<Record<string, unknown>>,
  options: MappingOptions = { trustEmail: false },
): MappedIdentity | MappingFailure {
  const subject = text(readClaim(claims, mapping.subject), 255);
  if (subject === undefined) return "missing_subject";

  let pin: string | undefined;
  if (mapping.pin !== undefined) {
    const raw = text(readClaim(claims, mapping.pin), 20);
    if (raw !== undefined) {
      const parsed = parsePersonnummer(raw);
      if (parsed === null) return "invalid_pin";
      pin = parsed.canonical;
    }
  }

  const groupsOverage = mapping.groups !== undefined && isOverage(claims, mapping.groups);
  const groups =
    mapping.groups === undefined || groupsOverage
      ? []
      : groupsOf(readClaim(claims, mapping.groups));
  const name = mapping.name === undefined ? undefined : text(readClaim(claims, mapping.name), 500);
  const emailVerified = claims.email_verified === true || claims.email_verified === "true";
  const email =
    mapping.email === undefined || !(emailVerified || options.trustEmail)
      ? undefined
      : text(readClaim(claims, mapping.email), 320);
  const upstreamAcr =
    mapping.acr === undefined ? undefined : text(readClaim(claims, mapping.acr), 255);
  const protectedRaw =
    mapping.protectedIdentity === undefined
      ? undefined
      : readClaim(claims, mapping.protectedIdentity);
  const protectedIdentity = PROTECTED_VALUES.includes(protectedRaw);

  const amrClaim = Array.isArray(claims.amr) ? claims.amr : [];
  const amr = [
    ...new Set(
      amrClaim.filter(
        (value): value is string => typeof value === "string" && AMR_VALUE.test(value),
      ),
    ),
  ].slice(0, 16);

  return {
    subject,
    attributes: {
      ...(name === undefined ? {} : { name }),
      ...(email === undefined ? {} : { email }),
      groups,
      protectedIdentity,
      ...(upstreamAcr === undefined ? {} : { upstreamAcr }),
    },
    pin,
    upstreamAcr,
    groupsOverage,
    amr: amr.length > 0 ? amr : [FEDERATED_AMR],
  };
}
