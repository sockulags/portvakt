import { readFileSync } from "node:fs";
import { z } from "zod";

/**
 * Test personas of the mock IdPs. Fictional people only: the personal identity numbers are
 * Luhn-valid test numbers, never real ones.
 */

/** Swedish eID Framework levels of assurance, lowest first (as Portvakt's default ranking). */
export const LOA_RANKING = [
  "http://id.elegnamnden.se/loa/1.0/loa2",
  "http://id.elegnamnden.se/loa/1.0/loa3",
  "http://id.elegnamnden.se/loa/1.0/loa4",
] as const;
export type Loa = (typeof LOA_RANKING)[number];

/** Entra tenant id (`tid`) of the mock employees unless a persona sets its own. */
export const MOCK_ENTRA_TENANT_ID = "8f0c6a1e-2b4d-4c7a-9e35-1d6b0f2a7c48";

/** Claim carrying the personal identity number (Swedish OIDC profile, oidc-sweden). */
export const PERSONAL_IDENTITY_NUMBER_CLAIM = "https://id.oidc.se/claim/personalIdentityNumber";

/** Luhn (mod 10) over the 10-digit form of a personnummer or samordningsnummer. */
export function luhnValid(digits: string): boolean {
  if (!/^\d+$/.test(digits)) return false;
  let sum = 0;
  for (let i = 0; i < digits.length; i += 1) {
    const weight = (digits.length - i) % 2 === 0 ? 2 : 1;
    const product = Number(digits[i]) * weight;
    sum += product > 9 ? product - 9 : product;
  }
  return sum % 10 === 0;
}

const personaId = z
  .string()
  .regex(/^[a-z0-9][a-z0-9-]{0,62}$/, "lowercase letters, digits, hyphens");

export const employeeSchema = z
  .object({
    id: personaId,
    /** Entra object id: the stable subject Portvakt maps (`oid`). */
    oid: z.uuid(),
    /** Entra tenant id (`tid` claim); default {@link MOCK_ENTRA_TENANT_ID}. */
    tid: z.uuid().default(MOCK_ENTRA_TENANT_ID),
    name: z.string().min(1).max(200),
    email: z.email(),
    groups: z.array(z.string().min(1).max(512)).max(500).default([]),
    /** Simulate Entra's groups overage: `_claim_names` / `_claim_sources` instead of `groups`. */
    groupsOverage: z.boolean().default(false),
  })
  .strict();
export type Employee = z.infer<typeof employeeSchema>;

export const citizenSchema = z
  .object({
    id: personaId,
    sub: z.string().min(1).max(255),
    /** `YYYYMMDDNNNC` (12 digits); a samordningsnummer has day + 60. */
    pin: z
      .string()
      .regex(/^\d{12}$/, "12 digits, YYYYMMDDNNNC")
      .refine((pin) => luhnValid(pin.slice(2)), "Luhn check digit does not match"),
    givenName: z.string().min(1).max(100),
    familyName: z.string().min(1).max(100),
    /** Highest level of assurance this persona can authenticate with. */
    acr: z.enum(LOA_RANKING),
    /** Skyddad identitet: upstream flags the identity as protected. */
    protectedIdentity: z.boolean().default(false),
  })
  .strict();
export type Citizen = z.infer<typeof citizenSchema>;

/** The mock SAML IdPs (Swedish eID Framework style), one per flavour. */
export const SAML_FLAVOURS = ["bankid", "freja", "siths"] as const;
export type SamlFlavour = (typeof SAML_FLAVOURS)[number];

/**
 * Attribute the mock SAML IdPs set (value `true`) for a protected identity. The framework
 * defines no such attribute; Portvakt's login method maps a configurable one.
 */
export const MOCK_PROTECTED_IDENTITY_ATTRIBUTE = "urn:portvakt:mock:protected-identity";

const pinSchema = z
  .string()
  .regex(/^\d{12}$/, "12 digits, YYYYMMDDNNNC")
  .refine((pin) => luhnValid(pin.slice(2)), "Luhn check digit does not match");

/**
 * A person at a mock SAML IdP, with Swedish eID Framework attributes. `loa` lists the levels
 * of assurance the persona can authenticate with, highest first.
 */
export const samlPersonaSchema = z
  .object({
    id: personaId,
    /** Persistent NameID (a pseudonym per IdP, as the Deployment Profile requires). */
    nameId: z.string().min(1).max(255),
    pin: pinSchema.optional(),
    givenName: z.string().min(1).max(100),
    sn: z.string().min(1).max(100),
    displayName: z.string().min(1).max(200).optional(),
    prid: z
      .string()
      .regex(/^[A-Z]{2}:[A-Za-z0-9]{10,30}$/)
      .optional(),
    pridPersistence: z.enum(["A", "B", "C"]).optional(),
    employeeHsaId: z.string().min(1).max(64).optional(),
    /** `uid@orgnr` values. */
    orgAffiliation: z
      .array(z.string().regex(/^[^@\s]+@\d{10}$/))
      .max(10)
      .default([]),
    mail: z.email().optional(),
    loa: z.array(z.string().min(1)).min(1),
    protectedIdentity: z.boolean().default(false),
  })
  .strict();
export type SamlPersona = z.infer<typeof samlPersonaSchema>;

export const personasSchema = z
  .object({
    entra: z.array(employeeSchema).min(1),
    bankid: z.array(citizenSchema).min(1),
    saml: z
      .object({
        bankid: z.array(samlPersonaSchema).default([]),
        freja: z.array(samlPersonaSchema).default([]),
        siths: z.array(samlPersonaSchema).default([]),
      })
      .strict()
      .prefault({}),
  })
  .strict()
  .refine((personas) => {
    const ids = [
      ...personas.entra,
      ...personas.bankid,
      ...personas.saml.bankid,
      ...personas.saml.freja,
      ...personas.saml.siths,
    ].map((persona) => persona.id);
    return new Set(ids).size === ids.length;
  }, "persona ids must be unique");
export type Personas = z.infer<typeof personasSchema>;

/** Reads and validates a personas file (default: apps/mock-idp/personas.json). */
export function loadPersonas(path: string | URL): Personas {
  return personasSchema.parse(JSON.parse(readFileSync(path, "utf8")));
}

export const DEFAULT_PERSONAS_PATH = new URL("../personas.json", import.meta.url);
