import { MOCK_PROTECTED_IDENTITY_ATTRIBUTE, type SamlFlavour } from "@portvakt/mock-idp";
import type { CreateSamlLoginMethodInput, SamlLoginMethod } from "../domain/login-method.js";
import type { SamlSettingsInput } from "../domain/saml.js";
import type { Tenant } from "../domain/tenant.js";
import { LOA2, LOA3, type TestIdp } from "./federation.js";
import type { TestServer } from "./test-server.js";

/** SAML login methods in tests: the mock IdP's SAML IdPs (`/saml/{flavour}`). */

type SamlDefaults = Omit<CreateSamlLoginMethodInput, "saml"> & {
  readonly saml: Omit<SamlSettingsInput, "idpEntityId" | "metadataUrl" | "metadataXml">;
};

const DEFAULTS: Record<SamlFlavour, SamlDefaults> = {
  bankid: {
    kind: "citizen",
    displayName: "Mock BankID (SAML)",
    assertedAcr: LOA3,
    sessionPolicy: { maxAgeSeconds: 3600, idleSeconds: 900, allowSso: false },
    saml: {
      requestedLoa: [LOA3],
      subjectSource: "personalIdentityNumber",
      entityCategories: ["http://id.elegnamnden.se/ec/1.0/loa3-pnr"],
      attributeMapping: {
        protectedIdentity: { attribute: MOCK_PROTECTED_IDENTITY_ATTRIBUTE, values: ["true"] },
      },
    },
  },
  freja: {
    kind: "citizen",
    displayName: "Mock Freja eID (SAML)",
    assertedAcr: LOA2,
    sessionPolicy: { maxAgeSeconds: 3600, idleSeconds: 900, allowSso: true },
    saml: {
      requestedLoa: [LOA3, LOA2],
      subjectSource: "personalIdentityNumber",
      entityCategories: [
        "http://id.elegnamnden.se/ec/1.0/loa3-pnr",
        "http://id.elegnamnden.se/ec/1.0/loa2-pnr",
      ],
    },
  },
  siths: {
    kind: "employee",
    displayName: "Mock SITHS (SAML)",
    assertedAcr: LOA3,
    sessionPolicy: { maxAgeSeconds: 8 * 3600, idleSeconds: 3600, allowSso: true },
    saml: {
      requestedLoa: [LOA3],
      subjectSource: "employeeHsaId",
      entityCategories: ["http://id.swedenconnect.se/ec/1.0/loa3-hsaid"],
    },
  },
};

export interface SamlMethodOverrides extends Partial<Omit<CreateSamlLoginMethodInput, "saml">> {
  readonly saml?: Partial<SamlSettingsInput>;
}

/**
 * A SAML login method of `tenant` for a mock SAML IdP (metadata URL, signature-checked with the
 * mock's metadata signing certificate), created through the admin service like the admin API
 * will. The mock fetches the SP metadata from `{entityID}/metadata` on the first request.
 */
export async function createSamlLoginMethod(
  ts: TestServer,
  testIdp: TestIdp,
  tenant: Tenant,
  flavour: SamlFlavour,
  overrides: SamlMethodOverrides = {},
): Promise<SamlLoginMethod> {
  const idp = testIdp.idp.saml(flavour);
  const defaults = DEFAULTS[flavour];
  return ts.portvakt.samlAdmin.create(tenant.id, {
    ...defaults,
    ...overrides,
    saml: {
      idpEntityId: idp.entityId,
      metadataUrl: idp.metadataUrl,
      metadataSigningCertificate: idp.metadataSigningCertificate,
      ...defaults.saml,
      ...overrides.saml,
    },
  });
}

/** The SP entityID of a SAML login method. */
export const spEntityId = (ts: TestServer, tenant: Tenant, method: { readonly id: string }) =>
  `${ts.baseUrl}/t/${tenant.slug}/saml/${method.id}`;
