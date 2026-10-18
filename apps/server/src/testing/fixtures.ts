import { randomBytes } from "node:crypto";
import { generateClientSecret } from "../crypto/secrets.js";
import type { Application, CreateApplicationInput } from "../domain/application.js";
import type { CreateLoginMethodInput, LoginMethod } from "../domain/login-method.js";
import type { JitLoginInput, JitLoginResult } from "../domain/person.js";
import type { Tenant } from "../domain/tenant.js";
import type { Repositories } from "../repositories/index.js";

export const uniqueSuffix = (): string => randomBytes(4).toString("hex");

export const EMPLOYEE_ACR = "urn:portvakt:acr:employee";

/** Luhn-valid personnummer used as test data. */
export const TEST_PINS = ["19121212-1212", "199001012385", "20000101-0008"] as const;
/** A Luhn-valid organisationsnummer. */
export const TEST_ORGNR = "556677-8899";

export async function createTenant(repos: Repositories, prefix = "tenant"): Promise<Tenant> {
  return repos.tenants.create({ slug: `${prefix}-${uniqueSuffix()}`, name: `Tenant ${prefix}` });
}

export async function createApplication(
  repos: Repositories,
  overrides: Partial<CreateApplicationInput> = {},
): Promise<Application> {
  const clientId = overrides.clientId ?? `app-${uniqueSuffix()}`;
  return repos.applications.create({
    clientId,
    name: `Application ${clientId}`,
    clientAuth: { method: "client_secret_basic", clientSecret: generateClientSecret() },
    redirectUris: [`https://${clientId}.example.test/callback`],
    roles: [{ role: "handlaggare" }, { role: "admin" }, { role: "reader" }],
    attributeKeys: [{ key: "unit" }],
    ...overrides,
  });
}

export async function createLoginMethod(
  repos: Repositories,
  tenantId: string,
  overrides: Partial<CreateLoginMethodInput> = {},
): Promise<LoginMethod> {
  return repos.loginMethods.create(tenantId, {
    kind: "employee",
    displayName: "Mock Entra",
    issuer: "https://idp.example.test",
    clientId: `upstream-${uniqueSuffix()}`,
    clientSecret: "upstream-secret-value",
    scopes: ["openid", "profile", "email"],
    claimMapping: { subject: "oid", name: "name", email: "email", groups: "groups" },
    assertedAcr: EMPLOYEE_ACR,
    sessionPolicy: { maxAgeSeconds: 8 * 3600, idleSeconds: 3600, allowSso: true },
    ...overrides,
  });
}

/** Tenant with one enabled application and one login method. */
export async function createTenantWithApp(repos: Repositories, prefix = "tenant") {
  const tenant = await createTenant(repos, prefix);
  const application = await createApplication(repos);
  await repos.applications.enableForTenant(tenant.id, application.id);
  const loginMethod = await createLoginMethod(repos, tenant.id);
  return { tenant, application, loginMethod };
}

/** JIT login with defaults: the login method's acr and no attributes. */
export async function login(
  repos: Repositories,
  tenantId: string,
  method: LoginMethod,
  subject: string,
  extra: Partial<Omit<JitLoginInput, "loginMethodId" | "subject">> = {},
): Promise<JitLoginResult> {
  return repos.persons.upsertFromLogin(tenantId, {
    loginMethodId: method.id,
    subject,
    acr: method.assertedAcr,
    attributes: {},
    ...extra,
  });
}
