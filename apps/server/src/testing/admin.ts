import * as client from "openid-client";
import {
  ADMIN_API_BASE,
  ADMIN_CLIENT_ID,
  PLATFORM_ADMIN_ROLE,
  TENANT_ADMIN_ROLE,
} from "../admin/constants.js";
import { ensureAdminApplication } from "../admin/bootstrap.js";
import { generateClientSecret } from "../crypto/secrets.js";
import type { Application } from "../domain/application.js";
import type { LoginMethod } from "../domain/login-method.js";
import { SYSTEM_TENANT_SLUG, type Tenant } from "../domain/tenant.js";
import { createLoginMethod, createTenant, login, uniqueSuffix } from "./fixtures.js";
import { codeFlow, discover } from "./oidc-flow.js";
import type { TestServer } from "./test-server.js";

/** The admin portal in tests: `portvakt-admin` with real tokens through the test login route. */
export interface AdminWorld {
  readonly ts: TestServer;
  readonly application: Application;
  readonly secret: string;
  /** Origin the redirect URIs are registered for (`{origin}/t/{tenant}/auth/callback`). */
  readonly adminUrl: string;
  readonly system: Tenant;
  readonly systemMethod: LoginMethod;
}

export const TEST_ADMIN_URL = "http://admin.portvakt.test";

/**
 * The system tenant (created when missing), `portvakt-admin` enabled in it, and a login method
 * of the system tenant for the test login route.
 */
export async function setupAdminWorld(
  ts: TestServer,
  adminUrl = TEST_ADMIN_URL,
): Promise<AdminWorld> {
  const { repos } = ts.db;
  const secret = generateClientSecret();
  const { application } = await ensureAdminApplication(repos, adminUrl, secret);
  let system = await repos.tenants.findBySlug(SYSTEM_TENANT_SLUG);
  system ??= await repos.tenants.create({ slug: SYSTEM_TENANT_SLUG, name: "Portvakt" });
  await repos.applications.enableForTenant(system.id, application.id);
  const systemMethod = await createLoginMethod(repos, system.id, { displayName: "System sign-in" });
  return { ts, application, secret, adminUrl, system, systemMethod };
}

export interface AdminTenant {
  readonly tenant: Tenant;
  readonly method: LoginMethod;
}

/** A tenant with `portvakt-admin` enabled and a login method. */
export async function createAdminTenant(world: AdminWorld, prefix = "org"): Promise<AdminTenant> {
  const { repos } = world.ts.db;
  const tenant = await createTenant(repos, prefix);
  await repos.applications.enableForTenant(tenant.id, world.application.id);
  const method = await createLoginMethod(repos, tenant.id);
  return { tenant, method };
}

/** A person of the tenant (JIT through `method`) with the given admin roles. */
export async function createAdmin(
  world: AdminWorld,
  tenant: Tenant,
  method: LoginMethod,
  roles: readonly string[],
): Promise<string> {
  const { repos } = world.ts.db;
  const { person } = await login(repos, tenant.id, method, `admin-${uniqueSuffix()}`, {
    attributes: { name: "Test Admin", email: "admin@example.test" },
  });
  for (const role of roles) {
    await repos.access.assignRole(tenant.id, {
      personId: person.id,
      applicationId: world.application.id,
      role,
    });
  }
  return person.id;
}

/** An access token of `portvakt-admin` for the person, from the tenant's issuer. */
export async function adminToken(
  world: AdminWorld,
  tenant: Tenant,
  method: LoginMethod,
  personId: string,
): Promise<string> {
  const config = await discover(
    world.ts,
    tenant.slug,
    ADMIN_CLIENT_ID,
    client.ClientSecretBasic(world.secret),
  );
  const tokens = await codeFlow(
    world.ts,
    config,
    `${world.adminUrl}/t/${tenant.slug}/auth/callback`,
    { personId, loginMethodId: method.id, acr: method.assertedAcr },
  );
  return tokens.access_token;
}

/** A client_credentials token of `portvakt-admin` (a service token: refused by the admin API). */
export async function adminServiceToken(world: AdminWorld, tenant: Tenant): Promise<string> {
  const config = await discover(
    world.ts,
    tenant.slug,
    ADMIN_CLIENT_ID,
    client.ClientSecretBasic(world.secret),
  );
  const tokens = await client.clientCredentialsGrant(config, {});
  return tokens.access_token;
}

export interface AdminResponse<T = unknown> {
  readonly status: number;
  readonly body: T;
  readonly etag: string | null;
  readonly contentType: string | null;
}

/** Calls the admin API of the test server. */
export async function adminCall<T = Record<string, unknown>>(
  ts: TestServer,
  token: string | undefined,
  method: string,
  path: string,
  options: {
    readonly body?: unknown;
    readonly ifMatch?: string;
    readonly headers?: Record<string, string>;
  } = {},
): Promise<AdminResponse<T>> {
  const headers: Record<string, string> = { accept: "application/json", ...options.headers };
  if (token !== undefined) headers.authorization = `Bearer ${token}`;
  if (options.body !== undefined) headers["content-type"] = "application/json";
  if (options.ifMatch !== undefined) headers["if-match"] = options.ifMatch;
  const response = await fetch(`${ts.baseUrl}${ADMIN_API_BASE}${path}`, {
    method,
    headers,
    ...(options.body === undefined ? {} : { body: JSON.stringify(options.body) }),
  });
  const text = await response.text();
  return {
    status: response.status,
    body: (text === "" ? null : JSON.parse(text)) as T,
    etag: response.headers.get("etag"),
    contentType: response.headers.get("content-type"),
  };
}

export { PLATFORM_ADMIN_ROLE, TENANT_ADMIN_ROLE };
