/** The admin portal is an application on Portvakt (docs/plan.md, "Admin"). */
export const ADMIN_CLIENT_ID = "portvakt-admin";

/** Meaningful only in the system tenant: administers every tenant and the global registry. */
export const PLATFORM_ADMIN_ROLE = "platform-admin";
/** Administers the tenant it is assigned in, nothing else. */
export const TENANT_ADMIN_ROLE = "tenant-admin";

export const ADMIN_ROLES = [
  { role: PLATFORM_ADMIN_ROLE, description: "Plattformsadministratör (endast system)" },
  { role: TENANT_ADMIN_ROLE, description: "Administratör för organisationen" },
] as const;

/** Redirect URIs of the admin portal: one SDK client per tenant issuer, below `/t/{slug}`. */
export function adminRedirectUris(adminPublicUrl: string): {
  readonly redirectUris: string[];
  readonly postLogoutRedirectUris: string[];
} {
  return {
    redirectUris: [`${adminPublicUrl}/t/{tenant}/auth/callback`],
    postLogoutRedirectUris: [`${adminPublicUrl}/t/{tenant}/`],
  };
}

/** Base path of the admin API. */
export const ADMIN_API_BASE = "/admin/api/v1";
