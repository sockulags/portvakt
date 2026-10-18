import type { ClientMetadata } from "oidc-provider";
import type { Application } from "../domain/application.js";
import { clientIdSchema } from "../domain/schemas.js";

/** Resource indicator (RFC 8707) of an application: `urn:portvakt:app:{client_id}`. */
export const APP_RESOURCE_PREFIX = "urn:portvakt:app:";

export const resourceIndicatorFor = (clientId: string): string =>
  `${APP_RESOURCE_PREFIX}${clientId}`;

/** The client_id an application resource indicator names, or `null` for anything else. */
export function clientIdFromResource(resource: string): string | null {
  if (!resource.startsWith(APP_RESOURCE_PREFIX)) return null;
  const clientId = resource.slice(APP_RESOURCE_PREFIX.length);
  return clientIdSchema.safeParse(clientId).success ? clientId : null;
}

/** Scopes every application may request. `pin` (allowed per application) arrives with M4. */
export const STANDARD_SCOPES = ["openid", "profile", "email"] as const;

/** Grant types every application gets: they are all confidential, first-party clients. */
export const CLIENT_GRANT_TYPES = ["authorization_code", "refresh_token", "client_credentials"];

/**
 * oidc-provider client metadata for an application enabled in the tenant. `clientSecret` is the
 * decrypted secret for the secret-based methods and `null` for `private_key_jwt`.
 */
export function clientMetadataFor(
  application: Application,
  clientSecret: string | null,
): ClientMetadata {
  const auth = application.clientAuth;
  const metadata: ClientMetadata = {
    client_id: application.clientId,
    client_name: application.name,
    application_type: "web",
    grant_types: CLIENT_GRANT_TYPES,
    response_types: ["code"],
    redirect_uris: [...application.redirectUris],
    post_logout_redirect_uris: [...application.postLogoutRedirectUris],
    scope: STANDARD_SCOPES.join(" "),
    token_endpoint_auth_method: auth.method,
    id_token_signed_response_alg: "ES256",
    // Claims contract: every ID token carries auth_time.
    require_auth_time: true,
  };
  if (auth.method === "private_key_jwt") {
    if ("jwksUri" in auth) metadata.jwks_uri = auth.jwksUri;
    else metadata.jwks = { keys: auth.jwks.keys.map((key) => ({ ...key })) };
  } else {
    if (clientSecret === null) throw new Error("Application has no client secret");
    metadata.client_secret = clientSecret;
  }
  return metadata;
}
