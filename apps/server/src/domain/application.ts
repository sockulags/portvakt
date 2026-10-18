import { z } from "zod";
import { MIN_CLIENT_SECRET_LENGTH } from "../crypto/secrets.js";
import {
  absoluteUrlSchema,
  attributeKeySchema,
  clientIdSchema,
  displayNameSchema,
  roleNameSchema,
} from "./schemas.js";

/** Extra scopes an application may be allowed to request beyond the standard OIDC ones. */
export const EXTRA_SCOPES = ["pin"] as const;
export type ExtraScope = (typeof EXTRA_SCOPES)[number];

export const SECRET_AUTH_METHODS = ["client_secret_basic", "client_secret_post"] as const;
export type SecretAuthMethod = (typeof SECRET_AUTH_METHODS)[number];

/** Public JWK as registered by a `private_key_jwt` client. Private members are refused. */
const clientJwkSchema = z
  .object({ kty: z.string().min(1) })
  .catchall(z.unknown())
  .refine(
    (jwk) => !["d", "p", "q", "dp", "dq", "qi", "k"].some((member) => member in jwk),
    "client JWKS must contain public keys only",
  );

export const clientJwksSchema = z.object({ keys: z.array(clientJwkSchema).min(1) });
export type ClientJwks = z.infer<typeof clientJwksSchema>;

/**
 * Client authentication as given on create/update. For the secret methods the plaintext secret
 * is passed in (generated with `generateClientSecret`) and stored encrypted; it is never part of
 * the returned {@link Application}.
 */
export const clientAuthSchema = z.union([
  z
    .object({
      method: z.enum(SECRET_AUTH_METHODS),
      clientSecret: z.string().min(MIN_CLIENT_SECRET_LENGTH).max(512),
    })
    .strict(),
  z.object({ method: z.literal("private_key_jwt"), jwksUri: absoluteUrlSchema }).strict(),
  z.object({ method: z.literal("private_key_jwt"), jwks: clientJwksSchema }).strict(),
]);
export type ClientAuthInput = z.input<typeof clientAuthSchema>;

/** Client authentication as stored. The secret itself is available via `getClientSecret`. */
export type ClientAuth =
  | { readonly method: SecretAuthMethod }
  | { readonly method: "private_key_jwt"; readonly jwksUri: string }
  | { readonly method: "private_key_jwt"; readonly jwks: ClientJwks };

export interface DeclaredRole {
  readonly role: string;
  readonly description: string | null;
}

export interface DeclaredAttributeKey {
  readonly key: string;
  readonly description: string | null;
}

export interface Application {
  readonly id: string;
  readonly clientId: string;
  readonly name: string;
  readonly enabled: boolean;
  readonly clientAuth: ClientAuth;
  readonly redirectUris: readonly string[];
  readonly postLogoutRedirectUris: readonly string[];
  readonly roles: readonly DeclaredRole[];
  readonly attributeKeys: readonly DeclaredAttributeKey[];
  readonly allowedExtraScopes: readonly ExtraScope[];
  readonly createdAt: Date;
  readonly updatedAt: Date;
}

/** Application as attached to a tenant. */
export interface TenantApplication {
  readonly tenantId: string;
  readonly application: Application;
  readonly enabled: boolean;
  readonly createdAt: Date;
}

const declaredRoleSchema = z.object({
  role: roleNameSchema,
  description: z.string().trim().max(500).nullable().default(null),
});
const declaredAttributeKeySchema = z.object({
  key: attributeKeySchema,
  description: z.string().trim().max(500).nullable().default(null),
});

const uniqueBy = <T>(items: readonly T[], key: (item: T) => string): boolean =>
  new Set(items.map(key)).size === items.length;

export const createApplicationInputSchema = z.object({
  clientId: clientIdSchema,
  name: displayNameSchema,
  enabled: z.boolean().default(true),
  clientAuth: clientAuthSchema,
  redirectUris: z.array(absoluteUrlSchema).min(1).max(50),
  postLogoutRedirectUris: z.array(absoluteUrlSchema).max(50).default([]),
  roles: z
    .array(declaredRoleSchema)
    .max(200)
    .default([])
    .refine((roles) => uniqueBy(roles, (r) => r.role), "roles must be unique"),
  attributeKeys: z
    .array(declaredAttributeKeySchema)
    .max(200)
    .default([])
    .refine((keys) => uniqueBy(keys, (k) => k.key), "attribute keys must be unique"),
  allowedExtraScopes: z.array(z.enum(EXTRA_SCOPES)).default([]),
});
export type CreateApplicationInput = z.input<typeof createApplicationInputSchema>;

export const updateApplicationInputSchema = z
  .object({
    name: displayNameSchema,
    enabled: z.boolean(),
    clientAuth: clientAuthSchema,
    redirectUris: z.array(absoluteUrlSchema).min(1).max(50),
    postLogoutRedirectUris: z.array(absoluteUrlSchema).max(50),
    allowedExtraScopes: z.array(z.enum(EXTRA_SCOPES)),
  })
  .partial();
export type UpdateApplicationInput = z.input<typeof updateApplicationInputSchema>;

export const declareRoleInputSchema = declaredRoleSchema;
export const declareAttributeKeyInputSchema = declaredAttributeKeySchema;
