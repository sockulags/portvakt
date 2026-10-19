import { z } from "zod";
import { MIN_CLIENT_SECRET_LENGTH } from "../crypto/secrets.js";
import {
  absoluteUrlSchema,
  attributeKeySchema,
  clientIdSchema,
  displayNameSchema,
  roleNameSchema,
} from "./schemas.js";

/**
 * Placeholder for the tenant slug in an application's redirect and post-logout URIs: an
 * application used in many tenants with per-tenant paths (the admin portal:
 * `https://admin.example.org/t/{tenant}/auth/callback`) registers one template, expanded to the
 * tenant's slug when the tenant's provider loads the client. Only allowed as a whole path segment.
 */
export const TENANT_PLACEHOLDER = "{tenant}";
const PLACEHOLDER_SAMPLE = "pv-tenant-placeholder";

/** A redirect URI with every `{tenant}` placeholder replaced by the tenant's slug. */
export const expandRedirectUri = (uri: string, tenantSlug: string): string =>
  uri.split(TENANT_PLACEHOLDER).join(tenantSlug);

/**
 * An absolute http(s) redirect URI without a fragment, optionally with `{tenant}` path segments
 * (see {@link TENANT_PLACEHOLDER}).
 */
export const redirectUriSchema = z
  .string()
  .max(2000)
  .superRefine((value, ctx) => {
    const sample = value.split(TENANT_PLACEHOLDER).join(PLACEHOLDER_SAMPLE);
    if (/[{}]/.test(sample)) {
      ctx.addIssue({ code: "custom", message: "only the {tenant} placeholder is allowed" });
      return;
    }
    if (!absoluteUrlSchema.safeParse(sample).success) {
      ctx.addIssue({
        code: "custom",
        message: "must be an absolute http(s) URL without a fragment",
      });
      return;
    }
    if (!value.includes(TENANT_PLACEHOLDER)) return;
    const url = new URL(sample);
    const segments = url.pathname.split("/");
    if (
      url.host.includes(PLACEHOLDER_SAMPLE) ||
      url.search.includes(PLACEHOLDER_SAMPLE) ||
      segments.some(
        (segment) => segment.includes(PLACEHOLDER_SAMPLE) && segment !== PLACEHOLDER_SAMPLE,
      )
    ) {
      ctx.addIssue({ code: "custom", message: "{tenant} is only allowed as a whole path segment" });
    }
  });

/** Scopes an application must be allowed: `pin` (personal identity number), `hsa` (SITHS). */
export const EXTRA_SCOPES = ["pin", "hsa"] as const;
export type ExtraScope = (typeof EXTRA_SCOPES)[number];

/**
 * Whether the application offers the representation chooser (docs/claims.md, `rep`): `none`
 * never (no `rep` is issued), `optional` the person may act for themselves or for a party they
 * hold a valid grant for, `required` the person must act for such a party.
 */
export const REPRESENTATION_MODES = ["none", "optional", "required"] as const;
export type RepresentationMode = (typeof REPRESENTATION_MODES)[number];

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
  readonly representationMode: RepresentationMode;
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
  redirectUris: z.array(redirectUriSchema).min(1).max(50),
  postLogoutRedirectUris: z.array(redirectUriSchema).max(50).default([]),
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
  representationMode: z.enum(REPRESENTATION_MODES).default("none"),
});
export type CreateApplicationInput = z.input<typeof createApplicationInputSchema>;

export const updateApplicationInputSchema = z
  .object({
    name: displayNameSchema,
    enabled: z.boolean(),
    clientAuth: clientAuthSchema,
    redirectUris: z.array(redirectUriSchema).min(1).max(50),
    postLogoutRedirectUris: z.array(redirectUriSchema).max(50),
    allowedExtraScopes: z.array(z.enum(EXTRA_SCOPES)),
    representationMode: z.enum(REPRESENTATION_MODES),
  })
  .partial();
export type UpdateApplicationInput = z.input<typeof updateApplicationInputSchema>;

export const declareRoleInputSchema = declaredRoleSchema;
export const declareAttributeKeyInputSchema = declaredAttributeKeySchema;
