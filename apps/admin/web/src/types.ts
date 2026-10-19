/**
 * The admin API's representations as the portal uses them (see the OpenAPI document at
 * `/admin/api/v1/openapi.json`; the server's zod schemas are the source of truth).
 */

export interface FieldError {
  readonly field: string;
  readonly message: string;
}

export interface Tenant {
  readonly id: string;
  readonly slug: string;
  readonly name: string;
  readonly status: "active" | "suspended";
  /** Where representation rights come from (registered sources, in order). */
  readonly representationSources: readonly string[];
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly etag: string;
}

export interface Me {
  readonly personId: string;
  readonly tenant: Tenant;
  readonly platform: boolean;
  readonly roles: readonly string[];
}

export interface List<T> {
  readonly items: readonly T[];
}

export type WarningCode =
  | "client_secret_expiring"
  | "client_secret_expired"
  | "sp_certificate_expiring"
  | "saml_metadata_error"
  | "saml_metadata_missing"
  | "saml_unsigned_metadata"
  | "saml_unencrypted_assertions"
  | "saml_unsigned_response"
  | "saml_minimum_comparison"
  | "saml_missing_logo"
  | "saml_missing_description"
  | "pin_login_hint_without_par";

export interface Warning {
  readonly code: WarningCode;
  readonly field?: string;
  readonly message: string;
  readonly expiresAt?: string;
  readonly purpose?: "signing" | "encryption";
}

export interface Dashboard {
  readonly logins: {
    readonly last24h: number;
    readonly last7d: number;
    readonly failedLast24h: number;
  };
  readonly activeSessions: number;
  readonly loginMethods: { readonly total: number; readonly enabled: number };
  readonly applications: { readonly attached: number; readonly enabled: number };
  readonly warnings: readonly (Warning & {
    readonly loginMethodId: string;
    readonly loginMethodName: string;
  })[];
  readonly keys: {
    readonly activeKid: string | null;
    readonly activatedAt: string | null;
    readonly nextKid: string | null;
    readonly retiringKids: readonly string[];
    readonly nextScheduledRotationAt: string | null;
  };
}

export interface DeclaredRole {
  readonly role: string;
  readonly description: string | null;
}

export interface DeclaredKey {
  readonly key: string;
  readonly description: string | null;
}

export type RepresentationMode = "none" | "optional" | "required";

export interface Application {
  readonly id: string;
  readonly clientId: string;
  readonly name: string;
  readonly enabled: boolean;
  readonly clientAuth:
    | { readonly method: "client_secret_basic" | "client_secret_post" }
    | { readonly method: "private_key_jwt"; readonly jwksUri?: string; readonly jwks?: unknown };
  readonly redirectUris: readonly string[];
  readonly postLogoutRedirectUris: readonly string[];
  readonly roles: readonly DeclaredRole[];
  readonly attributeKeys: readonly DeclaredKey[];
  readonly allowedExtraScopes: readonly ("pin" | "hsa")[];
  readonly serviceAudiences: readonly string[];
  readonly representationMode: RepresentationMode;
  readonly etag: string;
}

export interface ApplicationWithSecret {
  readonly application: Application;
  readonly clientSecret?: string;
}

export interface TenantApplication {
  readonly applicationId: string;
  readonly clientId: string;
  readonly name: string;
  readonly enabled: boolean;
  readonly applicationEnabled: boolean;
  readonly representationMode: RepresentationMode;
  readonly roles: readonly DeclaredRole[];
  readonly attributeKeys: readonly DeclaredKey[];
  readonly attachedAt: string;
  readonly etag: string;
}

export interface SessionPolicy {
  readonly maxAgeSeconds: number;
  readonly idleSeconds: number;
  readonly allowSso: boolean;
}

export interface SpKey {
  readonly id: string;
  readonly purpose: "signing" | "encryption";
  readonly state: "next" | "active" | "previous";
  readonly notAfter: string;
  readonly createdAt: string;
}

export interface OidcSettings {
  readonly issuer: string;
  readonly clientId: string;
  readonly hasClientSecret: boolean;
  readonly clientAuthMethod: "client_secret_basic" | "client_secret_post" | "private_key_jwt";
  readonly useUserinfo: boolean;
  readonly clientAssertionAudience: "token_endpoint" | "issuer";
  readonly allowedUpstreamTenants: readonly string[];
  readonly trustUpstreamEmail: boolean;
  readonly pinLoginHint: boolean;
  readonly scopes: readonly string[];
  readonly claimMapping: Readonly<Record<string, string>>;
  readonly redirectUri: string;
  readonly jwksUri: string;
}

export interface SamlSettings {
  readonly idpEntityId: string;
  readonly metadataUrl: string | null;
  readonly hasInlineMetadata: boolean;
  readonly metadataSigningCertificate: string | null;
  readonly requestedLoa: readonly string[];
  readonly authnContextComparison: "exact" | "minimum";
  readonly entityCategories: readonly string[];
  readonly subjectSource: "personalIdentityNumber" | "prid" | "employeeHsaId" | "nameId";
  readonly authnRequestBinding: "redirect" | "post";
  readonly requireEncryptedAssertions: boolean;
  readonly requireSignedResponse: boolean;
  readonly allowUnsignedMetadata: boolean;
  readonly trustEmail: boolean;
  readonly requireGcm: boolean;
  readonly clockSkewSeconds: number;
  readonly uiInfo: {
    readonly displayName?: { readonly sv: string; readonly en?: string };
    readonly description?: { readonly sv: string; readonly en?: string };
    readonly logos?: readonly {
      readonly url: string;
      readonly width: number;
      readonly height: number;
    }[];
  };
  readonly spEntityId: string;
  readonly spMetadataUrl: string;
  readonly acsUrl: string;
  readonly spKeys: readonly SpKey[];
  readonly metadataStatus: {
    readonly cachedAt: string | null;
    readonly checkedAt: string | null;
    readonly validUntil: string | null;
    readonly error: string | null;
  };
}

export interface LoginMethod {
  readonly id: string;
  readonly tenantId: string;
  readonly protocol: "oidc" | "saml";
  readonly kind: "employee" | "citizen";
  readonly displayName: string;
  readonly assertedAcr: string;
  readonly homeRealmDomains: readonly string[];
  readonly secretExpiresAt: string | null;
  readonly sessionPolicy: SessionPolicy;
  readonly linkByPin: boolean;
  readonly trustPinForRepresentation: boolean;
  readonly enabled: boolean;
  readonly oidc?: OidcSettings;
  readonly saml?: SamlSettings;
  readonly warnings: readonly Warning[];
  readonly etag: string;
}

export interface RoleRule {
  readonly id: string;
  readonly applicationId: string;
  readonly loginMethodId: string;
  readonly groupValue: string;
  readonly role: string;
  readonly createdAt: string;
}

export type AssignmentTarget =
  | { readonly kind: "person"; readonly personId: string }
  | { readonly kind: "identity"; readonly loginMethodId: string; readonly subject: string }
  | { readonly kind: "pin" };

export interface RoleAssignment {
  readonly id: string;
  readonly applicationId: string;
  readonly role: string;
  readonly target: AssignmentTarget;
  readonly pending: boolean;
  readonly createdAt: string;
}

export interface AttributeAssignment {
  readonly id: string;
  readonly applicationId: string;
  readonly key: string;
  readonly value: string;
  readonly target: AssignmentTarget;
  readonly pending: boolean;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly etag: string;
}

/** What removing roles/keys from an application, or detaching it, deletes. */
export interface ApplicationUsage {
  readonly roleAssignments: number;
  readonly pendingRoleAssignments: number;
  readonly roleRules: number;
  readonly attributeAssignments: number;
  readonly pendingAttributeAssignments: number;
  readonly grantLimits: number;
}

export interface RoleCatalogue {
  readonly applications: readonly {
    readonly applicationId: string;
    readonly clientId: string;
    readonly name: string;
    readonly enabled: boolean;
    readonly roles: readonly DeclaredRole[];
    readonly attributeKeys: readonly DeclaredKey[];
  }[];
}

export interface PersonSummary {
  readonly id: string;
  readonly displayName: string | null;
  readonly email: string | null;
  readonly protectedIdentity: boolean;
  readonly createdAt: string;
  readonly lastLoginAt: string | null;
}

export interface Party {
  readonly id: string;
  readonly type: "person" | "organisation";
  readonly identifier: string | null;
  readonly displayName: string;
  readonly protectedIdentity: boolean;
  readonly etag: string;
}

export interface Grant {
  readonly id: string;
  readonly party: {
    readonly id: string;
    readonly type: "person" | "organisation";
    readonly displayName: string;
  };
  readonly agent: { readonly kind: "person"; readonly personId: string } | { readonly kind: "pin" };
  readonly allApplications: boolean;
  readonly applicationIds: readonly string[];
  readonly validFrom: string;
  readonly validTo: string | null;
  readonly revokedAt: string | null;
  readonly status: "active" | "scheduled" | "expired" | "revoked";
  readonly etag: string;
}

export interface Person extends PersonSummary {
  readonly identities: readonly {
    readonly id: string;
    readonly loginMethodId: string;
    readonly loginMethodName: string | null;
    readonly kind: "employee" | "citizen" | null;
    readonly subject: string | null;
    readonly hasPin: boolean;
    readonly lastLoginAt: string;
  }[];
  readonly roleAssignments: readonly RoleAssignment[];
  readonly attributeAssignments: readonly {
    readonly id: string;
    readonly applicationId: string;
    readonly key: string;
    readonly value: string;
  }[];
  readonly grants: readonly Grant[];
  readonly etag: string;
}

export interface SigningKey {
  readonly kid: string;
  readonly alg: string;
  readonly state: "next" | "active" | "retiring" | "retired";
  readonly createdAt: string;
  readonly activatedAt: string | null;
  readonly retiringAt: string | null;
  readonly retiredAt: string | null;
  /** A next key of a manual rotation: when it becomes active. */
  readonly activateAt: string | null;
}

export interface SigningKeys {
  readonly keys: readonly SigningKey[];
  readonly policy: {
    readonly intervalSeconds: number;
    readonly publishAheadSeconds: number;
    readonly retireAfterSeconds: number;
    readonly manualPublishAheadSeconds: number;
  };
  readonly nextScheduledRotationAt: string | null;
  readonly etag: string;
}

/** The answer of `POST /signing-keys/rotate`. */
export interface KeyRotation {
  readonly status: "activated" | "scheduled";
  readonly activatedKid: string | null;
  readonly nextKid: string | null;
  readonly activatesAt: string | null;
  readonly keys: SigningKeys;
}

export interface AuditEvent {
  readonly id: string;
  readonly seq: string;
  readonly occurredAt: string;
  readonly tenantId: string | null;
  readonly actor: { readonly type: string; readonly id: string | null };
  readonly subject: { readonly type: string; readonly id: string } | null;
  readonly action: string;
  readonly outcome: "success" | "failure";
  readonly details: Readonly<Record<string, unknown>>;
}

export interface AuditPage {
  readonly items: readonly AuditEvent[];
  readonly nextCursor: string | null;
}

export interface SessionInfo {
  readonly authenticated: boolean;
  readonly principal?: { readonly name?: string; readonly sub: string; readonly tenant: string };
  readonly csrfToken?: string;
}
