import { randomUUID } from "node:crypto";
import type { SecretBox } from "../crypto/envelope.js";
import {
  generateSigningKey,
  privateJwkSchema,
  publicJwkSchema,
  type PrivateJwk,
  type PublicJwk,
} from "../crypto/jwk.js";
import { z } from "zod";
import { DEFAULT_ACR_RANKING } from "../config/index.js";
import type { Db } from "../db/database.js";
import {
  claimMappingSchema,
  createLoginMethodInputSchema,
  type CreateLoginMethodInput,
  createSamlLoginMethodInputSchema,
  type CreateSamlLoginMethodInput,
  type ClientAssertionAudience,
  emailDomain,
  type LoginMethod,
  type LoginMethodKind,
  type LoginMethodProtocol,
  loginMethodRuleViolations,
  pinTrustViolations,
  type OidcLoginMethod,
  type SamlLoginMethod,
  type UpstreamAuthMethod,
  updateLoginMethodInputSchema,
  type UpdateLoginMethodInput,
  updateSamlLoginMethodInputSchema,
  type UpdateSamlLoginMethodInput,
} from "../domain/login-method.js";
import {
  requestedAttributeSchema,
  samlAttributeMappingSchema,
  samlSettingsInputSchema,
  samlSettingsViolations,
  uiInfoSchema,
  type ParsedSamlSettings,
  type SamlBinding,
  type SamlComparison,
  type SamlSettings,
  type SamlSubjectSource,
} from "../domain/saml.js";
import { emailDomainSchema } from "../domain/schemas.js";
import { emitChange } from "./change-events.js";
import { mapDbErrors, NotFoundError, parseInput, requireUuids, ValidationError } from "./errors.js";
import { insertSpKey, type NewSpKey } from "./saml.js";

interface LoginMethodRow {
  id: string;
  tenant_id: string;
  protocol: LoginMethodProtocol;
  kind: LoginMethodKind;
  display_name: string;
  issuer: string | null;
  client_id: string | null;
  has_client_secret: boolean;
  token_endpoint_auth_method: UpstreamAuthMethod;
  client_key_kid: string | null;
  use_userinfo: boolean;
  client_assertion_audience: ClientAssertionAudience;
  allowed_upstream_tenants: string[];
  trust_upstream_email: boolean;
  pin_login_hint: boolean;
  scopes: string[];
  claim_mapping: unknown;
  asserted_acr: string;
  home_realm_domains: string[];
  secret_expires_at: Date | null;
  max_age_seconds: number;
  idle_seconds: number;
  allow_sso: boolean;
  link_by_pin: boolean;
  trust_pin_for_representation: boolean;
  enabled: boolean;
  created_at: Date;
  updated_at: Date;
  // login_method_saml (NULL for OIDC methods)
  saml_idp_entity_id: string | null;
  saml_metadata_url: string | null;
  saml_metadata_xml: string | null;
  saml_metadata_signing_certificate: string | null;
  saml_metadata_refresh_seconds: number | null;
  saml_requested_loa: string[] | null;
  saml_authn_context_comparison: SamlComparison | null;
  saml_entity_categories: string[] | null;
  saml_requested_attributes: unknown;
  saml_subject_source: SamlSubjectSource | null;
  saml_attribute_mapping: unknown;
  saml_authn_request_binding: SamlBinding | null;
  saml_require_encrypted_assertions: boolean | null;
  saml_require_signed_response: boolean | null;
  saml_sign_metadata: boolean | null;
  saml_clock_skew_seconds: number | null;
  saml_trust_email: boolean | null;
  saml_allow_unsigned_metadata: boolean | null;
  saml_require_gcm: boolean | null;
  saml_ui_info: unknown;
  saml_org_affiliation_scopes: string[] | null;
}

const SELECT_LOGIN_METHOD = `
  SELECT lm.id, lm.tenant_id, lm.protocol, lm.kind, lm.display_name, lm.issuer, lm.client_id,
         lm.client_secret_encrypted IS NOT NULL AS has_client_secret,
         lm.token_endpoint_auth_method, lm.client_key_kid, lm.use_userinfo,
         lm.client_assertion_audience, lm.allowed_upstream_tenants, lm.trust_upstream_email, lm.pin_login_hint, lm.scopes,
         lm.claim_mapping, lm.asserted_acr, lm.secret_expires_at, lm.max_age_seconds,
         lm.idle_seconds, lm.allow_sso, lm.link_by_pin, lm.trust_pin_for_representation, lm.enabled, lm.created_at, lm.updated_at,
         ARRAY(SELECT d.domain FROM login_method_domains d
                WHERE d.tenant_id = lm.tenant_id AND d.login_method_id = lm.id
                ORDER BY d.domain) AS home_realm_domains,
         s.idp_entity_id AS saml_idp_entity_id, s.metadata_url AS saml_metadata_url,
         s.metadata_xml AS saml_metadata_xml,
         s.metadata_signing_certificate AS saml_metadata_signing_certificate,
         s.metadata_refresh_seconds AS saml_metadata_refresh_seconds,
         s.requested_loa AS saml_requested_loa,
         s.authn_context_comparison AS saml_authn_context_comparison,
         s.entity_categories AS saml_entity_categories,
         s.requested_attributes AS saml_requested_attributes,
         s.subject_source AS saml_subject_source, s.attribute_mapping AS saml_attribute_mapping,
         s.authn_request_binding AS saml_authn_request_binding,
         s.require_encrypted_assertions AS saml_require_encrypted_assertions,
         s.require_signed_response AS saml_require_signed_response,
         s.sign_metadata AS saml_sign_metadata, s.clock_skew_seconds AS saml_clock_skew_seconds,
         s.trust_email AS saml_trust_email,
         s.allow_unsigned_metadata AS saml_allow_unsigned_metadata,
         s.require_gcm AS saml_require_gcm, s.ui_info AS saml_ui_info,
         s.org_affiliation_scopes AS saml_org_affiliation_scopes
    FROM login_methods lm
    LEFT JOIN login_method_saml s ON s.tenant_id = lm.tenant_id AND s.login_method_id = lm.id`;

const required = <T>(value: T | null, column: string): T => {
  if (value === null) throw new Error(`login method row without ${column}`);
  return value;
};

function samlSettingsOf(row: LoginMethodRow): SamlSettings {
  return {
    idpEntityId: required(row.saml_idp_entity_id, "SAML settings"),
    metadataUrl: row.saml_metadata_url,
    metadataXml: row.saml_metadata_xml,
    metadataSigningCertificate: row.saml_metadata_signing_certificate,
    metadataRefreshSeconds: required(row.saml_metadata_refresh_seconds, "SAML settings"),
    requestedLoa: required(row.saml_requested_loa, "SAML settings"),
    authnContextComparison: required(row.saml_authn_context_comparison, "SAML settings"),
    entityCategories: required(row.saml_entity_categories, "SAML settings"),
    requestedAttributes: z.array(requestedAttributeSchema).parse(row.saml_requested_attributes),
    subjectSource: required(row.saml_subject_source, "SAML settings"),
    attributeMapping: samlAttributeMappingSchema.parse(row.saml_attribute_mapping),
    authnRequestBinding: required(row.saml_authn_request_binding, "SAML settings"),
    requireEncryptedAssertions: required(row.saml_require_encrypted_assertions, "SAML settings"),
    requireSignedResponse: required(row.saml_require_signed_response, "SAML settings"),
    signMetadata: required(row.saml_sign_metadata, "SAML settings"),
    clockSkewSeconds: required(row.saml_clock_skew_seconds, "SAML settings"),
    trustEmail: required(row.saml_trust_email, "SAML settings"),
    allowUnsignedMetadata: required(row.saml_allow_unsigned_metadata, "SAML settings"),
    requireGcm: required(row.saml_require_gcm, "SAML settings"),
    uiInfo: uiInfoSchema.parse(row.saml_ui_info),
    orgAffiliationScopes: required(row.saml_org_affiliation_scopes, "SAML settings"),
  };
}

function toLoginMethod(row: LoginMethodRow): LoginMethod {
  const base = {
    id: row.id,
    tenantId: row.tenant_id,
    kind: row.kind,
    displayName: row.display_name,
    assertedAcr: row.asserted_acr,
    homeRealmDomains: row.home_realm_domains,
    secretExpiresAt: row.secret_expires_at,
    sessionPolicy: {
      maxAgeSeconds: row.max_age_seconds,
      idleSeconds: row.idle_seconds,
      allowSso: row.allow_sso,
    },
    linkByPin: row.link_by_pin,
    trustPinForRepresentation: row.trust_pin_for_representation,
    enabled: row.enabled,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
  if (row.protocol === "saml") return { ...base, protocol: "saml", saml: samlSettingsOf(row) };
  return {
    ...base,
    protocol: "oidc",
    issuer: required(row.issuer, "issuer"),
    clientId: required(row.client_id, "client_id"),
    hasClientSecret: row.has_client_secret,
    clientAuthMethod: row.token_endpoint_auth_method,
    clientKeyKid: row.client_key_kid,
    useUserinfo: row.use_userinfo,
    clientAssertionAudience: row.client_assertion_audience,
    allowedUpstreamTenants: row.allowed_upstream_tenants,
    trustUpstreamEmail: row.trust_upstream_email,
    pinLoginHint: row.pin_login_hint,
    scopes: row.scopes,
    claimMapping: claimMappingSchema.parse(row.claim_mapping),
  };
}

/** AAD context binding an encrypted upstream secret to its login method. */
export const clientSecretContext = (loginMethodId: string): string =>
  `login_method:${loginMethodId}:client_secret`;

/** AAD context binding the encrypted private client key (private_key_jwt) to its login method. */
export const clientPrivateJwkContext = (loginMethodId: string): string =>
  `login_method:${loginMethodId}:client_private_jwk`;

export interface LoginMethodRepositoryOptions {
  /**
   * Ceiling for `sessionPolicy.maxAgeSeconds` (SESSION_TTL): longer sessions are refused at write
   * time, because signing keys are only kept published for SESSION_TTL.
   */
  readonly maxSessionSeconds?: number;
  /**
   * ACR_RANKING: a login method asserting a ranked level must map the upstream acr (refused at
   * write time otherwise).
   */
  readonly acrRanking?: readonly string[];
}

/** The login method's client key pair, for signing private_key_jwt client assertions. */
export interface LoginMethodClientKey {
  readonly kid: string;
  readonly publicJwk: PublicJwk;
  readonly privateJwk: PrivateJwk;
}

interface EncryptedClientKey {
  readonly kid: string;
  readonly publicJwk: string;
  readonly privateJwkEncrypted: string;
}

/**
 * Login methods per tenant. Every write emits a `login_methods` change event: the tenant's
 * provider is built from its login methods (acr values) and is rebuilt on change.
 */
export class LoginMethodRepository {
  readonly #db: Db;
  readonly #secrets: SecretBox;
  readonly #maxSessionSeconds: number | undefined;
  readonly #acrRanking: readonly string[];

  constructor(db: Db, secrets: SecretBox, options: LoginMethodRepositoryOptions = {}) {
    this.#db = db;
    this.#secrets = secrets;
    this.#maxSessionSeconds = options.maxSessionSeconds;
    this.#acrRanking = options.acrRanking ?? [];
  }

  async create(tenantId: string, input: CreateLoginMethodInput): Promise<OidcLoginMethod> {
    requireUuids({ tenantId });
    const data = parseInput(createLoginMethodInputSchema, input);
    this.#checkMaxAge(data.sessionPolicy.maxAgeSeconds);
    this.#checkRules(data);
    const id = randomUUID();
    const encryptedSecret =
      data.clientSecret === undefined
        ? null
        : this.#secrets.encrypt(data.clientSecret, clientSecretContext(id));
    const key = this.#newClientKey(id);

    await this.#db.transaction(async (tx) => {
      await mapDbErrors(() =>
        tx.query(
          `INSERT INTO login_methods
             (id, tenant_id, kind, display_name, issuer, client_id, client_secret_encrypted, scopes,
              claim_mapping, asserted_acr, secret_expires_at, max_age_seconds, idle_seconds,
              allow_sso, link_by_pin, enabled, token_endpoint_auth_method, use_userinfo,
              client_key_kid, client_public_jwk, client_private_jwk_encrypted,
              client_assertion_audience, allowed_upstream_tenants, trust_upstream_email,
              pin_login_hint, trust_pin_for_representation)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10, $11, $12, $13, $14, $15, $16,
                   $17, $18, $19, $20::jsonb, $21, $22, $23, $24, $25, $26)`,
          [
            id,
            tenantId,
            data.kind,
            data.displayName,
            data.issuer,
            data.clientId,
            encryptedSecret,
            data.scopes,
            JSON.stringify(data.claimMapping),
            data.assertedAcr,
            data.secretExpiresAt,
            data.sessionPolicy.maxAgeSeconds,
            data.sessionPolicy.idleSeconds,
            data.sessionPolicy.allowSso,
            data.linkByPin,
            data.enabled,
            data.clientAuthMethod,
            data.useUserinfo,
            key.kid,
            key.publicJwk,
            key.privateJwkEncrypted,
            data.clientAssertionAudience,
            data.allowedUpstreamTenants,
            data.trustUpstreamEmail,
            data.pinLoginHint,
            data.trustPinForRepresentation,
          ],
        ),
      );
      await this.#replaceDomains(tx, tenantId, id, data.homeRealmDomains);
      await emitChange(tx, { type: "login_methods", tenantId });
    });
    return this.#requireOidc(tenantId, id);
  }

  async update(
    tenantId: string,
    id: string,
    patch: UpdateLoginMethodInput,
  ): Promise<OidcLoginMethod> {
    requireUuids({ tenantId, id });
    const data = parseInput(updateLoginMethodInputSchema, patch);
    if (data.sessionPolicy !== undefined) this.#checkMaxAge(data.sessionPolicy.maxAgeSeconds);
    const current = await this.#require(tenantId, id);
    if (current.protocol !== "oidc") {
      throw new ValidationError(["protocol: not an OIDC login method (use updateSaml)"]);
    }
    this.#checkRules({
      issuer: data.issuer ?? current.issuer,
      allowedUpstreamTenants: data.allowedUpstreamTenants ?? current.allowedUpstreamTenants,
      assertedAcr: data.assertedAcr ?? current.assertedAcr,
      claimMapping: data.claimMapping ?? current.claimMapping,
      trustPinForRepresentation:
        data.trustPinForRepresentation ?? current.trustPinForRepresentation,
    });
    const secretChanged = data.clientSecret !== undefined;
    const encryptedSecret =
      data.clientSecret === undefined || data.clientSecret === null
        ? null
        : this.#secrets.encrypt(data.clientSecret, clientSecretContext(id));

    await this.#db.transaction(async (tx) => {
      const rows = await mapDbErrors(() =>
        tx.query(
          `UPDATE login_methods SET
             kind = COALESCE($3, kind),
             display_name = COALESCE($4, display_name),
             issuer = COALESCE($5, issuer),
             client_id = COALESCE($6, client_id),
             client_secret_encrypted = CASE WHEN $7::boolean THEN $8 ELSE client_secret_encrypted END,
             scopes = COALESCE($9, scopes),
             claim_mapping = COALESCE($10::jsonb, claim_mapping),
             asserted_acr = COALESCE($11, asserted_acr),
             secret_expires_at = CASE WHEN $12::boolean THEN $13 ELSE secret_expires_at END,
             max_age_seconds = COALESCE($14, max_age_seconds),
             idle_seconds = COALESCE($15, idle_seconds),
             allow_sso = COALESCE($16, allow_sso),
             enabled = COALESCE($17, enabled),
             link_by_pin = COALESCE($18, link_by_pin),
             token_endpoint_auth_method = COALESCE($19, token_endpoint_auth_method),
             use_userinfo = COALESCE($20, use_userinfo),
             client_assertion_audience = COALESCE($21, client_assertion_audience),
             allowed_upstream_tenants = COALESCE($22, allowed_upstream_tenants),
             trust_upstream_email = COALESCE($23, trust_upstream_email),
             pin_login_hint = COALESCE($24, pin_login_hint),
             trust_pin_for_representation = COALESCE($25, trust_pin_for_representation)
           WHERE tenant_id = $1 AND id = $2 AND protocol = 'oidc'
           RETURNING id`,
          [
            tenantId,
            id,
            data.kind ?? null,
            data.displayName ?? null,
            data.issuer ?? null,
            data.clientId ?? null,
            secretChanged,
            encryptedSecret,
            data.scopes ?? null,
            data.claimMapping === undefined ? null : JSON.stringify(data.claimMapping),
            data.assertedAcr ?? null,
            data.secretExpiresAt !== undefined,
            data.secretExpiresAt ?? null,
            data.sessionPolicy?.maxAgeSeconds ?? null,
            data.sessionPolicy?.idleSeconds ?? null,
            data.sessionPolicy?.allowSso ?? null,
            data.enabled ?? null,
            data.linkByPin ?? null,
            data.clientAuthMethod ?? null,
            data.useUserinfo ?? null,
            data.clientAssertionAudience ?? null,
            data.allowedUpstreamTenants ?? null,
            data.trustUpstreamEmail ?? null,
            data.pinLoginHint ?? null,
            data.trustPinForRepresentation ?? null,
          ],
        ),
      );
      if (rows.length === 0) throw new NotFoundError("Login method");
      if (data.homeRealmDomains !== undefined) {
        await this.#replaceDomains(tx, tenantId, id, data.homeRealmDomains);
      }
      await emitChange(tx, { type: "login_methods", tenantId });
    });
    return this.#requireOidc(tenantId, id);
  }

  /**
   * Creates a SAML login method with its SP key pairs (generated by the caller, see
   * `SamlLoginMethodAdmin`) and, when known, the IdP metadata already fetched and checked.
   */
  async createSaml(
    tenantId: string,
    input: CreateSamlLoginMethodInput,
    extras: { readonly spKeys: readonly NewSpKey[]; readonly metadataCache: unknown },
  ): Promise<SamlLoginMethod> {
    requireUuids({ tenantId });
    const data = parseInput(createSamlLoginMethodInputSchema, input);
    this.#checkMaxAge(data.sessionPolicy.maxAgeSeconds);
    this.#checkSamlRules(data.saml, data.assertedAcr, data.trustPinForRepresentation);
    const id = randomUUID();
    await this.#db.transaction(async (tx) => {
      await mapDbErrors(() =>
        tx.query(
          `INSERT INTO login_methods
             (id, tenant_id, protocol, kind, display_name, issuer, client_id, scopes, claim_mapping,
              asserted_acr, max_age_seconds, idle_seconds, allow_sso, link_by_pin, enabled,
              trust_pin_for_representation)
           VALUES ($1, $2, 'saml', $3, $4, NULL, NULL, ARRAY['openid'], '{}'::jsonb, $5, $6, $7,
                   $8, $9, $10, $11)`,
          [
            id,
            tenantId,
            data.kind,
            data.displayName,
            data.assertedAcr,
            data.sessionPolicy.maxAgeSeconds,
            data.sessionPolicy.idleSeconds,
            data.sessionPolicy.allowSso,
            data.linkByPin,
            data.enabled,
            data.trustPinForRepresentation,
          ],
        ),
      );
      await this.#writeSaml(tx, tenantId, id, data.saml, extras.metadataCache, "insert");
      for (const key of extras.spKeys) {
        await insertSpKey(tx, this.#secrets, tenantId, id, key, "active");
      }
      await this.#replaceDomains(tx, tenantId, id, data.homeRealmDomains);
      await emitChange(tx, { type: "login_methods", tenantId });
    });
    return this.#requireSaml(tenantId, id);
  }

  /**
   * Updates a SAML login method. The settings patch is merged into the stored settings and the
   * result validated as a whole. `metadataCache` replaces the cached IdP metadata when the
   * metadata source changed (the caller fetched and checked it).
   */
  async updateSaml(
    tenantId: string,
    id: string,
    patch: UpdateSamlLoginMethodInput,
    extras: { readonly metadataCache?: unknown } = {},
  ): Promise<SamlLoginMethod> {
    requireUuids({ tenantId, id });
    const data = parseInput(updateSamlLoginMethodInputSchema, patch);
    if (data.sessionPolicy !== undefined) this.#checkMaxAge(data.sessionPolicy.maxAgeSeconds);
    const current = await this.#requireSaml(tenantId, id);
    const settings = mergeSamlSettings(current.saml, data.saml ?? {});
    const assertedAcr = data.assertedAcr ?? current.assertedAcr;
    this.#checkSamlRules(
      settings,
      assertedAcr,
      data.trustPinForRepresentation ?? current.trustPinForRepresentation,
    );
    await this.#db.transaction(async (tx) => {
      const rows = await mapDbErrors(() =>
        tx.query(
          `UPDATE login_methods SET
             kind = COALESCE($3, kind),
             display_name = COALESCE($4, display_name),
             asserted_acr = COALESCE($5, asserted_acr),
             max_age_seconds = COALESCE($6, max_age_seconds),
             idle_seconds = COALESCE($7, idle_seconds),
             allow_sso = COALESCE($8, allow_sso),
             link_by_pin = COALESCE($9, link_by_pin),
             enabled = COALESCE($10, enabled),
             trust_pin_for_representation = COALESCE($11, trust_pin_for_representation)
           WHERE tenant_id = $1 AND id = $2 AND protocol = 'saml'
           RETURNING id`,
          [
            tenantId,
            id,
            data.kind ?? null,
            data.displayName ?? null,
            data.assertedAcr ?? null,
            data.sessionPolicy?.maxAgeSeconds ?? null,
            data.sessionPolicy?.idleSeconds ?? null,
            data.sessionPolicy?.allowSso ?? null,
            data.linkByPin ?? null,
            data.enabled ?? null,
            data.trustPinForRepresentation ?? null,
          ],
        ),
      );
      if (rows.length === 0) throw new NotFoundError("Login method");
      await this.#writeSaml(tx, tenantId, id, settings, extras.metadataCache, "update");
      if (data.homeRealmDomains !== undefined) {
        await this.#replaceDomains(tx, tenantId, id, data.homeRealmDomains);
      }
      await emitChange(tx, { type: "login_methods", tenantId });
    });
    return this.#requireSaml(tenantId, id);
  }

  async findById(tenantId: string, id: string): Promise<LoginMethod | null> {
    requireUuids({ tenantId, id });
    const [row] = await this.#db.query<LoginMethodRow>(
      `${SELECT_LOGIN_METHOD} WHERE lm.tenant_id = $1 AND lm.id = $2`,
      [tenantId, id],
    );
    return row === undefined ? null : toLoginMethod(row);
  }

  async list(tenantId: string): Promise<LoginMethod[]> {
    requireUuids({ tenantId });
    const rows = await this.#db.query<LoginMethodRow>(
      `${SELECT_LOGIN_METHOD} WHERE lm.tenant_id = $1 ORDER BY lm.display_name, lm.id`,
      [tenantId],
    );
    return rows.map(toLoginMethod);
  }

  /** Login methods offered on the tenant's login page. */
  async listEnabled(tenantId: string): Promise<LoginMethod[]> {
    requireUuids({ tenantId });
    const rows = await this.#db.query<LoginMethodRow>(
      `${SELECT_LOGIN_METHOD} WHERE lm.tenant_id = $1 AND lm.enabled
        ORDER BY lm.display_name, lm.id`,
      [tenantId],
    );
    return rows.map(toLoginMethod);
  }

  /**
   * Home realm discovery: the enabled login method that owns the domain (or the domain of an
   * email address) in this tenant.
   */
  async findEnabledByHomeRealm(
    tenantId: string,
    domainOrEmail: string,
  ): Promise<LoginMethod | null> {
    requireUuids({ tenantId });
    const domain = domainOrEmail.includes("@")
      ? emailDomain(domainOrEmail)
      : emailDomainSchema.safeParse(domainOrEmail).data;
    if (domain === undefined) return null;
    const [row] = await this.#db.query<LoginMethodRow>(
      `${SELECT_LOGIN_METHOD}
         JOIN login_method_domains hr ON hr.tenant_id = lm.tenant_id AND hr.login_method_id = lm.id
        WHERE lm.tenant_id = $1 AND hr.domain = $2 AND lm.enabled`,
      [tenantId, domain],
    );
    return row === undefined ? null : toLoginMethod(row);
  }

  /** Login methods whose upstream secret expires before `before` (admin flagging). */
  async listSecretsExpiringBefore(tenantId: string, before: Date): Promise<LoginMethod[]> {
    requireUuids({ tenantId });
    const rows = await this.#db.query<LoginMethodRow>(
      `${SELECT_LOGIN_METHOD}
        WHERE lm.tenant_id = $1 AND lm.secret_expires_at IS NOT NULL AND lm.secret_expires_at < $2
        ORDER BY lm.secret_expires_at`,
      [tenantId, before],
    );
    return rows.map(toLoginMethod);
  }

  /** Decrypted upstream client secret, for the federation client only. Never log it. */
  async getClientSecret(tenantId: string, id: string): Promise<string | null> {
    requireUuids({ tenantId, id });
    const [row] = await this.#db.query<{ client_secret_encrypted: string | null }>(
      "SELECT client_secret_encrypted FROM login_methods WHERE tenant_id = $1 AND id = $2",
      [tenantId, id],
    );
    if (row === undefined) throw new NotFoundError("Login method");
    if (row.client_secret_encrypted === null) return null;
    return this.#secrets.decryptString(row.client_secret_encrypted, clientSecretContext(id));
  }

  /**
   * Public JWK of the login method's client key (what the tenant registers upstream for
   * private_key_jwt). Generates the key pair first if the method has none yet (rows created
   * before migration 0002). `null` for an unknown login method.
   */
  async ensureClientPublicJwk(tenantId: string, id: string): Promise<PublicJwk | null> {
    requireUuids({ tenantId, id });
    const read = async (): Promise<{ public: unknown } | undefined> =>
      (
        await this.#db.query<{ public: unknown }>(
          `SELECT client_public_jwk AS public FROM login_methods
            WHERE tenant_id = $1 AND id = $2 AND protocol = 'oidc'`,
          [tenantId, id],
        )
      )[0];
    let row = await read();
    if (row === undefined) return null;
    if (row.public === null) {
      const key = this.#newClientKey(id);
      // Of concurrent first requests, exactly one stores its key; the others read it back.
      await this.#db.query(
        `UPDATE login_methods
            SET client_key_kid = $3, client_public_jwk = $4::jsonb, client_private_jwk_encrypted = $5
          WHERE tenant_id = $1 AND id = $2 AND client_key_kid IS NULL`,
        [tenantId, id, key.kid, key.publicJwk, key.privateJwkEncrypted],
      );
      row = await read();
      if (row === undefined) return null;
    }
    return publicJwkSchema.parse(row.public);
  }

  /** Decrypted client key pair for private_key_jwt, for the federation client only. */
  async getClientKey(tenantId: string, id: string): Promise<LoginMethodClientKey | null> {
    requireUuids({ tenantId, id });
    await this.ensureClientPublicJwk(tenantId, id);
    const [row] = await this.#db.query<{
      kid: string | null;
      public: unknown;
      private: string | null;
    }>(
      `SELECT client_key_kid AS kid, client_public_jwk AS public,
              client_private_jwk_encrypted AS private
         FROM login_methods WHERE tenant_id = $1 AND id = $2`,
      [tenantId, id],
    );
    if (row === undefined || row.kid === null || row.private === null) return null;
    const privateJwk = privateJwkSchema.parse(
      JSON.parse(this.#secrets.decryptString(row.private, clientPrivateJwkContext(id))),
    );
    return { kid: row.kid, publicJwk: publicJwkSchema.parse(row.public), privateJwk };
  }

  /** How many identities link persons to the login method (a method with any cannot be deleted). */
  async identityCount(tenantId: string, id: string): Promise<number> {
    requireUuids({ tenantId, id });
    const [row] = await this.#db.query<{ count: string }>(
      "SELECT count(*) AS count FROM identities WHERE tenant_id = $1 AND login_method_id = $2",
      [tenantId, id],
    );
    return Number(row?.count ?? 0);
  }

  /** Deleting a login method that still has identities is refused; disable it instead. */
  async delete(tenantId: string, id: string): Promise<boolean> {
    requireUuids({ tenantId, id });
    return this.#db.transaction(async (tx) => {
      const rows = await mapDbErrors(() =>
        tx.query("DELETE FROM login_methods WHERE tenant_id = $1 AND id = $2 RETURNING id", [
          tenantId,
          id,
        ]),
      );
      if (rows.length > 0) await emitChange(tx, { type: "login_methods", tenantId });
      return rows.length > 0;
    });
  }

  #checkMaxAge(maxAgeSeconds: number): void {
    if (this.#maxSessionSeconds !== undefined && maxAgeSeconds > this.#maxSessionSeconds) {
      throw new ValidationError([
        `sessionPolicy.maxAgeSeconds: must not exceed SESSION_TTL (${this.#maxSessionSeconds} seconds)`,
      ]);
    }
  }

  #checkRules(
    method: Parameters<typeof loginMethodRuleViolations>[0] & {
      readonly trustPinForRepresentation: boolean;
    },
  ): void {
    const issues = [
      ...loginMethodRuleViolations(method, this.#acrRanking),
      ...pinTrustViolations(
        { ...method, mapsPin: method.claimMapping.pin !== undefined },
        this.#pinTrustRanking,
      ),
    ];
    if (issues.length > 0) throw new ValidationError(issues);
  }

  #checkSamlRules(
    settings: ParsedSamlSettings,
    assertedAcr: string,
    trustPinForRepresentation: boolean,
  ): void {
    const issues = [
      ...samlSettingsViolations(settings, assertedAcr, this.#acrRanking),
      // SAML methods always map personalIdentityNumber (the attribute name is required).
      ...pinTrustViolations(
        { trustPinForRepresentation, assertedAcr, mapsPin: true },
        this.#pinTrustRanking,
      ),
    ];
    if (issues.length > 0) throw new ValidationError(issues);
  }

  /** ACR_RANKING for the pin trust rule; the default ranking when none was configured. */
  get #pinTrustRanking(): readonly string[] {
    return this.#acrRanking.length > 0 ? this.#acrRanking : DEFAULT_ACR_RANKING;
  }

  async #writeSaml(
    tx: Db,
    tenantId: string,
    id: string,
    settings: ParsedSamlSettings,
    metadataCache: unknown,
    mode: "insert" | "update",
  ): Promise<void> {
    const values = [
      tenantId,
      id,
      settings.idpEntityId,
      settings.metadataUrl,
      settings.metadataXml,
      settings.metadataSigningCertificate,
      settings.metadataRefreshSeconds,
      settings.requestedLoa,
      settings.authnContextComparison,
      settings.entityCategories,
      JSON.stringify(settings.requestedAttributes),
      settings.subjectSource,
      JSON.stringify(settings.attributeMapping),
      settings.authnRequestBinding,
      settings.requireEncryptedAssertions,
      settings.requireSignedResponse,
      settings.signMetadata,
      settings.clockSkewSeconds,
      settings.trustEmail,
      metadataCache === undefined ? null : JSON.stringify(metadataCache),
      metadataCache !== undefined,
      settings.allowUnsignedMetadata,
      settings.requireGcm,
      JSON.stringify(settings.uiInfo),
      settings.orgAffiliationScopes,
    ];
    if (mode === "insert") {
      await mapDbErrors(() =>
        tx.query(
          `INSERT INTO login_method_saml
             (tenant_id, login_method_id, idp_entity_id, metadata_url, metadata_xml,
              metadata_signing_certificate, metadata_refresh_seconds, requested_loa,
              authn_context_comparison, entity_categories, requested_attributes, subject_source,
              attribute_mapping, authn_request_binding, require_encrypted_assertions,
              require_signed_response, sign_metadata, clock_skew_seconds, trust_email,
              metadata_cache, metadata_cached_at, metadata_checked_at, allow_unsigned_metadata,
              require_gcm, ui_info, org_affiliation_scopes)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb, $12, $13::jsonb, $14, $15,
                   $16, $17, $18, $19, $20::jsonb,
                   CASE WHEN $21::boolean THEN now() END, CASE WHEN $21::boolean THEN now() END,
                   $22, $23, $24::jsonb, $25)`,
          values,
        ),
      );
      return;
    }
    await mapDbErrors(() =>
      tx.query(
        `UPDATE login_method_saml SET
           idp_entity_id = $3, metadata_url = $4, metadata_xml = $5,
           metadata_signing_certificate = $6, metadata_refresh_seconds = $7, requested_loa = $8,
           authn_context_comparison = $9, entity_categories = $10, requested_attributes = $11::jsonb,
           subject_source = $12, attribute_mapping = $13::jsonb, authn_request_binding = $14,
           require_encrypted_assertions = $15, require_signed_response = $16, sign_metadata = $17,
           clock_skew_seconds = $18, trust_email = $19, allow_unsigned_metadata = $22,
           require_gcm = $23, ui_info = $24::jsonb, org_affiliation_scopes = $25,
           metadata_cache = CASE WHEN $21::boolean THEN $20::jsonb ELSE metadata_cache END,
           metadata_cached_at = CASE WHEN $21::boolean THEN now() ELSE metadata_cached_at END,
           metadata_checked_at = CASE WHEN $21::boolean THEN now() ELSE metadata_checked_at END,
           metadata_error = CASE WHEN $21::boolean THEN NULL ELSE metadata_error END
         WHERE tenant_id = $1 AND login_method_id = $2`,
        values,
      ),
    );
  }

  async #requireOidc(tenantId: string, id: string): Promise<OidcLoginMethod> {
    const method = await this.#require(tenantId, id);
    if (method.protocol !== "oidc") {
      throw new ValidationError(["protocol: not an OIDC login method"]);
    }
    return method;
  }

  async #requireSaml(tenantId: string, id: string): Promise<SamlLoginMethod> {
    const method = await this.#require(tenantId, id);
    if (method.protocol !== "saml") {
      throw new ValidationError(["protocol: not a SAML login method"]);
    }
    return method;
  }

  #newClientKey(id: string): EncryptedClientKey {
    const key = generateSigningKey();
    return {
      kid: key.kid,
      publicJwk: JSON.stringify(key.publicJwk),
      privateJwkEncrypted: this.#secrets.encrypt(
        JSON.stringify(key.privateJwk),
        clientPrivateJwkContext(id),
      ),
    };
  }

  async #replaceDomains(
    tx: Db,
    tenantId: string,
    id: string,
    domains: readonly string[],
  ): Promise<void> {
    await tx.query(
      "DELETE FROM login_method_domains WHERE tenant_id = $1 AND login_method_id = $2",
      [tenantId, id],
    );
    if (domains.length === 0) return;
    await mapDbErrors(() =>
      tx.query(
        `INSERT INTO login_method_domains (tenant_id, login_method_id, domain)
         SELECT $1, $2, unnest($3::text[])`,
        [tenantId, id, domains],
      ),
    );
  }

  async #require(tenantId: string, id: string): Promise<LoginMethod> {
    const method = await this.findById(tenantId, id);
    if (method === null) throw new NotFoundError("Login method");
    return method;
  }
}

/**
 * Stored SAML settings with a patch applied, validated as a whole. Unknown LoA URIs stay
 * accepted unless the patch changes the requested levels (then `allowCustomLoa` decides again).
 */
function mergeSamlSettings(
  current: SamlSettings,
  patch: NonNullable<z.output<typeof updateSamlLoginMethodInputSchema>["saml"]>,
): ParsedSamlSettings {
  return parseInput(samlSettingsInputSchema, {
    ...current,
    requestedLoa: [...current.requestedLoa],
    entityCategories: [...current.entityCategories],
    requestedAttributes: [...current.requestedAttributes],
    orgAffiliationScopes: [...current.orgAffiliationScopes],
    ...patch,
    allowCustomLoa: patch.allowCustomLoa ?? patch.requestedLoa === undefined,
  });
}

/** OIDC login method or nothing (the OIDC federation only handles those). */
export const asOidc = (method: LoginMethod | null): OidcLoginMethod | null =>
  method?.protocol === "oidc" ? method : null;

/**
 * Re-wraps every upstream secret and private client key not encrypted under the current master
 * key. Returns the number of values re-wrapped.
 */
export async function rewrapLoginMethodSecrets(db: Db, secrets: SecretBox): Promise<number> {
  const rows = await db.query<{ id: string; client_secret_encrypted: string }>(
    `SELECT id, client_secret_encrypted FROM login_methods
      WHERE client_secret_encrypted IS NOT NULL AND split_part(client_secret_encrypted, '.', 2) <> $1`,
    [secrets.currentKeyId],
  );
  for (const row of rows) {
    const rewrapped = secrets.rewrap(row.client_secret_encrypted, clientSecretContext(row.id));
    await db.query(
      `UPDATE login_methods SET client_secret_encrypted = $2
        WHERE id = $1 AND client_secret_encrypted = $3`,
      [row.id, rewrapped, row.client_secret_encrypted],
    );
  }
  const keys = await db.query<{ id: string; client_private_jwk_encrypted: string }>(
    `SELECT id, client_private_jwk_encrypted FROM login_methods
      WHERE client_private_jwk_encrypted IS NOT NULL
        AND split_part(client_private_jwk_encrypted, '.', 2) <> $1`,
    [secrets.currentKeyId],
  );
  for (const row of keys) {
    const rewrapped = secrets.rewrap(
      row.client_private_jwk_encrypted,
      clientPrivateJwkContext(row.id),
    );
    await db.query(
      `UPDATE login_methods SET client_private_jwk_encrypted = $2
        WHERE id = $1 AND client_private_jwk_encrypted = $3`,
      [row.id, rewrapped, row.client_private_jwk_encrypted],
    );
  }
  return rows.length + keys.length;
}
