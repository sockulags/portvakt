import { z } from "zod";
import {
  appendAuditEventInputSchema,
  type AppendAuditEventInput,
  type AuditActorType,
  type AuditOutcome,
} from "../domain/audit.js";
import { PARTY_TYPES, REPRESENTATION_SOURCE_IDS } from "../domain/representation.js";
import { clientIdSchema } from "../domain/schemas.js";
import { LOGIN_ERROR_CODES } from "../login/ui-shell.js";

/**
 * The audit event catalogue: every action Portvakt writes, its outcome and the schema of its
 * `details`. Details carry internal ids (UUIDs, client ids, key ids), protocol values (acr) and
 * fixed reason codes only: never a personal identity number, name, email, upstream NameID or
 * subject, token, secret or free text from a request. The schemas are strict, so an unexpected
 * field is refused before anything is written (`AuditCatalogueError`).
 *
 * Subjects (`subject.type`) are `person`, `login_method`, `signing_key`, `application` or
 * `party`, always with their internal id.
 */

const uuid = z.uuid();
const acr = z.string().min(1).max(255).regex(/^\S+$/);
/** A fixed reason or detail code chosen by Portvakt. */
const code = z.string().regex(/^[a-z][a-z0-9_]{0,63}$/);
const kid = z.string().regex(/^[A-Za-z0-9_-]{1,128}$/);
const roleName = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$/);
const attributeKey = z.string().regex(/^[A-Za-z][A-Za-z0-9_]{0,63}$/);

const loginFailureReason = z.enum(LOGIN_ERROR_CODES);

/** Why a representation was refused (`representation.denied`). */
export const REPRESENTATION_DENIAL_REASONS = [
  /** The application requires representation and the person has no valid grant for it. */
  "no_representation_available",
  /** The submitted party is not one the person may act for (now). */
  "not_allowed",
  /** Acting for oneself is not allowed (the application requires representation). */
  "self_not_allowed",
  /** A stored representation is no longer valid (revoked, expired, application removed). */
  "no_longer_valid",
] as const;

/** Why Portvakt revoked an application's grant (`grant.revoked`). */
export const GRANT_REVOCATION_REASONS = [
  /** The representation the grant was issued with is no longer valid. */
  "representation_invalid",
  /** The person chose another representation for the application (a new grant replaces it). */
  "representation_changed",
  /**
   * A kill switch ended the grant's login: its login method was disabled or deleted, the person
   * lost the identity or was deleted, the tenant was suspended or the application disabled.
   */
  "login_revoked",
] as const;

/** Why an administrator's change ended logins at once (`sessions.revoked`, the kill switches). */
export const SESSION_REVOCATION_REASONS = [
  "tenant_suspended",
  "application_disabled",
  "application_detached",
  "identity_unlinked",
  "login_method_disabled",
  "login_method_deleted",
  "person_deleted",
  /** `POST /tenants/{id}/persons/{personId}/end-sessions`. */
  "ended_by_admin",
] as const;

/** Why a refresh (`token.refresh_denied`) or a code exchange (`token.exchange_denied`) was refused. */
export const REFRESH_DENIAL_REASONS = [
  /** The broker session of the grant ended (expired, logged out, or its login is unknown). */
  "session_ended",
  /** The representation of the grant is no longer valid. */
  "representation_invalid",
  /** The application now requires representation and the grant has none. */
  "representation_required",
  /**
   * The grant's login may no longer be used: its login method is disabled or gone, the person
   * has no identity through it any more, or the tenant is suspended.
   */
  "login_revoked",
] as const;

/** Grant types a token can be issued for (`token.issued`). */
export const TOKEN_GRANT_TYPES = [
  "authorization_code",
  "refresh_token",
  "client_credentials",
] as const;

/** Why a step-up failed (`step_up.failure`). */
export const STEP_UP_FAILURE_REASONS = ["no_acceptable_method"] as const;

const event = <O extends AuditOutcome, D extends z.ZodType>(
  outcome: O,
  details: D,
  description: string,
) => ({ outcome, details, description });

/** A value in an admin change diff: a short scalar or a list of short scalars. */
const diffScalar = z.union([z.string().max(2048), z.number(), z.boolean(), z.null()]);
const diffValue = z.union([diffScalar, z.array(diffScalar).max(100)]);
/**
 * One changed field: its old and new value, or only `changed` for a field whose value is a
 * secret or personal data (or too large to record).
 */
const diffEntry = z.union([
  z.object({ from: diffValue.optional(), to: diffValue.optional() }).strict(),
  z.object({ changed: z.literal(true) }).strict(),
]);
const fieldPath = z
  .string()
  .max(128)
  .regex(/^[a-z][A-Za-z0-9]*(\.[a-z][A-Za-z0-9]*)*$/);

/**
 * The `changes` of an admin event: field paths (dotted, below the listed top-level fields) and
 * their old and new values. Fields in `redacted` (and anything below them) may only say
 * `changed`: their values never reach the audit log.
 */
function changesOf(fields: readonly string[], redacted: readonly string[]) {
  const top = new Set(fields);
  const isRedacted = (path: string): boolean =>
    redacted.some((field) => path === field || path.startsWith(`${field}.`));
  return z
    .record(fieldPath, diffEntry)
    .refine((changes) => Object.keys(changes).length <= 200, "too many changes")
    .refine(
      (changes) => Object.keys(changes).every((path) => top.has(path.split(".")[0]!)),
      "unknown field",
    )
    .refine(
      (changes) =>
        Object.entries(changes).every(([path, entry]) => !isRedacted(path) || "changed" in entry),
      "a redacted field carries a value",
    );
}

const TENANT_FIELDS = ["slug", "name", "status", "representationSources"] as const;
const APPLICATION_FIELDS = [
  "clientId",
  "name",
  "enabled",
  "clientAuth",
  "redirectUris",
  "postLogoutRedirectUris",
  "allowedExtraScopes",
  "serviceAudiences",
  "representationMode",
  "roles",
  "attributeKeys",
] as const;
/** Secrets and keys of an application: only "changed". */
const APPLICATION_REDACTED = ["clientAuth.clientSecret", "clientAuth.jwks"] as const;
const LOGIN_METHOD_FIELDS = [
  "protocol",
  "kind",
  "displayName",
  "assertedAcr",
  "homeRealmDomains",
  "secretExpiresAt",
  "sessionPolicy",
  "linkByPin",
  "trustPinForRepresentation",
  "enabled",
  "issuer",
  "clientId",
  "clientSecret",
  "clientAuthMethod",
  "useUserinfo",
  "clientAssertionAudience",
  "allowedUpstreamTenants",
  "trustUpstreamEmail",
  "pinLoginHint",
  "scopes",
  "claimMapping",
  "saml",
] as const;
const LOGIN_METHOD_REDACTED = [
  "clientSecret",
  "saml.metadataXml",
  "saml.metadataSigningCertificate",
] as const;
/** A person party's display name is personal data; party names are never recorded. */
const PARTY_FIELDS = ["type", "identifier", "displayName", "protectedIdentity"] as const;
const PARTY_REDACTED = ["identifier", "displayName"] as const;
const GRANT_FIELDS = ["allApplications", "applicationIds", "validFrom", "validTo"] as const;
const ATTRIBUTE_FIELDS = ["value"] as const;

/** Who the admin change was made for (never the subject or number itself). */
const ASSIGNMENT_TARGET_KINDS = ["person", "identity", "pin"] as const;

/** The administrator's own tenant (`null` for the system bootstrap). */
const actorTenantId = uuid.nullable();

export const AUDIT_EVENTS = {
  "login.success": event(
    "success",
    z
      .object({
        loginMethodId: uuid,
        acr,
        clientId: clientIdSchema.optional(),
        /** The login was a step-up of the session's person. */
        stepUp: z.boolean().optional(),
      })
      .strict(),
    "An upstream login completed for an interaction (subject: the person).",
  ),
  "login.failure": event(
    "failure",
    z
      .object({
        reason: loginFailureReason,
        clientId: clientIdSchema.optional(),
        /** Upstream OAuth error code or SAML status label (protocol value). */
        upstreamError: z
          .string()
          .regex(/^[A-Za-z0-9_]{1,64}$/)
          .optional(),
        detail: code.optional(),
      })
      .strict(),
    "A login of a real interaction was refused (subject: the login method, when known).",
  ),
  "login.groups_overage": event(
    "success",
    z.object({ loginMethodId: uuid }).strict(),
    "Entra ID groups overage: the groups of this login were treated as empty.",
  ),
  "person.created": event(
    "success",
    z.object({ loginMethodId: uuid }).strict(),
    "A person was created just in time at their first login.",
  ),
  "person.identity_linked": event(
    "success",
    z.object({ loginMethodId: uuid }).strict(),
    "A new identity was linked to an existing person by personal identity number.",
  ),
  "representation.selected": event(
    "success",
    z
      .object({
        clientId: clientIdSchema,
        choice: z.enum(["self", "party"]),
        partyId: uuid.optional(),
        partyType: z.enum(PARTY_TYPES).optional(),
        sources: z.array(z.enum(REPRESENTATION_SOURCE_IDS)).max(8).optional(),
      })
      .strict(),
    "A grant was issued with the representation the person chose (subject: the party, if any).",
  ),
  "representation.denied": event(
    "failure",
    z
      .object({
        clientId: clientIdSchema,
        reason: z.enum(REPRESENTATION_DENIAL_REASONS),
        partyId: uuid.optional(),
      })
      .strict(),
    "A representation was refused or is no longer valid (subject: the person). " +
      "`no_representation_available` is written once per interaction.",
  ),
  "step_up.success": event(
    "success",
    z
      .object({
        clientId: clientIdSchema,
        loginMethodId: uuid,
        acr,
        previousAcr: acr.optional(),
      })
      .strict(),
    "A step-up login of the same person raised the acr of this application's grant.",
  ),
  "step_up.failure": event(
    "failure",
    z
      .object({
        reason: z.enum(STEP_UP_FAILURE_REASONS),
        clientId: clientIdSchema.optional(),
        /** The requested values the tenant knows (its acr values); never other request input. */
        requestedAcr: z.array(acr).max(10).optional(),
        /** How many requested values were unknown (not recorded). */
        unknownAcr: z.number().int().min(1).optional(),
      })
      .strict(),
    "A step-up could not be offered (no login method satisfies the requested acr). Written " +
      "once per interaction.",
  ),
  "step_up.person_mismatch": event(
    "failure",
    z.object({ loginMethodId: uuid, clientId: clientIdSchema.optional() }).strict(),
    "A step-up login resolved to another person; the session was kept (actor: the person who " +
      "signed in, subject: the session's person).",
  ),
  "session.logout": event(
    "success",
    z
      .object({
        /** `rp`: RP-initiated logout; `idp`: IdP-initiated SAML logout; `slo`: SP-initiated SAML SLO. */
        initiator: z.enum(["rp", "idp", "slo"]),
        clientId: clientIdSchema.optional(),
        loginMethodId: uuid.optional(),
        /** Broker sessions ended (IdP-initiated logout). */
        sessions: z.number().int().min(0).optional(),
        /** `rp`: the whole session or only the application's grant. */
        scope: z.enum(["session", "application"]).optional(),
        /** `slo`: whether the IdP confirmed the logout (the local logout happened either way). */
        upstream: z.enum(["success", "failure"]).optional(),
      })
      .strict(),
    "A broker session (or an application's part of it) was logged out.",
  ),
  "grant.revoked": event(
    "success",
    z.object({ clientId: clientIdSchema, reason: z.enum(GRANT_REVOCATION_REASONS) }).strict(),
    "Portvakt revoked an application's grant with its tokens (subject: the person).",
  ),
  "sessions.revoked": event(
    "success",
    z
      .object({
        actorTenantId,
        reason: z.enum(SESSION_REVOCATION_REASONS),
        /** Broker sessions ended and grants revoked (with their codes and refresh tokens). */
        sessions: z.number().int().min(0),
        grants: z.number().int().min(0),
        clientId: clientIdSchema.optional(),
        loginMethodId: uuid.optional(),
      })
      .strict(),
    "An administrator's change ended logins at once, in the change's transaction: sessions and " +
      "grants of a suspended tenant, a disabled or detached application, a disabled or deleted " +
      "login method, an unlinked identity, a deleted person, or every login of a person " +
      "(end-sessions). Subject: the tenant, application, login method or person.",
  ),
  "token.refresh_denied": event(
    "failure",
    z.object({ clientId: clientIdSchema, reason: z.enum(REFRESH_DENIAL_REASONS) }).strict(),
    "A refresh token grant was refused (subject: the person).",
  ),
  "token.issued": event(
    "success",
    z.object({ clientId: clientIdSchema, grantType: z.enum(TOKEN_GRANT_TYPES) }).strict(),
    "The token endpoint issued tokens (subject: the person, except for client_credentials). " +
      "No token values.",
  ),
  "token.exchange_denied": event(
    "failure",
    z.object({ clientId: clientIdSchema, reason: z.enum(REFRESH_DENIAL_REASONS) }).strict(),
    "An authorization code exchange was refused although the code was valid: the session or " +
      "the representation of its grant ended (subject: the person).",
  ),
  "key.create": event(
    "success",
    z.object({}).strict(),
    "A signing key was created as `next` (subject: the key).",
  ),
  "key.activate": event(
    "success",
    z.object({ initial: z.boolean().optional() }).strict(),
    "A signing key became `active` (subject: the key).",
  ),
  "key.retire": event(
    "success",
    z.object({}).strict(),
    "A `retiring` signing key was retired (subject: the key).",
  ),
  "key.rotate": event(
    "success",
    z
      .object({
        /** The administrator's short reason (the admin API forbids personal data in it). */
        reason: z.string().trim().min(1).max(500),
        emergency: z.boolean(),
        retiringKid: kid.nullable(),
        retiredKids: z.array(kid).max(10),
        /** Without emergency: when the published key becomes active (ISO 8601). */
        activatesAt: z.iso.datetime().optional(),
      })
      .strict(),
    "Manual signing key rotation (subject: the new key; in an emergency a fresh key, active at " +
      "once, and `retiredKids` lists every other key, retired with it; otherwise published and " +
      "activated at `activatesAt`).",
  ),
  "audit.pruned": event(
    "success",
    z
      .object({
        deleted: z.number().int().min(0),
        /** Events that occurred before this instant (ISO 8601) were deleted. */
        before: z.iso.datetime(),
        retentionDays: z.number().int().min(90),
      })
      .strict(),
    "Audit retention deleted old events (npm run audit:prune, as the owner role).",
  ),
  "login_method.saml_unsigned_metadata_allowed": event(
    "success",
    z.object({ loginMethodId: uuid }).strict(),
    "A SAML login method was saved with an unsigned metadata URL (an explicit opt-out).",
  ),
  "assignment.pending_resolved": event(
    "success",
    z
      .object({
        pendingId: uuid,
        kind: z.enum(["role", "attribute"]),
        applicationId: uuid,
        /** The role, or the attribute key (never the attribute value). */
        name: roleName,
        targetKind: z.enum(["identity", "pin"]),
      })
      .strict(),
    "A login turned a pending role or attribute assignment into an assignment of the person " +
      "(subject: the person).",
  ),
  // Administration (admin API, M6). Actor: the administrator (person id; `actorTenantId` is
  // their own tenant). `changes` lists non-secret fields only; secrets and personal data say
  // `changed` and nothing else.
  "admin.bootstrap": event(
    "success",
    z
      .object({
        applicationId: uuid,
        loginMethodId: uuid,
        pendingAssignmentId: uuid,
        targetKind: z.enum(["identity", "pin"]),
      })
      .strict(),
    "First start on an empty database: the system tenant, portvakt-admin, the bootstrap login " +
      "method and a pending platform-admin assignment were created (subject: the tenant).",
  ),
  "admin.tenant.create": event(
    "success",
    z.object({ actorTenantId, changes: changesOf(TENANT_FIELDS, []) }).strict(),
    "An administrator created a tenant (subject: the tenant).",
  ),
  "admin.tenant.update": event(
    "success",
    z.object({ actorTenantId, changes: changesOf(TENANT_FIELDS, []) }).strict(),
    "An administrator changed a tenant (subject: the tenant).",
  ),
  "admin.tenant.suspend": event(
    "success",
    z.object({ actorTenantId }).strict(),
    "An administrator suspended a tenant: its issuer answers 404 (subject: the tenant).",
  ),
  "admin.tenant.reactivate": event(
    "success",
    z.object({ actorTenantId }).strict(),
    "An administrator reactivated a suspended tenant (subject: the tenant).",
  ),
  "admin.application.create": event(
    "success",
    z
      .object({ actorTenantId, changes: changesOf(APPLICATION_FIELDS, APPLICATION_REDACTED) })
      .strict(),
    "An administrator registered an application (subject: the application).",
  ),
  "admin.application.update": event(
    "success",
    z
      .object({ actorTenantId, changes: changesOf(APPLICATION_FIELDS, APPLICATION_REDACTED) })
      .strict(),
    "An administrator changed an application (subject: the application).",
  ),
  "admin.application.secret_rotate": event(
    "success",
    z.object({ actorTenantId }).strict(),
    "An administrator replaced an application's client secret (subject: the application).",
  ),
  "admin.tenant_application.attach": event(
    "success",
    z.object({ actorTenantId, applicationId: uuid }).strict(),
    "An administrator attached an application to the tenant and enabled it (subject: the " +
      "application).",
  ),
  "admin.tenant_application.update": event(
    "success",
    z.object({ actorTenantId, applicationId: uuid, changes: changesOf(["enabled"], []) }).strict(),
    "An administrator enabled or disabled an application in the tenant (subject: the " +
      "application).",
  ),
  "admin.login_method.create": event(
    "success",
    z
      .object({
        actorTenantId,
        protocol: z.enum(["oidc", "saml"]),
        changes: changesOf(LOGIN_METHOD_FIELDS, LOGIN_METHOD_REDACTED),
      })
      .strict(),
    "An administrator created a login method (subject: the login method).",
  ),
  "admin.login_method.update": event(
    "success",
    z
      .object({
        actorTenantId,
        protocol: z.enum(["oidc", "saml"]),
        changes: changesOf(LOGIN_METHOD_FIELDS, LOGIN_METHOD_REDACTED),
      })
      .strict(),
    "An administrator changed a login method (subject: the login method).",
  ),
  "admin.login_method.sp_keys_prepare": event(
    "success",
    z
      .object({
        actorTenantId,
        purposes: z
          .array(z.enum(["signing", "encryption"]))
          .min(1)
          .max(2),
        keyIds: z.array(uuid).max(2),
      })
      .strict(),
    "An administrator added `next` SAML SP keys, published next to the active ones (subject: " +
      "the login method).",
  ),
  "admin.login_method.sp_keys_rotate": event(
    "success",
    z
      .object({ actorTenantId, purposes: z.array(z.enum(["signing", "encryption"])).max(2) })
      .strict(),
    "An administrator made the `next` SAML SP keys active (subject: the login method).",
  ),
  "admin.login_method.client_key_prepare": event(
    "success",
    z.object({ actorTenantId, kid }).strict(),
    "An administrator added a `next` upstream client key (private_key_jwt), published next to " +
      "the active one (subject: the login method).",
  ),
  "admin.login_method.client_key_rotate": event(
    "success",
    z.object({ actorTenantId, kid, retiringKid: kid }).strict(),
    "An administrator made the `next` upstream client key active; the former one is retiring " +
      "(subject: the login method).",
  ),
  "admin.role_rule.create": event(
    "success",
    z.object({ actorTenantId, applicationId: uuid, loginMethodId: uuid, role: roleName }).strict(),
    "An administrator created a role rule; the group value is not recorded (subject: the rule).",
  ),
  "admin.role_rule.delete": event(
    "success",
    z.object({ actorTenantId, applicationId: uuid, loginMethodId: uuid, role: roleName }).strict(),
    "An administrator deleted a role rule (subject: the rule).",
  ),
  "admin.role_assignment.create": event(
    "success",
    z
      .object({
        actorTenantId,
        applicationId: uuid,
        role: roleName,
        targetKind: z.enum(ASSIGNMENT_TARGET_KINDS),
        pending: z.boolean(),
        loginMethodId: uuid.optional(),
      })
      .strict(),
    "An administrator assigned a role, to a person or pending for an identity reference or a " +
      "personal identity number (subject: the person, or the pending assignment).",
  ),
  "admin.role_assignment.delete": event(
    "success",
    z
      .object({
        actorTenantId,
        applicationId: uuid,
        role: roleName,
        targetKind: z.enum(ASSIGNMENT_TARGET_KINDS),
        pending: z.boolean(),
      })
      .strict(),
    "An administrator removed a role assignment (subject: the person, or the pending " +
      "assignment).",
  ),
  "admin.attribute_assignment.create": event(
    "success",
    z
      .object({
        actorTenantId,
        applicationId: uuid,
        key: attributeKey,
        targetKind: z.enum(ASSIGNMENT_TARGET_KINDS),
        pending: z.boolean(),
        changes: changesOf(ATTRIBUTE_FIELDS, ATTRIBUTE_FIELDS),
      })
      .strict(),
    "An administrator set an attribute; its value is not recorded (subject: the person, or " +
      "the pending assignment).",
  ),
  "admin.attribute_assignment.update": event(
    "success",
    z
      .object({
        actorTenantId,
        applicationId: uuid,
        key: attributeKey,
        pending: z.boolean(),
        changes: changesOf(ATTRIBUTE_FIELDS, ATTRIBUTE_FIELDS),
      })
      .strict(),
    "An administrator changed an attribute value (subject: the person, or the pending " +
      "assignment).",
  ),
  "admin.attribute_assignment.delete": event(
    "success",
    z
      .object({
        actorTenantId,
        applicationId: uuid,
        key: attributeKey,
        pending: z.boolean(),
      })
      .strict(),
    "An administrator removed an attribute assignment (subject: the person, or the pending " +
      "assignment).",
  ),
  "admin.person.protected_identity_clear": event(
    "success",
    z.object({ actorTenantId }).strict(),
    "An administrator cleared a person's protected identity flag (subject: the person).",
  ),
  "admin.party.create": event(
    "success",
    z
      .object({
        actorTenantId,
        partyType: z.enum(PARTY_TYPES),
        changes: changesOf(PARTY_FIELDS, PARTY_REDACTED),
      })
      .strict(),
    "An administrator created a party; its identifier and name are not recorded (subject: the " +
      "party).",
  ),
  "admin.party.update": event(
    "success",
    z
      .object({
        actorTenantId,
        partyType: z.enum(PARTY_TYPES),
        changes: changesOf(PARTY_FIELDS, PARTY_REDACTED),
      })
      .strict(),
    "An administrator changed a party (subject: the party).",
  ),
  "admin.grant.create": event(
    "success",
    z
      .object({
        actorTenantId,
        partyId: uuid,
        agentKind: z.enum(["person", "pin"]),
        agentPersonId: uuid.optional(),
        changes: changesOf(GRANT_FIELDS, []),
      })
      .strict(),
    "An administrator created a representation grant; an agent personal identity number is " +
      "not recorded (subject: the grant).",
  ),
  "admin.grant.update": event(
    "success",
    z.object({ actorTenantId, partyId: uuid, changes: changesOf(GRANT_FIELDS, []) }).strict(),
    "An administrator changed which applications a representation grant covers (subject: " +
      "the grant).",
  ),
  "admin.grant.revoke": event(
    "success",
    z.object({ actorTenantId, partyId: uuid }).strict(),
    "An administrator revoked a representation grant; refreshes of tokens issued with it fail " +
      "(subject: the grant).",
  ),
  "admin.login_method.delete": event(
    "success",
    z.object({ actorTenantId, protocol: z.enum(["oidc", "saml"]) }).strict(),
    "An administrator deleted a login method that had no identities (subject: the login " +
      "method).",
  ),
  "admin.tenant_application.detach": event(
    "success",
    z
      .object({
        actorTenantId,
        applicationId: uuid,
        /** What the detach deleted with the attachment (counts). */
        removed: z
          .object({
            roleAssignments: z.number().int().min(0),
            pendingRoleAssignments: z.number().int().min(0),
            roleRules: z.number().int().min(0),
            attributeAssignments: z.number().int().min(0),
            pendingAttributeAssignments: z.number().int().min(0),
            grantLimits: z.number().int().min(0),
          })
          .strict(),
      })
      .strict(),
    "An administrator detached an application from the tenant, deleting its assignments, rules " +
      "and grant limits there (subject: the application).",
  ),
  "admin.person.identity_unlink": event(
    "success",
    z.object({ actorTenantId, loginMethodId: uuid }).strict(),
    "An administrator removed one identity of a person; the upstream subject is not recorded " +
      "(subject: the person).",
  ),
  "admin.person.delete": event(
    "success",
    z.object({ actorTenantId, identities: z.number().int().min(0) }).strict(),
    "An administrator deleted a person with their identities, assignments and the grants made " +
      "out to them (subject: the person).",
  ),
  "admin.signing_key.rotate": event(
    "success",
    z
      .object({
        actorTenantId,
        emergency: z.boolean(),
        /** The key that signs now; null while the new key waits for its activation. */
        activatedKid: kid.nullable(),
        /** The published key and when it becomes active (rotation without emergency). */
        scheduledKid: kid.optional(),
        activatesAt: z.iso.datetime().optional(),
        retiringKid: kid.nullable(),
        retiredKids: z.array(kid).max(10),
      })
      .strict(),
    "An administrator rotated the signing keys (also `key.rotate`, with the reason; subject: " +
      "the new key).",
  ),
} as const;

export type AuditAction = keyof typeof AUDIT_EVENTS;
export type AuditDetails<A extends AuditAction> = z.input<(typeof AUDIT_EVENTS)[A]["details"]>;

export const AUDIT_ACTIONS = Object.keys(AUDIT_EVENTS) as AuditAction[];

/** One event of the catalogue, as a caller writes it. */
export interface CatalogueEvent<A extends AuditAction> {
  readonly action: A;
  /** `null` for platform-level events (signing keys). */
  readonly tenantId: string | null;
  readonly actor: { readonly type: AuditActorType; readonly id: string | null };
  readonly subject?: { readonly type: string; readonly id: string } | null;
  readonly details: AuditDetails<A>;
}

/** An event that does not match the catalogue; nothing was written. */
export class AuditCatalogueError extends Error {
  constructor(action: string, issues: readonly string[]) {
    super(`Audit event ${action} does not match the catalogue: ${issues.join("; ")}`);
    this.name = "AuditCatalogueError";
  }
}

/**
 * Validates an event against the catalogue and returns the repository input (outcome from the
 * catalogue). Throws {@link AuditCatalogueError} for unknown fields or values; the message names
 * the fields, never their values.
 */
export function auditEvent<A extends AuditAction>(input: CatalogueEvent<A>): AppendAuditEventInput {
  const definition = AUDIT_EVENTS[input.action];
  const details = definition.details.safeParse(input.details);
  if (!details.success) {
    throw new AuditCatalogueError(
      input.action,
      details.error.issues.map((issue) => `${issue.path.join(".") || "details"}: ${issue.code}`),
    );
  }
  const parsed = appendAuditEventInputSchema.safeParse({
    tenantId: input.tenantId,
    actor: input.actor,
    subject: input.subject ?? null,
    action: input.action,
    outcome: definition.outcome,
    details: details.data,
  });
  if (!parsed.success) {
    throw new AuditCatalogueError(
      input.action,
      parsed.error.issues.map((issue) => `${issue.path.join(".")}: ${issue.code}`),
    );
  }
  return parsed.data;
}
