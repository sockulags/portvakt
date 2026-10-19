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
] as const;

/** Why a refresh (`token.refresh_denied`) or a code exchange (`token.exchange_denied`) was refused. */
export const REFRESH_DENIAL_REASONS = [
  /** The broker session of the grant ended (expired, logged out, or its login is unknown). */
  "session_ended",
  /** The representation of the grant is no longer valid. */
  "representation_invalid",
  /** The application now requires representation and the grant has none. */
  "representation_required",
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
      })
      .strict(),
    "Manual signing key rotation (subject: the new active key).",
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
