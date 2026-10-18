import { createHash } from "node:crypto";
import { z } from "zod";
import type { SecretBox } from "../crypto/envelope.js";
import type { Db } from "../db/database.js";
import { SAML_BINDINGS, SAML_COMPARISONS } from "../domain/saml.js";
import { mapDbErrors, requireUuids } from "./errors.js";

/**
 * Server-side state of upstream authorization requests (`federation_states`). The upstream
 * callback (`/t/{slug}/federation/{loginMethodId}/callback`) is outside the interaction path, so
 * the interaction cookie never reaches it: this record links the upstream `state` to the
 * interaction, keeps the PKCE verifier and nonce, and makes both hops single use:
 *
 * 1. {@link pending} when the browser is sent upstream (a still valid pending request of the same
 *    interaction and login method is reused, so reloading the page does not add rows);
 * 2. {@link consumeCallback} once, when the upstream redirects back;
 * 3. {@link attachCompletion} stores what the callback established, under a fresh reference;
 * 4. {@link consumeCompletion} once, on the interaction path, where the interaction cookie proves
 *    it is the same browser.
 *
 * The state and the PKCE verifier are stored encrypted, the state also as a hash (the lookup key);
 * the completion reference only as a hash.
 */

/** AAD contexts of the encrypted PKCE verifier and state. */
const verifierContext = (stateHash: string): string => `federation_state:${stateHash}:verifier`;
const stateContext = (stateHash: string): string => `federation_state:${stateHash}:state`;

export const hashToken = (value: string): string =>
  createHash("sha256").update(value, "utf8").digest("base64url");

/** What the callback established; the interaction path completes the login with it. */
/**
 * The upstream SAML session a login established (for single logout): the NameID and the
 * SessionIndex the IdP sent. Pseudonymous identifiers (the Deployment Profile requires the
 * NameID not to reveal the person); never logged.
 */
const blindIndexSchema = z.string().regex(/^[A-Za-z0-9_-]{43}$/, "must be a blind index");

export const upstreamSessionSchema = z
  .object({
    protocol: z.literal("saml"),
    /** Blind index (keyed HMAC) of the NameID for the login method: IdP-initiated logout. */
    nameIdIndex: blindIndexSchema,
    /** Blind index of the SessionIndex, when the IdP sent one. */
    sessionIndexIndex: blindIndexSchema.optional(),
    /**
     * NameID, its format and qualifiers and the SessionIndex, sealed (SecretBox, context
     * `saml_upstream_session:<loginMethodId>`): the SP-initiated LogoutRequest names them.
     */
    sealed: z.string().startsWith("pv1.").max(16384),
  })
  .strict();
export type UpstreamSession = z.infer<typeof upstreamSessionSchema>;

export const federationCompletionSchema = z
  .object({
    personId: z.uuid(),
    acr: z.string().min(1).max(255),
    amr: z.array(z.string().min(1).max(64)).min(1).max(16),
    /** Epoch seconds of the upstream authentication (min(upstream auth_time, now)). */
    authTime: z.number().int().positive(),
    upstreamSession: upstreamSessionSchema.optional(),
  })
  .strict();
export type FederationCompletion = z.infer<typeof federationCompletionSchema>;

export interface FederationSecrets {
  readonly state: string;
  readonly codeVerifier: string;
  readonly nonce: string;
}

export interface PendingRequest {
  readonly loginMethodId: string;
  readonly interactionUid: string;
  readonly maxAge: number | undefined;
  readonly ttlSeconds: number;
  /** Fresh random values, used when no valid pending request exists. */
  readonly fresh: () => FederationSecrets;
}

/** What a pending SAML AuthnRequest asked for (protocol values only). */
export const samlRequestRecordSchema = z
  .object({
    forceAuthn: z.boolean(),
    requestedLoa: z.array(z.string().min(1).max(1024)).min(1).max(20),
    comparison: z.enum(SAML_COMPARISONS),
    binding: z.enum(SAML_BINDINGS),
    /** The request carries PrincipalSelection (the IdP advertises it; HTTP-POST only). */
    principalSelection: z.boolean(),
  })
  .strict();
export type SamlRequestRecord = z.infer<typeof samlRequestRecordSchema>;

export interface PendingSamlRequest {
  readonly loginMethodId: string;
  readonly interactionUid: string;
  readonly maxAge: number | undefined;
  readonly ttlSeconds: number;
  readonly request: SamlRequestRecord;
  /** PrincipalSelection personal identity number (canonical), when the person is known. */
  readonly principalPin: string | undefined;
  /** Fresh random values, used when no valid pending request exists. */
  readonly fresh: () => { readonly relayState: string; readonly requestId: string };
}

/** A pending SAML request as sent upstream (again). */
export interface SamlPendingSecrets {
  readonly relayState: string;
  readonly requestId: string;
  readonly request: SamlRequestRecord;
  readonly principalPin: string | undefined;
  /** When the request was first created (ForceAuthn: the AuthnInstant must be later). */
  readonly createdAt: Date;
}

interface PendingCommon {
  readonly stateHash: string;
  readonly loginMethodId: string;
  readonly interactionUid: string;
  readonly maxAge: number | undefined;
  readonly createdAt: Date;
}

export interface PendingOidcFederation extends PendingCommon {
  readonly protocol: "oidc";
  readonly codeVerifier: string;
  readonly nonce: string;
}

export interface PendingSamlFederation extends PendingCommon {
  readonly protocol: "saml";
  /** The AuthnRequest ID the response's InResponseTo must name. */
  readonly requestId: string;
  readonly request: SamlRequestRecord;
  readonly principalPin: string | undefined;
}

export type PendingFederation = PendingOidcFederation | PendingSamlFederation;

/** Why a callback's state was not accepted. */
export type CallbackRejection =
  /** Unknown state, or a state of another tenant or login method. */
  | { readonly reason: "invalid_state" }
  /** The callback for this state was already used (replay). */
  | { readonly reason: "state_replayed"; readonly interactionUid: string }
  | { readonly reason: "state_expired"; readonly interactionUid: string };

interface StateRow {
  state_hash: string;
  protocol: "oidc" | "saml";
  login_method_id: string;
  interaction_uid: string;
  code_verifier_encrypted: string | null;
  nonce: string | null;
  max_age: number | null;
  saml_request_id: string | null;
  saml_request: unknown;
  saml_principal_encrypted: string | null;
  created_at: Date;
}

const STATE_COLUMNS = `state_hash, protocol, login_method_id, interaction_uid, code_verifier_encrypted,
  nonce, max_age, saml_request_id, saml_request, saml_principal_encrypted, created_at`;

/** AAD context of the encrypted PrincipalSelection personal identity number. */
const principalContext = (stateHash: string): string => `federation_state:${stateHash}:principal`;

/** How long a completion reference may be redeemed after the callback. */
const COMPLETION_WINDOW_SECONDS = 120;

export class FederationStateRepository {
  readonly #db: Db;
  readonly #secrets: SecretBox;

  constructor(db: Db, secrets: SecretBox) {
    this.#db = db;
    this.#secrets = secrets;
  }

  /**
   * The pending upstream request of an interaction through a login method: the still valid one
   * if it exists, else a new one with `fresh()` values. Safe under concurrent calls (one pending
   * row per interaction and login method).
   */
  async pending(tenantId: string, input: PendingRequest): Promise<FederationSecrets> {
    requireUuids({ tenantId, loginMethodId: input.loginMethodId });
    if (!(input.ttlSeconds > 0)) throw new TypeError("ttlSeconds must be positive");
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const existing = await this.#findPending(tenantId, input.interactionUid, input.loginMethodId);
      if (existing !== undefined) return existing;
      // An expired pending row would block the unique index: it can never be used again.
      await this.#db.query(
        `DELETE FROM federation_states
          WHERE tenant_id = $1 AND interaction_uid = $2 AND login_method_id = $3
            AND callback_at IS NULL AND expires_at <= now()`,
        [tenantId, input.interactionUid, input.loginMethodId],
      );
      const secrets = input.fresh();
      const stateHash = hashToken(secrets.state);
      const inserted = await mapDbErrors(() =>
        this.#db.query(
          `INSERT INTO federation_states
             (state_hash, tenant_id, login_method_id, interaction_uid, state_encrypted,
              code_verifier_encrypted, nonce, max_age, expires_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8,
                   now() + make_interval(secs => $9::double precision))
           ON CONFLICT (tenant_id, interaction_uid, login_method_id) WHERE callback_at IS NULL
           DO NOTHING
           RETURNING 1`,
          [
            stateHash,
            tenantId,
            input.loginMethodId,
            input.interactionUid,
            this.#secrets.encrypt(secrets.state, stateContext(stateHash)),
            this.#secrets.encrypt(secrets.codeVerifier, verifierContext(stateHash)),
            secrets.nonce,
            input.maxAge ?? null,
            input.ttlSeconds,
          ],
        ),
      );
      if (inserted.length > 0) return secrets;
    }
    throw new Error("No pending federation request could be created");
  }

  async #findPending(
    tenantId: string,
    interactionUid: string,
    loginMethodId: string,
  ): Promise<FederationSecrets | undefined> {
    const [row] = await this.#db.query<{
      state_hash: string;
      state_encrypted: string;
      code_verifier_encrypted: string | null;
      nonce: string | null;
    }>(
      `SELECT state_hash, state_encrypted, code_verifier_encrypted, nonce FROM federation_states
        WHERE tenant_id = $1 AND interaction_uid = $2 AND login_method_id = $3
          AND callback_at IS NULL AND expires_at > now() AND protocol = 'oidc'`,
      [tenantId, interactionUid, loginMethodId],
    );
    if (row === undefined || row.code_verifier_encrypted === null || row.nonce === null) {
      return undefined;
    }
    return {
      state: this.#secrets.decryptString(row.state_encrypted, stateContext(row.state_hash)),
      codeVerifier: this.#secrets.decryptString(
        row.code_verifier_encrypted,
        verifierContext(row.state_hash),
      ),
      nonce: row.nonce,
    };
  }

  /**
   * Marks the state used by the callback of `loginMethodId` in `tenantId`. Atomic: of any number
   * of parallel callbacks with one state, exactly one gets the pending federation.
   */
  async consumeCallback(
    tenantId: string,
    loginMethodId: string,
    state: string,
  ): Promise<PendingFederation | CallbackRejection> {
    requireUuids({ tenantId, loginMethodId });
    if (state.length === 0 || state.length > 512) return { reason: "invalid_state" };
    const stateHash = hashToken(state);
    const [won] = await this.#db.query<StateRow>(
      `UPDATE federation_states SET callback_at = now()
        WHERE state_hash = $1 AND tenant_id = $2 AND login_method_id = $3
          AND callback_at IS NULL AND expires_at > now()
        RETURNING ${STATE_COLUMNS}`,
      [stateHash, tenantId, loginMethodId],
    );
    if (won !== undefined) return this.#toPending(won);
    const [existing] = await this.#db.query<{ interaction_uid: string; used: boolean }>(
      `SELECT interaction_uid, callback_at IS NOT NULL AS used FROM federation_states
        WHERE state_hash = $1 AND tenant_id = $2 AND login_method_id = $3`,
      [stateHash, tenantId, loginMethodId],
    );
    if (existing === undefined) return { reason: "invalid_state" };
    return existing.used
      ? { reason: "state_replayed", interactionUid: existing.interaction_uid }
      : { reason: "state_expired", interactionUid: existing.interaction_uid };
  }

  #toPending(row: StateRow): PendingFederation {
    const common = {
      stateHash: row.state_hash,
      loginMethodId: row.login_method_id,
      interactionUid: row.interaction_uid,
      maxAge: row.max_age ?? undefined,
      createdAt: row.created_at,
    };
    if (row.protocol === "saml") {
      if (row.saml_request_id === null) throw new Error("SAML state without request id");
      return {
        ...common,
        protocol: "saml",
        requestId: row.saml_request_id,
        request: samlRequestRecordSchema.parse(row.saml_request),
        principalPin:
          row.saml_principal_encrypted === null
            ? undefined
            : this.#secrets.decryptString(
                row.saml_principal_encrypted,
                principalContext(row.state_hash),
              ),
      };
    }
    if (row.code_verifier_encrypted === null || row.nonce === null) {
      throw new Error("OIDC state without verifier or nonce");
    }
    return {
      ...common,
      protocol: "oidc",
      codeVerifier: this.#secrets.decryptString(
        row.code_verifier_encrypted,
        verifierContext(row.state_hash),
      ),
      nonce: row.nonce,
    };
  }

  /**
   * The pending SAML AuthnRequest of an interaction through a login method: the still valid one
   * (same RelayState and request ID, so a reload sends the same request) when it asked for the
   * same thing, else a new one. Safe under concurrent calls (one pending row per interaction and
   * login method).
   */
  async pendingSaml(tenantId: string, input: PendingSamlRequest): Promise<SamlPendingSecrets> {
    requireUuids({ tenantId, loginMethodId: input.loginMethodId });
    if (!(input.ttlSeconds > 0)) throw new TypeError("ttlSeconds must be positive");
    const request = samlRequestRecordSchema.parse(input.request);
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const [existing] = await this.#db.query<{
        state_hash: string;
        state_encrypted: string;
        saml_request_id: string | null;
        saml_request: unknown;
        saml_principal_encrypted: string | null;
        max_age: number | null;
        created_at: Date;
      }>(
        `SELECT state_hash, state_encrypted, saml_request_id, saml_request,
                saml_principal_encrypted, max_age, created_at
           FROM federation_states
          WHERE tenant_id = $1 AND interaction_uid = $2 AND login_method_id = $3
            AND callback_at IS NULL AND expires_at > now() AND protocol = 'saml'
            AND saml_post_rendered_at IS NULL`,
        [tenantId, input.interactionUid, input.loginMethodId],
      );
      if (existing !== undefined && existing.saml_request_id !== null) {
        const principalPin =
          existing.saml_principal_encrypted === null
            ? undefined
            : this.#secrets.decryptString(
                existing.saml_principal_encrypted,
                principalContext(existing.state_hash),
              );
        const stored = samlRequestRecordSchema.safeParse(existing.saml_request);
        if (
          stored.success &&
          JSON.stringify(stored.data) === JSON.stringify(request) &&
          principalPin === input.principalPin &&
          (existing.max_age ?? undefined) === input.maxAge
        ) {
          return {
            relayState: this.#secrets.decryptString(
              existing.state_encrypted,
              stateContext(existing.state_hash),
            ),
            requestId: existing.saml_request_id,
            request,
            principalPin,
            createdAt: existing.created_at,
          };
        }
      }
      // An expired pending row, or one that asked for something else, is never used again.
      await this.#db.query(
        `DELETE FROM federation_states
          WHERE tenant_id = $1 AND interaction_uid = $2 AND login_method_id = $3
            AND callback_at IS NULL`,
        [tenantId, input.interactionUid, input.loginMethodId],
      );
      const fresh = input.fresh();
      const stateHash = hashToken(fresh.relayState);
      const inserted = await mapDbErrors(() =>
        this.#db.query<{ created_at: Date }>(
          `INSERT INTO federation_states
             (state_hash, tenant_id, login_method_id, interaction_uid, state_encrypted, protocol,
              saml_request_id, saml_request, saml_principal_encrypted, max_age, expires_at)
           VALUES ($1, $2, $3, $4, $5, 'saml', $6, $7::jsonb, $8, $9,
                   now() + make_interval(secs => $10::double precision))
           ON CONFLICT (tenant_id, interaction_uid, login_method_id) WHERE callback_at IS NULL
           DO NOTHING
           RETURNING created_at`,
          [
            stateHash,
            tenantId,
            input.loginMethodId,
            input.interactionUid,
            this.#secrets.encrypt(fresh.relayState, stateContext(stateHash)),
            fresh.requestId,
            JSON.stringify(request),
            input.principalPin === undefined
              ? null
              : this.#secrets.encrypt(input.principalPin, principalContext(stateHash)),
            input.maxAge ?? null,
            input.ttlSeconds,
          ],
        ),
      );
      const created = inserted[0];
      if (created !== undefined) {
        return {
          relayState: fresh.relayState,
          requestId: fresh.requestId,
          request,
          principalPin: input.principalPin,
          createdAt: created.created_at,
        };
      }
    }
    throw new Error("No pending SAML request could be created");
  }

  /**
   * Claims the HTTP-POST page of a pending SAML request: only the first call gets it (atomic),
   * so the page, and a personal identity number in it, is rendered once. `null` when the
   * RelayState is not an unanswered, unrendered request of this login method.
   */
  async claimSamlPostRender(
    tenantId: string,
    loginMethodId: string,
    relayState: string,
  ): Promise<(SamlPendingSecrets & { readonly interactionUid: string }) | null> {
    requireUuids({ tenantId, loginMethodId });
    if (relayState.length === 0 || relayState.length > 512) return null;
    const [row] = await this.#db.query<StateRow>(
      `UPDATE federation_states SET saml_post_rendered_at = now()
        WHERE state_hash = $1 AND tenant_id = $2 AND login_method_id = $3 AND protocol = 'saml'
          AND callback_at IS NULL AND expires_at > now() AND saml_post_rendered_at IS NULL
        RETURNING ${STATE_COLUMNS}`,
      [hashToken(relayState), tenantId, loginMethodId],
    );
    if (row === undefined) return null;
    const pending = this.#toPending(row);
    if (pending.protocol !== "saml") return null;
    return {
      relayState,
      requestId: pending.requestId,
      request: pending.request,
      principalPin: pending.principalPin,
      createdAt: pending.createdAt,
      interactionUid: pending.interactionUid,
    };
  }

  /** Stores the callback's outcome under `completionRef` (only once per state). */
  async attachCompletion(
    tenantId: string,
    stateHash: string,
    completionRef: string,
    completion: FederationCompletion,
  ): Promise<void> {
    requireUuids({ tenantId });
    const data = federationCompletionSchema.parse(completion);
    const rows = await this.#db.query(
      `UPDATE federation_states SET completion_hash = $3, completion = $4::jsonb
        WHERE tenant_id = $1 AND state_hash = $2 AND callback_at IS NOT NULL
          AND completion IS NULL
        RETURNING 1`,
      [tenantId, stateHash, hashToken(completionRef), JSON.stringify(data)],
    );
    if (rows.length === 0) throw new Error("Federation state cannot take a completion");
  }

  /**
   * Redeems a completion reference for the interaction `interactionUid`, once and only shortly
   * after the callback. `null` when unknown, used, too old or for another interaction.
   */
  async consumeCompletion(
    tenantId: string,
    interactionUid: string,
    completionRef: string,
  ): Promise<{ readonly loginMethodId: string; readonly completion: FederationCompletion } | null> {
    requireUuids({ tenantId });
    if (completionRef.length === 0 || completionRef.length > 512) return null;
    const [row] = await this.#db.query<{ login_method_id: string; completion: unknown }>(
      `UPDATE federation_states SET completed_at = now()
        WHERE tenant_id = $1 AND completion_hash = $2 AND interaction_uid = $3
          AND completed_at IS NULL
          AND callback_at > now() - make_interval(secs => $4::double precision)
        RETURNING login_method_id, completion`,
      [tenantId, hashToken(completionRef), interactionUid, COMPLETION_WINDOW_SECONDS],
    );
    if (row === undefined) return null;
    const completion = federationCompletionSchema.safeParse(row.completion);
    return completion.success
      ? { loginMethodId: row.login_method_id, completion: completion.data }
      : null;
  }

  /**
   * Deletes up to `batchSize` states that expired more than `retainSeconds` ago (they are kept a
   * while so a late replay is still recognised as one). Returns how many were removed.
   */
  async deleteExpiredBatch(batchSize: number, retainSeconds = 24 * 3600): Promise<number> {
    const rows = await this.#db.query<{ deleted: number }>(
      `WITH doomed AS (
           SELECT state_hash FROM federation_states
            WHERE expires_at <= now() - make_interval(secs => $2::double precision)
            LIMIT $1
         ), deleted AS (
           DELETE FROM federation_states f USING doomed
            WHERE f.state_hash = doomed.state_hash RETURNING 1
         )
         SELECT count(*)::int AS deleted FROM deleted`,
      [batchSize, retainSeconds],
    );
    return rows[0]?.deleted ?? 0;
  }
}
