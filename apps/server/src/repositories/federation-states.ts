import { createHash } from "node:crypto";
import { z } from "zod";
import type { SecretBox } from "../crypto/envelope.js";
import type { Db } from "../db/database.js";
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
export const federationCompletionSchema = z
  .object({
    personId: z.uuid(),
    acr: z.string().min(1).max(255),
    amr: z.array(z.string().min(1).max(64)).min(1).max(16),
    /** Epoch seconds of the upstream authentication (min(upstream auth_time, now)). */
    authTime: z.number().int().positive(),
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

export interface PendingFederation {
  readonly stateHash: string;
  readonly loginMethodId: string;
  readonly interactionUid: string;
  readonly codeVerifier: string;
  readonly nonce: string;
  readonly maxAge: number | undefined;
}

/** Why a callback's state was not accepted. */
export type CallbackRejection =
  /** Unknown state, or a state of another tenant or login method. */
  | { readonly reason: "invalid_state" }
  /** The callback for this state was already used (replay). */
  | { readonly reason: "state_replayed"; readonly interactionUid: string }
  | { readonly reason: "state_expired"; readonly interactionUid: string };

interface StateRow {
  state_hash: string;
  login_method_id: string;
  interaction_uid: string;
  code_verifier_encrypted: string;
  nonce: string;
  max_age: number | null;
}

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
      code_verifier_encrypted: string;
      nonce: string;
    }>(
      `SELECT state_hash, state_encrypted, code_verifier_encrypted, nonce FROM federation_states
        WHERE tenant_id = $1 AND interaction_uid = $2 AND login_method_id = $3
          AND callback_at IS NULL AND expires_at > now()`,
      [tenantId, interactionUid, loginMethodId],
    );
    if (row === undefined) return undefined;
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
        RETURNING state_hash, login_method_id, interaction_uid, code_verifier_encrypted, nonce,
                  max_age`,
      [stateHash, tenantId, loginMethodId],
    );
    if (won !== undefined) {
      return {
        stateHash: won.state_hash,
        loginMethodId: won.login_method_id,
        interactionUid: won.interaction_uid,
        codeVerifier: this.#secrets.decryptString(
          won.code_verifier_encrypted,
          verifierContext(won.state_hash),
        ),
        nonce: won.nonce,
        maxAge: won.max_age ?? undefined,
      };
    }
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
