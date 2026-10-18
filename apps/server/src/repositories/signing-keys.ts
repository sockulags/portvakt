import type { SecretBox } from "../crypto/envelope.js";
import {
  type GeneratedSigningKey,
  privateJwkSchema,
  publicJwkSchema,
  type SigningAlgorithm,
} from "../crypto/jwk.js";
import { z } from "zod";
import type { Db } from "../db/database.js";
import {
  type ActivationPolicy,
  PUBLISHED_KEY_STATES,
  type RetirementPolicy,
  type SigningKey,
  type SigningKeyMaterial,
  type SigningKeyState,
} from "../domain/signing-key.js";
import { AuditRepository } from "./audit.js";
import { emitChange } from "./change-events.js";
import {
  InvalidStateTransitionError,
  mapDbErrors,
  NotFoundError,
  parseInput,
  TransitionNotDueError,
  ValidationError,
} from "./errors.js";
import { requireRow } from "./sql.js";

interface SigningKeyRow {
  kid: string;
  alg: SigningAlgorithm;
  state: SigningKeyState;
  public_jwk: unknown;
  created_at: Date;
  activated_at: Date | null;
  retiring_at: Date | null;
  retired_at: Date | null;
}

interface SigningKeyMaterialRow extends SigningKeyRow {
  private_jwk_encrypted: string;
}

const forcedTransitionSchema = z.object({
  force: z.literal(true),
  actor: z.object({
    type: z.enum(["person", "system"]),
    id: z.string().min(1).max(255).nullable(),
  }),
  reason: z.string().trim().min(1).max(500),
});

const COLUMNS = "kid, alg, state, public_jwk, created_at, activated_at, retiring_at, retired_at";

/** Ordering for the provider's key store: the active key first, then next, then retiring. */
const STATE_ORDER = "array_position(ARRAY['active', 'next', 'retiring']::text[], state)";

/** AAD context binding an encrypted private JWK to its kid. */
export const privateJwkContext = (kid: string): string => `signing_key:${kid}:private_jwk`;

function toSigningKey(row: SigningKeyRow): SigningKey {
  return {
    kid: row.kid,
    alg: row.alg,
    state: row.state,
    publicJwk: publicJwkSchema.parse(row.public_jwk),
    createdAt: row.created_at,
    activatedAt: row.activated_at,
    retiringAt: row.retiring_at,
    retiredAt: row.retired_at,
  };
}

export interface ActivationResult {
  readonly activated: SigningKey;
  /** The previously active key, now `retiring`; `null` on first activation. */
  readonly retiring: SigningKey | null;
}

/**
 * Signing keys (global in v1). Lifecycle: `next` (published, not used) -> `active` (signs) ->
 * `retiring` (published so issued tokens stay verifiable) -> `retired` (private part erased).
 * A `next` key that is never used can be discarded straight to `retired`.
 */
export class SigningKeyRepository {
  readonly #db: Db;
  readonly #secrets: SecretBox;

  constructor(db: Db, secrets: SecretBox) {
    this.#db = db;
    this.#secrets = secrets;
  }

  /** Stores a freshly generated key as `next`. Fails with a conflict if a `next` key exists. */
  async createNext(key: GeneratedSigningKey): Promise<SigningKey> {
    const privateJwk = privateJwkSchema.parse(key.privateJwk);
    const publicJwk = publicJwkSchema.parse(key.publicJwk);
    if (privateJwk.kid !== key.kid || publicJwk.kid !== key.kid) {
      throw new ValidationError(["kid: JWKs must carry the key's kid"]);
    }
    if (privateJwk.x !== publicJwk.x || privateJwk.y !== publicJwk.y) {
      throw new ValidationError(["publicJwk: does not match the private key"]);
    }
    const encrypted = this.#secrets.encrypt(JSON.stringify(privateJwk), privateJwkContext(key.kid));
    const rows = await this.#db.transaction(async (tx) => {
      const inserted = await mapDbErrors(() =>
        tx.query<SigningKeyRow>(
          `INSERT INTO signing_keys (kid, alg, private_jwk_encrypted, public_jwk, state)
           VALUES ($1, $2, $3, $4::jsonb, 'next')
           RETURNING ${COLUMNS}`,
          [key.kid, key.alg, encrypted, JSON.stringify(publicJwk)],
        ),
      );
      await emitChange(tx, { type: "signing_keys" });
      return inserted;
    });
    return toSigningKey(requireRow(rows));
  }

  async findByKid(kid: string): Promise<SigningKey | null> {
    const [row] = await this.#db.query<SigningKeyRow>(
      `SELECT ${COLUMNS} FROM signing_keys WHERE kid = $1`,
      [kid],
    );
    return row === undefined ? null : toSigningKey(row);
  }

  async list(states?: readonly SigningKeyState[]): Promise<SigningKey[]> {
    const rows = await this.#db.query<SigningKeyRow>(
      `SELECT ${COLUMNS} FROM signing_keys
        WHERE $1::text[] IS NULL OR state = ANY ($1::text[])
        ORDER BY created_at DESC, kid`,
      [states === undefined ? null : [...states]],
    );
    return rows.map(toSigningKey);
  }

  /** Keys whose public part belongs in JWKS. */
  async listPublished(): Promise<SigningKey[]> {
    const rows = await this.#db.query<SigningKeyRow>(
      `SELECT ${COLUMNS} FROM signing_keys WHERE state = ANY ($1::text[])
        ORDER BY ${STATE_ORDER}, created_at DESC`,
      [PUBLISHED_KEY_STATES],
    );
    return rows.map(toSigningKey);
  }

  /** Published keys with decrypted private JWKs, active first. Never log the result. */
  async loadMaterial(): Promise<SigningKeyMaterial[]> {
    const rows = await this.#db.query<SigningKeyMaterialRow>(
      `SELECT ${COLUMNS}, private_jwk_encrypted FROM signing_keys WHERE state = ANY ($1::text[])
        ORDER BY ${STATE_ORDER}, created_at DESC`,
      [PUBLISHED_KEY_STATES],
    );
    return rows.map((row) => ({
      ...toSigningKey(row),
      privateJwk: privateJwkSchema.parse(
        JSON.parse(
          this.#secrets.decryptString(row.private_jwk_encrypted, privateJwkContext(row.kid)),
        ),
      ),
    }));
  }

  /**
   * Promotes a `next` key to `active` and demotes the current active key (if any) to `retiring`,
   * atomically. Allowed once the key has been published as `next` for
   * `policy.publishAheadSeconds` (KEY_PUBLISH_AHEAD), so every verifier has had time to fetch it;
   * otherwise {@link TransitionNotDueError}. The forced path skips the wait and is audited.
   * Concurrent callers are serialised by row locks; the loser gets
   * {@link InvalidStateTransitionError}.
   */
  async activate(kid: string, policy: ActivationPolicy): Promise<ActivationResult> {
    const minAge = this.#minAgeSeconds(policy, "publishAheadSeconds");
    return this.#db.transaction(async (tx) => {
      const locked = await tx.query<{ kid: string; state: SigningKeyState; due: boolean }>(
        `SELECT kid, state, created_at <= now() - make_interval(secs => $2) AS due
           FROM signing_keys WHERE state IN ('next', 'active') OR kid = $1
          ORDER BY kid FOR UPDATE`,
        [kid, minAge],
      );
      const target = locked.find((row) => row.kid === kid);
      if (target === undefined) throw new NotFoundError("Signing key");
      if (target.state !== "next") {
        throw new InvalidStateTransitionError("Signing key", target.state, "active");
      }
      if (!target.due) throw new TransitionNotDueError("Signing key", "active");
      const [retiringRow] = await tx.query<SigningKeyRow>(
        `UPDATE signing_keys SET state = 'retiring', retiring_at = now()
          WHERE state = 'active' RETURNING ${COLUMNS}`,
      );
      const activatedRow = requireRow(
        await tx.query<SigningKeyRow>(
          `UPDATE signing_keys SET state = 'active', activated_at = now()
            WHERE kid = $1 RETURNING ${COLUMNS}`,
          [kid],
        ),
      );
      await this.#auditForced(tx, policy, "key.activate_forced", kid, {
        retiringKid: retiringRow?.kid ?? null,
      });
      await emitChange(tx, { type: "signing_keys" });
      return {
        activated: toSigningKey(activatedRow),
        retiring: retiringRow === undefined ? null : toSigningKey(retiringRow),
      };
    });
  }

  /**
   * `retiring` -> `retired`; erases the private key and removes the key from JWKS. Allowed once
   * the key has been retiring for `policy.retireAfterSeconds` (KEY_RETIRE_AFTER, at least the
   * longest token lifetime), so tokens it signed have expired. The forced path (a compromised
   * key) skips the wait and is audited; the public key row is kept either way.
   */
  async retire(kid: string, policy: RetirementPolicy): Promise<SigningKey> {
    const minAge = this.#minAgeSeconds(policy, "retireAfterSeconds");
    return this.#db.transaction(async (tx) => {
      const [current] = await tx.query<{ state: SigningKeyState; due: boolean }>(
        `SELECT state, retiring_at <= now() - make_interval(secs => $2) AS due
           FROM signing_keys WHERE kid = $1 FOR UPDATE`,
        [kid, minAge],
      );
      if (current === undefined) throw new NotFoundError("Signing key");
      if (current.state !== "retiring") {
        throw new InvalidStateTransitionError("Signing key", current.state, "retired");
      }
      if (!current.due) throw new TransitionNotDueError("Signing key", "retired");
      const key = await this.#markRetired(tx, kid);
      await this.#auditForced(tx, policy, "key.retire_forced", kid, {});
      await emitChange(tx, { type: "signing_keys" });
      return key;
    });
  }

  /** Drops an unused `next` key (for example after a failed rotation): `next` -> `retired`. */
  async discardNext(kid: string): Promise<SigningKey> {
    return this.#db.transaction(async (tx) => {
      const [current] = await tx.query<{ state: SigningKeyState }>(
        "SELECT state FROM signing_keys WHERE kid = $1 FOR UPDATE",
        [kid],
      );
      if (current === undefined) throw new NotFoundError("Signing key");
      if (current.state !== "next") {
        throw new InvalidStateTransitionError("Signing key", current.state, "retired");
      }
      const key = await this.#markRetired(tx, kid);
      await emitChange(tx, { type: "signing_keys" });
      return key;
    });
  }

  #minAgeSeconds(
    policy: ActivationPolicy | RetirementPolicy,
    field: "publishAheadSeconds" | "retireAfterSeconds",
  ): number {
    if ("force" in policy) {
      parseInput(forcedTransitionSchema, policy);
      return 0;
    }
    const seconds = (policy as Record<typeof field, unknown>)[field];
    if (typeof seconds !== "number" || !Number.isInteger(seconds) || seconds < 0) {
      throw new ValidationError([`${field}: must be a non-negative integer`]);
    }
    return seconds;
  }

  async #markRetired(tx: Db, kid: string): Promise<SigningKey> {
    const row = requireRow(
      await tx.query<SigningKeyRow>(
        `UPDATE signing_keys
            SET state = 'retired', retired_at = now(), private_jwk_encrypted = NULL
          WHERE kid = $1 RETURNING ${COLUMNS}`,
        [kid],
      ),
    );
    return toSigningKey(row);
  }

  /** A forced transition is recorded in the same transaction: no audit, no transition. */
  async #auditForced(
    tx: Db,
    policy: ActivationPolicy | RetirementPolicy,
    action: string,
    kid: string,
    details: Record<string, string | null>,
  ): Promise<void> {
    if (!("force" in policy)) return;
    await new AuditRepository(tx).append({
      tenantId: null,
      actor: policy.actor,
      subject: { type: "signing_key", id: kid },
      action,
      outcome: "success",
      details: { reason: policy.reason, ...details },
    });
  }
}

/** Re-wraps every private JWK not encrypted under the current master key. */
export async function rewrapSigningKeys(db: Db, secrets: SecretBox): Promise<number> {
  const rows = await db.query<{ kid: string; private_jwk_encrypted: string }>(
    `SELECT kid, private_jwk_encrypted FROM signing_keys
      WHERE private_jwk_encrypted IS NOT NULL AND split_part(private_jwk_encrypted, '.', 2) <> $1`,
    [secrets.currentKeyId],
  );
  for (const row of rows) {
    const rewrapped = secrets.rewrap(row.private_jwk_encrypted, privateJwkContext(row.kid));
    await db.query(
      `UPDATE signing_keys SET private_jwk_encrypted = $2
        WHERE kid = $1 AND private_jwk_encrypted = $3`,
      [row.kid, rewrapped, row.private_jwk_encrypted],
    );
  }
  return rows.length;
}
