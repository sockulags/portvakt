import { z } from "zod";
import type { AuditLog } from "../audit/audit-log.js";
import { auditEvent } from "../audit/catalogue.js";
import { generateSigningKey } from "../crypto/jwk.js";
import type { KeyRing } from "../crypto/keyring.js";
import type { Db } from "../db/database.js";
import type { AppendAuditEventInput, AuditEvent } from "../domain/audit.js";
import type { SigningKey } from "../domain/signing-key.js";
import { JOB_LOCKS, runExclusive } from "../jobs/exclusive.js";
import type { Logger } from "../logging/logger.js";
import { createRepositories, type Repositories } from "../repositories/index.js";
import { TransitionNotDueError, ValidationError } from "../repositories/errors.js";

export interface RotationPolicy {
  /** How often a new key is introduced (KEY_ROTATION_INTERVAL). */
  readonly intervalSeconds: number;
  /** How long a `next` key is published before it signs (KEY_PUBLISH_AHEAD). */
  readonly publishAheadSeconds: number;
  /** How long a `retiring` key stays published (KEY_RETIRE_AFTER). */
  readonly retireAfterSeconds: number;
}

const SYSTEM_ACTOR = { type: "system", id: "key-rotation" } as const;

export const rotateNowInputSchema = z
  .object({
    /** Who asked: an admin person (M6 admin API) or the system. */
    actor: z
      .object({
        type: z.enum(["person", "system"]),
        id: z.string().min(1).max(255).nullable(),
      })
      .strict(),
    /** Short reason for the audit log. No personal data. */
    reason: z.string().trim().min(1).max(500),
    /**
     * Key compromise: the previous active key is retired immediately instead of retiring after
     * KEY_RETIRE_AFTER, so tokens it signed stop verifying at once.
     */
    emergency: z.boolean(),
  })
  .strict();
export type RotateNowInput = z.input<typeof rotateNowInputSchema>;

export interface RotationResult {
  /** The key that now signs. */
  readonly activatedKid: string;
  /** The previous active key, now `retiring` (published, no longer signing), if any. */
  readonly retiringKid: string | null;
  /** Keys retired by this call (the previous active key in an emergency). */
  readonly retiredKids: readonly string[];
}

export interface ScheduledRotationResult {
  /** False when another replica held the lock. */
  readonly ran: boolean;
  readonly createdKid: string | null;
  readonly activatedKid: string | null;
  readonly retiredKids: readonly string[];
}

export interface KeyRotationServiceOptions {
  readonly db: Db;
  readonly keys: KeyRing;
  readonly policy: RotationPolicy;
  readonly logger: Logger;
  /** Called after a change was committed (reload the local key cache without waiting for NOTIFY). */
  readonly onChange?: () => Promise<void>;
  /** Hands the committed key events to the audit sink. */
  readonly auditLog?: AuditLog;
}

/**
 * Drives signing keys through `next` -> `active` -> `retiring` -> `retired`. Every operation runs
 * under one advisory lock, so replicas never race; the timing guards themselves are enforced by
 * the repository in SQL. Repository writes emit `signing_keys` change events, which make every
 * replica reload its key cache.
 */
export class KeyRotationService {
  readonly #options: KeyRotationServiceOptions;
  /** Audit events written per transaction (by its repositories), forwarded after the commit. */
  readonly #written = new WeakMap<Repositories, AuditEvent[]>();

  constructor(options: KeyRotationServiceOptions) {
    const { publishAheadSeconds, retireAfterSeconds, intervalSeconds } = options.policy;
    if (publishAheadSeconds >= intervalSeconds || retireAfterSeconds >= intervalSeconds) {
      throw new TypeError("publish-ahead and retire-after must be shorter than the interval");
    }
    this.#options = options;
  }

  /**
   * Start-up: makes sure a key signs. With no active key (first start), a key is created and
   * activated at once: nothing can have cached the old JWKS, so there is no publish-ahead wait.
   * A `next` key left without an active key is activated the same way. Replicas starting
   * together wait for each other; only the first one creates the key.
   */
  async ensureActiveKey(): Promise<void> {
    const result = await this.#exclusive(true, async (repos) => {
      const [active] = await repos.signingKeys.list(["active"]);
      if (active !== undefined) return false;
      const next = (await repos.signingKeys.list(["next"]))[0] ?? (await this.#createNext(repos));
      await repos.signingKeys.activate(next.kid, { publishAheadSeconds: 0 });
      await this.#audit(repos, "key.activate", next.kid, { initial: true });
      return true;
    });
    if (result === true) {
      this.#options.logger.info("created the initial signing key");
      await this.#options.onChange?.();
    }
  }

  /**
   * One scheduled step (the rotation job). Introduces a `next` key once the active key has been
   * active for KEY_ROTATION_INTERVAL minus KEY_PUBLISH_AHEAD, activates it after
   * KEY_PUBLISH_AHEAD, and retires `retiring` keys after KEY_RETIRE_AFTER. Skips when another
   * replica is running it.
   */
  async runScheduled(now: Date = new Date()): Promise<ScheduledRotationResult> {
    const { intervalSeconds, publishAheadSeconds, retireAfterSeconds } = this.#options.policy;
    const outcome = await this.#exclusive(false, async (repos) => {
      let createdKid: string | null = null;
      let activatedKid: string | null = null;
      const retiredKids: string[] = [];

      let [next] = await repos.signingKeys.list(["next"]);
      const [active] = await repos.signingKeys.list(["active"]);
      const createDueAt = (key: SigningKey): number =>
        (key.activatedAt ?? key.createdAt).getTime() +
        (intervalSeconds - publishAheadSeconds) * 1000;
      if (next === undefined && (active === undefined || createDueAt(active) <= now.getTime())) {
        next = await this.#createNext(repos);
        createdKid = next.kid;
      }
      if (next !== undefined && (createdKid === null || active === undefined)) {
        const activated = await this.#activateIfDue(repos, next.kid, active === undefined);
        if (activated) activatedKid = next.kid;
      }
      for (const retiring of await repos.signingKeys.list(["retiring"])) {
        try {
          await repos.signingKeys.retire(retiring.kid, { retireAfterSeconds });
          await this.#audit(repos, "key.retire", retiring.kid, {});
          retiredKids.push(retiring.kid);
        } catch (error) {
          if (!(error instanceof TransitionNotDueError)) throw error;
        }
      }
      return { createdKid, activatedKid, retiredKids };
    });
    if (outcome === undefined) {
      return { ran: false, createdKid: null, activatedKid: null, retiredKids: [] };
    }
    const changed =
      outcome.createdKid !== null ||
      outcome.activatedKid !== null ||
      outcome.retiredKids.length > 0;
    if (changed) {
      this.#options.logger.info(
        {
          createdKid: outcome.createdKid,
          activatedKid: outcome.activatedKid,
          retiredKids: outcome.retiredKids,
        },
        "signing key rotation step",
      );
      await this.#options.onChange?.();
    }
    return { ran: true, ...outcome };
  }

  /**
   * Manual rotation (admin API, M6): a new key signs from now on. The pending `next` key is used
   * when there is one (it is already published), otherwise a new key is created. The previous
   * active key becomes `retiring`, so tokens it signed stay verifiable; verifiers pick up the new
   * kid by refetching JWKS on an unknown kid. With `emergency` (key compromise) the previous key is
   * retired at once instead. Every forced transition is audited with the actor and reason.
   */
  async rotateNow(input: RotateNowInput): Promise<RotationResult> {
    const parsed = rotateNowInputSchema.safeParse(input);
    if (!parsed.success) {
      throw new ValidationError(parsed.error.issues.map((issue) => issue.message));
    }
    const { actor, reason, emergency } = parsed.data;
    const forced = { force: true, actor, reason } as const;
    const result = await this.#exclusive(true, async (repos): Promise<RotationResult> => {
      const next = (await repos.signingKeys.list(["next"]))[0] ?? (await this.#createNext(repos));
      const activation = await repos.signingKeys.activate(next.kid, forced);
      const retiredKids: string[] = [];
      if (emergency && activation.retiring !== null) {
        await repos.signingKeys.retire(activation.retiring.kid, forced);
        retiredKids.push(activation.retiring.kid);
      }
      await this.#append(
        repos,
        auditEvent({
          tenantId: null,
          actor,
          subject: { type: "signing_key", id: next.kid },
          action: "key.rotate",
          details: {
            reason,
            emergency,
            retiringKid: activation.retiring?.kid ?? null,
            retiredKids,
          },
        }),
      );
      return {
        activatedKid: activation.activated.kid,
        retiringKid: emergency ? null : (activation.retiring?.kid ?? null),
        retiredKids,
      };
    });
    if (result === undefined) throw new Error("Key rotation lock was not acquired");
    this.#options.logger.warn(
      { activatedKid: result.activatedKid, retiredKids: result.retiredKids, emergency },
      "signing key rotated manually",
    );
    await this.#options.onChange?.();
    return result;
  }

  async #activateIfDue(repos: Repositories, kid: string, noActive: boolean): Promise<boolean> {
    try {
      // Without an active key nothing is signing: activate at once rather than wait.
      await repos.signingKeys.activate(kid, {
        publishAheadSeconds: noActive ? 0 : this.#options.policy.publishAheadSeconds,
      });
      await this.#audit(repos, "key.activate", kid, {});
      return true;
    } catch (error) {
      if (error instanceof TransitionNotDueError) return false;
      throw error;
    }
  }

  async #createNext(repos: Repositories): Promise<SigningKey> {
    const key = await repos.signingKeys.createNext(generateSigningKey());
    await this.#audit(repos, "key.create", key.kid, {});
    return key;
  }

  /** Key events commit with the transition they describe (the rotation's transaction). */
  async #audit(
    repos: Repositories,
    action: "key.create" | "key.activate" | "key.retire",
    kid: string,
    details: { readonly initial?: boolean },
  ): Promise<void> {
    await this.#append(
      repos,
      auditEvent({
        tenantId: null,
        actor: SYSTEM_ACTOR,
        subject: { type: "signing_key", id: kid },
        action,
        details,
      }),
    );
  }

  async #exclusive<T>(
    wait: boolean,
    fn: (repos: Repositories) => Promise<T>,
  ): Promise<T | undefined> {
    const written: AuditEvent[] = [];
    const result = await runExclusive(this.#options.db, JOB_LOCKS.keyRotation, { wait }, (tx) => {
      const repos = createRepositories(tx, this.#options.keys);
      this.#written.set(repos, written);
      return fn(repos);
    });
    // Committed: the key events go to the audit sink.
    if (result.ran) this.#options.auditLog?.forward(written);
    return result.ran ? result.value : undefined;
  }

  async #append(repos: Repositories, input: AppendAuditEventInput): Promise<void> {
    const stored = await repos.audit.append(input);
    this.#written.get(repos)?.push(stored);
  }
}
