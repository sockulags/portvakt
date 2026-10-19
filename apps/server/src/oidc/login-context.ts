import { z } from "zod";
import type { Db } from "../db/database.js";
import type { AuditEvent } from "../domain/audit.js";
import { LOGIN_METHOD_KINDS } from "../domain/login-method.js";
import { representationChoiceSchema, type RepresentationChoice } from "../domain/representation.js";
import { AuditRepository } from "../repositories/audit.js";
import { upstreamSessionSchema } from "../repositories/federation-states.js";
import { OidcPayloadRepository } from "../repositories/oidc-payloads.js";

/**
 * What Portvakt knows about a broker session and its logins beyond oidc-provider's own Session
 * model (account, acr, amr, login time). Two records, both in `oidc_payloads`:
 *
 * - The **session record** (kind `PortvaktSession`, keyed by the oidc-provider session `uid`):
 *   the latest login of the browser session and the policy it established (absolute end, idle
 *   timeout, allowSso and the application it was established for), plus the last activity
 *   (authorization or refresh). The login prompt checks read it.
 * - The **grant login** (kind `PortvaktGrantLogin`, keyed by the grant id): a snapshot of the login an application's grant was issued
 *   for. Claims and token lifetimes of that application read it, so a fresh login for another
 *   application in the same browser never changes this application's claims at its next refresh.
 *
 * The grant login also holds the representation the grant was issued with (`representation`,
 * chosen per application grant, never per browser session), re-checked at every refresh and at
 * every authorization that reuses the grant.
 */

const acrSchema = z.string().min(1).max(255);
const amrSchema = z.array(z.string().min(1).max(64)).max(16);
const epochSchema = z.number().int().positive();

export const sessionRecordSchema = z
  .object({
    personId: z.uuid(),
    loginMethodId: z.uuid(),
    loginMethodKind: z.enum(LOGIN_METHOD_KINDS),
    acr: acrSchema,
    amr: amrSchema,
    /** Epoch seconds of the latest login. */
    authTime: epochSchema,
    /** Epoch seconds: end of the latest login's session (its login method's maxAge). */
    sessionExpiresAt: epochSchema,
    /**
     * Epoch seconds the record and the oidc-provider session are kept: SESSION_TTL beyond the
     * latest end of any login of this session. A shorter fresh login thus never cuts the grants
     * of an earlier, longer one short, and an expired session stays recognisable (the login
     * prompt then asks the upstream IdP for a fresh login).
     */
    retainUntil: epochSchema,
    idleSeconds: z.number().int().positive(),
    allowSso: z.boolean(),
    /** The application the latest login was made for (allowSso = false). */
    clientId: z.string().min(1).max(128),
    /** Epoch seconds of the last authorization or refresh in this session. */
    lastActivityAt: epochSchema,
    /**
     * The upstream SAML session of the latest login (NameID, SessionIndex): single logout
     * towards the IdP, and IdP-initiated logout finds the session by it.
     */
    upstream: upstreamSessionSchema.optional(),
  })
  .strict();
export type SessionRecord = z.infer<typeof sessionRecordSchema>;

export const loginContextSchema = z
  .object({
    personId: z.uuid(),
    loginMethodId: z.uuid(),
    loginMethodKind: z.enum(LOGIN_METHOD_KINDS),
    acr: acrSchema,
    amr: amrSchema,
    /** Epoch seconds of the upstream authentication. */
    authTime: epochSchema,
    /** Epoch seconds: absolute end of the broker session for this grant (`session_exp`). */
    sessionExpiresAt: epochSchema,
    idleSeconds: z.number().int().positive(),
    /** The application the grant belongs to. */
    clientId: z.string().min(1).max(128),
    /** oidc-provider session uid the grant was issued in. */
    sessionUid: z.string().min(1).max(512),
    /**
     * The representation chosen for this grant; absent when the application does not offer
     * representation or the person had nothing to choose (acting for themselves).
     */
    representation: representationChoiceSchema.optional(),
  })
  .strict();
/** The login an application's grant was issued for: what its claims and lifetimes follow. */
export type LoginContext = z.infer<typeof loginContextSchema>;

/** What `completeLogin` hands over to the authorization resume, through the interaction result. */
export const pendingLoginSchema = z
  .object({
    loginMethodId: z.uuid(),
    upstream: upstreamSessionSchema.optional(),
    /** The login was a step-up of the session's person (same person, higher acr or fresher). */
    stepUp: z.object({ previousAcr: acrSchema.optional() }).strict().optional(),
  })
  .strict();
export type PendingLogin = z.infer<typeof pendingLoginSchema>;

/** Key of the pending login in the interaction result (next to oidc-provider's `login`). */
export const PENDING_LOGIN_RESULT_KEY = "portvakt";

/** Key of the representation chosen in the chooser, in the interaction result. */
export const REPRESENTATION_RESULT_KEY = "portvakt_representation";

/** oidc_payloads kinds; distinct from every oidc-provider model name. */
export const SESSION_RECORD_KIND = "PortvaktSession";
export const GRANT_LOGIN_KIND = "PortvaktGrantLogin";

const MAX_ID_LENGTH = 512;

/**
 * Lookup key (`oidc_payloads.uid`) of the session records of an upstream SAML session: the login
 * method and the NameID's blind index (the NameID itself is never stored in the clear).
 */
export const upstreamSessionKey = (loginMethodId: string, nameIdIndex: string): string =>
  `saml:${loginMethodId}:${nameIdIndex}`;

const epochNow = (): number => Math.floor(Date.now() / 1000);
const ttlUntil = (end: number): number => Math.max(1, end - epochNow());
const validId = (id: string | undefined): id is string =>
  id !== undefined && id.length > 0 && id.length <= MAX_ID_LENGTH;

/** Audit writes that commit together with a login state change (success events). */
export type AuditWrites = (audit: AuditRepository) => Promise<readonly AuditEvent[]>;

export class LoginStateStore {
  readonly #tenantId: string;
  readonly #db: Db;
  readonly #payloads: OidcPayloadRepository;

  constructor(tenantId: string, db: Db) {
    this.#tenantId = tenantId;
    this.#db = db;
    this.#payloads = new OidcPayloadRepository(db);
  }

  /**
   * Stores the session record until `retainUntil` (at least a second, never immortal). A record
   * with an upstream SAML session is indexed by it (`uid` column), for IdP-initiated logout.
   */
  async saveSession(sessionUid: string, record: SessionRecord): Promise<void> {
    const parsed = sessionRecordSchema.parse(record);
    await this.#payloads.upsert(
      this.#tenantId,
      SESSION_RECORD_KIND,
      sessionUid,
      parsed,
      ttlUntil(record.retainUntil),
      parsed.upstream === undefined
        ? {}
        : { uid: upstreamSessionKey(parsed.loginMethodId, parsed.upstream.nameIdIndex) },
    );
  }

  /**
   * Ends every broker session whose latest login came through `loginMethodId` with this upstream
   * NameID (and, when given, one of the SessionIndexes): IdP-initiated single logout. The NameID
   * and SessionIndexes arrive as their blind indexes under every configured master key. The
   * oidc-provider session and its grants (with their tokens) are deleted, so the next
   * authorization needs a login and refresh tokens stop working. Returns how many ended.
   */
  async endSessionsOfUpstream(
    loginMethodId: string,
    nameIdIndexes: readonly string[],
    sessionIndexIndexes: readonly string[] | undefined,
  ): Promise<number> {
    let ended = 0;
    for (const nameIdIndex of nameIdIndexes) {
      for (const { id, payload } of await this.#payloads.listByUid(
        this.#tenantId,
        SESSION_RECORD_KIND,
        upstreamSessionKey(loginMethodId, nameIdIndex),
      )) {
        const record = sessionRecordSchema.safeParse(payload);
        if (!record.success || record.data.loginMethodId !== loginMethodId) continue;
        const upstream = record.data.upstream;
        if (upstream === undefined || !nameIdIndexes.includes(upstream.nameIdIndex)) continue;
        if (
          sessionIndexIndexes !== undefined &&
          (upstream.sessionIndexIndex === undefined ||
            !sessionIndexIndexes.includes(upstream.sessionIndexIndex))
        ) {
          continue;
        }
        await this.endSession(id);
        ended += 1;
      }
    }
    return ended;
  }

  /** Deletes a broker session: oidc-provider's Session, its grants, and the session record. */
  async endSession(sessionUid: string): Promise<void> {
    if (!validId(sessionUid)) return;
    const session = await this.#payloads.findByUid(this.#tenantId, "Session", sessionUid);
    const authorizations = z
      .record(z.string(), z.looseObject({ grantId: z.string().min(1).max(512).optional() }))
      .safeParse(session?.authorizations);
    if (authorizations.success) {
      for (const { grantId } of Object.values(authorizations.data)) {
        if (grantId !== undefined) await this.#payloads.revokeGrant(this.#tenantId, grantId);
      }
    }
    await this.#payloads.destroyByUid(this.#tenantId, "Session", sessionUid);
    await this.#payloads.destroy(this.#tenantId, SESSION_RECORD_KIND, sessionUid);
  }

  /** The record of a live session; `undefined` when unknown, expired or malformed. */
  async findSession(sessionUid: string | undefined): Promise<SessionRecord | undefined> {
    if (!validId(sessionUid)) return undefined;
    const stored = await this.#payloads.find(this.#tenantId, SESSION_RECORD_KIND, sessionUid);
    const parsed = sessionRecordSchema.safeParse(stored);
    return parsed.success ? parsed.data : undefined;
  }

  /**
   * Records activity (an authorization or a refresh) on the session record, only while it is
   * still the record of the login `authTime` of `personId`: a refresh of an older login's grant
   * does not keep a newer login alive. Updates `lastActivityAt` alone, atomically.
   */
  async touchSession(
    sessionUid: string,
    personId: string,
    authTime: number,
    now: number,
  ): Promise<boolean> {
    if (!validId(sessionUid)) return false;
    return this.#payloads.setFieldIf(
      this.#tenantId,
      SESSION_RECORD_KIND,
      sessionUid,
      "lastActivityAt",
      now,
      { personId, authTime },
    );
  }

  /**
   * Stores a grant's login until its session end. Not indexed by grant: a revoked grant already
   * fails at the token endpoint, and a code replay must not race the legitimate redemption.
   */
  async saveGrantLogin(grantId: string, login: LoginContext): Promise<void> {
    await this.#saveGrantLogin(this.#payloads, grantId, login);
  }

  /**
   * Stores a grant's login and writes `audit` events in the same transaction (the success
   * events of what the grant login commits: a representation choice, a step-up). Returns the
   * events written, for the audit sink once committed.
   */
  async saveGrantLoginAudited(
    grantId: string,
    login: LoginContext,
    audit: AuditWrites,
  ): Promise<readonly AuditEvent[]> {
    return this.#db.transaction(async (tx) => {
      await this.#saveGrantLogin(new OidcPayloadRepository(tx), grantId, login);
      return audit(new AuditRepository(tx));
    });
  }

  /**
   * Revokes an application's grant (its tokens and the grant itself) and writes the audit event
   * of the revocation in the same transaction. Returns the events written.
   */
  async revokeGrantAudited(grantId: string, audit: AuditWrites): Promise<readonly AuditEvent[]> {
    if (!validId(grantId)) return [];
    return this.#db.transaction(async (tx) => {
      await new OidcPayloadRepository(tx).revokeGrant(this.#tenantId, grantId);
      return audit(new AuditRepository(tx));
    });
  }

  async #saveGrantLogin(
    payloads: OidcPayloadRepository,
    grantId: string,
    login: LoginContext,
  ): Promise<void> {
    await payloads.upsert(
      this.#tenantId,
      GRANT_LOGIN_KIND,
      grantId,
      loginContextSchema.parse(login),
      ttlUntil(login.sessionExpiresAt),
    );
  }

  async findGrantLogin(grantId: string | undefined): Promise<LoginContext | undefined> {
    if (!validId(grantId)) return undefined;
    const stored = await this.#payloads.find(this.#tenantId, GRANT_LOGIN_KIND, grantId);
    const parsed = loginContextSchema.safeParse(stored);
    return parsed.success ? parsed.data : undefined;
  }
}

/**
 * Request-scoped cache: oidc-provider's TTL callbacks are synchronous, so the session record and
 * the grant login are resolved once per request and read from here afterwards.
 */
const sessionPerRequest = new WeakMap<object, SessionRecord>();
const loginPerRequest = new WeakMap<object, LoginContext>();

export function rememberSessionRecord(ctx: object, record: SessionRecord): void {
  sessionPerRequest.set(ctx, record);
}

export function rememberedSessionRecord(ctx: object | undefined): SessionRecord | undefined {
  return ctx === undefined ? undefined : sessionPerRequest.get(ctx);
}

export function rememberLoginContext(ctx: object, context: LoginContext): void {
  loginPerRequest.set(ctx, context);
}

export function rememberedLoginContext(ctx: object | undefined): LoginContext | undefined {
  return ctx === undefined ? undefined : loginPerRequest.get(ctx);
}

/** The representation decided for the authorization of this request (select_account prompt). */
export interface RepresentationDecision {
  /** `undefined`: the application offers no representation or there was nothing to choose. */
  readonly choice: RepresentationChoice | undefined;
  /** The choice was made in the chooser of this authorization (audited when the grant saves). */
  readonly selected: boolean;
}

const representationPerRequest = new WeakMap<object, RepresentationDecision>();

export function rememberRepresentation(ctx: object, decision: RepresentationDecision): void {
  representationPerRequest.set(ctx, decision);
}

export function rememberedRepresentation(
  ctx: object | undefined,
): RepresentationDecision | undefined {
  return ctx === undefined ? undefined : representationPerRequest.get(ctx);
}
