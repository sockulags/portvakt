import { z } from "zod";
import type { OidcPayloadRepository } from "../repositories/oidc-payloads.js";

/**
 * What Portvakt knows about a broker session beyond what oidc-provider's Session model stores
 * (account, acr, amr, login time): which login method authenticated the person, and when the
 * session ends. Stored per tenant, keyed by the oidc-provider session `uid` (stable for the life
 * of the session; tokens carry it as `sessionUid`).
 *
 * M3 extends this with the session policy (idle, allowSso) and M4 with representation; claims
 * that depend on the login (`idp`, `acr`, `session_exp`, roles from group rules) read it.
 */
export const loginContextSchema = z
  .object({
    personId: z.uuid(),
    loginMethodId: z.uuid(),
    acr: z.string().min(1).max(255),
    amr: z.array(z.string().min(1).max(64)).max(16),
    /** Epoch seconds of the upstream authentication. */
    authTime: z.number().int().positive(),
    /** Epoch seconds: absolute end of the broker session. */
    sessionExpiresAt: z.number().int().positive(),
    /** The application the session was established for (allowSso = false, M3). */
    clientId: z.string().min(1).max(128),
  })
  .strict();
export type LoginContext = z.infer<typeof loginContextSchema>;

/** What `completeLogin` hands over to the authorization resume, through the interaction result. */
export const pendingLoginSchema = z.object({ loginMethodId: z.uuid() }).strict();
export type PendingLogin = z.infer<typeof pendingLoginSchema>;

/** Key of the pending login in the interaction result (next to oidc-provider's `login`). */
export const PENDING_LOGIN_RESULT_KEY = "portvakt";

/** oidc_payloads kind; distinct from every oidc-provider model name. */
const KIND = "PortvaktLoginContext";

const epochNow = (): number => Math.floor(Date.now() / 1000);

export class LoginContextStore {
  readonly #tenantId: string;
  readonly #payloads: OidcPayloadRepository;

  constructor(tenantId: string, payloads: OidcPayloadRepository) {
    this.#tenantId = tenantId;
    this.#payloads = payloads;
  }

  /** Stores the context until the session ends (or at least a second, so it is never immortal). */
  async save(sessionUid: string, context: LoginContext): Promise<void> {
    const ttl = Math.max(1, context.sessionExpiresAt - epochNow());
    await this.#payloads.upsert(this.#tenantId, KIND, sessionUid, context, ttl);
  }

  /** The context of a live session; `undefined` when unknown, expired or malformed. */
  async find(sessionUid: string | undefined): Promise<LoginContext | undefined> {
    if (sessionUid === undefined || sessionUid.length === 0 || sessionUid.length > 512) {
      return undefined;
    }
    const stored = await this.#payloads.find(this.#tenantId, KIND, sessionUid);
    const parsed = loginContextSchema.safeParse(stored);
    return parsed.success ? parsed.data : undefined;
  }
}

/**
 * Request-scoped cache: oidc-provider's TTL callbacks are synchronous, so the login context is
 * resolved once per request (in findAccount or at resume) and read from here afterwards.
 */
const perRequest = new WeakMap<object, LoginContext>();

export function rememberLoginContext(ctx: object, context: LoginContext): void {
  perRequest.set(ctx, context);
}

export function rememberedLoginContext(ctx: object | undefined): LoginContext | undefined {
  return ctx === undefined ? undefined : perRequest.get(ctx);
}
