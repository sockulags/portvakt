import type { IncomingMessage, ServerResponse } from "node:http";
import { errors } from "oidc-provider";
import { z } from "zod";
import { upstreamSessionSchema } from "../repositories/federation-states.js";
import type { Repositories } from "../repositories/index.js";
import { PENDING_LOGIN_RESULT_KEY, type PendingLogin } from "./login-context.js";
import type { TenantProvider } from "./provider.js";

/**
 * The request an interaction runs in: the tenant's provider, the interaction uid from the URL
 * (`/t/{slug}/interaction/{uid}`) and the raw HTTP exchange (oidc-provider reads its cookies).
 */
export interface InteractionContext {
  readonly tenantProvider: TenantProvider;
  readonly uid: string;
  readonly req: IncomingMessage;
  readonly res: ServerResponse;
}

const amrValueSchema = z.string().regex(/^[A-Za-z0-9_.:-]{1,64}$/, "invalid amr value");

export const completeLoginInputSchema = z
  .object({
    /** The person the upstream login resolved to (JIT-provisioned by M3's federation). */
    personId: z.uuid(),
    /** The login method used; the person must have an identity through it. */
    loginMethodId: z.uuid(),
    /**
     * The acr Portvakt asserts for this login: the login method's asserted acr (OIDC), or the
     * requested level the IdP returned (SAML).
     */
    acr: z.string().min(1).max(255),
    /** Authentication methods (RFC 8176 values such as `pwd`, `mfa`, `hwk`). */
    amr: z.array(amrValueSchema).min(1).max(16),
    /**
     * Epoch seconds of the upstream authentication (its `auth_time`), when known; never later than
     * now. Becomes the session login time (`auth_time`, `max_age` checks).
     */
    authTime: z.number().int().positive().optional(),
    /** The upstream SAML session (NameID, SessionIndex), for single logout. */
    upstreamSession: upstreamSessionSchema.optional(),
  })
  .strict();
export type CompleteLoginInput = z.input<typeof completeLoginInputSchema>;

export type InteractionErrorCode =
  "invalid_input" | "interaction_not_found" | "person_not_found" | "login_method_unavailable";

/** A login that cannot complete. The message never contains personal data. */
export class InteractionError extends Error {
  readonly code: InteractionErrorCode;

  constructor(code: InteractionErrorCode, message: string) {
    super(message);
    this.name = "InteractionError";
    this.code = code;
  }
}

export interface InteractionDetails {
  readonly uid: string;
  readonly prompt: string;
  /** Why the prompt is required (oidc-provider and Portvakt check reasons, e.g. `max_age`). */
  readonly reasons: readonly string[];
  readonly clientId: string | undefined;
  /** Authorization request parameters the login flow uses (strings only, as sent). */
  readonly params: {
    readonly acrValues: string | undefined;
    readonly loginHint: string | undefined;
    readonly uiLocales: string | undefined;
    readonly maxAge: number | undefined;
  };
}

const stringParam = (value: unknown, max = 2048): string | undefined =>
  typeof value === "string" && value.length > 0 && value.length <= max ? value : undefined;

/** Loads the pending interaction of this browser (cookie-bound) and checks it is `ctx.uid`. */
export async function loadInteraction(ctx: InteractionContext): Promise<InteractionDetails> {
  let details;
  try {
    details = await ctx.tenantProvider.provider.interactionDetails(ctx.req, ctx.res);
  } catch (error) {
    if (error instanceof errors.SessionNotFound) {
      throw new InteractionError("interaction_not_found", "Interaction not found or expired");
    }
    throw error;
  }
  if (details.uid !== ctx.uid) {
    throw new InteractionError("interaction_not_found", "Interaction not found or expired");
  }
  const { params } = details;
  const maxAge = Number(params.max_age);
  return {
    uid: details.uid,
    prompt: details.prompt.name,
    reasons: [...details.prompt.reasons],
    clientId: stringParam(params.client_id, 128),
    params: {
      acrValues: stringParam(params.acr_values),
      loginHint: stringParam(params.login_hint, 320),
      uiLocales: stringParam(params.ui_locales, 256),
      maxAge:
        params.max_age !== undefined && Number.isSafeInteger(maxAge) && maxAge >= 0
          ? maxAge
          : undefined,
    },
  };
}

export interface InteractionService {
  /**
   * Finishes the login prompt of an interaction: records the authenticated person and how they
   * signed in, and returns the URL to send the browser to (the authorization resume, answered
   * with a 303). The broker session and its login context are created there; consent is
   * implicit.
   *
   * The federation calls this after the upstream login and JIT provisioning; M4 adds the
   * representation step before it. Checks that the person and the login method belong to the
   * tenant, the method is enabled, and the person has an identity through it; otherwise throws
   * {@link InteractionError}.
   */
  completeLogin(
    ctx: InteractionContext,
    input: CompleteLoginInput,
  ): Promise<{ readonly returnTo: string }>;
  /** Ends the interaction without a login: the application receives `access_denied`. */
  abort(ctx: InteractionContext): Promise<{ readonly returnTo: string }>;
}

export function createInteractionService(repos: Repositories): InteractionService {
  return {
    async completeLogin(ctx, input) {
      const parsed = completeLoginInputSchema.safeParse(input);
      if (!parsed.success) {
        throw new InteractionError("invalid_input", "Invalid login result");
      }
      const login = parsed.data;
      await loadInteraction(ctx);
      const tenantId = ctx.tenantProvider.tenant.id;
      const [person, method, identities] = await Promise.all([
        repos.persons.findById(tenantId, login.personId),
        repos.loginMethods.findById(tenantId, login.loginMethodId),
        repos.persons.listIdentities(tenantId, login.personId),
      ]);
      if (person === null) throw new InteractionError("person_not_found", "Person not found");
      if (
        method === null ||
        !method.enabled ||
        !identities.some((identity) => identity.loginMethodId === method.id)
      ) {
        throw new InteractionError("login_method_unavailable", "Login method not available");
      }
      const pending: PendingLogin = {
        loginMethodId: method.id,
        ...(login.upstreamSession === undefined ? {} : { upstream: login.upstreamSession }),
      };
      const returnTo = await ctx.tenantProvider.provider.interactionResult(
        ctx.req,
        ctx.res,
        {
          login: {
            accountId: person.id,
            acr: login.acr,
            amr: [...login.amr],
            remember: true,
            ts: Math.min(login.authTime ?? Number.MAX_SAFE_INTEGER, Math.floor(Date.now() / 1000)),
          },
          [PENDING_LOGIN_RESULT_KEY]: pending,
        },
        { mergeWithLastSubmission: false },
      );
      return { returnTo };
    },
    async abort(ctx) {
      await loadInteraction(ctx);
      const returnTo = await ctx.tenantProvider.provider.interactionResult(
        ctx.req,
        ctx.res,
        { error: "access_denied", error_description: "End-User aborted interaction" },
        { mergeWithLastSubmission: false },
      );
      return { returnTo };
    },
  };
}
