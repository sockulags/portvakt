import { interactionPolicy, type KoaContextWithOIDC } from "oidc-provider";
import { representationChoiceSchema } from "../domain/representation.js";
import type { Tenant } from "../domain/tenant.js";
import { revalidateChoice, type RepresentationRegistry } from "../representation/registry.js";
import type { Repositories } from "../repositories/index.js";
import {
  REPRESENTATION_RESULT_KEY,
  rememberedSessionRecord,
  rememberRepresentation,
  type LoginStateStore,
} from "./login-context.js";

/** The prompt that shows the representation chooser (`prompt=select_account` re-opens it). */
export const REPRESENTATION_PROMPT = "select_account";

export interface RepresentationPromptDependencies {
  readonly tenant: Tenant;
  readonly repos: Repositories;
  readonly registry: RepresentationRegistry;
  readonly loginState: LoginStateStore;
  /**
   * Runs first, once the login prompt has passed: stores the session record of a login that
   * just completed, so an abandoned chooser never leaves the browser session and Portvakt's
   * record of it apart.
   */
  readonly loginPassed: (ctx: KoaContextWithOIDC) => Promise<void>;
}

/**
 * The representation chooser as an oidc-provider prompt (`select_account`), after the login
 * prompt and before consent. Representation is chosen per application grant, never per browser
 * session, so it runs for every authorization of an application whose `representationMode` is
 * not `none` and decides (remembered for the request, stored with the grant login by the
 * consent check):
 *
 * - the choice just made in the chooser (the interaction result), re-validated;
 * - otherwise, unless the person just signed in or the application sent
 *   `prompt=select_account`, the choice of the grant being reused, if it is still valid
 *   (not revoked, inside its validity window, the application still covered; self only while
 *   the mode is `optional`). A grant whose choice no longer holds was already revoked and
 *   replaced by `loadExistingGrant` (provider.ts), so the person is asked again;
 * - otherwise the chooser, when there is something to choose: at least one party, or the mode
 *   is `required` (with no party the login UI shows `no_representation_available`). With mode
 *   `optional` and no party the person simply acts for themselves.
 *
 * Another application's choice in the same browser session is never looked at.
 */
export function representationPrompt(
  deps: RepresentationPromptDependencies,
): interactionPolicy.Prompt {
  const { tenant, repos, registry, loginState, loginPassed } = deps;

  const decide = async (ctx: KoaContextWithOIDC): Promise<boolean> => {
    const { session, client, result, grant } = ctx.oidc;
    const personId = session?.accountId;
    if (personId === undefined || client === undefined)
      return interactionPolicy.Check.NO_NEED_TO_PROMPT;
    await loginPassed(ctx);
    // The current login: its method decides whether a pin-addressed right counts.
    const agent = { personId, loginMethodId: rememberedSessionRecord(ctx)?.loginMethodId };
    const application = await repos.applications.findEnabledByClientId(tenant.id, client.clientId);
    if (application === null || application.representationMode === "none") {
      rememberRepresentation(ctx, { choice: undefined, selected: false });
      return interactionPolicy.Check.NO_NEED_TO_PROMPT;
    }
    const now = new Date();

    const chosen = representationChoiceSchema.safeParse(result?.[REPRESENTATION_RESULT_KEY]);
    if (chosen.success) {
      const valid = await revalidateChoice(registry, tenant, agent, application, chosen.data, now);
      if (valid !== null) {
        rememberRepresentation(ctx, { choice: valid, selected: true });
        return interactionPolicy.Check.NO_NEED_TO_PROMPT;
      }
      return interactionPolicy.Check.REQUEST_PROMPT;
    }

    const explicit = ctx.oidc.prompts.has(REPRESENTATION_PROMPT);
    const freshLogin = result?.login !== undefined;
    if (!explicit && !freshLogin && grant?.jti !== undefined) {
      const previous = await loginState.findGrantLogin(grant.jti);
      if (
        previous?.representation !== undefined &&
        previous.personId === personId &&
        previous.clientId === client.clientId
      ) {
        const valid = await revalidateChoice(
          registry,
          tenant,
          agent,
          application,
          previous.representation,
          now,
        );
        if (valid !== null) {
          rememberRepresentation(ctx, { choice: valid, selected: false });
          return interactionPolicy.Check.NO_NEED_TO_PROMPT;
        }
      }
    }

    const options = await registry.options(tenant, agent, application.id, now);
    if (options.length === 0 && application.representationMode === "optional") {
      rememberRepresentation(ctx, { choice: undefined, selected: false });
      return interactionPolicy.Check.NO_NEED_TO_PROMPT;
    }
    return interactionPolicy.Check.REQUEST_PROMPT;
  };

  const prompt = new interactionPolicy.Prompt(
    { name: REPRESENTATION_PROMPT, requestable: true },
    new interactionPolicy.Check(
      "representation_required",
      "the End-User must choose whom to act for",
      decide,
    ),
  );
  // `prompt=select_account` is handled by the check above (it respects the application's mode),
  // not by oidc-provider's generic "was it requested" check.
  prompt.checks.remove(`${REPRESENTATION_PROMPT}_prompt`);
  return prompt;
}
