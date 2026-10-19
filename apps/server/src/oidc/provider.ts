import { EventEmitter } from "node:events";
import type { IncomingMessage, ServerResponse } from "node:http";
import Provider, {
  errors,
  interactionPolicy,
  type Account,
  type ClientMetadata,
  type Configuration,
  type FindAccount,
  type Grant,
  type KoaContextWithOIDC,
  type ResourceServer,
} from "oidc-provider";
import type { AuditLog } from "../audit/audit-log.js";
import type { AuditDetails } from "../audit/catalogue.js";
import type { Config } from "../config/index.js";
import type { Db } from "../db/database.js";
import type { AuditEvent } from "../domain/audit.js";
import type { LoginMethod } from "../domain/login-method.js";
import { representationChoiceSchema, type RepresentationChoice } from "../domain/representation.js";
import type { Tenant } from "../domain/tenant.js";
import type { LoadedKeys } from "../keys/key-cache.js";
import type { Logger } from "../logging/logger.js";
import type { OutboundGuard } from "../net/outbound.js";
import { revalidateChoice, type RepresentationRegistry } from "../representation/registry.js";
import type { AuditRepository } from "../repositories/audit.js";
import type { Repositories } from "../repositories/index.js";
import { parseAcrValues, type AcrRanking } from "./acr.js";
import { createAdapterFactory } from "./adapter.js";
import { CLAIMS_BY_SCOPE, ClaimsService } from "./claims.js";
import { clientIdFromResource, clientMetadataFor, resourceIndicatorFor } from "./clients.js";
import {
  LoginStateStore,
  PENDING_LOGIN_RESULT_KEY,
  pendingLoginSchema,
  REPRESENTATION_RESULT_KEY,
  rememberedLoginContext,
  rememberedRepresentation,
  rememberedSessionRecord,
  rememberLoginContext,
  rememberSessionRecord,
  type LoginContext,
  type SessionRecord,
} from "./login-context.js";
import type { ProviderPages } from "./pages.js";
import { representationPrompt } from "./representation-prompt.js";
import type { SessionPolicyService } from "./session-policy.js";

const SIGNING_ALG = "ES256";
const AUTHORIZATION_CODE_TTL_SECONDS = 60;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const epochNow = (): number => Math.floor(Date.now() / 1000);

/**
 * Login prompt reasons after which the upstream IdP must authenticate the person again
 * (`prompt=login` upstream): its own SSO session would otherwise defeat the policy. A first
 * login (`no_session`, `session_unknown`) may reuse the upstream session.
 */
export const FRESH_LOGIN_REASONS: ReadonlySet<string> = new Set([
  "login_prompt",
  "max_age",
  "session_expired",
  "session_idle",
  "sso_not_allowed",
  "acr_not_met",
]);

/** RP-initiated logout ended a broker session whose latest login was upstream SAML. */
export interface UpstreamLogoutInput {
  readonly tenant: Tenant;
  readonly record: SessionRecord;
  /** Where oidc-provider sends the browser after the logout (post_logout_redirect_uri). */
  readonly returnTo: string;
}

export interface ProviderDependencies {
  readonly config: Config;
  /** The runtime pool: login state changes that commit together with their audit events. */
  readonly db: Db;
  readonly repos: Repositories;
  readonly auditLog: AuditLog;
  /** Representation sources of the tenants (the chooser, `rep`, re-checks at refresh). */
  readonly representation: RepresentationRegistry;
  readonly logger: Logger;
  readonly sessionPolicy: SessionPolicyService;
  readonly acrRanking: AcrRanking;
  readonly pages: ProviderPages;
  /**
   * Single logout towards the upstream IdP after the local logout: returns where to send the
   * browser instead (the IdP's SLO endpoint, which returns to `returnTo`), or `undefined` to
   * keep oidc-provider's redirect. Must never throw: the local logout has already happened.
   */
  readonly upstreamLogout?: (input: UpstreamLogoutInput) => Promise<string | undefined>;
  /** Fetches of client `jwks_uri` documents go through the outbound guard (SSRF). */
  readonly outbound?: OutboundGuard;
}

/** What a tenant's provider is built from (loaded by the registry). */
export interface TenantBuildInput {
  readonly tenant: Tenant;
  readonly keys: LoadedKeys;
  /** Tenant, application and login method configuration the provider is built with. */
  readonly fingerprint: string;
  readonly loginMethods: readonly LoginMethod[];
}

/** A built provider for one tenant, as cached by the registry. */
export interface TenantProvider {
  readonly tenant: Tenant;
  readonly issuer: string;
  /** Path of the issuer (`/t/{slug}`); everything of the tenant lives below it. */
  readonly basePath: string;
  readonly provider: Provider;
  readonly loginState: LoginStateStore;
  /** Signing key set the provider was built with. */
  readonly keysVersion: string;
  /** Every acr value a login of this tenant can assert (the provider's `acrValues`). */
  readonly acrValues: readonly string[];
  /** Tenant, application and login method configuration the provider was built with. */
  readonly fingerprint: string;
  /** Hands a request below `basePath` (already stripped of it) to the provider. */
  readonly handle: (req: IncomingMessage, res: ServerResponse) => void;
}

/** The grant login a session record establishes for `clientId`. */
function loginFromRecord(
  record: SessionRecord,
  clientId: string,
  sessionUid: string,
): LoginContext {
  return {
    personId: record.personId,
    loginMethodId: record.loginMethodId,
    loginMethodKind: record.loginMethodKind,
    acr: record.acr,
    amr: record.amr,
    authTime: record.authTime,
    sessionExpiresAt: record.sessionExpiresAt,
    idleSeconds: record.idleSeconds,
    clientId,
    sessionUid,
  };
}

/**
 * Builds the oidc-provider instance for one tenant: issuer `{PUBLIC_URL}/t/{slug}`, storage in
 * `oidc_payloads` scoped to the tenant, clients from the applications enabled for the tenant,
 * and the shared signing keys. Secure defaults: authorization code flow with PKCE (S256) for
 * every client, refresh token rotation, client_credentials, no implicit or hybrid flows, no
 * development interactions, no claims parameter, no request objects.
 */
export function buildTenantProvider(
  input: TenantBuildInput,
  deps: ProviderDependencies,
): TenantProvider {
  const { tenant, keys, fingerprint } = input;
  const { config, db, repos, logger, sessionPolicy, acrRanking, pages, auditLog } = deps;
  const registry = deps.representation;
  const basePath = `/t/${tenant.slug}`;
  const issuer = `${config.publicUrl}${basePath}`;
  const issuerPath = new URL(issuer).pathname;
  const loginState = new LoginStateStore(tenant.id, db);
  const claims = new ClaimsService(repos);
  const tokens = config.tokens;
  const log = logger.child({ tenant: tenant.slug });
  // Every value a login can assert: the ranking, the tenant's login methods' acr values and
  // the levels SAML methods request (a SAML login asserts the level the IdP returned).
  const acrValues = [
    ...new Set([
      ...acrRanking.values,
      ...input.loginMethods.flatMap((method) =>
        method.protocol === "saml"
          ? [method.assertedAcr, ...method.saml.requestedLoa]
          : [method.assertedAcr],
      ),
    ]),
  ];

  /** The session record of the request's broker session, cached for the rest of the request. */
  async function sessionRecordFor(
    ctx: KoaContextWithOIDC,
    sessionUid: string | undefined,
  ): Promise<SessionRecord | undefined> {
    const remembered = rememberedSessionRecord(ctx);
    if (remembered !== undefined) return remembered;
    const found = await loginState.findSession(sessionUid);
    if (found !== undefined) rememberSessionRecord(ctx, found);
    return found;
  }

  /** The login of a token's grant, cached for the rest of the request. */
  async function grantLoginFor(
    ctx: KoaContextWithOIDC,
    grantId: string | undefined,
  ): Promise<LoginContext | undefined> {
    const remembered = rememberedLoginContext(ctx);
    if (remembered !== undefined) return remembered;
    const found = await loginState.findGrantLogin(grantId);
    if (found !== undefined) rememberLoginContext(ctx, found);
    return found;
  }

  const resolveClient = async (clientId: string): Promise<ClientMetadata | undefined> => {
    const application = await repos.applications.findEnabledByClientId(tenant.id, clientId);
    if (application === null) return undefined;
    const secret =
      application.clientAuth.method === "private_key_jwt"
        ? null
        : await repos.applications.getClientSecret(application.id);
    return clientMetadataFor(application, secret, tenant.slug);
  };

  const findAccount: FindAccount = async (ctx, sub, token) => {
    if (!UUID.test(sub)) return undefined;
    const person = await repos.persons.findById(tenant.id, sub);
    if (person === null) return undefined;
    // At the token endpoint (a code or refresh token) the grant's login must still be known and
    // live: claims and lifetimes follow it, so without it the grant fails. During authorization
    // the login prompt checks the session record instead (see `policy` below).
    let login: LoginContext | undefined;
    if (token !== undefined) {
      const presented = token as { grantId?: string; kind?: string; consumed?: unknown };
      const refresh = presented.kind === "RefreshToken";
      const clientId = ctx.oidc.client?.clientId;
      login = await grantLoginFor(ctx, presented.grantId);
      if (login === undefined || login.personId !== sub || login.sessionExpiresAt <= epochNow()) {
        if (clientId !== undefined) await tokenDenied(refresh, clientId, sub, "session_ended");
        return undefined;
      }
      // The representation the grant was issued with must still hold (not revoked, inside its
      // validity window, the application still covered): otherwise the grant is revoked.
      const denial =
        clientId === undefined ? undefined : await representationDenial(clientId, login);
      if (denial !== undefined && clientId !== undefined && presented.grantId !== undefined) {
        await revokeGrant(presented.grantId, clientId, sub, "representation_invalid");
        await tokenDenied(refresh, clientId, sub, denial);
        return undefined;
      }
      // The ID token (and a rotated refresh token) carries the grant login's acr, amr and
      // auth_time, exactly like the access token: never values of a later login in the same
      // browser session.
      Object.assign(token, { acr: login.acr, amr: [...login.amr], authTime: login.authTime });
      if (refresh && presented.consumed === undefined) {
        // A refresh is activity: the session's idle timeout starts again.
        await loginState.touchSession(login.sessionUid, sub, login.authTime, epochNow());
      }
    }
    const account: Account = {
      accountId: sub,
      claims: async (use, scope) => {
        const context = login ?? rememberedLoginContext(ctx);
        if (context === undefined || context.personId !== sub) {
          throw new errors.InvalidGrant("the session of this grant has ended");
        }
        const audience = ctx.oidc.client?.clientId;
        if (audience === undefined) throw new errors.InvalidClient();
        return {
          sub,
          ...(await claims.claimsFor({
            tenant,
            personId: sub,
            login: context,
            audienceClientId: audience,
            scopes: new Set(scope.split(" ")),
            target: use === "userinfo" ? "userinfo" : "id_token",
          })),
        };
      },
    };
    return account;
  };

  /**
   * Why the grant login's representation no longer holds for the application, if it does not:
   * `representation_invalid` (the party's right ended) or `representation_required` (the
   * application now requires a party and the grant has none).
   */
  async function representationDenial(
    clientId: string,
    login: LoginContext,
  ): Promise<AuditDetails<"token.refresh_denied">["reason"] | undefined> {
    const application = await repos.applications.findEnabledByClientId(tenant.id, clientId);
    if (application === null || application.representationMode === "none") return undefined;
    const choice = login.representation;
    if (choice === undefined) {
      return application.representationMode === "required" ? "representation_required" : undefined;
    }
    const agent = { personId: login.personId, loginMethodId: login.loginMethodId };
    const valid = await revalidateChoice(registry, tenant, agent, application, choice);
    if (valid !== null) return undefined;
    return choice.type === "self" ? "representation_required" : "representation_invalid";
  }

  /** A refresh (`token.refresh_denied`) or code exchange (`token.exchange_denied`) refused. */
  async function tokenDenied(
    refresh: boolean,
    clientId: string,
    personId: string,
    reason: AuditDetails<"token.refresh_denied">["reason"],
  ): Promise<void> {
    await auditLog.record({
      action: refresh ? "token.refresh_denied" : "token.exchange_denied",
      tenantId: tenant.id,
      actor: { type: "application", id: clientId },
      subject: { type: "person", id: personId },
      details: { clientId, reason },
    });
  }

  /** Revokes an application's grant with its tokens; the audit event commits with it. */
  async function revokeGrant(
    grantId: string,
    clientId: string,
    personId: string,
    reason: AuditDetails<"grant.revoked">["reason"],
  ): Promise<void> {
    const events = await loginState.revokeGrantAudited(grantId, async (audit) => [
      await auditLog.recordIn(audit, {
        action: "grant.revoked",
        tenantId: tenant.id,
        actor: { type: "system", id: null },
        subject: { type: "person", id: personId },
        details: { clientId, reason },
      }),
    ]);
    auditLog.forward(events);
  }

  const extraTokenClaims: NonNullable<Configuration["extraTokenClaims"]> = async (ctx, token) => {
    if (token.kind === "ClientCredentials") return { tid: tenant.slug };
    const accessToken = token;
    const audience = typeof accessToken.aud === "string" ? accessToken.aud : undefined;
    if (accessToken.accountId === undefined || audience === undefined) {
      return { tid: tenant.slug };
    }
    const login = await grantLoginFor(ctx, accessToken.grantId);
    if (login === undefined || login.personId !== accessToken.accountId) {
      throw new errors.InvalidGrant("the session of this grant has ended");
    }
    return claims.claimsFor({
      tenant,
      personId: accessToken.accountId,
      login,
      audienceClientId: audience,
      scopes: new Set(accessToken.scope?.split(" ") ?? []),
      target: "access_token",
    });
  };

  const getResourceServerInfo = async (
    ctx: KoaContextWithOIDC,
    resourceIndicator: string,
    client: { clientId: string },
  ): Promise<ResourceServer> => {
    const target = clientIdFromResource(resourceIndicator);
    if (target === null) throw new errors.InvalidTarget("unknown resource indicator");
    if (target !== client.clientId) {
      // Only service-to-service tokens may name another application, and only one that is
      // enabled in the same tenant. User tokens are always for the requesting application.
      const grantType = (ctx.oidc.params as { grant_type?: unknown } | undefined)?.grant_type;
      if (ctx.oidc.route !== "token" || grantType !== "client_credentials") {
        throw new errors.InvalidTarget("the resource must be the requesting application");
      }
      const application = await repos.applications.findEnabledByClientId(tenant.id, target);
      if (application === null) {
        throw new errors.InvalidTarget("the resource is not an application of this tenant");
      }
    }
    return {
      audience: target,
      scope: "",
      accessTokenFormat: "jwt",
      accessTokenTTL: tokens.accessTokenSeconds,
      jwt: { sign: { alg: SIGNING_ALG, kid: keys.activeKid } },
    };
  };

  /** The session record a login that just completed establishes (resume after `completeLogin`). */
  async function recordForFreshLogin(
    ctx: KoaContextWithOIDC,
    clientId: string,
  ): Promise<SessionRecord> {
    const { session, result } = ctx.oidc;
    const pending = pendingLoginSchema.safeParse(result?.[PENDING_LOGIN_RESULT_KEY]);
    if (!pending.success || session?.accountId === undefined || typeof session.acr !== "string") {
      throw new errors.AccessDenied("the login did not complete");
    }
    const policyOf = await sessionPolicy.forLoginMethod(tenant.id, pending.data.loginMethodId);
    if (policyOf === null) throw new errors.AccessDenied("the login method is not available");
    const now = epochNow();
    const authTime = session.authTime() ?? now;
    // The session lasts maxAge from this login at Portvakt; auth_time may be older (upstream SSO).
    const sessionExpiresAt = now + policyOf.maxAgeSeconds;
    const previous = await loginState.findSession(session.uid);
    // Kept past the login's end (SESSION_TTL longer), so an expired session is recognised as
    // one and its next login is a fresh upstream login, not a first visit the IdP may answer
    // from its own session.
    const retained = sessionExpiresAt + tokens.sessionSeconds;
    const retainUntil =
      previous?.personId === session.accountId
        ? Math.max(previous.retainUntil, retained)
        : retained;
    return {
      personId: session.accountId,
      loginMethodId: pending.data.loginMethodId,
      loginMethodKind: policyOf.loginMethodKind,
      acr: session.acr,
      amr: session.amr ?? [],
      authTime,
      sessionExpiresAt,
      retainUntil,
      idleSeconds: policyOf.idleSeconds,
      allowSso: policyOf.allowSso,
      clientId,
      lastActivityAt: now,
      ...(pending.data.upstream === undefined ? {} : { upstream: pending.data.upstream }),
    };
  }

  /**
   * Implicit consent (first-party applications): the grant always covers the requested scopes,
   * which oidc-provider has already limited to the scopes the client may request. This runs
   * before the login prompt checks, so it only resolves the session record and the login the
   * grant is for; they are stored once the checks passed (`portvakt_session_activity` below).
   */
  const loadExistingGrant = async (ctx: KoaContextWithOIDC): Promise<Grant | undefined> => {
    const { session, client, result } = ctx.oidc;
    if (session === undefined || client === undefined || session.accountId === undefined) {
      return undefined;
    }
    let record: SessionRecord | undefined;
    if (ctx.oidc.route === "resume" && result?.login !== undefined) {
      record = await recordForFreshLogin(ctx, client.clientId);
      rememberSessionRecord(ctx, record);
    } else {
      record = await sessionRecordFor(ctx, session.uid);
    }
    if (record !== undefined && usableFor(record, session.accountId, client.clientId)) {
      // The grant expires with the session's real end, so its login is known before it is saved.
      // A record the login prompt will refuse is not used: the existing grant keeps its expiry.
      rememberLoginContext(ctx, loginFromRecord(record, client.clientId, session.uid));
    }
    const grantId =
      (result?.consent as { grantId?: string } | undefined)?.grantId ??
      session.grantIdFor(client.clientId);
    let grant = grantId === undefined ? undefined : await ctx.oidc.provider.Grant.find(grantId);
    if (grant !== undefined && grant.accountId !== session.accountId) grant = undefined;
    // A grant at (or, with clock skew against the database, past) its end would be saved with no
    // time left: it is over, so the authorization starts a new one.
    if (grant?.exp !== undefined && grant.exp <= epochNow()) grant = undefined;
    if (grant?.jti !== undefined && (await representationEnds(ctx, grant.jti))) grant = undefined;
    grant ??= new ctx.oidc.provider.Grant({
      accountId: session.accountId,
      clientId: client.clientId,
    });
    grant.addOIDCScope([...ctx.oidc.requestParamOIDCScopes].join(" "));
    await grant.save();
    return grant;
  };

  /**
   * Right after a login (the resume that completed it) the login prompt has passed: the session
   * record is stored now, before the representation chooser or consent, so it always matches
   * oidc-provider's session (whose acr and login time the login just replaced), even when the
   * person abandons the chooser.
   */
  async function persistFreshLogin(ctx: KoaContextWithOIDC): Promise<void> {
    const { session, result } = ctx.oidc;
    if (ctx.oidc.route !== "resume" || result?.login === undefined) return;
    const record = rememberedSessionRecord(ctx);
    if (session?.accountId === undefined || record?.personId !== session.accountId) return;
    await loginState.saveSession(session.uid, { ...record, lastActivityAt: epochNow() });
  }

  /** Two representations are the same (no stored representation: the person acted as self). */
  const sameRepresentation = (
    a: RepresentationChoice | undefined,
    b: RepresentationChoice,
  ): boolean =>
    a === undefined || a.type === "self"
      ? b.type === "self"
      : b.type === "party" && a.partyId === b.partyId;

  /**
   * Representation is chosen per grant, so a grant ends with its representation: when the person
   * just chose another one than the grant was issued with (`representation_changed`), or the
   * grant's representation no longer holds (`representation_invalid`, audited as
   * `representation.denied` too). The grant and its tokens are revoked and the authorization
   * continues with a new grant, so earlier refresh tokens never switch to another
   * representation. Returns whether the grant was revoked.
   */
  async function representationEnds(ctx: KoaContextWithOIDC, grantId: string): Promise<boolean> {
    const { session, client, result } = ctx.oidc;
    const personId = session?.accountId;
    if (personId === undefined || client === undefined) return false;
    const previous = await loginState.findGrantLogin(grantId);
    if (previous?.personId !== personId || previous.clientId !== client.clientId) return false;
    const chosen = representationChoiceSchema.safeParse(result?.[REPRESENTATION_RESULT_KEY]);
    if (chosen.success) {
      if (sameRepresentation(previous.representation, chosen.data)) return false;
      await revokeGrant(grantId, client.clientId, personId, "representation_changed");
      return true;
    }
    if (previous.representation === undefined) return false;
    if ((await representationDenial(client.clientId, previous)) === undefined) return false;
    await auditLog.record({
      action: "representation.denied",
      tenantId: tenant.id,
      actor: { type: "person", id: personId },
      subject: { type: "person", id: personId },
      details: {
        clientId: client.clientId,
        reason: "no_longer_valid",
        ...(previous.representation.type === "party"
          ? { partyId: previous.representation.partyId }
          : {}),
      },
    });
    await revokeGrant(grantId, client.clientId, personId, "representation_invalid");
    return true;
  }

  /** Whether the session's latest login may serve an authorization of `clientId` right now. */
  const usableFor = (record: SessionRecord, accountId: string, clientId: string): boolean => {
    const now = epochNow();
    return (
      record.personId === accountId &&
      record.sessionExpiresAt > now &&
      now - record.lastActivityAt <= record.idleSeconds &&
      (record.allowSso || record.clientId === clientId)
    );
  };

  /** Remaining seconds of the broker session, if the request knows it. */
  const remainingSession = (end: number | undefined, fallbackEnd: number): number =>
    Math.max(1, (end ?? fallbackEnd) - epochNow());

  /**
   * The default prompts (login, consent) plus the session policy (docs/plan.md, "Session policy
   * semantics"). Each check is skipped right after a login (`result.login`): that login is the
   * fresh one the check would ask for.
   */
  const sessionCheck = (
    reason: string,
    description: string,
    fails: (record: SessionRecord, ctx: KoaContextWithOIDC, now: number) => boolean,
  ): interactionPolicy.Check =>
    new interactionPolicy.Check(reason, description, async (ctx) => {
      const { session, result } = ctx.oidc;
      if (session?.accountId === undefined || result?.login !== undefined) {
        return interactionPolicy.Check.NO_NEED_TO_PROMPT;
      }
      const record = await sessionRecordFor(ctx, session.uid);
      if (record === undefined || record.personId !== session.accountId) {
        return reason === "session_unknown";
      }
      return fails(record, ctx, epochNow());
    });

  const policy = interactionPolicy.base();
  const loginChecks = policy.get("login")?.checks;
  const consentChecks = policy.get("consent")?.checks;
  if (loginChecks === undefined || consentChecks === undefined) {
    throw new Error("oidc-provider base policy without login or consent prompt");
  }
  // The representation chooser: after the login, before consent (where the grant login is saved).
  policy.add(
    representationPrompt({ tenant, repos, registry, loginState, loginPassed: persistFreshLogin }),
    policy.findIndex((prompt) => prompt.name === "consent"),
  );
  loginChecks.add(
    sessionCheck("session_unknown", "the broker session must be established again", () => false),
  );
  loginChecks.add(
    sessionCheck(
      "session_expired",
      "the broker session reached its maximum age",
      (record, _ctx, now) => record.sessionExpiresAt <= now,
    ),
  );
  loginChecks.add(
    sessionCheck(
      "session_idle",
      "the broker session was idle for too long",
      (record, _ctx, now) => now - record.lastActivityAt > record.idleSeconds,
    ),
  );
  loginChecks.add(
    sessionCheck(
      "sso_not_allowed",
      "the login method requires a fresh login for every application",
      (record, ctx) => !record.allowSso && record.clientId !== ctx.oidc.client?.clientId,
    ),
  );
  loginChecks.add(
    sessionCheck(
      "acr_not_met",
      "the requested assurance level requires a new login",
      (record, ctx) =>
        !acrRanking.satisfiesAny(record.acr, parseAcrValues(ctx.oidc.params?.acr_values)),
    ),
  );
  // Runs only once the login prompt is satisfied (prompts are evaluated in order), just before
  // the authorization response: the session's activity and the grant's login are stored here.
  consentChecks.add(
    new interactionPolicy.Check(
      "portvakt_session_activity",
      "records the session activity",
      async (ctx) => {
        const { session, grant, client, result } = ctx.oidc;
        const record = rememberedSessionRecord(ctx);
        const remembered = rememberedLoginContext(ctx);
        if (
          session?.accountId === undefined ||
          record?.personId !== session.accountId ||
          remembered === undefined ||
          grant?.jti === undefined ||
          client === undefined
        ) {
          throw new errors.AccessDenied("the broker session must be established again");
        }
        const decision = rememberedRepresentation(ctx);
        const login: LoginContext = {
          ...remembered,
          ...(decision?.choice === undefined ? {} : { representation: decision.choice }),
        };
        const pending = pendingLoginSchema.safeParse(result?.[PENDING_LOGIN_RESULT_KEY]);
        const stepUp =
          result?.login !== undefined && pending.success ? pending.data.stepUp : undefined;
        await loginState.saveSession(session.uid, { ...record, lastActivityAt: epochNow() });
        if (decision?.selected !== true && stepUp === undefined) {
          await loginState.saveGrantLogin(grant.jti, login);
          return interactionPolicy.Check.NO_NEED_TO_PROMPT;
        }
        // What this grant login commits (a representation choice, a step-up) is audited with it.
        const events = await loginState.saveGrantLoginAudited(grant.jti, login, (audit) =>
          grantAudits(audit, client.clientId, login, decision?.selected === true, stepUp),
        );
        auditLog.forward(events);
        return interactionPolicy.Check.NO_NEED_TO_PROMPT;
      },
    ),
  );

  /** The success events a grant login commits: the chosen representation, a step-up. */
  async function grantAudits(
    audit: AuditRepository,
    clientId: string,
    login: LoginContext,
    selected: boolean,
    stepUp: { readonly previousAcr?: string | undefined } | undefined,
  ): Promise<AuditEvent[]> {
    const events: AuditEvent[] = [];
    const person = { type: "person", id: login.personId } as const;
    const choice = login.representation;
    if (selected && choice !== undefined) {
      events.push(
        await auditLog.recordIn(audit, {
          action: "representation.selected",
          tenantId: tenant.id,
          actor: person,
          subject: choice.type === "party" ? { type: "party", id: choice.partyId } : person,
          details:
            choice.type === "party"
              ? {
                  clientId,
                  choice: "party",
                  partyId: choice.partyId,
                  partyType: choice.partyType,
                  sources: [...choice.sources],
                }
              : { clientId, choice: "self" },
        }),
      );
    }
    if (stepUp !== undefined) {
      events.push(
        await auditLog.recordIn(audit, {
          action: "step_up.success",
          tenantId: tenant.id,
          actor: person,
          subject: person,
          details: {
            clientId,
            loginMethodId: login.loginMethodId,
            acr: login.acr,
            ...(stepUp.previousAcr === undefined ? {} : { previousAcr: stepUp.previousAcr }),
          },
        }),
      );
    }
    return events;
  }

  const configuration: Configuration = {
    adapter: createAdapterFactory({
      tenantId: tenant.id,
      payloads: repos.oidcPayloads,
      resolveClient,
    }),
    jwks: { keys: keys.jwks.keys.map((key) => ({ ...key })) },
    cookies: {
      keys: [...config.cookieKeys],
      names: {
        session: "_pv_session",
        interaction: "_pv_interaction",
        resume: "_pv_resume",
      },
      // Lax: sent on the top-level navigations of the code flow (authorization request, resume,
      // RP-initiated logout), never on cross-site subrequests. The session cookie is scoped to
      // the tenant's path, so a browser holds an independent session per tenant; the short-lived
      // interaction and resume cookies get oidc-provider's narrower paths below it.
      long: { httpOnly: true, sameSite: "lax", secure: config.isProduction, path: issuerPath },
      short: { httpOnly: true, sameSite: "lax", secure: config.isProduction },
    },
    clientAuthMethods: ["client_secret_basic", "client_secret_post", "private_key_jwt"],
    clientDefaults: {
      grant_types: ["authorization_code", "refresh_token", "client_credentials"],
      response_types: ["code"],
      token_endpoint_auth_method: "client_secret_basic",
      id_token_signed_response_alg: SIGNING_ALG,
    },
    clientBasedCORS: () => false,
    responseTypes: ["code"],
    scopes: ["openid"],
    claims: { ...CLAIMS_BY_SCOPE, sid: null, iss: null },
    acrValues,
    conformIdTokenClaims: true,
    pkce: { required: () => true },
    enabledJWA: {
      idTokenSigningAlgValues: [SIGNING_ALG],
      clientAuthSigningAlgValues: ["ES256", "ES384", "PS256", "RS256", "EdDSA", "Ed25519"],
    },
    features: {
      devInteractions: { enabled: false },
      claimsParameter: { enabled: false },
      requestObjects: { enabled: false },
      dPoP: { enabled: false },
      clientCredentials: { enabled: true },
      // Userinfo only accepts access tokens without an audience, and every access token here is
      // a JWT for one application (fixed decision); RPs read the claims from the ID token.
      userinfo: { enabled: false },
      introspection: {
        enabled: true,
        // Only the client a token was issued to may introspect it (the storage is tenant-scoped,
        // so a token of another tenant is never even found).
        allowedPolicy: (_ctx, client, token) => token.clientId === client.clientId,
      },
      revocation: {
        enabled: true,
        allowedPolicy: (_ctx, client, token) => {
          if (token.clientId !== client.clientId) {
            throw new errors.InvalidRequest(
              "client is not authorized to revoke the presented token",
            );
          }
          return true;
        },
      },
      rpInitiatedLogout: {
        enabled: true,
        logoutSource: (ctx, form) => pages.logoutSource(ctx, form),
        postLogoutSuccessSource: (ctx) => pages.postLogoutSuccessSource(ctx),
      },
      resourceIndicators: {
        enabled: true,
        // The requesting application itself, so every access token is a JWT for it.
        defaultResource: (_ctx, client) => resourceIndicatorFor(client.clientId),
        useGrantedResource: () => true,
        getResourceServerInfo,
      },
    },
    ...(deps.outbound === undefined
      ? {}
      : {
          // Client jwks_uri: the shared outbound guard instead of oidc-provider's dispatcher.
          fetch: (input: string | URL | Request, init?: RequestInit) => {
            if (input instanceof Request) throw new TypeError("unexpected Request input");
            const { dispatcher: _dispatcher, ...rest } = (init ?? {}) as RequestInit & {
              dispatcher?: unknown;
            };
            void _dispatcher;
            return deps.outbound!.fetch(input, { ...rest, maxBytes: 256 * 1024 });
          },
        }),
    findAccount,
    extraTokenClaims,
    loadExistingGrant,
    // Refresh tokens for the code flow without offline_access: they stay bound to the broker
    // session (expiresWithSession) and end with it. Rotation issues the successors.
    issueRefreshToken: (_ctx, client, code) =>
      client.grantTypeAllowed("refresh_token") && code.kind === "AuthorizationCode",
    rotateRefreshToken: true,
    interactions: {
      policy,
      url: (_ctx, interaction) => `${issuerPath}/interaction/${interaction.uid}`,
    },
    ttl: {
      AccessToken: tokens.accessTokenSeconds,
      ClientCredentials: tokens.accessTokenSeconds,
      IdToken: tokens.idTokenSeconds,
      AuthorizationCode: AUTHORIZATION_CODE_TTL_SECONDS,
      Interaction: tokens.interactionSeconds,
      RefreshToken: (ctx) => sessionPolicy.refreshTokenTtl(rememberedLoginContext(ctx), epochNow()),
      // The oidc-provider session outlives each login only as long as one of its grants may.
      // Without a resolved record, an existing session keeps its expiry (never extended).
      Session: (ctx, session) =>
        remainingSession(
          rememberedSessionRecord(ctx)?.retainUntil,
          session.exp ?? (session.loginTs ?? epochNow()) + tokens.sessionSeconds,
        ),
      Grant: (ctx, grant) =>
        remainingSession(
          rememberedLoginContext(ctx)?.sessionExpiresAt,
          grant.exp ?? epochNow() + tokens.sessionSeconds,
        ),
    },
    renderError: (ctx, out) => {
      pages.renderError(ctx, out);
    },
  };

  const provider = new Provider(issuer, configuration);
  // Host, protocol and client IP are pinned in oidc/routes.ts before a request gets here (from
  // PUBLIC_URL and Express's TRUST_PROXY-resolved req.ip), so the provider reads the forwarded
  // headers set there, never the client's.
  provider.proxy = true;

  // Discovery and JWKS may be cached briefly: JWKS lists the next key well before it signs, and
  // verifiers refetch on an unknown kid.
  provider.use(async (ctx, next) => {
    await next();
    const route = (ctx as { oidc?: { route?: string } }).oidc?.route;
    if (ctx.status === 200 && (route === "discovery" || route === "jwks")) {
      ctx.set("Cache-Control", route === "jwks" ? "public, max-age=60" : "public, max-age=300");
    }
  });

  // Every token endpoint success: `token.issued` (grant type and client; never a token value),
  // written before the response is sent.
  provider.use(async (ctx, next) => {
    await next();
    const oidc = (ctx as { oidc?: KoaContextWithOIDC["oidc"] }).oidc;
    if (oidc?.route !== "token" || ctx.status !== 200) return;
    const grantType = (oidc.params as { grant_type?: unknown } | undefined)?.grant_type;
    const clientId = oidc.client?.clientId;
    if (
      clientId === undefined ||
      (grantType !== "authorization_code" &&
        grantType !== "refresh_token" &&
        grantType !== "client_credentials")
    ) {
      return;
    }
    const personId = oidc.account?.accountId;
    await auditLog.record({
      action: "token.issued",
      tenantId: tenant.id,
      actor: { type: "application", id: clientId },
      subject: personId === undefined ? null : { type: "person", id: personId },
      details: { clientId, grantType },
    });
  });

  // RP-initiated logout (the confirmation form): audited as `session.logout` (`rp`), the whole
  // session (`logout=yes`) or only the application's part. Not the session switch during a
  // login, whose redirect resumes an authorization.
  provider.use(async (ctx, next) => {
    await next();
    const oidc = (ctx as { oidc?: KoaContextWithOIDC["oidc"] }).oidc;
    if (oidc?.route !== "end_session_confirm" || ctx.status !== 303) return;
    const personId = oidc.session?.accountId;
    if (personId === undefined || ctx.response.get("Location").startsWith(`${issuer}/auth`)) return;
    const whole = (oidc.params as { logout?: unknown } | undefined)?.logout !== undefined;
    const clientId = oidc.client?.clientId;
    await auditLog.record({
      action: "session.logout",
      tenantId: tenant.id,
      actor: { type: "person", id: personId },
      subject: { type: "person", id: personId },
      details: {
        initiator: "rp",
        scope: whole ? "session" : "application",
        ...(clientId === undefined ? {} : { clientId }),
      },
    });
  });

  // RP-initiated logout of a whole session (`logout=yes`) whose latest login was upstream SAML:
  // after oidc-provider ended the session locally, the browser is sent through the IdP's single
  // logout and back. Not for the session switch during a login (its redirect resumes the
  // authorization), and never blocking: without an upstream target the redirect stays.
  const upstreamLogout = deps.upstreamLogout;
  if (upstreamLogout !== undefined) {
    provider.use(async (ctx, next) => {
      await next();
      const oidc = (ctx as { oidc?: KoaContextWithOIDC["oidc"] }).oidc;
      if (oidc?.route !== "end_session_confirm" || ctx.status !== 303) return;
      if ((oidc.params as { logout?: unknown } | undefined)?.logout === undefined) return;
      const returnTo = ctx.response.get("Location");
      if (returnTo === "" || returnTo.startsWith(`${issuer}/auth`)) return;
      try {
        const record = await loginState.findSession(oidc.session?.uid);
        if (record?.upstream === undefined) return;
        const target = await upstreamLogout({ tenant, record, returnTo });
        if (target !== undefined) {
          ctx.status = 303;
          ctx.redirect(target);
        }
      } catch (error) {
        log.warn({ err: error }, "upstream logout skipped");
      }
    });
  }

  provider.on("server_error", (_ctx: unknown, error: unknown) => {
    log.error({ err: error }, "oidc provider error");
  });
  // Koa's default handler would print errors to stderr, outside the structured log.
  // (The typings only declare oidc-provider's own events, hence the EventEmitter call.)
  EventEmitter.prototype.on.call(provider, "error", (error: unknown) => {
    log.error({ err: error }, "oidc provider request error");
  });
  const refused =
    (event: string) =>
    (ctx: KoaContextWithOIDC, error: errors.OIDCProviderError): void => {
      // OAuth error code and the library's description only: no request values.
      log.info(
        {
          event,
          error: error.error,
          description: error.error_description,
          clientId: ctx.oidc?.client?.clientId,
        },
        "oidc request refused",
      );
    };
  provider.on("authorization.error", refused("authorization.error"));
  provider.on("grant.error", refused("grant.error"));
  provider.on("introspection.error", refused("introspection.error"));
  provider.on("revocation.error", refused("revocation.error"));
  provider.on("end_session.error", refused("end_session.error"));
  provider.on("pushed_authorization_request.error", refused("pushed_authorization_request.error"));

  const callback = provider.callback();
  return {
    tenant,
    issuer,
    basePath,
    provider,
    loginState,
    keysVersion: keys.version,
    acrValues,
    fingerprint,
    handle: (req, res) => {
      void callback(req, res);
    },
  };
}
