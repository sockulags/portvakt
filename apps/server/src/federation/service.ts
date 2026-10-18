import { randomBytes } from "node:crypto";
import { decodeProtectedHeader } from "jose";
import * as client from "openid-client";
import type { Config } from "../config/index.js";
import type { KeyRing } from "../crypto/keyring.js";
import type { LoginMethod, OidcLoginMethod } from "../domain/login-method.js";
import type { Tenant } from "../domain/tenant.js";
import type { Logger } from "../logging/logger.js";
import type { LoginErrorCode } from "../login/ui-shell.js";
import { METRICS, type Counter, type MetricRegistry } from "../metrics/registry.js";
import type { OutboundGuard } from "../net/outbound.js";
import type { AcrRanking } from "../oidc/acr.js";
import {
  loadInteraction,
  type InteractionContext,
  type InteractionDetails,
  type InteractionService,
} from "../oidc/interactions.js";
import { FRESH_LOGIN_REASONS, type TenantProvider } from "../oidc/provider.js";
import type { Repositories } from "../repositories/index.js";
import { asOidc } from "../repositories/login-methods.js";
import { mapUpstreamClaims } from "./claim-mapping.js";
import { FederationError, type FailureContext, type UpstreamLoginResult } from "./flow.js";
import { SamlFederation, type SamlBeginOptions } from "./saml/service.js";
import {
  classifyUpstreamError,
  UPSTREAM_ID_TOKEN_ALGS,
  UpstreamMisconfiguredError,
  UpstreamTenantRefusedError,
  type UpstreamClients,
} from "./upstream.js";

export { FederationError, type FailureContext, type UpstreamLoginResult } from "./flow.js";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
/** Upstream error codes are recorded only when they look like OAuth error codes. */
const OAUTH_ERROR_CODE = /^[a-z0-9_]{1,64}$/i;

export interface FederationServiceOptions {
  readonly config: Config;
  readonly repos: Repositories;
  readonly logger: Logger;
  readonly upstream: UpstreamClients;
  readonly acrRanking: AcrRanking;
  readonly interactions: InteractionService;
  readonly metrics: MetricRegistry;
  /** Master-key material (SAML: sealing and indexing upstream sessions). */
  readonly keys: KeyRing;
  /** Outbound requests to administrator-configured URLs (SAML metadata). */
  readonly outbound: OutboundGuard;
}

/** Fixed redirect URI of a login method: what the tenant registers at the upstream IdP. */
export const federationCallbackPath = (slug: string, loginMethodId: string): string =>
  `/t/${slug}/federation/${loginMethodId}/callback`;

/** Public JWKS of a login method's client key (for upstream private_key_jwt). */
export const federationJwksPath = (slug: string, loginMethodId: string): string =>
  `/t/${slug}/federation/${loginMethodId}/jwks`;

/**
 * Upstream federation. OIDC: sends the browser to the login method's IdP (authorization code
 * flow with PKCE S256, state and nonce), handles the callback (single-use state, token exchange,
 * full ID token validation, optional userinfo, claim mapping, JIT provisioning). SAML: see
 * {@link SamlFederation} (`saml`), which shares the failure handling, the JIT provisioning and
 * the completion below. Either way the login is finished on the interaction path with
 * `completeLogin`.
 *
 * Every failure tied to a real interaction ends in the login UI with an error view and is
 * audited (`login.failure`, written on its own, never inside a transaction that could roll
 * back). Callbacks with an unknown state are not audited, since anyone can send them: they are
 * logged and counted (`portvakt_federation_callback_rejected_total`). Logs and audit details
 * carry ids and reason codes only, never personal data or tokens.
 */
export class FederationService {
  readonly #options: FederationServiceOptions;
  readonly #log: Logger;
  readonly #rejected: Counter;
  /** SAML login methods (Swedish eID Framework). */
  readonly saml: SamlFederation;

  constructor(options: FederationServiceOptions) {
    this.#options = options;
    this.#log = options.logger.child({ component: "federation" });
    this.#rejected = options.metrics.counter(
      METRICS.federationCallbackRejected,
      "Upstream callbacks refused before an interaction was known, by reason",
    );
    this.saml = new SamlFederation({
      config: options.config,
      repos: options.repos,
      logger: options.logger,
      acrRanking: options.acrRanking,
      metrics: options.metrics,
      keys: options.keys,
      outbound: options.outbound,
      flow: {
        errorUrl: (tenant, code, uid) => this.#errorUrl(tenant, code, uid),
        refuse: (tenant, reason) => this.#refuse(tenant, reason),
        fail: (tenant, code, context, uid) => this.#fail(tenant, code, context, uid),
        complete: (result) => this.#completeUpstream(result),
        recordFailure: (code, context) => this.#auditFailure(code, context),
      },
    });
  }

  /** Redirect URI of a login method, as registered upstream. */
  redirectUri(slug: string, loginMethodId: string): string {
    return `${this.#options.config.publicUrl}${federationCallbackPath(slug, loginMethodId)}`;
  }

  /**
   * Whether a login through `method` can satisfy the request's `acr_values`: its asserted acr
   * does (OIDC), or one of the levels it requests upstream does (SAML, step-up through
   * RequestedAuthnContext).
   */
  satisfies(method: LoginMethod, requested: readonly string[]): boolean {
    if (method.protocol === "saml") return this.saml.requestedLoa(method, requested).length > 0;
    return this.#options.acrRanking.satisfiesAny(method.assertedAcr, requested);
  }

  /**
   * Returns the upstream authorization URL for a login through `method`, reusing the pending
   * request of this interaction and method while it is valid. `prompt=login` is sent when the
   * broker needs a fresh authentication (the session policy or the application asked for one);
   * `max_age`, `login_hint` and `ui_locales` are passed through; `acr_values` carries the
   * method's asserted acr when the method maps an upstream acr. SAML methods send a signed
   * AuthnRequest instead (`saml.begin`); `options.principalPin` is the PrincipalSelection hook
   * for a step-up of a known person (M4).
   */
  async begin(
    tenantProvider: TenantProvider,
    interaction: InteractionDetails,
    method: LoginMethod,
    options: SamlBeginOptions = {},
  ): Promise<string> {
    const { tenant } = tenantProvider;
    const failure = {
      tenantId: tenant.id,
      loginMethodId: method.id,
      clientId: interaction.clientId,
    };
    if (!method.enabled || method.tenantId !== tenant.id) {
      await this.#auditFailure("login_method_unavailable", failure);
      throw new FederationError("login_method_unavailable", "Login method not available");
    }
    if (method.protocol === "saml") {
      return this.saml.begin(tenantProvider, interaction, method, options);
    }
    const setup = await this.#setupFor(method, failure);
    const { maxAge, loginHint, uiLocales } = interaction.params;
    const secrets = await this.#options.repos.federationStates.pending(tenant.id, {
      loginMethodId: method.id,
      interactionUid: interaction.uid,
      maxAge,
      ttlSeconds: this.#options.config.tokens.interactionSeconds,
      fresh: () => ({
        state: client.randomState(),
        nonce: client.randomNonce(),
        codeVerifier: client.randomPKCECodeVerifier(),
      }),
    });
    const params: Record<string, string> = {
      redirect_uri: this.redirectUri(tenant.slug, method.id),
      response_type: "code",
      scope: method.scopes.join(" "),
      code_challenge: await client.calculatePKCECodeChallenge(secrets.codeVerifier),
      code_challenge_method: "S256",
      state: secrets.state,
      nonce: secrets.nonce,
    };
    if (interaction.reasons.some((reason) => FRESH_LOGIN_REASONS.has(reason))) {
      params.prompt = "login";
    }
    if (maxAge !== undefined) params.max_age = String(maxAge);
    if (method.claimMapping.acr !== undefined) params.acr_values = method.assertedAcr;
    if (loginHint !== undefined) params.login_hint = loginHint;
    if (uiLocales !== undefined) params.ui_locales = uiLocales;
    return client.buildAuthorizationUrl(setup.config, params).href;
  }

  /**
   * The upstream callback (`currentUrl`: the public callback URL with its query). Returns where
   * to send the browser: the interaction path to finish the login, or a login UI error view.
   */
  async callback(
    tenantProvider: TenantProvider,
    loginMethodId: string,
    currentUrl: URL,
  ): Promise<string> {
    const { tenant } = tenantProvider;
    const { repos } = this.#options;

    if (!UUID.test(loginMethodId)) return this.#refuse(tenant, "malformed_login_method");
    const state = currentUrl.searchParams.get("state") ?? "";
    const pending = await repos.federationStates.consumeCallback(tenant.id, loginMethodId, state);
    if ("reason" in pending) {
      if (pending.reason === "invalid_state") return this.#refuse(tenant, "unknown_state");
      const code = pending.reason === "state_replayed" ? "state_replayed" : "state_expired";
      return this.#fail(
        tenant,
        code,
        { tenantId: tenant.id, loginMethodId },
        pending.interactionUid,
      );
    }

    const uid = pending.interactionUid;
    const interaction = await tenantProvider.provider.Interaction.find(uid);
    const clientId =
      typeof interaction?.params.client_id === "string" ? interaction.params.client_id : undefined;
    const failure: FailureContext = { tenantId: tenant.id, loginMethodId, clientId };
    const fail = (code: LoginErrorCode, context: FailureContext = failure) =>
      this.#fail(tenant, code, context, uid);
    // The interaction is gone (expired): nothing to finish, so the code is not even redeemed.
    if (interaction === undefined) return fail("interaction_expired");
    if (pending.protocol !== "oidc")
      return fail("state_invalid", { ...failure, detail: "protocol" });

    const upstreamError = currentUrl.searchParams.get("error");
    if (upstreamError !== null) {
      const recorded = OAUTH_ERROR_CODE.test(upstreamError) ? upstreamError : "other";
      return fail(upstreamError === "access_denied" ? "upstream_denied" : "upstream_error", {
        ...failure,
        upstreamError: recorded,
      });
    }

    const method = asOidc(await repos.loginMethods.findById(tenant.id, loginMethodId));
    if (method === null || !method.enabled) return fail("login_method_unavailable");
    // A ranked acr needs upstream evidence (enforced at write time; methods saved before that).
    if (
      this.#options.acrRanking.rank(method.assertedAcr) !== undefined &&
      method.claimMapping.acr === undefined
    ) {
      return fail("insufficient_assurance");
    }

    let exchange: Awaited<ReturnType<UpstreamClients["exchangeCode"]>>;
    try {
      exchange = await this.#options.upstream.exchangeCode(method, currentUrl, {
        pkceCodeVerifier: pending.codeVerifier,
        expectedState: state,
        expectedNonce: pending.nonce,
        // With max_age sent upstream, the ID token must carry a recent enough auth_time.
        ...(pending.maxAge === undefined ? {} : { maxAge: pending.maxAge }),
      });
    } catch (error) {
      if (error instanceof UpstreamTenantRefusedError) return fail("account_not_allowed");
      if (error instanceof UpstreamMisconfiguredError) {
        this.#log.error({ loginMethodId, err: error }, "login method misconfigured");
        return fail("upstream_error");
      }
      const code = classifyUpstreamError(error);
      if (code === "upstream_unavailable") this.#options.upstream.forget(method.id);
      this.#log.info(
        {
          loginMethodId,
          reason: code,
          error: error instanceof Error ? error.name : "unknown",
          // openid-client's messages and codes are fixed strings, never token or user values.
          ...(error instanceof client.ClientError
            ? { detail: error.message, errorCode: error.code }
            : {}),
        },
        "upstream token exchange failed",
      );
      return fail(code);
    }
    const { tokens } = exchange;

    const idToken = tokens.id_token;
    const idClaims = tokens.claims();
    if (idToken === undefined || idClaims === undefined) return fail("upstream_error");
    if (!UPSTREAM_ID_TOKEN_ALGS.has(String(decodeProtectedHeader(idToken).alg))) {
      this.#log.info({ loginMethodId }, "upstream ID token algorithm not allowed");
      return fail("upstream_error");
    }
    // Multi-tenant issuers already refused other tenants; any listed tenants are enforced here.
    if (
      method.allowedUpstreamTenants.length > 0 &&
      (typeof idClaims.tid !== "string" || !method.allowedUpstreamTenants.includes(idClaims.tid))
    ) {
      return fail("account_not_allowed");
    }
    const now = Math.floor(Date.now() / 1000);
    const authTime =
      typeof idClaims.auth_time === "number" && idClaims.auth_time > 0
        ? Math.min(Math.floor(idClaims.auth_time), now)
        : now;

    let claims: Record<string, unknown> = { ...idClaims };
    if (method.useUserinfo) {
      try {
        const userinfo = await client.fetchUserInfo(
          exchange.config,
          tokens.access_token,
          idClaims.sub,
        );
        // Userinfo only fills in: the ID token's (signed, validated) claims take precedence.
        claims = { ...userinfo, ...idClaims };
      } catch (error) {
        return fail(classifyUpstreamError(error));
      }
    }

    const mapped = mapUpstreamClaims(method.claimMapping, claims, {
      trustEmail: method.trustUpstreamEmail,
    });
    if (typeof mapped === "string") {
      this.#log.info({ loginMethodId, reason: mapped }, "upstream identity rejected");
      return fail("invalid_identity");
    }
    if (
      method.claimMapping.acr !== undefined &&
      (mapped.upstreamAcr === undefined ||
        !this.#options.acrRanking.satisfies(mapped.upstreamAcr, method.assertedAcr))
    ) {
      return fail("insufficient_assurance");
    }

    return this.#completeUpstream({
      tenant,
      interactionUid: uid,
      stateHash: pending.stateHash,
      method,
      mapped,
      subjectFromPin: false,
      acr: method.assertedAcr,
      authTime,
    });
  }

  /**
   * Finishes a login on the interaction path: the completion reference must belong to this
   * browser's interaction (the interaction cookie) and is redeemed once. Returns the
   * authorization resume URL.
   */
  async finish(ctx: InteractionContext, completionRef: string): Promise<string> {
    const { tenant } = ctx.tenantProvider;
    const details = await loadInteraction(ctx);
    const found = await this.#options.repos.federationStates.consumeCompletion(
      tenant.id,
      details.uid,
      completionRef,
    );
    if (found === null) {
      await this.#auditFailure("state_invalid", {
        tenantId: tenant.id,
        clientId: details.clientId,
      });
      throw new FederationError("state_invalid", "Unknown or used completion reference");
    }
    const { completion, loginMethodId } = found;
    const { returnTo } = await this.#options.interactions.completeLogin(ctx, {
      personId: completion.personId,
      loginMethodId,
      acr: completion.acr,
      amr: completion.amr,
      authTime: completion.authTime,
      ...(completion.upstreamSession === undefined
        ? {}
        : { upstreamSession: completion.upstreamSession }),
    });
    await this.#audit({
      tenantId: tenant.id,
      actor: { type: "person", id: completion.personId },
      subject: { type: "person", id: completion.personId },
      action: "login.success",
      details: {
        loginMethodId,
        acr: completion.acr,
        ...(details.clientId === undefined ? {} : { clientId: details.clientId }),
      },
    });
    return returnTo;
  }

  /** Records a refused login (`login.failure`) of a real interaction. */
  async recordFailure(code: LoginErrorCode, context: FailureContext): Promise<void> {
    await this.#auditFailure(code, context);
  }

  /**
   * JIT provisioning of an upstream login (OIDC callback or SAML ACS) and the completion hop:
   * the person is found or created, audits are written, and the browser is sent to the
   * interaction path with a single-use completion reference.
   */
  async #completeUpstream(result: UpstreamLoginResult): Promise<string> {
    const { tenant, method, mapped } = result;
    const { repos } = this.#options;
    const jit = await repos.persons.upsertFromLogin(tenant.id, {
      loginMethodId: method.id,
      subject: mapped.subject,
      subjectFromPin: result.subjectFromPin,
      // Linking by pin needs the login to have met the method's level, which it has here.
      acr: method.assertedAcr,
      attributes: mapped.attributes,
      ...(mapped.pin === undefined ? {} : { pin: mapped.pin }),
    });
    const person = jit.person;
    if (mapped.groupsOverage) {
      // Groups are not fetched from Microsoft Graph: rules see no groups for this login.
      this.#log.warn(
        { loginMethodId: method.id, event: "groups_overage" },
        "upstream groups overage: groups treated as empty (configure group filtering upstream)",
      );
      await this.#audit({
        tenantId: tenant.id,
        actor: { type: "person", id: person.id },
        subject: { type: "person", id: person.id },
        action: "login.groups_overage",
        details: { loginMethodId: method.id },
      });
    }
    if (jit.created || jit.linked) {
      await this.#audit({
        tenantId: tenant.id,
        actor: { type: "system", id: null },
        subject: { type: "person", id: person.id },
        action: jit.created ? "person.created" : "person.identity_linked",
        details: { loginMethodId: method.id },
      });
    }

    const completionRef = randomBytes(32).toString("base64url");
    await repos.federationStates.attachCompletion(tenant.id, result.stateHash, completionRef, {
      personId: person.id,
      acr: result.acr,
      amr: mapped.amr,
      authTime: result.authTime,
      ...(result.upstreamSession === undefined ? {} : { upstreamSession: result.upstreamSession }),
    });
    const base = `${this.#options.config.publicUrl}/t/${tenant.slug}`;
    return `${base}/interaction/${encodeURIComponent(result.interactionUid)}/federation/complete?ref=${completionRef}`;
  }

  #errorUrl(tenant: Tenant, code: LoginErrorCode, uid?: string): string {
    const base = `${this.#options.config.publicUrl}/t/${tenant.slug}`;
    return uid === undefined
      ? `${base}/login/error?code=${code}`
      : `${base}/interaction/${encodeURIComponent(uid)}?error=${code}`;
  }

  /** Unauthenticated noise (no interaction known): counted and logged, never audited. */
  #refuse(tenant: Tenant, reason: string): string {
    this.#rejected.inc({ reason });
    this.#log.info({ reason, tenant: tenant.slug }, "upstream callback refused");
    return this.#errorUrl(tenant, "state_invalid");
  }

  /** A refused login of a real interaction: audited, then the interaction's error view. */
  async #fail(
    tenant: Tenant,
    code: LoginErrorCode,
    context: FailureContext,
    uid: string,
  ): Promise<string> {
    await this.#auditFailure(code, context);
    return this.#errorUrl(tenant, code, uid);
  }

  async #setupFor(method: OidcLoginMethod, failure: FailureContext) {
    try {
      return await this.#options.upstream.setupFor(method);
    } catch (error) {
      if (error instanceof UpstreamMisconfiguredError) {
        this.#log.error({ loginMethodId: method.id, err: error }, "login method misconfigured");
        await this.#auditFailure("upstream_error", failure);
        throw new FederationError("upstream_error", "Login method misconfigured");
      }
      const code = classifyUpstreamError(error);
      this.#log.warn(
        {
          loginMethodId: method.id,
          reason: code,
          error: error instanceof Error ? error.name : "unknown",
        },
        "upstream discovery failed",
      );
      await this.#auditFailure("upstream_unavailable", failure);
      throw new FederationError("upstream_unavailable", "Upstream IdP unavailable");
    }
  }

  async #auditFailure(code: LoginErrorCode, context: FailureContext): Promise<void> {
    this.#log.info(
      {
        reason: code,
        loginMethodId: context.loginMethodId,
        clientId: context.clientId,
        ...(context.detail === undefined ? {} : { detail: context.detail }),
      },
      "login failed",
    );
    await this.#audit({
      tenantId: context.tenantId,
      actor: { type: "system", id: null },
      subject:
        context.loginMethodId === undefined
          ? null
          : { type: "login_method", id: context.loginMethodId },
      action: "login.failure",
      outcome: "failure",
      details: {
        reason: code,
        ...(context.clientId === undefined ? {} : { clientId: context.clientId }),
        ...(context.upstreamError === undefined ? {} : { upstreamError: context.upstreamError }),
        ...(context.detail === undefined ? {} : { detail: context.detail }),
      },
    });
  }

  /** Audit writes never break the login flow; a failed write is logged instead. */
  async #audit(event: Parameters<Repositories["audit"]["append"]>[0]): Promise<void> {
    try {
      await this.#options.repos.audit.append(event);
    } catch (error) {
      this.#log.error({ err: error, action: event.action }, "audit event could not be written");
    }
  }
}
