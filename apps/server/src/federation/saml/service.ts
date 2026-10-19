import { createHash } from "node:crypto";
import { z } from "zod";
import type { AuditLog } from "../../audit/audit-log.js";
import type { Config } from "../../config/index.js";
import type { KeyRing } from "../../crypto/keyring.js";
import type { SamlLoginMethod } from "../../domain/login-method.js";
import { SAML_ATTRIBUTES, SAML_STATUS } from "../../domain/saml.js";
import type { Tenant } from "../../domain/tenant.js";
import type { Logger } from "../../logging/logger.js";
import type { LoginErrorCode } from "../../login/ui-shell.js";
import { METRICS, type Counter, type MetricRegistry } from "../../metrics/registry.js";
import {
  OutboundRefusedError,
  withOutboundContext,
  type OutboundGuard,
} from "../../net/outbound.js";
import { parseAcrValues, type AcrRanking } from "../../oidc/acr.js";
import type { InteractionDetails } from "../../oidc/interactions.js";
import {
  MAX_SESSION_UPSTREAMS,
  sessionUpstreamSchema,
  type SessionUpstream,
} from "../../oidc/login-context.js";
import {
  FRESH_LOGIN_REASONS,
  type TenantProvider,
  type UpstreamLogoutInput,
} from "../../oidc/provider.js";
import { hashToken } from "../../repositories/federation-states.js";
import type { Repositories } from "../../repositories/index.js";
import type { SpKeyPair } from "../../repositories/saml.js";
import { FederationError, type FailureContext, type UpstreamLoginResult } from "../flow.js";
import { mapSamlAttributes } from "./attributes.js";
import { MetadataError, parseIdpMetadata, type IdpMetadata } from "./metadata.js";
import {
  buildAuthnRequest,
  buildLogoutRequest,
  buildLogoutResponse,
  isCancel,
  newRelayState,
  newSamlId,
  readLogoutMessage,
  readResponse,
  ResponseRejected,
  validateResponse,
  type ResponseEnvelope,
  type SamlStatus,
  type SloParameters,
  type SpEndpoints,
  type SpSigner,
} from "./protocol.js";
import { buildSpMetadata } from "./sp-metadata.js";
import {
  nameIdIndexCandidates,
  sealUpstreamSession,
  sessionIndexCandidates,
  unsealUpstreamSession,
} from "./upstream-session.js";
import { MAX_XML_BYTES, RESPONSE_LIMITS, XmlError, type XmlLimits } from "./xml.js";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** An assertion older than this (IssueInstant) is refused, whatever its NotOnOrAfter says. */
const MAX_ASSERTION_AGE_SECONDS = 300;
/** A pending SP-initiated logout waits this long for the IdP's LogoutResponse. */
const LOGOUT_STATE_TTL_SECONDS = 600;
/** oidc_payloads kinds of pending SP-initiated logouts and their HTTP-POST pages. */
const LOGOUT_STATE_KIND = "PortvaktSamlLogout";
const LOGOUT_POST_KIND = "PortvaktSamlLogoutPost";
/** A LogoutRequest ID is remembered this long (its IssueInstant window, with room). */
const LOGOUT_REQUEST_REPLAY_SECONDS = 15 * 60;
/** A failed metadata refresh is retried after this long (not the full refresh interval). */
const METADATA_RETRY_SECONDS = 300;
const METADATA_BATCH = 50;

/** The SP of a login method lives below `/t/{slug}/saml/{loginMethodId}` (its entityID). */
export const samlBasePath = (slug: string, loginMethodId: string): string =>
  `/t/${slug}/saml/${loginMethodId}`;

/** What the OIDC and SAML federation share (implemented by `FederationService`). */
export interface UpstreamLoginFlow {
  errorUrl(tenant: Tenant, code: LoginErrorCode, uid?: string): string;
  /** Unauthenticated noise (no interaction known): counted and logged, never audited. */
  refuse(tenant: Tenant, reason: string): string;
  /** A refused login of a real interaction: audited; returns its error view. */
  fail(tenant: Tenant, code: LoginErrorCode, context: FailureContext, uid: string): Promise<string>;
  /** JIT provisioning and the completion hop; returns the completion URL. */
  complete(result: UpstreamLoginResult): Promise<string>;
  /** Audits a refused login (`login.failure`) without an error view (the caller throws). */
  recordFailure(code: LoginErrorCode, context: FailureContext): Promise<void>;
}

export interface SamlFederationOptions {
  readonly config: Config;
  readonly repos: Repositories;
  readonly auditLog: AuditLog;
  readonly keys: KeyRing;
  readonly logger: Logger;
  readonly acrRanking: AcrRanking;
  readonly metrics: MetricRegistry;
  readonly flow: UpstreamLoginFlow;
  /** Outbound requests (metadata URLs) through the SSRF guard. */
  readonly outbound: OutboundGuard;
}

export interface SamlBeginOptions {
  /**
   * PrincipalSelection: the personal identity number of the person expected to sign in (step-up
   * or signing for a known person; `federation.begin` sets it for a step-up). It is sent (over
   * HTTP-POST only) when the IdP's metadata advertises PrincipalSelection; either way the
   * returned personal identity number must match.
   */
  readonly principalPin?: string | undefined;
}

/** What an HTTP-POST binding page renders: an auto-submitting form. */
export interface AutoPostForm {
  readonly action: string;
  readonly fields: Readonly<Record<string, string>>;
}

export type SloOutcome =
  | { readonly kind: "redirect"; readonly url: string }
  | { readonly kind: "post"; readonly form: AutoPostForm }
  | { readonly kind: "logged_out" }
  | { readonly kind: "refused"; readonly status: number };

const acsBodySchema = z.object({
  SAMLResponse: z
    .string()
    .min(1)
    .max(Math.ceil((RESPONSE_LIMITS.maxBytes * 4) / 3) + 8),
  RelayState: z.string().min(1).max(512),
});

const logoutStateSchema = z
  .object({
    loginMethodId: z.uuid(),
    requestId: z.string().min(1).max(128),
    returnTo: z.url(),
    /** The session's other upstream sessions, logged out in turn after this one answers. */
    remaining: z.array(sessionUpstreamSchema).max(MAX_SESSION_UPSTREAMS).default([]),
  })
  .loose();

const logoutPostSchema = z
  .object({
    action: z.url(),
    fields: z.record(z.string(), z.string().max(1_000_000)),
  })
  .loose();

/** Second-level SAML status → login UI error code. */
function errorCodeOfStatus(status: SamlStatus): LoginErrorCode {
  if (isCancel(status)) return "upstream_cancelled";
  switch (status.subCode) {
    case SAML_STATUS.noAuthnContext:
      return "insufficient_assurance";
    case SAML_STATUS.authnFailed:
      return "authentication_failed";
    case SAML_STATUS.unknownPrincipal:
      return "account_not_allowed";
    case SAML_STATUS.requestDenied:
    case SAML_STATUS.fraud:
    case SAML_STATUS.possibleFraud:
      return "upstream_denied";
    default:
      return "upstream_error";
  }
}

/** A status code recorded in audit details: its last URI segment, when it looks like one. */
function statusLabel(status: SamlStatus): string {
  const last = (status.subCode ?? status.code).split(/[:/]/).at(-1) ?? "";
  return /^[A-Za-z]{1,64}$/.test(last) ? last : "other";
}

/** Whether the IdP's metadata advertises PrincipalSelection by personal identity number. */
const principalSelectionAdvertised = (metadata: IdpMetadata): boolean =>
  metadata.principalSelection.includes(SAML_ATTRIBUTES.personalIdentityNumber);

/**
 * Upstream SAML 2.0 following the Swedish eID Framework: one SP per login method (entityID
 * `{PUBLIC_URL}/t/{slug}/saml/{id}`), signed AuthnRequests, the ACS (HTTP-POST), single logout in
 * both directions and both bindings, SP metadata, and the IdP metadata cache with its scheduled
 * refresh.
 *
 * The ACS is reached by a cross-site POST, so no SameSite=Lax cookie arrives there: the request
 * is correlated only through the RelayState (the `federation_states` row, single use) and the
 * response's InResponseTo (its request ID), then the browser is sent (303) to the interaction
 * path, where the interaction cookie is present, exactly as after an OIDC callback.
 */
/** Signed SP metadata documents kept per login method (least recently used evicted first). */
const SP_METADATA_CACHE_MAX = 500;

export class SamlFederation {
  readonly #options: SamlFederationOptions;
  /**
   * Built (and signed) SP metadata per tenant and login method, with the fingerprint of what it
   * was built from: the settings, display name, tenant name and SP keys. Any change of those
   * builds it again; an unchanged one is served without signing (anyone can request it).
   */
  readonly #spMetadata = new Map<string, { readonly fingerprint: string; readonly xml: string }>();
  readonly #log: Logger;
  readonly #metadataRefresh: Counter;
  readonly #logouts: Counter;
  readonly #responseLimits: XmlLimits;

  constructor(options: SamlFederationOptions) {
    this.#options = options;
    this.#responseLimits = {
      ...RESPONSE_LIMITS,
      maxElements: options.config.federation.samlXmlMaxElements,
    };
    this.#log = options.logger.child({ component: "saml" });
    this.#metadataRefresh = options.metrics.counter(
      METRICS.samlMetadataRefresh,
      "SAML IdP metadata refreshes, by outcome and reason",
    );
    this.#logouts = options.metrics.counter(
      METRICS.samlLogout,
      "SAML single logout messages, by direction and outcome",
    );
  }

  spEndpoints(slug: string, loginMethodId: string): SpEndpoints {
    const entityId = `${this.#options.config.publicUrl}${samlBasePath(slug, loginMethodId)}`;
    return { entityId, acsUrl: `${entityId}/acs`, sloUrl: `${entityId}/slo` };
  }

  /**
   * The levels to request from the IdP for an authorization asking for `requested` (its
   * `acr_values`): the configured LoA that meet the login method's asserted acr and the request
   * (step-up: an application asking for a higher level narrows RequestedAuthnContext to it).
   * Empty when the method cannot satisfy the request.
   */
  requestedLoa(method: SamlLoginMethod, requested: readonly string[]): string[] {
    const ranking = this.#options.acrRanking;
    return method.saml.requestedLoa.filter(
      (loa) => ranking.satisfies(loa, method.assertedAcr) && ranking.satisfiesAny(loa, requested),
    );
  }

  /**
   * Sends the browser to the IdP with a signed AuthnRequest: a pending request (RelayState and
   * request ID) is stored, reused while this interaction asks for the same thing. ForceAuthn is
   * set when the broker needs a fresh authentication (prompt=login, max_age, an expired or idle
   * session, allowSso=false across applications, a higher acr). Returns the IdP URL
   * (HTTP-Redirect) or the POST-binding page.
   */
  async begin(
    tenantProvider: TenantProvider,
    interaction: InteractionDetails,
    method: SamlLoginMethod,
    options: SamlBeginOptions = {},
  ): Promise<string> {
    const { tenant } = tenantProvider;
    const failure = {
      tenantId: tenant.id,
      loginMethodId: method.id,
      clientId: interaction.clientId,
    };
    const requestedLoa = this.requestedLoa(method, parseAcrValues(interaction.params.acrValues));
    if (requestedLoa.length === 0) {
      await this.#recordFailure("no_acceptable_method", failure);
      throw new FederationError("no_acceptable_method", "No requested LoA meets the request");
    }
    const metadata = await this.idpMetadata(method);
    if (metadata === null) {
      await this.#recordFailure("upstream_unavailable", { ...failure, detail: "no_metadata" });
      throw new FederationError("upstream_unavailable", "IdP metadata not available");
    }
    const signer = await this.#signer(tenant.id, method.id);
    if (signer === undefined) {
      this.#log.error({ loginMethodId: method.id }, "SAML login method has no active signing key");
      await this.#recordFailure("upstream_error", { ...failure, detail: "no_signing_key" });
      throw new FederationError("upstream_error", "Login method misconfigured");
    }
    // PrincipalSelection is sent only to an IdP that advertises it, and only over HTTP-POST: a
    // personal identity number never goes into a URL.
    const principalSelection =
      options.principalPin !== undefined && principalSelectionAdvertised(metadata);
    if (principalSelection && metadata.sso.post === null) {
      await this.#recordFailure("upstream_error", {
        ...failure,
        detail: "principal_selection_needs_post",
      });
      throw new FederationError("upstream_error", "PrincipalSelection needs HTTP-POST");
    }
    const binding =
      (principalSelection || method.saml.authnRequestBinding === "post") &&
      metadata.sso.post !== null
        ? "post"
        : metadata.sso.redirect !== null
          ? "redirect"
          : "post";
    const forceAuthn =
      interaction.reasons.some((reason) => FRESH_LOGIN_REASONS.has(reason)) ||
      interaction.params.maxAge !== undefined;
    const pending = await this.#options.repos.federationStates.pendingSaml(tenant.id, {
      loginMethodId: method.id,
      interactionUid: interaction.uid,
      maxAge: interaction.params.maxAge,
      ttlSeconds: this.#options.config.tokens.interactionSeconds,
      request: {
        forceAuthn,
        requestedLoa,
        comparison: method.saml.authnContextComparison,
        binding,
        principalSelection,
      },
      principalPin: options.principalPin,
      fresh: () => ({ relayState: newRelayState(), requestId: newSamlId() }),
    });
    const sp = this.spEndpoints(tenant.slug, method.id);
    if (binding === "post") {
      return `${sp.entityId}/post?RelayState=${encodeURIComponent(pending.relayState)}`;
    }
    const message = await buildAuthnRequest(sp, metadata, signer, {
      requestId: pending.requestId,
      relayState: pending.relayState,
      binding,
      forceAuthn,
      requestedLoa,
      comparison: method.saml.authnContextComparison,
      principalPin: undefined,
    });
    return message.url;
  }

  /**
   * The HTTP-POST binding page of a pending request: the signed AuthnRequest (same ID) as an
   * auto-submitting form. Rendered once: the first render claims it, so a request naming a
   * personal identity number cannot be fetched again. `null` when the RelayState is not an
   * unrendered pending request of this login method.
   */
  async postForm(
    tenantProvider: TenantProvider,
    loginMethodId: string,
    relayState: string,
  ): Promise<AutoPostForm | null> {
    const { tenant } = tenantProvider;
    if (!UUID.test(loginMethodId)) return null;
    const method = await this.#method(tenant.id, loginMethodId);
    if (method === null) return null;
    const metadata = await this.idpMetadata(method);
    const signer = await this.#signer(tenant.id, method.id);
    if (metadata === null || signer === undefined || metadata.sso.post === null) return null;
    const pending = await this.#options.repos.federationStates.claimSamlPostRender(
      tenant.id,
      loginMethodId,
      relayState,
    );
    if (pending === null) return null;
    const message = await buildAuthnRequest(
      this.spEndpoints(tenant.slug, method.id),
      metadata,
      signer,
      {
        requestId: pending.requestId,
        relayState,
        binding: "post",
        forceAuthn: pending.request.forceAuthn,
        requestedLoa: pending.request.requestedLoa,
        comparison: pending.request.comparison,
        principalPin: pending.request.principalSelection ? pending.principalPin : undefined,
      },
    );
    return message.binding === "post" ? { action: message.url, fields: message.fields } : null;
  }

  /**
   * The AssertionConsumerService (HTTP-POST). Returns where to send the browser: the interaction
   * path with a completion reference, or a login UI error view.
   */
  async acs(tenantProvider: TenantProvider, loginMethodId: string, body: unknown): Promise<string> {
    const { tenant } = tenantProvider;
    const { repos, flow } = this.#options;
    if (!UUID.test(loginMethodId)) return flow.refuse(tenant, "malformed_login_method");
    const parsedBody = acsBodySchema.safeParse(body);
    if (!parsedBody.success) return flow.refuse(tenant, "malformed_saml_response");
    const { SAMLResponse: samlResponse, RelayState: relayState } = parsedBody.data;

    const pending = await repos.federationStates.consumeCallback(
      tenant.id,
      loginMethodId,
      relayState,
    );
    if ("reason" in pending) {
      if (pending.reason === "invalid_state") return flow.refuse(tenant, "unknown_state");
      const code = pending.reason === "state_replayed" ? "state_replayed" : "state_expired";
      return flow.fail(
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
    const context: FailureContext = { tenantId: tenant.id, loginMethodId, clientId };
    const fail = (code: LoginErrorCode, extra: Partial<FailureContext> = {}): Promise<string> =>
      flow.fail(tenant, code, { ...context, ...extra }, uid);
    if (interaction === undefined) return fail("interaction_expired");
    if (pending.protocol !== "saml") return fail("state_invalid", { detail: "protocol" });

    const method = await this.#method(tenant.id, loginMethodId);
    if (method === null) return fail("login_method_unavailable");
    const metadata = await this.idpMetadata(method);
    if (metadata === null) return fail("upstream_unavailable", { detail: "no_metadata" });
    const sp = this.spEndpoints(tenant.slug, method.id);
    const settings = method.saml;
    const skewMs = settings.clockSkewSeconds * 1000;
    const invalid = (detail: string) => fail("upstream_response_invalid", { detail });

    let envelope: ResponseEnvelope;
    try {
      envelope = await readResponse(samlResponse, metadata, this.#responseLimits);
    } catch (error) {
      return invalid(error instanceof XmlError ? error.reason : "malformed");
    }
    // Pre-checks (from the signed bytes when the Response is signed); the assertion's own
    // values are checked again below.
    if (settings.requireSignedResponse && !envelope.responseSigned) {
      return invalid("response_not_signed");
    }
    if (envelope.inResponseTo !== undefined && envelope.inResponseTo !== pending.requestId) {
      return fail("state_invalid", { detail: "in_response_to_mismatch" });
    }
    if (envelope.issuer !== undefined && envelope.issuer !== metadata.entityId) {
      return invalid("issuer_mismatch");
    }
    if (envelope.destination !== undefined && envelope.destination !== sp.acsUrl) {
      return invalid("destination_mismatch");
    }
    if (envelope.responseSigned && envelope.destination === undefined) {
      // Bindings 3.5.5.2: a signed response over HTTP-POST must name its Destination.
      return invalid("destination_missing");
    }

    const status = envelope.status;
    if (status === undefined) return invalid("status_missing");
    if (status.code !== SAML_STATUS.success) {
      if (envelope.inResponseTo !== pending.requestId) {
        return fail("state_invalid", { detail: "in_response_to_missing" });
      }
      return fail(errorCodeOfStatus(status), { upstreamError: statusLabel(status) });
    }
    if (envelope.assertionCount !== 1) return invalid("assertion_count");
    if (settings.requireEncryptedAssertions && !envelope.hasEncryptedAssertion) {
      return invalid("assertion_not_encrypted");
    }

    const now = Date.now();
    let assertion;
    try {
      const keys = envelope.hasEncryptedAssertion
        ? await repos.saml.spKeyPairs(tenant.id, method.id, "encryption")
        : [];
      assertion = await validateResponse(sp, metadata, envelope, {
        requireSignedResponse: settings.requireSignedResponse,
        decryptionKeys: keys.map((key) => key.privateKey),
        requireGcm: settings.requireGcm,
        clockSkewSeconds: settings.clockSkewSeconds,
        now,
        limits: this.#responseLimits,
      });
    } catch (error) {
      if (error instanceof ResponseRejected || error instanceof XmlError) {
        return invalid(error.reason);
      }
      throw error;
    }

    if (assertion.issuer !== metadata.entityId) return invalid("issuer_mismatch");
    if (assertion.confirmation.inResponseTo !== pending.requestId) {
      return fail("state_invalid", { detail: "in_response_to_mismatch" });
    }
    if (assertion.confirmation.recipient !== sp.acsUrl) return invalid("recipient_mismatch");
    if (
      assertion.confirmation.notOnOrAfter === undefined ||
      now - skewMs >= assertion.confirmation.notOnOrAfter ||
      (assertion.confirmation.notBefore !== undefined &&
        now + skewMs < assertion.confirmation.notBefore)
    ) {
      return invalid("assertion_expired");
    }
    if (
      assertion.issueInstant > now + skewMs ||
      now - assertion.issueInstant > MAX_ASSERTION_AGE_SECONDS * 1000 + skewMs
    ) {
      return invalid("assertion_expired");
    }
    if (assertion.authnInstant > now + skewMs) return invalid("authn_instant_in_future");

    // One-time use of the assertion ID (per tenant and login method), until it expires.
    const fresh = await repos.saml.rememberAssertion(
      tenant.id,
      method.id,
      assertion.id,
      new Date(assertion.notOnOrAfter + skewMs),
    );
    if (!fresh) return fail("state_replayed", { detail: "assertion_replayed" });

    // The returned level must be one that was requested (exact) or rank at least as high as the
    // lowest requested one (minimum), and meet the login method's asserted acr.
    const loa = assertion.authnContextClassRef;
    const ranking = this.#options.acrRanking;
    const requested = pending.request.requestedLoa;
    const levelOk =
      (pending.request.comparison === "exact"
        ? requested.includes(loa)
        : requested.some((value) => ranking.satisfies(loa, value))) &&
      ranking.satisfies(loa, method.assertedAcr);
    if (!levelOk) return fail("insufficient_assurance", { detail: "loa_not_met" });

    if (
      pending.request.forceAuthn &&
      assertion.authnInstant + skewMs < pending.createdAt.getTime()
    ) {
      // ForceAuthn: the IdP must have authenticated the person after the request was sent.
      return fail("upstream_error", { detail: "authn_not_fresh" });
    }
    if (
      pending.maxAge !== undefined &&
      now - assertion.authnInstant > pending.maxAge * 1000 + skewMs
    ) {
      return fail("upstream_error", { detail: "max_age_exceeded" });
    }

    const mapping = mapSamlAttributes(
      settings,
      {
        nameId: assertion.nameId,
        nameIdFormat: assertion.nameIdFormat,
        attributes: assertion.attributes,
        loa,
      },
      [...metadata.scopes, ...settings.orgAffiliationScopes],
    );
    if (typeof mapping === "string") {
      this.#log.info({ loginMethodId, reason: mapping }, "upstream identity rejected");
      return fail("invalid_identity", { detail: mapping });
    }
    if (mapping.droppedAffiliations > 0) {
      this.#log.info(
        { loginMethodId, dropped: mapping.droppedAffiliations },
        "orgAffiliation values outside the accepted scopes were ignored",
      );
    }
    if (pending.principalPin !== undefined && mapping.mapped.pin !== pending.principalPin) {
      return fail("account_not_allowed", { detail: "principal_mismatch" });
    }

    return flow.complete({
      tenant,
      interactionUid: uid,
      stateHash: pending.stateHash,
      method,
      mapped: mapping.mapped,
      subjectFromPin: mapping.subjectFromPin,
      acr: loa,
      authTime: Math.floor(Math.min(assertion.authnInstant, now) / 1000),
      upstreamSession:
        assertion.nameId === undefined
          ? undefined
          : sealUpstreamSession(this.#options.keys, method.id, {
              nameId: assertion.nameId,
              nameIdFormat: assertion.nameIdFormat,
              nameQualifier: assertion.nameQualifier,
              spNameQualifier: assertion.spNameQualifier,
              sessionIndex: assertion.sessionIndex,
            }),
    });
  }

  /** The SP metadata of a SAML login method; `null` for unknown or non-SAML ids. */
  async spMetadata(tenantProvider: TenantProvider, loginMethodId: string): Promise<string | null> {
    const { tenant } = tenantProvider;
    if (!UUID.test(loginMethodId)) return null;
    const found = await this.#options.repos.loginMethods.findById(tenant.id, loginMethodId);
    if (found?.protocol !== "saml") return null;
    const keys = await this.#options.repos.saml.listSpKeys(tenant.id, found.id);
    const cacheKey = `${tenant.id}:${found.id}`;
    const fingerprint = createHash("sha256")
      .update(
        JSON.stringify({
          settings: found.saml,
          displayName: found.displayName,
          tenant: tenant.name,
          keys: keys.map((key) => [key.id, key.purpose, key.state]),
        }),
      )
      .digest("base64url");
    const cached = this.#spMetadata.get(cacheKey);
    if (cached !== undefined && cached.fingerprint === fingerprint) {
      this.#spMetadata.delete(cacheKey);
      this.#spMetadata.set(cacheKey, cached);
      return cached.xml;
    }
    const xml = buildSpMetadata({
      sp: this.spEndpoints(tenant.slug, found.id),
      settings: found.saml,
      displayName: found.displayName,
      organization: { name: tenant.name, url: this.#options.config.publicUrl },
      keys,
      signer: found.saml.signMetadata ? await this.#signer(tenant.id, found.id) : undefined,
    });
    this.#spMetadata.delete(cacheKey);
    while (this.#spMetadata.size >= SP_METADATA_CACHE_MAX) {
      const oldest = this.#spMetadata.keys().next();
      if (oldest.done === true) break;
      this.#spMetadata.delete(oldest.value);
    }
    this.#spMetadata.set(cacheKey, { fingerprint, xml });
    return xml;
  }

  /**
   * SP-initiated single logout after an RP-initiated logout ended the broker session locally:
   * a signed LogoutRequest (HTTP-Redirect, or the HTTP-POST page `/logout`) to the first IdP of
   * `upstreams` that can take one, which answers at the SLO endpoint; from there the browser
   * goes on to the next IdP of the list, and after the last one to `returnTo`. `undefined`
   * (keep the local redirect) when none of them can do it; never throws. Best effort: a failed
   * or unanswered logout at one IdP never blocks the local logout or the others.
   */
  async startLogout(input: UpstreamLogoutInput): Promise<string | undefined> {
    const { tenant, upstreams, returnTo } = input;
    for (const [position, upstream] of upstreams.entries()) {
      const target = await this.#sendLogout(
        tenant,
        upstream,
        upstreams.slice(position + 1),
        returnTo,
      );
      if (target !== undefined) return target;
    }
    return undefined;
  }

  /** Where the browser goes after an IdP answered: the next IdP's logout, or `returnTo`. */
  async #continueLogout(
    tenant: Tenant,
    pending: z.infer<typeof logoutStateSchema>,
  ): Promise<string> {
    return (
      (await this.startLogout({
        tenant,
        upstreams: pending.remaining,
        returnTo: pending.returnTo,
      })) ?? pending.returnTo
    );
  }

  async #sendLogout(
    tenant: Tenant,
    upstream: SessionUpstream,
    remaining: readonly SessionUpstream[],
    returnTo: string,
  ): Promise<string | undefined> {
    try {
      const method = await this.#method(tenant.id, upstream.loginMethodId);
      if (method === null) return undefined;
      const metadata = await this.idpMetadata(method);
      const signer = await this.#signer(tenant.id, method.id);
      if (metadata === null || signer === undefined) return undefined;
      if (metadata.slo.redirect === null && metadata.slo.post === null) return undefined;
      const relayState = newRelayState();
      const requestId = newSamlId();
      await this.#options.repos.oidcPayloads.upsert(
        tenant.id,
        LOGOUT_STATE_KIND,
        hashToken(relayState),
        { loginMethodId: method.id, requestId, returnTo, remaining: [...remaining] },
        LOGOUT_STATE_TTL_SECONDS,
      );
      const sp = this.spEndpoints(tenant.slug, method.id);
      const message = await buildLogoutRequest(sp, metadata, signer, {
        requestId,
        relayState,
        subject: unsealUpstreamSession(this.#options.keys, method.id, upstream),
      });
      this.#logouts.inc({ direction: "sp_initiated", outcome: "sent" });
      if (message.binding === "redirect") return message.url;
      await this.#options.repos.oidcPayloads.upsert(
        tenant.id,
        LOGOUT_POST_KIND,
        hashToken(relayState),
        { action: message.url, fields: { ...message.fields } },
        LOGOUT_STATE_TTL_SECONDS,
      );
      return `${sp.entityId}/logout?RelayState=${encodeURIComponent(relayState)}`;
    } catch (error) {
      this.#logouts.inc({ direction: "sp_initiated", outcome: "error" });
      this.#log.warn(
        { err: error, loginMethodId: upstream.loginMethodId },
        "SAML logout request not sent",
      );
      return undefined;
    }
  }

  /** The HTTP-POST page of an SP-initiated LogoutRequest (rendered once). */
  async logoutForm(
    tenantProvider: TenantProvider,
    relayState: string,
  ): Promise<AutoPostForm | null> {
    if (relayState.length === 0 || relayState.length > 512) return null;
    const { oidcPayloads } = this.#options.repos;
    const { tenant } = tenantProvider;
    const id = hashToken(relayState);
    const stored = await oidcPayloads.find(tenant.id, LOGOUT_POST_KIND, id);
    const parsed = logoutPostSchema.safeParse(stored);
    if (!parsed.success || stored?.consumed !== undefined) return null;
    const { consumed } = await oidcPayloads.consume(tenant.id, LOGOUT_POST_KIND, id);
    return consumed ? { action: parsed.data.action, fields: parsed.data.fields } : null;
  }

  /**
   * The SLO endpoint (HTTP-Redirect or HTTP-POST): an IdP-initiated LogoutRequest ends the
   * broker sessions of that person and login method and is answered with a signed
   * LogoutResponse; a LogoutResponse to an SP-initiated logout continues to where the local
   * logout was going. Failures never undo or block the local logout.
   */
  async slo(
    tenantProvider: TenantProvider,
    loginMethodId: string,
    params: SloParameters,
  ): Promise<SloOutcome> {
    const { tenant } = tenantProvider;
    if (!UUID.test(loginMethodId)) return { kind: "refused", status: 404 };
    const method = await this.#method(tenant.id, loginMethodId);
    if (method === null) return { kind: "refused", status: 404 };
    const metadata = await this.idpMetadata(method);
    const signer = await this.#signer(tenant.id, method.id);
    if (metadata === null || signer === undefined) return { kind: "refused", status: 503 };
    const sp = this.spEndpoints(tenant.slug, method.id);
    const now = Date.now();

    let message;
    try {
      message = await readLogoutMessage(sp, metadata, params, {
        clockSkewSeconds: method.saml.clockSkewSeconds,
        now,
      });
    } catch (error) {
      const reason =
        error instanceof ResponseRejected || error instanceof XmlError ? error.reason : "error";
      this.#logouts.inc({ direction: "unknown", outcome: "refused" });
      this.#log.info({ loginMethodId, reason }, "SAML logout message refused");
      // A response to our own logout still ends where the local logout was going.
      const relayState = relayStateOf(params);
      if (isResponse(params) && relayState !== undefined) {
        const pending = await this.#consumeLogoutState(tenant.id, relayState);
        if (pending !== null) {
          return { kind: "redirect", url: await this.#continueLogout(tenant, pending) };
        }
      }
      return { kind: "refused", status: 400 };
    }

    if (message.kind === "response") {
      const pending =
        message.relayState === undefined
          ? null
          : await this.#consumeLogoutState(tenant.id, message.relayState);
      const success =
        message.verified &&
        pending !== null &&
        pending.loginMethodId === method.id &&
        message.inResponseTo === pending.requestId &&
        message.issuer === metadata.entityId &&
        message.status?.code === SAML_STATUS.success;
      this.#logouts.inc({ direction: "sp_initiated", outcome: success ? "success" : "failure" });
      if (pending !== null) {
        await this.#options.auditLog.record({
          action: "session.logout",
          tenantId: tenant.id,
          actor: { type: "system", id: null },
          subject: { type: "login_method", id: method.id },
          details: {
            initiator: "slo",
            loginMethodId: method.id,
            upstream: success ? "success" : "failure",
          },
        });
      }
      if (!success) {
        this.#log.info(
          { loginMethodId, verified: message.verified },
          "SAML logout response not successful",
        );
      }
      return pending === null
        ? { kind: "logged_out" }
        : { kind: "redirect", url: await this.#continueLogout(tenant, pending) };
    }

    // A signed LogoutRequest is accepted once (its ID, per tenant and login method).
    const first = await this.#options.repos.saml.rememberAssertion(
      tenant.id,
      method.id,
      `logout-request:${message.id}`,
      new Date(now + LOGOUT_REQUEST_REPLAY_SECONDS * 1000),
    );
    if (!first) {
      this.#logouts.inc({ direction: "idp_initiated", outcome: "replayed" });
      this.#log.info({ loginMethodId }, "SAML LogoutRequest replayed");
      return { kind: "refused", status: 400 };
    }
    const keys = this.#options.keys;
    const ended = await tenantProvider.loginState.endSessionsOfUpstream(
      method.id,
      nameIdIndexCandidates(keys, method.id, message.nameId),
      message.sessionIndexes.length === 0
        ? undefined
        : message.sessionIndexes.flatMap((index) => sessionIndexCandidates(keys, method.id, index)),
    );
    this.#logouts.inc({ direction: "idp_initiated", outcome: "success" });
    await this.#options.auditLog.record({
      action: "session.logout",
      tenantId: tenant.id,
      actor: { type: "system", id: null },
      subject: { type: "login_method", id: method.id },
      details: { initiator: "idp", loginMethodId: method.id, sessions: ended },
    });
    try {
      const response = await buildLogoutResponse(
        sp,
        metadata,
        signer,
        { id: message.id, relayState: message.relayState },
        true,
      );
      return response.binding === "redirect"
        ? { kind: "redirect", url: response.url }
        : { kind: "post", form: { action: response.url, fields: response.fields } };
    } catch (error) {
      this.#log.warn({ err: error, loginMethodId }, "SAML logout response not sent");
      return { kind: "logged_out" };
    }
  }

  /**
   * The IdP metadata of a login method: the cached copy (a login never fetches the metadata
   * URL while one exists). It fails closed (`null`) once its validUntil has passed, or, without a
   * validUntil, once it is older than SAML_METADATA_MAX_AGE. Without a cached copy (never
   * fetched yet), inline metadata is parsed and a metadata URL fetched once.
   */
  async idpMetadata(method: SamlLoginMethod): Promise<IdpMetadata | null> {
    const { repos, config } = this.#options;
    const cache = await repos.saml.metadataCache(method.tenantId, method.id);
    if (cache.metadata !== null) {
      const now = Date.now();
      const validUntil = cache.metadata.validUntil;
      const tooOld =
        validUntil === null &&
        cache.cachedAt !== null &&
        now - cache.cachedAt.getTime() > config.federation.samlMetadataMaxAgeSeconds * 1000;
      if ((validUntil !== null && validUntil <= now) || tooOld) {
        this.#log.warn(
          { loginMethodId: method.id, reason: tooOld ? "too_old" : "expired" },
          "cached IdP metadata is no longer valid; the login method is unavailable",
        );
        return null;
      }
      return cache.metadata;
    }
    if (cache.cachedAt !== null || cache.error === "entity_not_found") return null;
    const result = await this.refreshMetadata(method.tenantId, method.id, {
      idpEntityId: method.saml.idpEntityId,
      metadataUrl: method.saml.metadataUrl,
      metadataXml: method.saml.metadataXml,
      signingCertificate: method.saml.metadataSigningCertificate,
    });
    return result.ok ? result.metadata : null;
  }

  /**
   * Loads, checks and caches the metadata of a login method from its source. A failure keeps
   * the last good metadata, records the reason and is counted and logged, except an entity that
   * is no longer listed in a metadata document that is otherwise valid (and correctly signed,
   * with a signing certificate): it was removed, so the cached copy is dropped (fail closed).
   */
  async refreshMetadata(
    tenantId: string,
    loginMethodId: string,
    source: {
      readonly idpEntityId: string;
      readonly metadataUrl: string | null;
      readonly metadataXml: string | null;
      readonly signingCertificate: string | null;
    },
  ): Promise<
    | { readonly ok: true; readonly metadata: IdpMetadata }
    | { readonly ok: false; readonly reason: string }
  > {
    const { repos } = this.#options;
    const expected = {
      url: source.metadataUrl,
      xml: source.metadataXml,
      signingCertificate: source.signingCertificate,
      entityId: source.idpEntityId,
    };
    try {
      const metadata = await withOutboundContext({ loginMethodId, purpose: "saml_metadata" }, () =>
        this.loadMetadata(source),
      );
      await repos.saml.storeMetadata(tenantId, loginMethodId, metadata, expected);
      this.#metadataRefresh.inc({ outcome: "success" });
      return { ok: true, metadata };
    } catch (error) {
      const reason = error instanceof MetadataError ? error.reason : "fetch_failed";
      this.#metadataRefresh.inc({ outcome: "failure", reason });
      if (reason === "entity_not_found") {
        this.#log.warn({ loginMethodId }, "the IdP is no longer in its metadata; cache dropped");
        await repos.saml.dropMetadata(tenantId, loginMethodId, reason, expected);
        return { ok: false, reason };
      }
      this.#log.warn(
        { loginMethodId, reason, error: error instanceof Error ? error.name : "unknown" },
        "SAML IdP metadata refresh failed; keeping the last good metadata",
      );
      await repos.saml.recordMetadataFailure(tenantId, loginMethodId, reason);
      return { ok: false, reason };
    }
  }

  /** Fetches (or reads inline) and checks IdP metadata. Throws {@link MetadataError}. */
  async loadMetadata(source: {
    readonly idpEntityId: string;
    readonly metadataUrl: string | null;
    readonly metadataXml: string | null;
    readonly signingCertificate: string | null;
  }): Promise<IdpMetadata> {
    let xml: string;
    if (source.metadataXml !== null) xml = source.metadataXml;
    else if (source.metadataUrl !== null) xml = await this.#fetchMetadata(source.metadataUrl);
    else throw new MetadataError("no_source", "no metadata source");
    return parseIdpMetadata(xml, {
      entityId: source.idpEntityId,
      signingCertificate: source.signingCertificate,
      now: new Date(),
    });
  }

  /** Scheduled refresh of every metadata URL that is due (all tenants). Returns how many ran. */
  async refreshDue(): Promise<number> {
    const due = await this.#options.repos.saml.listMetadataDue(
      METADATA_BATCH,
      METADATA_RETRY_SECONDS,
    );
    for (const target of due) {
      await this.refreshMetadata(target.tenantId, target.loginMethodId, {
        idpEntityId: target.idpEntityId,
        metadataUrl: target.metadataUrl,
        metadataXml: null,
        signingCertificate: target.signingCertificate,
      });
    }
    return due.length;
  }

  /** Fetches metadata through the outbound guard; failures become generic reason codes. */
  async #fetchMetadata(url: string): Promise<string> {
    let response: Response;
    try {
      response = await this.#options.outbound.fetch(url, {
        headers: { accept: "application/samlmetadata+xml, application/xml, text/xml" },
        maxBytes: MAX_XML_BYTES,
      });
    } catch (error) {
      if (error instanceof OutboundRefusedError) {
        this.#log.warn({ reason: error.reason }, "SAML metadata URL refused by the outbound guard");
        throw new MetadataError(
          error.reason === "too_large" ? "too_large" : "fetch_refused",
          "metadata URL refused",
        );
      }
      throw new MetadataError("fetch_failed", "metadata could not be fetched");
    }
    if (!response.ok) throw new MetadataError("http_status", "metadata URL did not answer 200");
    return response.text();
  }

  async #method(tenantId: string, loginMethodId: string): Promise<SamlLoginMethod | null> {
    const method = await this.#options.repos.loginMethods.findById(tenantId, loginMethodId);
    return method?.protocol === "saml" && method.enabled ? method : null;
  }

  async #signer(tenantId: string, loginMethodId: string): Promise<SpSigner | undefined> {
    const keys: SpKeyPair[] = await this.#options.repos.saml.spKeyPairs(
      tenantId,
      loginMethodId,
      "signing",
    );
    const active = keys.find((key) => key.state === "active");
    return active === undefined
      ? undefined
      : { privateKey: active.privateKey, certificate: active.certificate };
  }

  async #consumeLogoutState(
    tenantId: string,
    relayState: string,
  ): Promise<z.infer<typeof logoutStateSchema> | null> {
    if (relayState.length === 0 || relayState.length > 512) return null;
    const { oidcPayloads } = this.#options.repos;
    const id = hashToken(relayState);
    const stored = await oidcPayloads.find(tenantId, LOGOUT_STATE_KIND, id);
    const parsed = logoutStateSchema.safeParse(stored);
    if (!parsed.success || stored?.consumed !== undefined) return null;
    const { consumed } = await oidcPayloads.consume(tenantId, LOGOUT_STATE_KIND, id);
    return consumed ? parsed.data : null;
  }

  async #recordFailure(code: LoginErrorCode, context: FailureContext): Promise<void> {
    await this.#options.flow.recordFailure(code, context);
  }
}

/** Whether SLO parameters carry a SAMLResponse (by binding, without trusting anything else). */
function isResponse(params: SloParameters): boolean {
  if (params.binding === "post") return typeof params.fields.SAMLResponse === "string";
  return params.rawQuery.split("&").some((token) => token.startsWith("SAMLResponse="));
}

function relayStateOf(params: SloParameters): string | undefined {
  if (params.binding === "post") return params.fields.RelayState;
  const token = params.rawQuery.split("&").find((part) => part.startsWith("RelayState="));
  if (token === undefined) return undefined;
  try {
    return decodeURIComponent(token.slice("RelayState=".length).replace(/\+/g, " "));
  } catch {
    return undefined;
  }
}
