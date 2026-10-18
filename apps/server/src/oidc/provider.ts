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
import type { Config } from "../config/index.js";
import type { Tenant } from "../domain/tenant.js";
import type { LoadedKeys } from "../keys/key-cache.js";
import type { Logger } from "../logging/logger.js";
import type { Repositories } from "../repositories/index.js";
import { createAdapterFactory } from "./adapter.js";
import { CLAIMS_BY_SCOPE, ClaimsService } from "./claims.js";
import { clientIdFromResource, clientMetadataFor, resourceIndicatorFor } from "./clients.js";
import {
  LoginContextStore,
  PENDING_LOGIN_RESULT_KEY,
  pendingLoginSchema,
  rememberedLoginContext,
  rememberLoginContext,
  type LoginContext,
} from "./login-context.js";
import { renderErrorPage, renderLogoutPage, renderLogoutSuccessPage } from "./pages.js";
import type { SessionPolicy } from "./session-policy.js";

const SIGNING_ALG = "ES256";
const AUTHORIZATION_CODE_TTL_SECONDS = 60;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const epochNow = (): number => Math.floor(Date.now() / 1000);

export interface ProviderDependencies {
  readonly config: Config;
  readonly repos: Repositories;
  readonly logger: Logger;
  readonly sessionPolicy: SessionPolicy;
}

/** A built provider for one tenant, as cached by the registry. */
export interface TenantProvider {
  readonly tenant: Tenant;
  readonly issuer: string;
  /** Path of the issuer (`/t/{slug}`); everything of the tenant lives below it. */
  readonly basePath: string;
  readonly provider: Provider;
  readonly loginContexts: LoginContextStore;
  /** Signing key set the provider was built with. */
  readonly keysVersion: string;
  /** Tenant and application configuration the provider was built with. */
  readonly fingerprint: string;
  /** Hands a request below `basePath` (already stripped of it) to the provider. */
  readonly handle: (req: IncomingMessage, res: ServerResponse) => void;
}

/**
 * Builds the oidc-provider instance for one tenant: issuer `{PUBLIC_URL}/t/{slug}`, storage in
 * `oidc_payloads` scoped to the tenant, clients from the applications enabled for the tenant,
 * and the shared signing keys. Secure defaults: authorization code flow with PKCE (S256) for
 * every client, refresh token rotation, client_credentials, no implicit or hybrid flows, no
 * development interactions, no claims parameter, no request objects.
 */
export function buildTenantProvider(
  tenant: Tenant,
  keys: LoadedKeys,
  fingerprint: string,
  deps: ProviderDependencies,
): TenantProvider {
  const { config, repos, logger, sessionPolicy } = deps;
  const basePath = `/t/${tenant.slug}`;
  const issuer = `${config.publicUrl}${basePath}`;
  const issuerPath = new URL(issuer).pathname;
  const loginContexts = new LoginContextStore(tenant.id, repos.oidcPayloads);
  const claims = new ClaimsService(repos);
  const tokens = config.tokens;
  const log = logger.child({ tenant: tenant.slug });

  /** The login context for a token's session, cached for the rest of the request. */
  async function loginContextFor(
    ctx: KoaContextWithOIDC,
    sessionUid: string | undefined,
  ): Promise<LoginContext | undefined> {
    const remembered = rememberedLoginContext(ctx);
    if (remembered !== undefined) return remembered;
    const found = await loginContexts.find(sessionUid);
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
    return clientMetadataFor(application, secret);
  };

  const findAccount: FindAccount = async (ctx, sub, token) => {
    if (!UUID.test(sub)) return undefined;
    const person = await repos.persons.findById(tenant.id, sub);
    if (person === null) return undefined;
    // At the token endpoint (a code or refresh token) the session must still be known: claims
    // and lifetimes depend on how the person signed in, so without it the grant fails. During
    // authorization the login prompt checks it instead (see `policy` below), because the context
    // of a fresh login is only stored at the resume, after this runs.
    let login: LoginContext | undefined;
    if (token !== undefined) {
      login = await loginContextFor(ctx, (token as { sessionUid?: string }).sessionUid);
      if (login === undefined || login.personId !== sub) return undefined;
    }
    const account: Account = {
      accountId: sub,
      claims: async (use, scope) => {
        const context = login ?? (await loginContextFor(ctx, ctx.oidc.session?.uid));
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

  const extraTokenClaims: NonNullable<Configuration["extraTokenClaims"]> = async (ctx, token) => {
    if (token.kind === "ClientCredentials") return { tid: tenant.slug };
    const accessToken = token;
    const audience = typeof accessToken.aud === "string" ? accessToken.aud : undefined;
    if (accessToken.accountId === undefined || audience === undefined) {
      return { tid: tenant.slug };
    }
    const login = await loginContextFor(ctx, accessToken.sessionUid);
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

  /**
   * Implicit consent (first-party applications): the grant always covers the requested scopes,
   * which oidc-provider has already limited to the scopes the client may request. On the resume
   * after a login, this is also where the login context is stored: the session uid and the
   * login result are both known here, and it runs before the authorization code is issued.
   */
  const loadExistingGrant = async (ctx: KoaContextWithOIDC): Promise<Grant | undefined> => {
    const { session, client, result } = ctx.oidc;
    if (session === undefined || client === undefined || session.accountId === undefined) {
      return undefined;
    }
    if (ctx.oidc.route === "resume" && result?.login !== undefined) {
      await storeLoginContext(ctx, session.uid, session.accountId, client.clientId);
    } else {
      // An existing session: the grant expires with the session's real end, so load it now.
      await loginContextFor(ctx, session.uid);
    }
    const grantId =
      (result?.consent as { grantId?: string } | undefined)?.grantId ??
      session.grantIdFor(client.clientId);
    let grant = grantId === undefined ? undefined : await ctx.oidc.provider.Grant.find(grantId);
    if (grant !== undefined && grant.accountId !== session.accountId) grant = undefined;
    grant ??= new ctx.oidc.provider.Grant({
      accountId: session.accountId,
      clientId: client.clientId,
    });
    grant.addOIDCScope([...ctx.oidc.requestParamOIDCScopes].join(" "));
    await grant.save();
    return grant;
  };

  async function storeLoginContext(
    ctx: KoaContextWithOIDC,
    sessionUid: string,
    personId: string,
    clientId: string,
  ): Promise<void> {
    const pending = pendingLoginSchema.safeParse(ctx.oidc.result?.[PENDING_LOGIN_RESULT_KEY]);
    const { session } = ctx.oidc;
    if (!pending.success || session === undefined) {
      throw new errors.AccessDenied("the login did not complete");
    }
    const authTime = session.authTime() ?? epochNow();
    const context: LoginContext = {
      personId,
      loginMethodId: pending.data.loginMethodId,
      acr: session.acr ?? "",
      amr: session.amr ?? [],
      authTime,
      sessionExpiresAt: await sessionPolicy.sessionExpiresAt({
        tenantId: tenant.id,
        loginMethodId: pending.data.loginMethodId,
        authTime,
      }),
      clientId,
    };
    await loginContexts.save(sessionUid, context);
    rememberLoginContext(ctx, context);
  }

  /** Remaining seconds of the broker session, if the request knows it. */
  const remainingSession = (ctx: KoaContextWithOIDC | undefined, loginTs?: number): number => {
    const now = epochNow();
    const end =
      rememberedLoginContext(ctx)?.sessionExpiresAt ?? (loginTs ?? now) + tokens.sessionSeconds;
    return Math.max(1, end - now);
  };

  /**
   * The default prompts (login, consent) plus Portvakt's own login checks. M3 adds the session
   * policy checks (idle, allowSso, acr) here.
   */
  const policy = interactionPolicy.base();
  policy.get("login")?.checks.add(
    new interactionPolicy.Check(
      "login_context_missing",
      "the broker session must be established again",
      async (ctx) => {
        const { session, result } = ctx.oidc;
        if (session?.accountId === undefined || result?.login !== undefined) {
          return interactionPolicy.Check.NO_NEED_TO_PROMPT;
        }
        const context = await loginContextFor(ctx, session.uid);
        return context === undefined || context.personId !== session.accountId;
      },
    ),
  );

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
    claims: { ...CLAIMS_BY_SCOPE, acr: null, auth_time: null, sid: null, iss: null },
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
        // Only tokens of applications enabled in this tenant (the storage is tenant-scoped too).
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
        logoutSource: renderLogoutPage,
        postLogoutSuccessSource: renderLogoutSuccessPage,
      },
      resourceIndicators: {
        enabled: true,
        // The requesting application itself, so every access token is a JWT for it.
        defaultResource: (_ctx, client) => resourceIndicatorFor(client.clientId),
        useGrantedResource: () => true,
        getResourceServerInfo,
      },
    },
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
      Session: (ctx, session) => remainingSession(ctx, session.loginTs),
      Grant: (ctx) => remainingSession(ctx),
    },
    renderError: renderErrorPage,
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
    loginContexts,
    keysVersion: keys.version,
    fingerprint,
    handle: (req, res) => {
      void callback(req, res);
    },
  };
}
