import { randomBytes } from "node:crypto";
import express, { Router, type Request, type Response } from "express";
import { decodeJwt, decodeProtectedHeader, exportJWK, generateKeyPair, SignJWT } from "jose";
import Provider, {
  type Account,
  type ClientMetadata,
  type Configuration,
  type KoaContextWithOIDC,
} from "oidc-provider";
import type { IssuerKind, MockClient } from "./clients.js";
import { MemoryStore } from "./memory-adapter.js";
import { renderLoginPage } from "./page.js";
import {
  LOA_RANKING,
  PERSONAL_IDENTITY_NUMBER_CLAIM,
  MOCK_ENTRA_TENANT_ID,
  type Citizen,
  type Employee,
  type Personas,
} from "./personas.js";

/** A persona as one issuer sees it: the subject, the claims, and the strongest acr it can do. */
interface IssuerPersona {
  readonly id: string;
  readonly label: string;
  readonly detail: string;
  readonly subject: string;
  readonly email: string | undefined;
  readonly maxAcr: string | undefined;
  readonly claims: () => Record<string, unknown>;
}

function employeePersona(employee: Employee): IssuerPersona {
  return {
    id: employee.id,
    label: employee.name,
    detail: employee.groupsOverage ? `${employee.email} (groups overage)` : employee.email,
    subject: employee.oid,
    email: employee.email,
    maxAcr: undefined,
    claims: () => ({
      sub: employee.oid,
      oid: employee.oid,
      tid: employee.tid,
      name: employee.name,
      email: employee.email,
      // Entra ID with too many groups: the claim is replaced by a pointer to Microsoft Graph.
      ...(employee.groupsOverage
        ? {
            _claim_names: { groups: "src1" },
            _claim_sources: {
              src1: {
                endpoint: `https://graph.microsoft.com/v1.0/users/${employee.oid}/getMemberObjects`,
              },
            },
          }
        : { groups: [...employee.groups] }),
    }),
  };
}

function citizenPersona(citizen: Citizen): IssuerPersona {
  return {
    id: citizen.id,
    label: `${citizen.givenName} ${citizen.familyName}`,
    detail: `${citizen.pin.slice(0, 8)}-${citizen.pin.slice(8)}${
      citizen.protectedIdentity ? " (protected identity)" : ""
    } ${citizen.acr.split("/").at(-1) ?? ""}`,
    subject: citizen.sub,
    email: undefined,
    maxAcr: citizen.acr,
    claims: () => ({
      sub: citizen.sub,
      [PERSONAL_IDENTITY_NUMBER_CLAIM]: citizen.pin,
      name: `${citizen.givenName} ${citizen.familyName}`,
      given_name: citizen.givenName,
      family_name: citizen.familyName,
      ...(citizen.protectedIdentity ? { protected_identity: true } : {}),
    }),
  };
}

const rank = (acr: string): number => (LOA_RANKING as readonly string[]).indexOf(acr);

/**
 * The acr a persona authenticates with: the first requested value it can reach (Swedish eID
 * levels), or its own maximum when nothing is requested. `null` when no requested level is
 * possible for it.
 */
export function acrFor(
  persona: { maxAcr: string | undefined },
  requested: string[],
): string | null | undefined {
  // Entra ID style issuers do not speak acr: requested values are ignored, none is returned.
  if (persona.maxAcr === undefined) return undefined;
  if (requested.length === 0) return persona.maxAcr;
  const reachable = requested.find(
    (value) => rank(value) >= 0 && rank(value) <= rank(persona.maxAcr!),
  );
  return reachable ?? null;
}

export interface MockIssuer {
  readonly kind: IssuerKind;
  /** The issuer of the ID tokens. */
  readonly issuer: string;
  /** What a login method configures as its issuer (`entra-mt`: the /organizations alias). */
  readonly configuredIssuer: string;
  /** Paths the router is mounted at. */
  readonly mountPaths: readonly string[];
  readonly provider: Provider;
  readonly router: Router;
  registerClient(client: MockClient): void;
  /** `aud` of the last private_key_jwt client assertion a client authenticated with. */
  lastClientAssertionAudience(clientId: string): unknown;
}

const ENTRA_CLAIMS: Configuration["claims"] = {
  openid: ["sub", "oid", "tid", "groups", "amr"],
  profile: ["name"],
  email: ["email"],
};

const CLAIMS: Record<IssuerKind, Configuration["claims"]> = {
  entra: ENTRA_CLAIMS,
  "entra-mt": ENTRA_CLAIMS,
  bankid: {
    openid: ["sub", "acr", "amr", PERSONAL_IDENTITY_NUMBER_CLAIM, "protected_identity"],
    profile: ["name", "given_name", "family_name"],
  },
};

const AMR: Record<IssuerKind, string[]> = {
  entra: ["pwd", "mfa"],
  "entra-mt": ["pwd", "mfa"],
  bankid: ["mfa"],
};

/**
 * One mock upstream IdP (`{publicUrl}/{kind}`) built on oidc-provider: code flow with PKCE,
 * client_secret_basic / client_secret_post / private_key_jwt client authentication, userinfo,
 * and a login page listing the personas. `login_hint` with a persona id (or an employee's
 * email) signs that persona in without the page; `login_hint=cancel` answers `access_denied`.
 */
export async function createMockIssuer(options: {
  readonly kind: IssuerKind;
  readonly publicUrl: string;
  readonly personas: Personas;
}): Promise<MockIssuer> {
  const { kind } = options;
  const entraLike = kind !== "bankid";
  // Multi-tenant Entra: tokens come from the tenant's issuer; discovery at /organizations
  // reports the issuer as a {tenantid} template (as Entra ID does).
  const basePath = kind === "entra-mt" ? `/entra-mt/${MOCK_ENTRA_TENANT_ID}/v2.0` : `/${kind}`;
  const aliasPath = kind === "entra-mt" ? "/entra-mt/organizations/v2.0" : undefined;
  const issuer = `${options.publicUrl}${basePath}`;
  const personas: IssuerPersona[] = entraLike
    ? options.personas.entra.map(employeePersona)
    : options.personas.bankid.map(citizenPersona);
  const bySubject = new Map(personas.map((persona) => [persona.subject, persona]));
  const store = new MemoryStore();
  const clients = new Map<string, MockClient>();

  // Entra signs with RS256, the BankID broker with ES256: Portvakt must accept both.
  const alg = entraLike ? "RS256" : "ES256";
  const { privateKey } = await generateKeyPair(alg, { extractable: true });
  const jwk = {
    ...(await exportJWK(privateKey)),
    alg,
    use: "sig",
    kid: `${kind}-${randomBytes(4).toString("hex")}`,
  };

  const toMetadata = (client: MockClient): ClientMetadata => ({
    client_id: client.client_id,
    ...(client.client_secret === undefined ? {} : { client_secret: client.client_secret }),
    token_endpoint_auth_method: client.token_endpoint_auth_method,
    ...(client.jwks_uri === undefined ? {} : { jwks_uri: client.jwks_uri }),
    redirect_uris:
      client.redirect_uris.length > 0
        ? [...client.redirect_uris]
        : [...client.redirect_uri_prefixes],
    grant_types: ["authorization_code"],
    response_types: ["code"],
    id_token_signed_response_alg: alg,
    // ID tokens carry auth_time (removed again for `omit_auth_time` clients).
    require_auth_time: true,
  });

  const configuration: Configuration = {
    adapter: (model: string) =>
      model === "Client"
        ? {
            ...store.adapterFor("Client"),
            find: (id: string) => {
              const client = clients.get(id);
              return Promise.resolve(client === undefined ? undefined : toMetadata(client));
            },
          }
        : store.adapterFor(model),
    jwks: { keys: [jwk] },
    cookies: {
      keys: [randomBytes(32).toString("base64url")],
      names: {
        session: `_mock_${kind}_session`,
        interaction: `_mock_${kind}_interaction`,
        resume: `_mock_${kind}_resume`,
      },
      long: { path: `/${kind}`, sameSite: "lax", httpOnly: true },
      short: { sameSite: "lax", httpOnly: true },
    },
    claims: CLAIMS[kind],
    ...(kind === "bankid" ? { acrValues: [...LOA_RANKING] } : {}),
    // Entra puts the profile claims into the ID token; so does this mock.
    conformIdTokenClaims: false,
    clientAuthMethods: ["client_secret_basic", "client_secret_post", "private_key_jwt"],
    pkce: { required: () => true },
    responseTypes: ["code"],
    features: {
      devInteractions: { enabled: false },
      userinfo: { enabled: true },
      // Needed when another persona signs in over an existing session: oidc-provider ends the
      // old session first, through the logout confirmation.
      rpInitiatedLogout: { enabled: true },
    },
    findAccount: (_ctx, sub): Account | undefined => {
      const persona = bySubject.get(sub);
      if (persona === undefined) return undefined;
      return { accountId: sub, claims: () => persona.claims() as never };
    },
    // First-party mock: every requested scope is granted without a consent screen.
    loadExistingGrant: async (ctx: KoaContextWithOIDC) => {
      const { session, client } = ctx.oidc;
      if (session?.accountId === undefined || client === undefined) return undefined;
      const grantId = session.grantIdFor(client.clientId);
      const existing =
        grantId === undefined ? undefined : await ctx.oidc.provider.Grant.find(grantId);
      const grant =
        existing ??
        new ctx.oidc.provider.Grant({ accountId: session.accountId, clientId: client.clientId });
      grant.addOIDCScope([...ctx.oidc.requestParamOIDCScopes].join(" "));
      await grant.save();
      return grant;
    },
    interactions: { url: (_ctx, interaction) => `${basePath}/interaction/${interaction.uid}` },
    // Development tool: oidc-provider's SSRF guard refuses loopback addresses, but here the
    // client JWKS (Portvakt's federation JWKS for private_key_jwt) is on localhost.
    fetch: (input, init) => {
      const options: RequestInit & { dispatcher?: unknown } = { ...init };
      delete options.dispatcher;
      return globalThis.fetch(input, options);
    },
    ttl: {
      AccessToken: 300,
      AuthorizationCode: 60,
      IdToken: 300,
      Interaction: 600,
      Session: 3600,
      Grant: 3600,
    },
  };

  const provider = new Provider(issuer, configuration);
  provider.proxy = true;
  if (aliasPath !== undefined) {
    const template = `${options.publicUrl}/entra-mt/{tenantid}/v2.0`;
    provider.use(async (ctx, next) => {
      await next();
      const route = (ctx as { oidc?: { route?: string } }).oidc?.route;
      if (route === "discovery" && typeof ctx.body === "object" && ctx.body !== null) {
        ctx.body = { ...(ctx.body as Record<string, unknown>), issuer: template };
      }
    });
  }
  const assertionAudiences = new Map<string, unknown>();
  provider.on("grant.success", (ctx: KoaContextWithOIDC) => {
    const params = ctx.oidc.params as { client_assertion?: unknown } | undefined;
    const clientId = ctx.oidc.client?.clientId;
    if (typeof params?.client_assertion === "string" && clientId !== undefined) {
      assertionAudiences.set(clientId, decodeJwt(params.client_assertion).aud);
    }
  });
  // Exact redirect URIs, or (development prefixes) any redirect URI below a registered prefix.
  provider.Client.prototype.redirectUriAllowed = function redirectUriAllowed(
    this: InstanceType<typeof provider.Client>,
    redirectUri: string,
  ): boolean {
    const client = clients.get(this.clientId);
    if (client?.redirect_uri_prefixes.some((prefix) => redirectUri.startsWith(prefix)) === true) {
      return true;
    }
    return client?.redirect_uris.includes(redirectUri) === true;
  };

  const router = Router();
  // Test aid (`omit_auth_time` clients): the token response's ID token is re-signed without
  // auth_time, as an upstream that ignores max_age would send it.
  const withoutAuthTime = async (text: string): Promise<string | undefined> => {
    const body = JSON.parse(text) as { id_token?: unknown };
    if (typeof body.id_token !== "string") return undefined;
    const claims = decodeJwt(body.id_token);
    const client = typeof claims.aud === "string" ? clients.get(claims.aud) : undefined;
    if (client?.omit_auth_time !== true) return undefined;
    const kept: Record<string, unknown> = { ...claims };
    delete kept.auth_time;
    const header = decodeProtectedHeader(body.id_token);
    body.id_token = await new SignJWT(kept)
      .setProtectedHeader({ alg, ...(header.kid === undefined ? {} : { kid: header.kid }) })
      .sign(privateKey);
    return JSON.stringify(body);
  };
  router.post("/token", (_req, res, next) => {
    const end = res.end.bind(res) as (chunk?: unknown) => Response;
    res.end = ((chunk?: unknown) => {
      const text = Buffer.isBuffer(chunk) ? chunk.toString("utf8") : chunk;
      if (typeof text !== "string" || !text.includes("id_token")) return end(chunk);
      withoutAuthTime(text)
        .catch(() => undefined)
        .then((replaced) => {
          if (replaced === undefined) return end(chunk);
          res.setHeader("Content-Length", Buffer.byteLength(replaced));
          return end(replaced);
        })
        .catch(() => undefined);
      return res;
    }) as typeof res.end;
    next();
  });
  const finish = async (req: Request, res: Response, persona: IssuerPersona | "cancel") => {
    const details = await provider.interactionDetails(req, res);
    if (persona === "cancel") {
      await provider.interactionFinished(
        req,
        res,
        { error: "access_denied", error_description: "The user cancelled the login" },
        { mergeWithLastSubmission: false },
      );
      return;
    }
    const requested =
      typeof details.params.acr_values === "string"
        ? details.params.acr_values.split(" ").filter((value) => value.length > 0)
        : [];
    const acr = acrFor(persona, requested);
    if (acr === null) {
      await provider.interactionFinished(
        req,
        res,
        {
          error: "unmet_authentication_requirements",
          error_description: "The persona cannot reach the requested level of assurance",
        },
        { mergeWithLastSubmission: false },
      );
      return;
    }
    await provider.interactionFinished(
      req,
      res,
      {
        login: {
          accountId: persona.subject,
          amr: AMR[kind],
          ...(acr === undefined ? {} : { acr }),
          ts: Math.floor(Date.now() / 1000),
        },
      },
      { mergeWithLastSubmission: false },
    );
  };
  const byHint = (hint: unknown): IssuerPersona | "cancel" | undefined => {
    if (typeof hint !== "string") return undefined;
    if (hint === "cancel") return "cancel";
    return personas.find((persona) => persona.id === hint || persona.email === hint);
  };

  router.get("/interaction/:uid", (req, res, next) => {
    void (async () => {
      const details = await provider.interactionDetails(req, res);
      const hinted = byHint(details.params.login_hint);
      if (hinted !== undefined) {
        await finish(req, res, hinted);
        return;
      }
      res
        .status(200)
        .set({ "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" })
        .send(
          renderLoginPage({
            kind,
            action: `${basePath}/interaction/${encodeURIComponent(details.uid)}`,
            personas: personas.map(({ id, label, detail }) => ({ id, label, detail })),
          }),
        );
    })().catch(next);
  });
  router.post(
    "/interaction/:uid/login",
    express.urlencoded({ extended: false, limit: "2kb" }),
    (req, res, next) => {
      void (async () => {
        const chosen = byHint((req.body as { persona?: unknown }).persona);
        if (chosen === undefined || chosen === "cancel") {
          res.status(400).send("Unknown persona");
          return;
        }
        await finish(req, res, chosen);
      })().catch(next);
    },
  );
  router.post("/interaction/:uid/cancel", (req, res, next) => {
    finish(req, res, "cancel").catch(next);
  });
  const callback = provider.callback();
  router.use((req, res) => {
    void callback(req, res);
  });

  return {
    kind,
    issuer,
    configuredIssuer: aliasPath === undefined ? issuer : `${options.publicUrl}${aliasPath}`,
    mountPaths: aliasPath === undefined ? [basePath] : [basePath, aliasPath],
    provider,
    router,
    lastClientAssertionAudience: (clientId) => assertionAudiences.get(clientId),
    registerClient(client) {
      if (client.issuer !== kind) throw new Error(`client for ${client.issuer}, not ${kind}`);
      clients.set(client.client_id, client);
    },
  };
}
