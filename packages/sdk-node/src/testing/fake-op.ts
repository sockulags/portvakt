import { createHash, randomBytes, randomUUID } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo, Socket } from "node:net";
import {
  exportJWK,
  generateKeyPair,
  SignJWT,
  type CryptoKey,
  type JWK,
  type JWTPayload,
} from "jose";

/**
 * A minimal OpenID provider for the SDK's unit tests (no database): discovery, JWKS, an
 * authorization endpoint that answers at once, a token endpoint (code with PKCE, refresh token
 * rotation, client_credentials) and an end-session endpoint. It issues tokens shaped like
 * Portvakt's (claims contract v1). Integration tests use the real server instead.
 */
export interface FakeOp {
  readonly baseUrl: string;
  readonly issuer: string;
  readonly clientId: string;
  readonly clientSecret: string;
  /** Claims of the next logins' ID and access tokens (merged over the defaults). */
  claims: Record<string, unknown>;
  /** Lifetime of issued access tokens, seconds. */
  accessTokenTtl: number;
  /** Delay of every refresh response, milliseconds. */
  refreshDelayMs: number;
  /** Every refresh token grant answers `invalid_grant`. */
  refuseRefresh: boolean;
  /**
   * The kid the token endpoint signs ID and access tokens with (default: the first key). Set it
   * to a key from {@link addKey} to simulate a key rotation that activates a new key at once.
   */
  signingKid: string | undefined;
  /** Kids of keys that sign but are left out of the JWKS. */
  readonly unpublished: Set<string>;
  /** Token, JWKS and discovery requests fail at the network level (connection reset). */
  down: boolean;
  /** Token, JWKS and discovery requests answer this 5xx with an HTML page (a proxy's error). */
  serverError: number | undefined;
  /**
   * Code and refresh token grants answer this instead (a rate limit, `temporarily_unavailable`):
   * the status, the body (JSON when an object, else text/html) and an optional Retry-After.
   */
  tokenError:
    { readonly status: number; readonly body: unknown; readonly retryAfter?: string } | undefined;
  /** The same for client_credentials grants (which `tokenError` leaves alone). */
  clientCredentialsError:
    { readonly status: number; readonly body: unknown; readonly retryAfter?: string } | undefined;
  /**
   * Every token request fails client authentication as oidc-provider answers it: 401
   * `invalid_client`, plus a `WWW-Authenticate: Basic ...` challenge when the request carried an
   * Authorization header (client_secret_basic).
   */
  rejectClient: boolean;
  readonly counters: {
    refresh: number;
    jwks: number;
    discovery: number;
    token: number;
    /** Requests answered while `down` or in `serverError` mode. */
    failed: number;
  };
  /** Authorization request parameters, in order. */
  readonly authorizations: URLSearchParams[];
  /** Refresh tokens presented, in order (a replay shows up twice). */
  readonly presentedRefreshTokens: string[];
  signAccessToken(
    claims: JWTPayload,
    options?: { readonly kid?: string; readonly typ?: string; readonly key?: CryptoKey },
  ): Promise<string>;
  /** Adds a signing key (published in the JWKS); returns its kid. */
  addKey(kid?: string): Promise<string>;
  /** A key pair that is not published (tokens signed with it must be refused). */
  foreignKey(): Promise<{ readonly kid: string; readonly key: CryptoKey }>;
  close(): Promise<void>;
}

interface Key {
  readonly kid: string;
  readonly privateKey: CryptoKey;
  readonly publicJwk: JWK;
}

async function newKey(kid: string): Promise<Key> {
  const { privateKey, publicKey } = await generateKeyPair("ES256", { extractable: true });
  return {
    kid,
    privateKey,
    publicJwk: { ...(await exportJWK(publicKey)), kid, alg: "ES256", use: "sig" },
  };
}

const b64url = (buffer: Buffer): string => buffer.toString("base64url");

async function readBody(req: IncomingMessage): Promise<URLSearchParams> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  return new URLSearchParams(Buffer.concat(chunks).toString("utf8"));
}

export async function startFakeOp(): Promise<FakeOp> {
  const server: Server = createServer();
  const sockets = new Set<Socket>();
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const issuer = `${baseUrl}/t/fake`;
  const keys: Key[] = [await newKey("key-1")];
  const codes = new Map<
    string,
    { nonce: string; challenge: string; redirectUri: string; claims: Record<string, unknown> }
  >();
  const refreshTokens = new Map<string, Record<string, unknown>>();

  const signing = (): Key => keys.find((candidate) => candidate.kid === op.signingKid) ?? keys[0]!;

  const op: FakeOp = {
    baseUrl,
    issuer,
    clientId: "fake-app",
    clientSecret: "fake-app-secret-0123456789abcdef",
    claims: {},
    accessTokenTtl: 300,
    refreshDelayMs: 0,
    refuseRefresh: false,
    signingKid: undefined,
    unpublished: new Set(),
    down: false,
    serverError: undefined,
    tokenError: undefined,
    clientCredentialsError: undefined,
    rejectClient: false,
    counters: { refresh: 0, jwks: 0, discovery: 0, token: 0, failed: 0 },
    authorizations: [],
    presentedRefreshTokens: [],
    async signAccessToken(claims, options = {}) {
      const kid = options.kid ?? signing().kid;
      const key = keys.find((candidate) => candidate.kid === kid);
      return new SignJWT(claims)
        .setProtectedHeader({ alg: "ES256", typ: options.typ ?? "at+jwt", kid })
        .sign(options.key ?? key!.privateKey);
    },
    async addKey(kid = `key-${keys.length + 1}`) {
      keys.push(await newKey(kid));
      return kid;
    },
    async foreignKey() {
      const key = await newKey(`foreign-${randomUUID()}`);
      return { kid: key.kid, key: key.privateKey };
    },
    close: async () => {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };

  const now = (): number => Math.floor(Date.now() / 1000);

  const personClaims = (extra: Record<string, unknown>): Record<string, unknown> => ({
    sub: "3f2b8c4e-91d7-4a3e-8b6f-2d4c9e1a7b55",
    tid: "fake",
    idp: "0f1976f6-7f6c-4baf-a88c-2bc6f2e68ce7",
    idp_kind: "employee",
    acr: "http://id.elegnamnden.se/loa/1.0/loa3",
    auth_time: now(),
    roles: ["handlaggare"],
    attrs: { unit: "north" },
    session_exp: now() + 3600,
    name: "Anna Andersson",
    email: "anna@example.test",
    ...extra,
  });

  /** ID and access token claims are split like Portvakt's (access tokens are minimal). */
  async function issue(claims: Record<string, unknown>, nonce: string | undefined) {
    const {
      name: _n,
      email: _e,
      pin: _p,
      session_exp: _s,
      protected_identity: _pi,
      ...base
    } = claims;
    void [_n, _e, _p, _s, _pi];
    const rep = claims.rep as { sub: string; type: string } | undefined;
    const accessToken = await op.signAccessToken({
      ...base,
      ...(rep === undefined ? {} : { rep: { sub: rep.sub, type: rep.type } }),
      iss: issuer,
      aud: op.clientId,
      client_id: op.clientId,
      jti: randomUUID(),
      iat: now(),
      exp: now() + op.accessTokenTtl,
    });
    const idToken = await new SignJWT({ ...claims, ...(nonce === undefined ? {} : { nonce }) })
      .setProtectedHeader({ alg: "ES256", kid: signing().kid })
      .setIssuer(issuer)
      .setAudience(op.clientId)
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(signing().privateKey);
    const refreshToken = b64url(randomBytes(24));
    refreshTokens.set(refreshToken, claims);
    return {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: op.accessTokenTtl,
      refresh_token: refreshToken,
      id_token: idToken,
      scope: "openid profile email",
    };
  }

  const json = (res: ServerResponse, status: number, body: unknown): void => {
    res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" });
    res.end(JSON.stringify(body));
  };

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? "/", baseUrl);
    const path = url.pathname.replace(/^\/t\/fake/, "");
    if (op.down && path !== "/auth") {
      op.counters.failed += 1;
      req.socket.destroy();
      return;
    }
    if (op.serverError !== undefined && path !== "/auth") {
      op.counters.failed += 1;
      res.writeHead(op.serverError, { "content-type": "text/html" });
      res.end("<html><body>Bad gateway</body></html>");
      return;
    }
    if (path === "/.well-known/openid-configuration") {
      op.counters.discovery += 1;
      json(res, 200, {
        issuer,
        authorization_endpoint: `${issuer}/auth`,
        token_endpoint: `${issuer}/token`,
        jwks_uri: `${issuer}/jwks`,
        end_session_endpoint: `${issuer}/session/end`,
        response_types_supported: ["code"],
        subject_types_supported: ["public"],
        id_token_signing_alg_values_supported: ["ES256"],
        code_challenge_methods_supported: ["S256"],
        token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
      });
      return;
    }
    if (path === "/jwks") {
      op.counters.jwks += 1;
      json(res, 200, {
        keys: keys.filter((key) => !op.unpublished.has(key.kid)).map((key) => key.publicJwk),
      });
      return;
    }
    if (path === "/auth") {
      op.authorizations.push(url.searchParams);
      const code = b64url(randomBytes(16));
      const redirectUri = url.searchParams.get("redirect_uri") ?? "";
      codes.set(code, {
        nonce: url.searchParams.get("nonce") ?? "",
        challenge: url.searchParams.get("code_challenge") ?? "",
        redirectUri,
        claims: personClaims({
          ...(url.searchParams.get("acr_values") === null
            ? {}
            : { acr: url.searchParams.get("acr_values")!.split(" ")[0] }),
          ...op.claims,
        }),
      });
      const target = new URL(redirectUri);
      target.searchParams.set("code", code);
      target.searchParams.set("state", url.searchParams.get("state") ?? "");
      res.writeHead(302, { location: target.href });
      res.end();
      return;
    }
    if (path === "/session/end") {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("logged out");
      return;
    }
    if (path === "/token" && req.method === "POST") {
      op.counters.token += 1;
      const body = await readBody(req);
      const authorization = req.headers.authorization ?? "";
      if (!authorization.startsWith("Basic ") && body.get("client_secret") === null) {
        json(res, 401, { error: "invalid_client" });
        return;
      }
      const grantType = body.get("grant_type");
      if (op.rejectClient) {
        if (grantType === "refresh_token") {
          op.counters.refresh += 1;
          op.presentedRefreshTokens.push(body.get("refresh_token") ?? "");
        }
        res.writeHead(401, {
          "content-type": "application/json",
          "cache-control": "no-store",
          ...(authorization === ""
            ? {}
            : {
                "www-authenticate": `Basic realm="${issuer}", error="invalid_client", error_description="client authentication failed"`,
              }),
        });
        res.end(
          JSON.stringify({
            error: "invalid_client",
            error_description: "client authentication failed",
          }),
        );
        return;
      }
      const refused =
        grantType === "client_credentials" ? op.clientCredentialsError : op.tokenError;
      if (refused !== undefined) {
        if (grantType === "refresh_token") {
          op.counters.refresh += 1;
          op.presentedRefreshTokens.push(body.get("refresh_token") ?? "");
        }
        const isJson = typeof refused.body === "object" && refused.body !== null;
        res.writeHead(refused.status, {
          "content-type": isJson ? "application/json" : "text/html",
          "cache-control": "no-store",
          ...(refused.retryAfter === undefined ? {} : { "retry-after": refused.retryAfter }),
        });
        res.end(
          isJson
            ? JSON.stringify(refused.body)
            : typeof refused.body === "string"
              ? refused.body
              : "",
        );
        return;
      }
      if (grantType === "authorization_code") {
        const entry = codes.get(body.get("code") ?? "");
        codes.delete(body.get("code") ?? "");
        const verifier = body.get("code_verifier") ?? "";
        const challenge = b64url(createHash("sha256").update(verifier).digest());
        if (
          entry === undefined ||
          entry.challenge !== challenge ||
          entry.redirectUri !== body.get("redirect_uri")
        ) {
          json(res, 400, { error: "invalid_grant" });
          return;
        }
        json(res, 200, await issue(entry.claims, entry.nonce));
        return;
      }
      if (grantType === "refresh_token") {
        op.counters.refresh += 1;
        const presented = body.get("refresh_token") ?? "";
        op.presentedRefreshTokens.push(presented);
        if (op.refreshDelayMs > 0) {
          await new Promise((resolve) => setTimeout(resolve, op.refreshDelayMs));
        }
        const claims = refreshTokens.get(presented);
        refreshTokens.delete(presented);
        if (claims === undefined || op.refuseRefresh) {
          json(res, 400, { error: "invalid_grant", error_description: "grant request is invalid" });
          return;
        }
        json(res, 200, await issue({ ...claims, ...op.claims }, undefined));
        return;
      }
      if (grantType === "client_credentials") {
        const resource = body.get("resource") ?? `urn:portvakt:app:${op.clientId}`;
        const audience = resource.replace(/^urn:portvakt:app:/, "");
        json(res, 200, {
          access_token: await op.signAccessToken({
            iss: issuer,
            aud: audience,
            sub: op.clientId,
            client_id: op.clientId,
            tid: "fake",
            jti: randomUUID(),
            iat: now(),
            exp: now() + op.accessTokenTtl,
          }),
          token_type: "Bearer",
          expires_in: op.accessTokenTtl,
        });
        return;
      }
      json(res, 400, { error: "unsupported_grant_type" });
      return;
    }
    json(res, 404, { error: "not_found" });
  }

  server.on("request", (req, res) => {
    handle(req, res).catch(() => {
      if (!res.headersSent) json(res, 500, { error: "server_error" });
    });
  });
  return op;
}
