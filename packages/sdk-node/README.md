# @portvakt/sdk-node

Portvakt for Node.js (20 or later) and Express 4 or 5:

- **BFF** (backend for frontend): server-side sessions for web applications, login with the
  authorization code flow and PKCE, refresh token rotation, step-up, representation switch and
  logout. The browser only holds a signed, opaque session cookie; tokens never reach it.
- **API validation**: Express middleware that validates Portvakt access tokens (JWT, ES256) and
  checks roles, assurance level, service callers and representation.
- **Service-to-service**: cached `client_credentials` tokens for calling another application of
  the tenant.

ESM only. Dependencies: `jose`, `openid-client`, `zod`. Peer dependencies: `express` (4.21+ or 5),
and optionally `pg` for `PgSessionStore`.

## Install

```sh
npm install @portvakt/sdk-node express
npm install pg   # only for PgSessionStore
```

## One client per application

```ts
import { createPortvaktClient } from "@portvakt/sdk-node";

const portvakt = createPortvaktClient({
  issuer: "https://login.example.org/t/kommunen", // the tenant's issuer, exactly
  clientId: "case-service",
  clientAuth: { method: "client_secret_basic", clientSecret: process.env.CLIENT_SECRET! },
  redirectUri: "https://case.example.org/auth/callback",
  postLogoutRedirectUri: "https://case.example.org/",
});
```

The configuration is validated at once (`PortvaktConfigError` lists every problem, never a secret
value). Portvakt itself is contacted lazily; discovery metadata is cached and refreshed.

## BFF quick start

```ts
import express from "express";
import { MemoryStore } from "@portvakt/sdk-node";

const bff = portvakt.bff({
  sessionStore: new MemoryStore(), // PgSessionStore in production
  encryptionKey: process.env.SESSION_ENCRYPTION_KEY!, // 32 random bytes, base64
  cookie: {
    name: "case_session",
    secrets: [process.env.COOKIE_SECRET!], // at least 32 characters
    secure: true,
    sameSite: "lax",
  },
});

const app = express();
app.use(bff); // GET /auth/login, /auth/callback, /auth/session, /auth/step-up,
// /auth/select-representation; POST /auth/logout

app.get("/cases", bff.requireLogin(), async (req, res, next) => {
  try {
    const principal = bff.principal(req)!; // the signed-in person (from the ID token)
    const token = await bff.getAccessToken(req); // fresh, refreshed under a per-session lock
    const response = await fetch("https://api.example.org/cases", {
      headers: { authorization: `Bearer ${token}` },
    });
    res.json({ for: principal.sub, cases: await response.json() });
  } catch (error) {
    next(error);
  }
});

app.post("/cases/:id/decide", bff.requireAcr("http://id.elegnamnden.se/loa/1.0/loa4"), handler);
app.use(bff.errorHandler()); // LoginRequiredError -> 401/redirect, PortvaktUnavailableError -> 503
```

### Routes

| Route                                  | What it does                                                                                                                                                                                                   |
| -------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GET /auth/login`                      | Starts a login. Query: `returnTo` (same-origin relative path; anything else falls back to `defaultReturnTo`), `acr`, `prompt` (`login`, `select_account`, `none`), `loginHint`, `uiLocales`.                   |
| `GET /auth/callback`                   | Verifies the pending login (single use, bound to the browser by a cookie), state, PKCE and nonce, validates the ID token, then starts a **new** session id and redirects to `returnTo`.                        |
| `POST /auth/logout`                    | Requires the CSRF token (`_csrf` form field or `X-CSRF-Token` header). Ends the session and redirects to Portvakt's end-session endpoint with `id_token_hint` and `post_logout_redirect_uri` (JSON for fetch). |
| `GET /auth/session`                    | JSON for SPAs: `authenticated`, `principal` (without `pin`), `expiresAt`, `sessionEndsAt`, `csrfToken`. Never tokens. Not counted as activity.                                                                 |
| `GET /auth/select-representation`      | A new authorization with `prompt=select_account`: the representation chooser, without a new upstream login.                                                                                                    |
| `GET /auth/step-up?acr=...&returnTo=/` | A new authorization with `acr_values`; the callback answers 403 `acr_not_met` if the login did not reach it.                                                                                                   |

`requireLogin()` and `requireAcr(acr)` redirect browser navigations (`Sec-Fetch-Mode: navigate`, or
a GET accepting HTML) to the login or step-up and answer XHR/fetch with 401 JSON:
`{ "error": "login_required", "loginUrl" }` or `{ "error": "step_up_required", "acr", "stepUpUrl" }`.

Step-up and the representation switch replace the session's login, so another site must not be
able to start them; the same holds for `/auth/login` with `acr` or `prompt`, and for any login
while a session exists. When the browser sends `Sec-Fetch-Site`, it must be `same-origin` or
`none` (otherwise 403 `cross_site_request`); without it, a same-origin `Referer` or the session's
CSRF token as `csrf` query parameter is required. Plain links from your own pages work as they
are, and a plain login without a session may be linked from anywhere.
A step-up whose login does not reach the requested level answers 403 `acr_not_met` and leaves
the existing session exactly as it was.

### Session semantics

- Sessions are server-side only. The cookie holds a random id, HMAC-signed; the store key is its
  SHA-256 hash, and the stored value is AES-256-GCM encrypted (tokens and profile claims never sit
  in the store in the clear; the store key is bound as additional data).
- A session ends at the earliest of: the ID token's `session_exp` (the broker session's end),
  `maxAgeSeconds` (default 12 h) and `idleTimeoutSeconds` without activity (default 30 min).
  Activity is `requireLogin`, `requireAcr`, `loadSession` and `getAccessToken`; reading
  `GET /auth/session` is not.
- `getAccessToken` refreshes when the token has less than `minValiditySeconds` left (default: clock
  skew + 30 s). Refreshes of one session never run concurrently: an in-process lock, plus the
  store's `withLock` across replicas (`PgSessionStore` uses an advisory lock). Portvakt rotates
  refresh tokens and treats a replay as theft, so concurrent refreshes would end the grant.
- A refused refresh (`invalid_grant`: grant revoked, representation no longer valid, broker
  session ended) ends the session: `LoginRequiredError`.
- Portvakt unreachable during a refresh (network error, timeout or a 5xx answer): with
  `outageGraceSeconds` 0 (default) the session ends. With a grace, the first failed refresh starts
  the outage: `getAccessToken` throws `PortvaktUnavailableError` (503) and the session continues.
  The session ends only when a refresh fails again after the grace has passed since that first
  failure; a successful refresh ends the outage. Requests that need no new token are never ended
  by an outage, and a token that is still valid needs no Portvakt. New logins fail with a clear
  page while Portvakt is unreachable.

### Session stores

`MemoryStore` is for development and single-instance demos (it logs a warning with
`NODE_ENV=production`). In production use `PgSessionStore`:

```ts
import pg from "pg";
import { migratePgSessionStore, PgSessionStore, pgSessionStoreSchema } from "@portvakt/sdk-node";

// Once, with a role that may create tables (or put pgSessionStoreSchema() in your migrations):
const owner = new pg.Pool({ connectionString: process.env.MIGRATION_DATABASE_URL, max: 1 });
await migratePgSessionStore(owner);
await owner.end();

// At runtime, with a role that has SELECT, INSERT, UPDATE and DELETE on the table:
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  max: 10,
  connectionTimeoutMillis: 10_000,
});
const store = new PgSessionStore({ pool, tableName: "portvakt_sessions" });
const stopCleanup = store.startCleanup(300); // deletes expired rows every 5 minutes
```

Pool sizing: a refresh holds one connection for its transaction-scoped advisory lock during one
round trip to Portvakt, and every store operation inside the lock runs on that same connection, so
the store never needs a second connection while it holds one. Size `max` for the concurrent
refreshes you expect plus ordinary reads (10 per instance suits most applications). When the pool
is exhausted, `withLock` gives up after `connectTimeoutSeconds` (default 10) with
`PortvaktUnavailableError`; a session lock held by another replica is waited for at most
`lockTimeoutSeconds` (default 15).

The runtime role needs `SELECT, INSERT, UPDATE, DELETE` on the table. Any object implementing
`SessionStore` (`get`, `set`, `destroy`, optional `withLock`) works too.

## API quick start

```ts
app.get(
  "/api/cases",
  portvakt.requireAccessToken({ audience: "case-service", anyRole: ["handlaggare", "admin"] }),
  (req, res) => {
    const principal = portvakt.principal(req)!;
    res.json({ caller: principal.sub });
  },
);
```

Options: `audience` (required: this API's client_id), `roles` (all required), `anyRole` (one of),
`acr` (minimum assurance level), `allowService` (`true` or a list of client_ids; default false),
`allowRepresentation` (default true). Role and acr requirements apply to person tokens; service
principals never have roles.

Failures answer with RFC 6750 errors and `WWW-Authenticate: Bearer realm="portvakt", error=...`:
400 `invalid_request` (malformed header), 401 without error (no token), 401 `invalid_token`,
403 `insufficient_scope` (with `reason`: `missing_role`, `service_not_allowed`,
`representation_not_allowed`), 401 `insufficient_user_authentication` with `acr_values` (RFC 9470),
and 503 `temporarily_unavailable` when Portvakt's keys were never fetched.

## Service-to-service

```ts
const tokens = portvakt.clientCredentials({ audience: "archive-service" });
const response = await fetch(url, {
  headers: { authorization: `Bearer ${await tokens.getToken()}` },
});
```

Tokens are cached until shortly before they expire (10% of the lifetime, at least 30 s) and
fetched once at a time. The target must be enabled in the same tenant.

## Principal

```ts
type Principal = PersonPrincipal | ServicePrincipal;
// PersonPrincipal: { isService: false, sub, tenant, idp, idpKind, acr, authTime, roles, attrs,
//   rep?, clientId?, name?, email?, pin?, hsaId?, orgAffiliation?, protectedIdentity? }
// ServicePrincipal: { isService: true, sub (= clientId), tenant, clientId, roles: [], attrs: {} }
```

Profile fields (`name`, `email`, `pin`, `hsaId`, `orgAffiliation`, `protectedIdentity`, `rep.name`)
come from the ID token and exist only in BFF sessions, never from access tokens. Helpers:
`hasRole(principal, role)` and `acrAtLeast(principalOrAcr, required, ranking?)` with Portvakt's
semantics and its default ranking (`DEFAULT_ACR_RANKING`: loa2 < loa3 < loa4).

## Configuration reference

| Option                               | Default                    | Meaning                                                                                                                                                                                            |
| ------------------------------------ | -------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `issuer`                             | required                   | The tenant issuer `{PUBLIC_URL}/t/{tenant}`, exactly (no trailing slash).                                                                                                                          |
| `clientId`                           | required                   | The application's client_id.                                                                                                                                                                       |
| `clientAuth`                         | required                   | `client_secret_basic`/`client_secret_post` with `clientSecret`, or                                                                                                                                 |
|                                      |                            | `private_key_jwt` with `privateJwk` (its public key registered in Portvakt).                                                                                                                       |
| `redirectUri`                        | (required for the BFF)     | `{origin}{mountPath}/callback`.                                                                                                                                                                    |
| `postLogoutRedirectUri`              | none                       | Registered post-logout URI.                                                                                                                                                                        |
| `scopes`                             | `openid profile email`     | Must include `openid`; `pin`/`hsa` only if the application is allowed them.                                                                                                                        |
| `clockSkewSeconds`                   | 30                         | Tolerance for `exp`, `nbf`, `iat`.                                                                                                                                                                 |
| `httpTimeoutSeconds`                 | 10                         | Every request to Portvakt.                                                                                                                                                                         |
| `discoveryCacheSeconds`              | 3600                       | Discovery is refetched after this (stale metadata is kept on failure).                                                                                                                             |
| `jwks.cacheMaxAgeSeconds`            | 600                        | Keys are refetched after this.                                                                                                                                                                     |
| `failureCacheSeconds`                | 5                          | With nothing cached, a failed discovery or JWKS fetch is retried after this.                                                                                                                       |
| `jwks.cooldownSeconds`               | 30                         | At most one JWKS fetch per this for access tokens; an unknown `kid` within it is refused. ID tokens from the token endpoint always refetch an unknown `kid` (a key rotation never ends a session). |
| `jwks.staleMaxAgeSeconds`            | 86400                      | While refetches fail, keys stay in use until `cacheMaxAgeSeconds` plus this                                                                                                                        |
|                                      |                            | after their last successful fetch; then validation answers 503.                                                                                                                                    |
| `outageGraceSeconds`                 | 0                          | See "Session semantics".                                                                                                                                                                           |
| `acrRanking`                         | `DEFAULT_ACR_RANKING`      | Must match Portvakt's `ACR_RANKING`.                                                                                                                                                               |
| `allowInsecureRequests`              | false                      | Allows an `http:` issuer (local development only).                                                                                                                                                 |
| `logger`                             | console (warnings, errors) | pino-compatible `{ debug, info, warn, error }(details, message)`.                                                                                                                                  |
| `fetch`                              | global fetch               | For proxies and tests.                                                                                                                                                                             |
| `bff.mountPath`                      | `/auth`                    | Where the BFF routes live.                                                                                                                                                                         |
| `bff.idleTimeoutSeconds`             | 1800                       | Idle timeout of the BFF session.                                                                                                                                                                   |
| `bff.maxAgeSeconds`                  | 43200                      | The BFF's own cap (the broker's `session_exp` caps it further).                                                                                                                                    |
| `bff.defaultReturnTo`                | `/`                        | After login without `returnTo`, after logout without a post-logout URI.                                                                                                                            |
| `bff.loginTimeoutSeconds`            | 600                        | How long a started login may take.                                                                                                                                                                 |
| `bff.cookie.*`                       | see above                  | `name` must differ between applications on one host (cookies ignore ports).                                                                                                                        |
| `bff.onError`, `bff.sessionResponse` | built in                   | Custom error page; custom `/auth/session` body.                                                                                                                                                    |

## Security notes

- **Issuer pinning is mandatory.** Portvakt signs the tokens of every tenant with the same keys,
  so a token of another tenant has a valid signature. The SDK accepts only `iss` exactly equal to
  the configured issuer, `typ: at+jwt`, ES256, and `aud` equal to the route's audience.
- **Protected identity.** When `protectedIdentity` is true, Portvakt issues no name or email and
  the SDK never keeps them. Applications must minimise what they display and store about the
  person (show "Skyddad identitet", never look the person up elsewhere to fill in details).
- **Representation (`rep`).** `sub` is always the signed-in person; `rep.sub` is the party they
  act for, and `roles` are the person's own. Portvakt only attests that the person holds a
  representation right for the party in this application. **Authorise every action on behalf of
  `rep.sub` with your own rules.** APIs that must not be used on someone's behalf set
  `allowRepresentation: false`.
- No tokens, cookies, session ids or personal data are logged; log details carry error codes only.
- Use `sameSite: "lax"` (default). `strict` drops the session cookie on the first navigation after
  the login redirect.
- Rotate `encryptionKey` and `cookie.secrets` by putting the new value first and removing the old
  one after the longest session has ended.
