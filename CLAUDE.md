# Portvakt project policy

Portvakt is a multi-tenant identity broker: upstream IdPs authenticate people, Portvakt federates
them, applies tenant policy and issues OIDC tokens (one issuer per tenant) to the organisation's
own services.

The plan, fixed decisions and milestones live in [docs/plan.md](docs/plan.md). Fixed decisions
there are not reopened during delivery.

## Layout

| Path                     | Contents                                                         |
| ------------------------ | ---------------------------------------------------------------- |
| `apps/server`            | Broker (Express 5); `createApp()` in `src/app.ts`                |
| `apps/login`             | Login/interaction SPA (Vite + React 19), served by the server    |
| `apps/admin`             | Admin portal SPA (Vite + React 19)                               |
| `apps/mock-idp`          | Dev/test upstream IdPs: OIDC `/entra`, `/bankid`; SAML `/saml/*` |
| `packages/sdk-node`      | TypeScript SDK for Node/Express                                  |
| `packages/design-system` | Delivered design system; source in `src/` kept as delivered      |
| `packages/fonts`         | Self-hosted design-system fonts (`@portvakt/fonts/fonts.css`)    |
| `examples/demo-service`  | Demo downstream service (Service A and B)                        |
| `e2e`                    | Playwright suite                                                 |
| `deploy`                 | `docker-compose.dev.yml` (dev/test Postgres), later images/Helm  |
| `docs`                   | Plan, claims contract (`claims.md`); architecture later          |

Shared config at the root: `tsconfig.base.json` (strict), `tsconfig.node.json` (NodeNext, Node
packages), `tsconfig.vite.json` (Bundler resolution, Vite apps), `eslint.config.js`,
`vitest.config.ts` (one Vitest project per workspace), `.prettierrc.json`.

## Verify commands

Run from the repo root:

```sh
npm install
npm run typecheck      # tsc --noEmit in the root and every workspace
npm run lint           # eslint . (type-aware typescript-eslint, react-hooks for React code)
npm run format:check   # prettier --check . (npm run format writes)
npm test               # vitest run over apps/*, packages/*, examples/*
npm run build          # vite build for apps/login and apps/admin
npm run db:up          # Postgres 16 on localhost:5433, waits until healthy; npm run db:down stops it
npm run test:e2e       # Playwright (browsers: npm run install-browsers --workspace e2e)
npm run migrate -w apps/server         # migrate as MIGRATION_DATABASE_URL, grant the runtime role
npm run rewrap-secrets -w apps/server  # after MASTER_KEY rotation: re-wrap secrets, re-index pins
npm run dev -w apps/server             # broker with reload (migrates on start outside production)
npm run dev -w apps/mock-idp           # mock upstream IdPs on :4500 (/entra, /bankid, /saml/*)
npm run dev -w apps/login              # rebuilds apps/login/dist on change; the server serves it
```

Local login flow: `npm run db:up`, the server and the mock IdP as above, and `npm run build -w
apps/login` once (or its `dev` watch). Create a tenant, an application and a login method with
issuer `http://localhost:4500/entra` (or `/bankid`), client id `portvakt-dev` and the dev secret
from `.env.example`; the mock's default clients accept every redirect URI below
`http://localhost:3000/t/`. Personas are in `apps/mock-idp/personas.json`; `login_hint=<persona
id>` (or an employee's email) signs one in without the persona page, and `login_hint=cancel`
answers `access_denied`. SAML: the mock's IdPs are `http://localhost:4500/saml/{bankid,freja,siths}`
(metadata at `.../metadata`, signed with a key whose certificate is
`idp.saml(flavour).metadataSigningCertificate`); create the login method with
`portvakt.samlAdmin.create` (the admin API is M6). The mock fetches the SP metadata from
`{SP entityID}/metadata` on the first request; its persona page has a test switch select
(`data-testid="switch"`).

`TEST_LOG_LEVEL=debug npm test` shows the server logs of integration tests (silent by default).

Databases: `portvakt` (dev) and `portvakt_test` (tests), created by `deploy/postgres-init` on first
volume init. Two roles: the app runs as the restricted `portvakt_app` (`DATABASE_URL`,
`TEST_DATABASE_URL`) and migrations as the owner `portvakt` (`MIGRATION_DATABASE_URL`,
`TEST_MIGRATION_DATABASE_URL`). See `.env.example`.

## Server modules (`apps/server/src`)

| Module          | Contents                                                                    |
| --------------- | --------------------------------------------------------------------------- |
| `config/`       | `loadConfig()`: zod-validated env, typed `Config`, production refusals      |
| `crypto/`       | `SecretBox` envelopes, `BlindIndex`, `KeyRing`, client secrets, ES256 keys  |
| `db/`           | `pg` pool, `Db` (query + nested transactions), migration runner and CLIs    |
| `domain/`       | Domain types, zod input schemas, personnummer/organisationsnummer parsing   |
| `repositories/` | Parameterised SQL per aggregate; rows mapped to domain types; change events |
| `oidc/`         | Per-tenant oidc-provider: config, adapter, registry, claims, interactions,  |
|                 | session policy, acr ranking, login state (session record, grant login)      |
| `federation/`   | Upstream OIDC (openid-client): discovery cache, client auth, claim mapping; |
|                 | `saml/`: upstream SAML: IdP and SP metadata, protocol, signatures, mapping, |
|                 | ACS and SLO service, admin operations (`SamlLoginMethodAdmin`)              |
| `login/`        | Login flow routes (interaction API, callback, JWKS, SAML SP endpoints in    |
|                 | `saml-routes.ts`), CSRF, login UI shell                                     |
| `keys/`         | `SigningKeyCache` (keys of this replica) and `KeyRotationService`           |
| `jobs/`         | Advisory-locked `runExclusive` and the `PeriodicTask` scheduler             |
| `net/`          | `OutboundGuard`: every request to a configured URL (SSRF, redirects, size)  |
| `logging/`      | pino JSON logger with redaction, request logging                            |
| `server.ts`     | `createPortvakt()`: composition root, start-up, jobs, graceful shutdown     |
| `main.ts`       | Process entry: config, migrations, role check, signals                      |
| `testing/`      | Test database, fixtures, test server, cookie-jar browser, RP helpers        |

OIDC request path: `app.ts` (health probes) -> `/ui/login/*` (login UI assets) ->
`oidc/routes.ts` (`/t/:slug`, 404 for unknown or suspended tenants) -> `login/routes.ts` (login
flow) -> `ProviderRegistry` (one cached oidc-provider per tenant, built lazily) -> the provider.

Login flow: authorization -> `GET /t/{slug}/interaction/{uid}` (the login UI, or straight
upstream when one method is acceptable or `login_hint` is an email of a home realm) -> `POST
.../login` (CSRF token from `.../details`) -> `federation.begin` (state row, PKCE, nonce) ->
upstream -> `GET /t/{slug}/federation/{loginMethodId}/callback` (`federation.callback`: state
consumed once, code exchange, ID token validation, userinfo, claim mapping, JIT) -> `GET
.../interaction/{uid}/federation/complete?ref=` (completion consumed once, interaction cookie
present, `interactions.completeLogin`) -> resume -> application. SAML methods replace the upstream
hop: `federation.begin` -> `saml.begin` (pending AuthnRequest in `federation_states`; signed
HTTP-Redirect, or `/t/{slug}/saml/{id}/post` for HTTP-POST) -> IdP -> `POST
/t/{slug}/saml/{id}/acs` (`saml.acs`: RelayState consumed once, InResponseTo = the stored request
ID, signature verification with the allowlisted algorithms, decryption, Portvakt's checks, attribute
mapping, JIT) -> the same completion hop.

Entry points for later milestones: `interactions.completeLogin(ctx, {personId, loginMethodId,
acr, amr})` (M4 adds the representation step before it), `rotation.rotateNow({actor, reason,
emergency})` (M6 admin API), the claim contributors in `oidc/claims.ts` (`rep`, M4), the login
prompt checks in `oidc/provider.ts` (`acr_not_met` is the step-up hook, M4),
`federation.begin(tp, interaction, method, { principalPin })` (SAML PrincipalSelection for a
step-up of a known person, M4) and `portvakt.samlAdmin` (create and update SAML login methods,
SP key rotation, SP certificate expiry: the M6 admin API calls these).

Migrations are plain SQL in `apps/server/migrations/NNNN_name.sql`, applied by our own runner
(`src/db/migrate.ts`): it is ~150 lines, takes an advisory lock and keeps checksums, which a
dependency would only wrap.

## Conventions

- Claims contract (docs/plan.md): `sub` is always the signed-in person, also when representing;
  representation is `rep: { sub: <party UUID>, type: "person" | "organisation", name }` and there
  is no `act` claim. Access tokens carry only `sub`, `tid`, `idp`, `idp_kind`, `acr`,
  `auth_time`, `roles`, `attrs` and `rep` (plus the JWT/OAuth basics), never `name`, `email`
  or `pin`; ID tokens carry profile claims per scope. Userinfo stays disabled, so apps read
  profile claims from the ID token. New claims go into the contributors in `oidc/claims.ts` and
  into `CLAIMS_BY_SCOPE` (oidc-provider drops unlisted ID token claims); `docs/claims.md` is
  the versioned contract.
- TypeScript strict, ESM only (`"type": "module"`). Node packages use NodeNext, so relative imports
  carry a `.js` extension; Vite apps use Bundler resolution and extensionless imports.
- Validate every boundary (HTTP input, config, env, database rows from JSON columns) with zod.
- No personal data in logs: no names, emails, personal identity numbers, tokens or secrets.
- Code, comments, commits and docs in English.
- UI only through `@portvakt/design-system` (`/components`, `/patterns`, `/tokens.css`). Do not
  edit files under `packages/design-system/src`; they are the delivered design system. App CSS
  (layout only) uses the tokens and lives in a stylesheet file: the login UI's CSP allows no
  inline scripts or style elements.
- Login UI text lives in `apps/login/src/i18n.ts` (Swedish default, English); interactive
  elements carry stable `data-testid`s; error codes are shared with `login/ui-shell.ts`.
- Tests live next to the code as `*.test.ts(x)`; the design-system tests live in its `test/`.
- Every tenant-scoped repository method takes `tenantId` explicitly; tenant-scoped tables carry
  `tenant_id` and reference each other through composite `(tenant_id, id)` foreign keys.
- Secrets and personal identity numbers at rest go through `SecretBox` with a per-row context
  (`application:<id>:client_secret`, `login_method:<id>:client_secret`, `identity:<id>:pin`,
  `signing_key:<kid>:private_jwk`); repositories never return plaintext except through explicit
  getters such as `getClientSecret` and `getPin`. Equality lookups on personal identifiers use the
  blind index (`*_index` columns), never the plaintext.
- Id arguments are validated with `requireUuids` before SQL; a malformed id raises
  `InvalidIdError`.
- Failure audit events (login failures, refused tokens and the like) must be written outside any
  business transaction that may roll back, so the failure is recorded even when the work is undone.
  Success events may share the business transaction.

## Gotchas

- TypeScript is pinned to `~6.0.3`: typescript-eslint 8.x supports only `<6.1.0`, so TypeScript 7
  cannot be used yet.
- Each tsconfig preset lists its ambient types explicitly (`node` or `vite/client`); add new
  ambient types there rather than relying on automatic `@types` inclusion.
- npm 11 blocks dependency install scripts by default (it warns about esbuild). tsx and Vite work
  without them; approve a script only when something actually breaks.
- The delivered design-system `contracts.ts` files have an intentional empty interface; ESLint's
  `no-empty-object-type` is off for those files only.
- Prettier ignores `packages/design-system/src` and `docs/plan.md` so they stay as authored.
- Never edit an applied migration: the runner refuses to start on a checksum mismatch, a missing
  applied file, or a new file numbered below the latest applied one. Add a new file instead.
- Integration tests call `setupTestDatabase()`, which creates a private schema per test file as the
  owner (`TEST_MIGRATION_DATABASE_URL`), migrates it, and runs the repositories as the runtime role
  (`TEST_DATABASE_URL`); both fall back to the local compose database. Locally they skip with a
  message when Postgres is down; with `CI` set they fail instead.
- The runtime role is created by `deploy/postgres-init/02-create-app-role.sql`. An older dev volume
  lacks it: run `docker exec -i portvakt-dev-postgres-1 psql -U portvakt -d portvakt <
deploy/postgres-init/02-create-app-role.sql` (idempotent), or recreate the volume.
- Runtime privileges live in `migrations/grants/runtime-role.sql`, re-applied by the runner after
  every run (not checksummed). New tables get DML automatically; add exceptions there.
- `audit_events` is append-only twice over: the runtime role has only SELECT and INSERT on it, and a
  trigger rejects UPDATE, DELETE and TRUNCATE even for the owner. It has no foreign key to tenants,
  so audit history outlives a deleted tenant. In production, start-up calls
  `assertRestrictedRuntimeRole` (`main.ts`).
- Downstream client secrets are stored encrypted (oidc-provider needs the plaintext to verify
  `client_secret_basic`/`client_secret_post`); read them with `applications.getClientSecret`.
- Signing key transitions are time-guarded in SQL (`KEY_PUBLISH_AHEAD`, `KEY_RETIRE_AFTER`, passed
  by the caller). Only the audited `force` path (key compromise) skips the wait.
- Rotating `MASTER_KEY` also changes the blind-index key: lookups try every configured key until
  `rewrap-secrets` has re-indexed the rows. Representation grant lookups therefore take the
  agent's indexes under every key (`persons.pinIndexCandidates`), never a stored `pinIndex`.
- oidc-provider is 9.x with `@types/oidc-provider` 9.x; upgrade them together. Read its source in
  `node_modules/oidc-provider/lib` for behaviour (`helpers/defaults.js` lists every option).
- One provider per tenant: issuer `{PUBLIC_URL}/t/{slug}`, storage scoped by `tenant_id`, cookies
  scoped to `/t/{slug}`. A cached provider is rebuilt when its tenant, the tenant's applications
  or the signing key set change (NOTIFY on `portvakt_changes`, plus `PROVIDER_RELOAD_INTERVAL`).
  Clients are looked up live through the adapter (`findEnabledByClientId`), never stored.
- Change events: a repository write emits one (`emitChange`, inside the write's transaction)
  when it changes a row a cached provider or the key cache is built from: tenant, application
  client configuration, tenant attachment, login methods (their acr values become the
  provider's `acrValues`), signing key state. Roles, rules, attributes and
  persons are read live and emit nothing. NOTIFY is database-wide, so parallel test files see
  each other's events; they only cause harmless invalidations, so never assert on cache sizes.
- `oidc/routes.ts` deletes `req.originalUrl` before handing a request to the provider:
  oidc-provider derives its mount path with `originalUrl.indexOf(url)`, which is wrong for a slug
  starting with a route name (`/t/authority/auth`); without it, it uses `req.baseUrl`.
- Access tokens are always JWTs for one application (`aud` = client_id, resource
  `urn:portvakt:app:{client_id}`); only client_credentials may name another app of the tenant.
  The userinfo endpoint is disabled: oidc-provider only accepts audience-less access tokens there,
  so RPs read claims from the ID token.
- Signing: oidc-provider signs with the first matching key of its `jwks`, so `SigningKeyCache`
  orders active, next, retiring. Access tokens also pin `jwt.sign.kid` to the active key.
- Login state lives in `oidc_payloads` in two kinds (`oidc/login-context.ts`): the session
  record `PortvaktSession` (keyed by the oidc-provider session uid: latest login, its policy,
  the app it was made for, last activity) and the grant login `PortvaktGrantLogin` (keyed by
  grant id: the login one app's grant was issued for). The grant login is deliberately not
  indexed by grant id, so a code replay's revocation cannot race the legitimate redemption; a
  revoked grant fails at `validateGrant` anyway. Claims and refresh lifetimes read the grant
  login, so a fresh login for app B never changes app A's claims. Activity updates set only
  `lastActivityAt`, atomically, and only while the record is still the same login. Both are
  computed in `loadExistingGrant` (which runs before the prompt checks and implements implicit
  consent) and stored by the never-prompting consent check `portvakt_session_activity`, which
  only runs once the login prompt passed. A session without a record goes back to the login
  prompt.
- Session policy checks are login prompt checks in `oidc/provider.ts` (`session_expired`,
  `session_idle`, `sso_not_allowed`, `acr_not_met`); their reasons (and `max_age`,
  `login_prompt`) send `prompt=login` upstream (`FRESH_LOGIN_REASONS`). The session record
  outlives its login by SESSION_TTL, so an expired session is recognised as one instead of
  looking like a first visit the upstream IdP could answer from its own session. Times are
  whole seconds: timing tests need a second of margin.
- Refresh tokens are issued without `offline_access` and stay bound to the broker session: logout
  or session expiry ends them. They rotate on every use; replaying one revokes the grant.
- ID token `acr`, `amr` and `auth_time` come from the login itself (oidc-provider copies them
  from the session); `acrValues` is ACR_RANKING plus every login method's acr, and the claims
  are listed under the `openid` scope. `auth_time` is always present (`require_auth_time` on
  every client).
- `PUBLIC_URL` is an origin without a path (enforced). Before a request reaches a provider,
  `oidc/routes.ts` pins Host, X-Forwarded-Host and X-Forwarded-Proto to it, so endpoint URLs and
  cookie security never follow client headers, and sets X-Forwarded-For to Express's `req.ip`.
  `TRUST_PROXY` therefore only decides the client IP. Cookies are `Secure` in production.
- Single use is decided by the database in the adapter: `consume` is an atomic
  `UPDATE ... WHERE consumed_at IS NULL`, and a lost race on a code or refresh token is a replay
  (invalid_grant, grant revoked); client assertion `jti`s (ReplayDetection) are insert-once
  (invalid_client on reuse). oidc-provider's own check-then-consume is not atomic.
- Introspection answers only the client a token was issued to.
- Logs: the logger censors the keys named in `REDACTED_PATHS` at any depth and in any case
  (`redactKeys`, run before the serializers); errors go through `serializeError`, which keeps
  type, message, code and stack only.
- Graceful shutdown: on SIGTERM readiness turns 503 at once, requests are still served for
  `SHUTDOWN_DRAIN_DELAY` (default 5s, 0 in tests), then the listener closes and in-flight requests
  get `SHUTDOWN_TIMEOUT`. On Kubernetes keep `terminationGracePeriodSeconds` above the sum; a
  `preStop` sleep is not needed when the drain delay covers the endpoint propagation time (add
  one only if the load balancer needs longer than `SHUTDOWN_DRAIN_DELAY`).
- `KEY_RETIRE_AFTER` must cover the longest signed token and the longest broker session
  (`SESSION_TTL`): ID tokens return as `id_token_hint` at logout. A login method
  `maxAgeSeconds` above `SESSION_TTL` is refused at write time by the server's repositories
  (`createRepositories(db, keys, { maxSessionSeconds })`; the plain test database repositories
  have no ceiling) and capped at runtime.
- NODE_ENV=test is refused unless `PUBLIC_URL` is loopback, `.localhost` or `.test`, and the
  server logs a warning whenever the test-only login route is mounted.
- The test-only login route `POST /t/{slug}/interaction/{uid}/__test__/login` exists only with
  NODE_ENV=test. It lives below the interaction path because the interaction cookie is scoped to
  it.
- Integration tests that need HTTP use `startTestServer()` (`testing/test-server.ts`): a private
  schema, the real app on 127.0.0.1 with `PUBLIC_URL` pointing at it, and `TestBrowser` for the
  front channel (host-only cookies per host and port). Signing keys are global per schema: tests
  that rotate keys run in their own file, in order. Test servers serve a fixture login UI shell
  (`testLoginUiDir`), never apps/login/dist, because CI runs the tests before it builds.
- Federated flows in tests: `startTestIdp()` runs the mock IdP in-process,
  `createFederatedLoginMethod` creates a login method and registers it there as a client, and
  `FlowDriver` (`testing/federation.ts`) follows redirects and does what the login UI and the
  persona page would; it reads Portvakt pages through their bootstrap block.
- Server scripts load the root `.env` with `--env-file-if-exists=../../.env`; they print a notice
  when it is missing.
- Upstream federation: `federation_states` (migration 0002) holds the hashed state, the
  encrypted PKCE verifier and the nonce; the callback and the completion are each consumed once
  by an atomic UPDATE, scoped by tenant and login method. The interaction cookie never reaches
  the callback path, which is why the completion hop exists. Every failure ends in a login UI
  error view and a `login.failure` audit event written on its own (never inside a transaction).
- Upstream ID tokens: openid-client validates iss, aud, exp, nonce and the alg against the
  issuer's metadata, `enableNonRepudiationChecks` verifies the signature against the upstream
  JWKS, and Portvakt adds an asymmetric-only alg allowlist. Production refuses http issuers.
- Login methods authenticate upstream with `client_secret_basic`, `client_secret_post` or
  `private_key_jwt` (a per-login-method ES256 key, encrypted as
  `login_method:<id>:client_private_jwk`, public at `/t/{slug}/federation/{id}/jwks`).
  `rewrap-secrets` re-wraps it with the secrets.
- Multi-tenant upstream issuers (Entra `/common`, `/organizations`, `/consumers`, or a
  discovered `{tenantid}` issuer) need `allowedUpstreamTenants` (refused at write time without).
  openid-client only accepts `{tenantid}` issuers for login.microsoftonline.com, so
  `UpstreamClients.exchangeCode` redeems the code once with a capturing custom fetch, reads the
  unverified `tid` to pick the tenant (refused unless listed), and validates the same captured
  response against that tenant's issuer. The mock IdP's `entra-mt` issuer exercises it.
- A login method's asserted acr that is in ACR_RANKING requires an upstream acr mapping (write
  time, and again at login for older rows). Upstream email is mapped only with `email_verified`
  or `trustUpstreamEmail`. Protected identity is sticky on the person (`persons.protected_identity`;
  `persons.clearProtectedIdentity` is the admin hook for M6).
- Upstream callbacks with an unknown state are not audited (anyone can send them): they are
  logged and counted in `portvakt_federation_callback_rejected_total` (`metrics/registry.ts`, an
  in-process registry that M8 exposes to Prometheus). One pending `federation_states` row per
  (interaction, login method) is reused while valid. Discovery failures are cached for
  `UPSTREAM_FAILURE_CACHE`. Follow-up: rotation of the per-login-method upstream client key
  (private_key_jwt) with an overlap; today a key is generated once.
- Entra ID groups overage (`_claim_names` instead of `groups`) is not resolved through Graph:
  the groups count as empty and `login.groups_overage` is audited. Configure the Entra app to
  emit only groups assigned to the application (docs/claims.md).
- The login UI is `apps/login/dist` (or `LOGIN_UI_DIR`), served by the server: every page is its
  `index.html` plus a `<script type="application/json" id="pv-bootstrap">` block that selects
  the view. Production refuses to start without the build. oidc-provider's logout form is
  rendered into the page and the SPA's buttons submit it (`form="op.logoutForm"`).
- The design system's tokens.css imports Google Fonts; the login UI build drops that import
  (`vite.config.ts`) and self-hosts the fonts through `@portvakt/fonts` (Fontsource, latin
  subsets, imported once in the app entry), so the page loads nothing from third parties and fits
  its CSP (`font-src 'self'`). The admin app can import the same entry.
- A different person signing in over an existing session goes through oidc-provider's
  auto-submitting logout form (`response_modes/form_post.js`, called from `resume.js`). It is
  hard-coded and cannot be branded or localised without patching oidc-provider; it shows only for
  an instant with JavaScript on. `FlowDriver` posts it like a browser would.
- Session-policy tests fake `Date` only (`vi.useFakeTimers({ toFake: ["Date"], shouldAdvanceTime:
true })`): expiry decisions use the app clock, and database expiry by its own clock is only a
  cleanup, so jumping the clock forward is deterministic and needs no sleeps.
- The mock IdP overrides oidc-provider's `fetch` to drop its SSRF guard, because Portvakt's
  federation JWKS is on localhost in tests. Never do that in the server.
- oidc-provider answers a scope the client may not request (`pin` without
  `allowedExtraScopes`) with `invalid_scope`; it does not drop it.
- SAML upstream follows the Swedish eID Framework as published at
  docs.swedenconnect.se/technical-framework/latest: Deployment Profile 1.8 (2024-12-04), Attribute
  Specification 1.8 (2024-12-04), Registry for identifiers 1.8 (2024-12-04), Entity Categories 1.9
  (2024-12-04) and Principal Selection 1.0 (2020-01-17). The default clock skew (60 s) follows the
  Deployment Profile 1.9 draft (2025-10-16); 1.8 allows 3 to 5 minutes. Identifiers live in
  `domain/saml.ts`.
- SAML library: @node-saml/node-saml, because it is an SP library that is maintained and builds
  and signs AuthnRequests (HTTP-Redirect with SigAlg, HTTP-POST enveloped), LogoutRequests and
  LogoutResponses; samlify needs a separate schema validator and had a signature-wrapping CVE in 2025. Incoming messages are not validated by node-saml (it cannot restrict algorithms or verify
  ECDSA): `federation/saml/xml.ts` verifies enveloped signatures with xml-crypto's `SignedXml`,
  restricted to the allowlist of `algorithms.ts` (RSA and ECDSA with SHA-256/384/512; SHA-1, MD5,
  HMAC and comment-preserving c14n refused; transforms only exclusive c14n and
  enveloped-signature, as Sweden Connect IdPs use; the KeyInfo certificate is never used), with
  structural rules against signature wrapping (exactly one Signature, one Reference to the
  element itself, its ID carried by no other element as an `ID`/`Id`/`id` attribute in any
  namespace, found by a linear DOM walk, never XPath), and returns only the signed bytes.
  Portvakt never canonicalises or verifies signatures itself. `xml.ts` is the only module that
  imports node-saml's `lib/xml` helpers, so node-saml is pinned to `~5.1.0`.
- XML parsing is bounded before anything else (`parseXml`): size (Responses 512 KB, logout
  messages 64 KB, metadata 10 MB), element count (Responses SAML_XML_MAX_ELEMENTS, default 20,000)
  and depth 64, counted lexically before the DOM is built and exactly after; a DTD is refused. All
  later walks over the DOM are linear.
- The XML libraries' typings refer to global DOM types: `src/types/xml-dom.d.ts` (server and mock)
  declares the members we use. Never import `@xmldom/xmldom` or `xpath` types directly: their
  typings pull in `lib.dom`, which clashes with that file.
- SAML decryption is `decrypt.ts` (Node's crypto, not xml-encryption, which falls back to SHA-1
  for the `xmlenc#sha256` DigestMethod and decrypts 3DES): key transport `rsa-oaep-mgf1p` (SHA-1)
  or `xmlenc11#rsa-oaep` with an MGF of the same hash as the DigestMethod (Node's OAEP uses one
  hash for both, so `rsa-oaep-mgf1p` with SHA-256, MGF1-SHA1, is refused); content AES-128/192/256
  GCM, and CBC only inside a required and verified Response signature (CBC has no integrity of its
  own; with `requireSignedResponse: false` GCM is mandatory) and unless the method sets
  `requireGcm`. At most 4 EncryptedKey candidates are tried (more refuse the response before any
  RSA operation). RSA PKCS#1 v1.5 and 3DES are refused. The SP
  metadata advertises exactly these.
- The HTTP-Redirect binding is parsed from the raw query by `redirect.ts`: binding keys only as
  literally written (an encoded key such as `SAML%52equest`, a duplicate, or two messages refuse
  the message), the signed octets built from the received tokens, the message decoded from the
  same token, and the signature verified with the allowlisted algorithms.
- The SAML ACS checks: the Response signature (required by default) and, from its signed bytes,
  Issuer, Destination (required when signed) and InResponseTo; exactly one Assertion or
  EncryptedAssertion; the assertion's own signature; Conditions and every AudienceRestriction;
  exactly one bearer SubjectConfirmation with Recipient = ACS and InResponseTo = the stored request
  ID; NotOnOrAfter with the method's skew; an IssueInstant at most 5 minutes old; AuthnInstant
  (after the request with ForceAuthn, and within `max_age`); the returned AuthnContextClassRef
  (one of the requested, `exact`; or ranked at least as high, `minimum`; and meeting the method's
  asserted acr); value lengths (NameID, SessionIndex, attributes; too long refuses the response);
  and the assertion ID once (`saml_replay_cache`, emptied by the payload cleanup job). A SAML
  login's `acr` is the level the IdP returned. ForceAuthn is sent for every FRESH_LOGIN_REASONS
  reason and whenever the application sends `max_age`. `acr_values` narrows RequestedAuthnContext
  to the levels that satisfy it (step-up).
- The ACS is reached by a cross-site POST, so no SameSite=Lax cookie arrives there; it correlates
  the response by RelayState (the `federation_states` row) and InResponseTo only. `FlowDriver`
  posts SAML forms to Portvakt without cookies (`TestBrowser.request(..., { sendCookies: false })`)
  to keep that honest, and `holdSamlResponses` stops at a response form so a test can replay it
  or send it elsewhere.
- PrincipalSelection (`federation.begin(..., { principalPin })`) is sent only when the IdP's
  metadata advertises it, and only over HTTP-POST (refused when the IdP has no POST SSO
  endpoint); the returned pin must match either way. The `/post` page renders a pending request
  once (`saml_post_rendered_at`).
- A SAML identity keyed by the personal identity number (subject source `personalIdentityNumber`)
  has the subject `pin-index:<blind index>`, never the number. Lookups try every master key's
  index, a login re-keys the subject, and `rewrap-secrets` re-indexes it for identities of such
  methods only.
- The framework has no signal for protected identity. It is the configurable
  `attributeMapping.protectedIdentity` ({ attribute, values }); the mock sends
  `urn:portvakt:mock:protected-identity` = `true`. orgAffiliation values count only when their
  scope is a `shibmd:Scope` of the IdP's metadata or one of the method's `orgAffiliationScopes`.
  employeeHsaId and those values become `hsa_id` and `org_affiliation` (scope `hsa`, ID token).
- SAML metadata: `login_method_saml.metadata_cache` holds the parsed, signature-checked metadata
  as JSON. A login never fetches the metadata URL while a cached copy exists. It fails closed
  (`upstream_unavailable`) once its validUntil has passed or, without validUntil, after
  SAML_METADATA_MAX_AGE (7 days) without a successful refresh, and an IdP missing from a valid
  (signed) metadata document is treated as removed (cache dropped). The `saml-metadata-refresh` job
  (SAML_METADATA_CHECK_INTERVAL, advisory lock) refreshes each method after its
  `metadataRefreshSeconds`, retries a failure after 5 minutes, keeps the last good copy on any
  other failure and counts `portvakt_saml_metadata_refresh_total`. Production requires a metadata
  signing certificate for a metadata URL unless `allowUnsignedMetadata` is set (audited as
  `login_method.saml_unsigned_metadata_allowed`), and at least one `uiInfo` logo (Deployment
  Profile). `samlAdmin.warningsFor` lists what the M6 portal should flag.
- Outbound requests to configured URLs (SAML metadata, upstream OIDC discovery, JWKS, token and
  userinfo, downstream client `jwks_uri`) go through `net/outbound.ts`: the connection's DNS
  lookup refuses loopback, private, link-local (169.254.169.254), unique-local, unspecified,
  multicast and NAT64/6to4 (64:ff9b::/96, 64:ff9b:1::/48, 2002::/16) addresses (also after DNS rebinding), literal IP hosts are checked first, redirects are
  followed by hand (3 hops, each checked), bodies are capped, and production requires https.
  The guard uses `undici` (a direct dependency, `~7.29.1`) for its `Agent` and `fetch`, so the
  connect-time lookup does not depend on the undici version bundled in Node.
  Development and tests list exceptions in ALLOW_PRIVATE_UPSTREAM_HOSTS (refused in production);
  without `localhost,127.0.0.1` there, a local mock IdP is unreachable.
- SAML SP keys (`saml_sp_keys`) are RSA 3072 with self-signed certificates; the private keys are
  SecretBox envelopes (`saml_sp_key:<id>:private_key`) that `rewrap-secrets` re-wraps. Rotation:
  `prepareSpKeyRotation` adds a `next` key per purpose, published next to the active one;
  `rotateSpKeys` makes it active and the old key `previous` (no longer published, still used for
  decryption until the next rotation or `deletePreviousSpKey`). Requests are signed with the
  active key.
- SAML single logout: the session record keeps the upstream session as `upstream`: the NameID's
  and SessionIndex's blind indexes (HMAC with the blind-index key, per login method) and the
  values sealed with SecretBox (for the SP-initiated LogoutRequest); never in the clear. The
  record is indexed by `saml:<loginMethodId>:<NameID index>` (`oidc_payloads.uid`). An
  RP-initiated logout of the whole session goes through the IdP's SLO after the local logout
  (HTTP-Redirect, or the `/logout` HTTP-POST page; the `upstreamLogout` hook in
  `oidc/provider.ts`, never for the session switch during a login), and a LogoutResponse that
  cannot be verified still ends at the application. A signed IdP-initiated LogoutRequest (its
  Destination the SP's SLO URL, IssueInstant within 5 minutes plus skew, its ID accepted once)
  ends the matching sessions (their oidc-provider Session and grants are deleted,
  `logout.idp_initiated` is audited) and gets a signed LogoutResponse over HTTP-Redirect, or
  HTTP-POST when the IdP has no Redirect SLO endpoint. Sealed sessions are not re-wrapped by
  `rewrap-secrets`: keep the old key in MASTER_KEY_PREVIOUS until SESSION_TTL has passed.
- The init script in `deploy/postgres-init` only runs on a fresh volume. To recreate the databases:
  `docker compose -f deploy/docker-compose.dev.yml down -v` then `npm run db:up`.
