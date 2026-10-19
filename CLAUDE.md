# Portvakt project policy

Portvakt is a multi-tenant identity broker: upstream IdPs authenticate people, Portvakt federates
them, applies tenant policy and issues OIDC tokens (one issuer per tenant) to the organisation's
own services.

The plan, fixed decisions and milestones live in [docs/plan.md](docs/plan.md). Fixed decisions
there are not reopened during delivery.

## Layout

| Path                         | Contents                                                            |
| ---------------------------- | ------------------------------------------------------------------- |
| `apps/server`                | Broker (Express 5); `createApp()` in `src/app.ts`                   |
| `apps/login`                 | Login/interaction SPA (Vite + React 19), served by the server       |
| `apps/admin`                 | Admin portal SPA (Vite + React 19)                                  |
| `apps/mock-idp`              | Dev/test upstream IdPs: OIDC `/entra`, `/bankid`; SAML `/saml/*`    |
| `packages/sdk-node`          | `@portvakt/sdk-node`: BFF, access token validation, s2s tokens      |
| `packages/design-system`     | Delivered design system; source in `src/` kept as delivered         |
| `packages/fonts`             | Self-hosted design-system fonts (`@portvakt/fonts/fonts.css`)       |
| `examples/demo-service`      | Demo service (Express + SDK, React SPA in `web/`), run as A and B   |
| `sdk-java`                   | Java SDK (Maven, Java 21): `portvakt-sdk-core`, Spring Boot starter |
| `examples/demo-service-java` | Java demo "Tjänst C" (Spring Boot + starter, Thymeleaf), :3300      |
| `e2e`                        | Playwright suite                                                    |
| `deploy`                     | `docker-compose.dev.yml` (dev/test Postgres), later images/Helm     |
| `docs`                       | Plan, claims contract (`claims.md`); architecture later             |

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
npm test               # vitest run over apps/*, packages/*, examples/* (6 files at a time)
npm run build          # vite build for apps/login and apps/admin
npm run db:up          # Postgres 16 on localhost:5433, waits until healthy; npm run db:down stops it
npm run test:e2e       # Playwright (browsers: npm run install-browsers --workspace e2e)
npm run migrate -w apps/server         # migrate as MIGRATION_DATABASE_URL, grant the runtime role
npm run rewrap-secrets -w apps/server  # after MASTER_KEY rotation: re-wrap secrets, re-index pins
npm run audit:prune -w apps/server     # delete audit events older than AUDIT_RETENTION (owner role)
npm run dev -w apps/server             # broker with reload (migrates on start outside production)
npm run dev -w apps/mock-idp           # mock upstream IdPs on :4500 (/entra, /bankid, /saml/*)
npm run dev -w apps/login              # rebuilds apps/login/dist on change; the server serves it
npm run dev:stack                      # whole local stack (below); Ctrl+C stops it, not the DB
npm run seed:dev -w apps/server        # demo tenant (idempotent); needs the mock IdP running
npm run build -w examples/demo-service # demo SPA into examples/demo-service/dist/web
npm run build -w packages/sdk-node     # SDK into packages/sdk-node/dist (JS + .d.ts)
npm run test:java      # Java SDK and Java demo: mvn verify in Docker against a real Portvakt
```

Local stack (`npm run dev:stack`, `scripts/dev-stack.js`, plain Node, works on Windows): db:up,
migrate, the login UI and demo SPA builds when missing (`npm run dev:stack -- --build` forces
them), the mock IdP (:4500), `seed:dev`, Portvakt (:3000), the demo as Tjänst A (:3100,
`service-a`, enabled) and Tjänst B (:3200, `service-b`, attached but disabled). The seed also
registers `service-c` (Tjänst C, the Java demo on :3300, enabled), which dev:stack does not
start (see "Java SDK" below). Without a root
`.env` it uses the values of `.env.example`. The demo tenant's issuer is
`http://localhost:3000/t/demo`. Its login methods: Mock Entra (employees, home realm
`kommun.example`, groups to roles), Mock BankID OIDC (loa3) and Mock BankID hög OIDC (loa4, the
step-up target; persona `maja-loa4` can do both), Mock BankID SAML (`linkByPin`,
`trustPinForRepresentation`; persona `saml-sven` may represent Bygg AB and Samuel Samordning),
and Mock SITHS SAML (`sara@2321000016` gives the role `lakare`).

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

| Module            | Contents                                                                    |
| ----------------- | --------------------------------------------------------------------------- |
| `config/`         | `loadConfig()`: zod-validated env, typed `Config`, production refusals      |
| `audit/`          | Event catalogue (`catalogue.ts`, zod details per action), `AuditLog`,       |
|                   | `AuditSink` (no-op default), retention (`retention.ts`, `prune-cli.ts`)     |
| `representation/` | `RepresentationSource` (internal register), `RepresentationRegistry`        |
|                   | (merge per tenant, re-validation, chooser views with masked identifiers)    |
| `crypto/`         | `SecretBox` envelopes, `BlindIndex`, `KeyRing`, client secrets, ES256 keys  |
| `db/`             | `pg` pool, `Db` (query + nested transactions), migration runner and CLIs    |
| `domain/`         | Domain types, zod input schemas, personnummer/organisationsnummer parsing   |
| `repositories/`   | Parameterised SQL per aggregate; rows mapped to domain types; change events |
| `oidc/`           | Per-tenant oidc-provider: config, adapter, registry, claims, interactions,  |
|                   | session policy, acr ranking, login state (session record, grant login),     |
|                   | the representation chooser prompt (`representation-prompt.ts`)              |
| `federation/`     | Upstream OIDC (openid-client): discovery cache, client auth, claim mapping; |
|                   | `saml/`: upstream SAML: IdP and SP metadata, protocol, signatures, mapping, |
|                   | ACS and SLO service, admin operations (`SamlLoginMethodAdmin`)              |
| `login/`          | Login flow routes (interaction API, representation chooser API, callback,   |
|                   | JWKS, SAML SP endpoints in `saml-routes.ts`), CSRF, login UI shell          |
| `keys/`           | `SigningKeyCache` (keys of this replica) and `KeyRotationService`           |
| `jobs/`           | Advisory-locked `runExclusive` and the `PeriodicTask` scheduler             |
| `net/`            | `OutboundGuard`: every request to a configured URL (SSRF, redirects, size)  |
| `logging/`        | pino JSON logger with redaction, request logging                            |
| `server.ts`       | `createPortvakt()`: composition root, start-up, jobs, graceful shutdown     |
| `main.ts`         | Process entry: config, migrations, role check, signals                      |
| `testing/`        | Test database, fixtures, test server, cookie-jar browser, RP helpers        |

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
mapping, JIT) -> the same completion hop. After the resume, an application whose
`representationMode` is not `none` gets the `select_account` prompt (the representation
chooser): `GET .../interaction/{uid}` (bootstrap view `representation`) -> `GET
.../representation` (parties, masked identifiers, CSRF token) -> `POST .../representation`
(`{ self: true }` or `{ partyId }`, re-checked against the sources) -> resume -> the consent
check stores the choice in the grant login.

Entry points for later milestones: `rotation.rotateNow({actor, reason, emergency})` (M6 admin
API), `portvakt.samlAdmin` (create and update SAML login methods, SP key rotation, SP
certificate expiry), `repos.grants` (`create`, `revoke`, `setApplications`) and
`repos.parties.setProtectedIdentity` (M6 admin API), `portvakt.representation` (add
Bolagsverket or Mina ombud as further `RepresentationSource`s in `server.ts` and enable them per
tenant), and `createPortvakt({ auditSink })` (forwarding audit events to the starter kit's log
service).

Migrations are plain SQL in `apps/server/migrations/NNNN_name.sql`, applied by our own runner
(`src/db/migrate.ts`): it is ~150 lines, takes an advisory lock and keeps checksums, which a
dependency would only wrap.

## SDK (`packages/sdk-node/src`)

| Module              | Contents                                                                       |
| ------------------- | ------------------------------------------------------------------------------ |
| `client.ts`         | `createPortvaktClient`: config, discovery, JWKS, `bff`, `requireAccessToken`   |
| `config.ts`         | zod-validated client config with defaults (`PortvaktConfigError`)              |
| `discovery.ts`      | openid-client discovery cache (stale-if-error), client auth, `isUnavailable`   |
| `jwks.ts`           | ES256 JWKS cache: unknown-kid refetch with cooldown, stale-if-error            |
| `access-token.ts`   | JWT validation (iss pinned, typ at+jwt, aud), middleware, RFC 6750 errors      |
| `principal.ts`      | Principal types, claim schemas, person/service discriminator, `acrAtLeast`     |
| `service-tokens.ts` | Cached client_credentials tokens (`resource` = `urn:portvakt:app:{client_id}`) |
| `bff/`              | BFF router and helpers, sealed sessions, signed cookies, returnTo, keyed lock  |
| `stores/`           | `SessionStore`, `MemoryStore`, `PgSessionStore` (advisory-lock `withLock`)     |
| `testing/`          | Test-only: `FakeOp` (minimal OP for unit tests), `MiniBrowser`                 |

Integration tests (`integration.test.ts`, the demo's `smoke.test.ts`) run an in-process Portvakt
and mock IdP through `@portvakt/server/testing` (the server package's only export). The dev seed
lives in `apps/server/src/dev` (`seed.ts`, `seed-cli.ts`).

## Java SDK (`sdk-java`, `examples/demo-service-java`)

Maven multi-module (Java 21, groupId `se.portvakt`, 1.0.0-SNAPSHOT). The reactor is
`sdk-java/pom.xml`; it includes `../examples/demo-service-java`. Spring Boot 4.1 (Spring
Framework 7, Spring Security 7.1, Jackson 3 `tools.jackson`, JUnit 6 from Boot's BOM); Boot 3.5 is
not supported. Versions are pinned in the parent POM (the Spring Boot BOM is imported for
dependency versions only; Nimbus pinned to the version Spring Security declares; every plugin
pinned) and the Maven Enforcer checks the Maven and Java versions, pinned
plugins, no SNAPSHOT dependencies, upper bounds and convergence. Same behaviour as the
TypeScript SDK; `sdk-java/README.md` is the user documentation.

| Module                         | Contents                                                                    |
| ------------------------------ | --------------------------------------------------------------------------- |
| `portvakt-sdk-core`            | `PortvaktConfig` (builder, validation), `PortvaktClient`, discovery, JWKS   |
|                                | cache, `PortvaktTokenVerifier` (Nimbus), `PortvaktPrincipal`, `AcrRanking`, |
|                                | `ClientCredentialsTokenProvider`, typed exceptions (RFC 6750 codes)         |
| `portvakt-spring-boot-starter` | `PortvaktAutoConfiguration`, `PortvaktProperties` (`portvakt.*`), `login/`  |
|                                | (oauth2Login wiring, token store: memory/JDBC), `resource/` (JwtDecoder,    |
|                                | converter enforcing the defaults, RFC 6750),                                |
|                                | `web/` (`@RequireAcr` interceptor, exception resolver), `PortvaktSecurity`  |
| `examples/demo-service-java`   | Demo pages, `/api/whoami`, and `it/DemoServiceIT` (failsafe) with           |
|                                | `TestBrowser` and `FlowDriver`, Java ports of the TypeScript test helpers   |

Build and test only in Docker (no local JDK). `npm run test:java` (`scripts/test-java.js`):
db:up, a fresh database `portvakt_java_test`, migrations, the login UI build when missing, the
mock IdP on :4900, `seed:dev` (with `SEED_ISOLATION_TENANT=demo-isolation` and service-d with
private_key_jwt, a key made for the run: `DEMO_SERVICE_D_PUBLIC_JWK`), Portvakt on :3900,
then `mvn verify` in `maven:3.9-eclipse-temurin-21` (the named volume `portvakt-m2` holds
~/.m2, or the host directory `PORTVAKT_M2_DIR`, as in CI), then it stops what it started.
`--build` rebuilds the login UI, `--keep` leaves Portvakt and the mock running, every other
argument goes to Maven (`npm run test:java -- -pl portvakt-sdk-core`). Unit tests alone:

```sh
docker run --rm -v "<repo>:/workspace" -v portvakt-m2:/root/.m2 -w /workspace/sdk-java \
  maven:3.9-eclipse-temurin-21 mvn -B -ntp verify
```

The integration tests (the demo's `DemoServiceIT`, the starter's `JdbcTokenStoreIT` against the
stack's Postgres) skip without `portvakt.it.issuer` / `portvakt.it.jdbc-url`; with
`portvakt.it.required=true` (the orchestrator) they fail instead. To run the Java demo by hand against `npm run dev:stack`
(Portvakt :3000, mock :4500), open http://localhost:3300 after:

```sh
docker run --rm -p 3300:3300 -v "<repo>:/workspace" -v portvakt-m2:/root/.m2 \
  -w /workspace/sdk-java maven:3.9-eclipse-temurin-21 sh -c "java \
  /workspace/scripts/java-test/PortForward.java host.docker.internal 3000 4500 & \
  mvn -B -ntp -q -DskipTests package && java -jar \
  ../examples/demo-service-java/target/portvakt-demo-service-java-1.0.0-SNAPSHOT.jar"
```

(on Linux add `--add-host=host.docker.internal:host-gateway`).

## Conventions

- Claims contract (docs/plan.md): `sub` is always the signed-in person, also when representing;
  representation is `rep: { sub: <party UUID>, type: "person" | "organisation", name }` and there
  is no `act` claim. Access tokens carry only `sub`, `tid`, `idp`, `idp_kind`, `acr`,
  `auth_time`, `roles`, `attrs` and `rep` (plus the JWT/OAuth basics), never `name`, `email`
  or `pin`; their `rep` has no `name`, and the ID token's `rep` has none for a protected person
  party. `roles` and `attrs` stay the signed-in person's; applications authorise actions for
  `rep.sub` with their own rules. ID tokens carry profile claims per scope. Userinfo stays disabled, so apps read
  profile claims from the ID token. New claims go into the contributors in `oidc/claims.ts` and
  into `CLAIMS_BY_SCOPE` (oidc-provider drops unlisted ID token claims); `docs/claims.md` is
  the versioned contract.
- TypeScript strict, ESM only (`"type": "module"`). Node packages use NodeNext, so relative imports
  carry a `.js` extension; Vite apps use Bundler resolution and extensionless imports.
- Validate every boundary (HTTP input, config, env, database rows from JSON columns) with zod.
- No personal data in logs: no names, emails, personal identity numbers, tokens or secrets.
- Code, comments, commits and docs in English; user-facing text of the demo SPA in Swedish.
- UI only through `@portvakt/design-system` (`/components`, `/patterns`, `/tokens.css`). Do not
  edit files under `packages/design-system/src`; they are the delivered design system. App CSS
  (layout only) uses the tokens and lives in a stylesheet file: the login UI's CSP allows no
  inline scripts or style elements.
- Login UI text lives in `apps/login/src/i18n.ts` (Swedish default, English); interactive
  elements carry stable `data-testid`s; error codes are shared with `login/ui-shell.ts`. Views:
  `login` (`LoginView`), `representation` (`RepresentationView`, `PartyList`: test ids
  `representation-option-self`, `representation-option-{partyId}`, `cancel-representation`),
  `error`, `logout`, `logged_out`.
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
- Audit events come from the catalogue in `audit/catalogue.ts` (one zod schema per action,
  strict, ids and reason codes only, never a pin, name, email, NameID, upstream subject, token or
  request text); add an action there before writing it, and list it in the catalogue's docs.
  Failure events (refused logins, refused refreshes, denied representations, step-up failures)
  go through `AuditLog.record`, on their own statement, outside any business transaction that
  may roll back. Success events are written with `AuditLog.recordIn` through the transaction's
  repository that commits the change they describe (JIT provisioning with `person.created`, a
  grant login with `representation.selected` / `step_up.success`, a grant revocation with
  `grant.revoked`, key transitions), then forwarded to the sink after the commit.

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
  `assertRestrictedRuntimeRole` (`main.ts`), which also refuses a runtime role that may execute
  the retention function.
- Audit retention (migration 0004): the delete path is `audit_events_prune(cutoff,
batch_size)`, which refuses a cutoff younger than 90 days, sets a transaction-local cutoff
  (`portvakt.audit_prune_before`) and deletes one batch. The trigger lets a DELETE through only
  with that setting, only when the cutoff is at least 90 days old, only for rows older than it,
  and only by a role that owns the table; a plain DELETE by the owner, or one with a younger
  cutoff, is refused. The owner can still drop the trigger: the guarantee is against the runtime
  role and against accidents, not against the owner. EXECUTE is revoked from PUBLIC and the
  runtime role. `npm run audit:prune` connects with MIGRATION_DATABASE_URL, runs it in batches
  (one transaction each) for AUDIT_RETENTION (default 400d, at least 90d) and writes
  `audit.pruned`; schedule it (a daily CronJob).
- The grants script also revokes TEMPORARY on the database from PUBLIC and the runtime role
  (only when the migration role owns the database, otherwise a notice): the runtime role creates
  nothing, not even temporary tables.
- Audit volume and once-only events: `token.issued` is written for every token endpoint success
  (code, refresh, client_credentials) from a provider middleware before the response is sent;
  `token.exchange_denied` / `token.refresh_denied` for a valid code or refresh token whose
  session or representation ended. Failures a page shows on every reload
  (`no_acceptable_method` with its `step_up.failure`, `no_representation_available`) are
  written once per interaction (insert-once marker `PortvaktAuditOnce` in `oidc_payloads`).
  `step_up.failure.requestedAcr` keeps only values the tenant's provider knows (`acrValues`);
  unknown ones are only counted.
- Capacity planning (M9 docs): each replica holds up to DATABASE_POOL_MAX (at least 2, default 10) runtime connections plus one LISTEN connection; the migration job and the audit prune job
  hold one owner connection each while they run. Keep `replicas × (DATABASE_POOL_MAX + 1) + 2`
  (plus any admin tooling) below the database's max_connections minus its reserved slots.
- `AuditSink` (`audit/audit-log.ts`) receives committed events; the default forwards nothing.
  Events that `SamlLoginMethodAdmin` writes are not forwarded (it has no audit log yet); a real
  forwarder should rather tail `audit_events` by `seq`, which also covers every transaction.
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
- Representation (`representation/`, `oidc/representation-prompt.ts`): the chooser is the
  requestable `select_account` prompt between login and consent (oidc-provider's generic
  "was it requested" check is replaced by ours, which respects `representationMode`). Its check
  decides per authorization and remembers the decision for the request; the consent check
  `portvakt_session_activity` stores it in the grant login (`representation`). It reuses a
  grant's still valid choice unless the person just signed in or the app sent
  `prompt=select_account`; another app's choice is never read. `loadExistingGrant` ends a grant
  with its representation: a different choice (`representation_changed`) or one that no longer
  holds (`representation_invalid`, also `representation.denied`) revokes the grant and its
  tokens and starts a new grant, so old refresh tokens never switch representation. At the token
  endpoint `findAccount` re-validates the grant login's representation (revoked, validity window
  at the app clock, application covered and enabled, mode): otherwise the grant is revoked and
  the refresh answers `invalid_grant` (`token.refresh_denied`). Validity uses the app clock
  (`at` is passed to SQL), so fake timers work. Rights are looked up per request through the
  registry with a `RepresentationAgent` (person and the current login's method; at a refresh the
  grant login's method). Grants made out to the person id always count; grants made out to a
  personal identity number count only for the number of the current login's identity, and only
  when that method has `trustPinForRepresentation` (allowed at save only for methods asserting
  at least loa3 that map a pin; SAML methods always map one). A pin another identity of the
  person carries never counts. Re-checking one choice filters by party in SQL, and the protected
  check of all person parties is one query. A failing source contributes nothing (fail closed). The chooser never receives a full personal identity number: person
  parties are sent as the date part only, protected ones (party flag, or a protected person with
  that pin) with no identifier, and the POST only names a party id that is looked up again.
- Step-up (`isStepUp` in `oidc/interactions.ts`): a login prompt whose only reasons are
  `acr_not_met` and/or `max_age` with a signed-in session. `federation.begin` then names the
  person upstream (`persons.latestPin`: SAML PrincipalSelection, or an OIDC `login_hint` when
  the method sets `pinLoginHint`), `completeLogin` refuses another person
  (`step_up_person_mismatch`, audited, nothing about the session changes; the login UI treats it
  as terminal), and the pending login carries `stepUp` so the consent check audits
  `step_up.success` with the grant login. The session record follows the latest login, so the
  step-up method's policy (maxAge, idle, allowSso) governs the session from then on (allowSso can
  flip either way) and a later SSO authorization sees the higher acr; every other
  application's grant login keeps its own acr and auth_time.
- After a fresh login the session record is stored as soon as the login prompt has passed
  (`persistFreshLogin`, called first by the representation prompt), before the chooser or
  consent, so an abandoned chooser never leaves oidc-provider's session and the record apart.
  At the token endpoint `findAccount` sets the code's or refresh token's acr, amr and auth_time
  from the grant login, so the ID token always carries the same login as the access token.
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
- `npm test` runs at most 6 test files at once (`--maxWorkers=6` in the root `test` script; a
  `maxWorkers` in the root vitest.config.ts is not applied to the projects): a server integration
  file holds up to about twelve Postgres connections and Postgres allows 100 by default. With
  more workers (plain `npx vitest run` on a many-core machine) requests fail at random with
  "remaining connection slots are reserved", which surfaces as HTTP 500 in tests.
- Integration tests that need HTTP use `startTestServer()` (`testing/test-server.ts`): a private
  schema, the real app on 127.0.0.1 with `PUBLIC_URL` pointing at it, and `TestBrowser` for the
  front channel (host-only cookies per host and port). Signing keys are global per schema: tests
  that rotate keys run in their own file, in order. Test servers serve a fixture login UI shell
  (`testLoginUiDir`), never apps/login/dist, because CI runs the tests before it builds.
- Federated flows in tests: `startTestIdp()` runs the mock IdP in-process,
  `createFederatedLoginMethod` creates a login method and registers it there as a client, and
  `FlowDriver` (`testing/federation.ts`) follows redirects and does what the login UI and the
  persona page would (`chooseAndFollow` for login methods, `chooseRepresentationAndFollow` for
  the representation chooser); it reads Portvakt pages through their bootstrap block. The mock
  BankID issuer signs a citizen in directly for `login_hint=<persona id or personal identity
number>`.
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
- Person and service access tokens are told apart by the claims the server issues: person tokens
  always carry `idp`, `idp_kind`, `acr`, `auth_time`, `roles` and `attrs` and a person UUID
  as `sub`; client_credentials tokens carry none of them (`extraTokenClaims` adds only `tid`)
  and oidc-provider sets their `sub` to the client_id. The SDK refuses anything in between, so
  changing those claims in `oidc/provider.ts` or `oidc/claims.ts` breaks the SDK.
- Node's fetch always sends `Sec-Fetch-Mode: cors` (it sets the header itself), so the SDK
  treats test requests as XHR. Tests of browser-navigation behaviour use `MiniBrowser.navigate`
  (node:http).
- The mock IdP generates new SAML keys at every start and the server caches IdP metadata: after
  restarting the mock alone, run `npm run seed:dev -w apps/server` again (it fetches the metadata
  of the demo's SAML methods again). Local SAML metadata is unsigned (`allowUnsignedMetadata`).
- Cookies on localhost ignore ports: every demo instance (and any other BFF on localhost) needs
  its own `COOKIE_NAME`. For XHR 401s the BFF's `returnTo` is `defaultReturnTo`, never the API
  URL that was called.
- The SDK supports Express 4 and 5: its handlers never rely on Express 5's promise handling, and
  `bff.test.ts` runs the BFF on Express 4 through the devDependency alias `express4`.
- The SDK's `exports` point at `src/index.ts` (workspace convention); `npm run build -w
packages/sdk-node` emits `dist/` with declarations. Publishing (exports pointing at `dist`)
  belongs to M9.
- `PgSessionStore.withLock` holds one pool connection (transaction-scoped advisory lock) and runs
  every store operation inside the lock on that connection (AsyncLocalStorage), never a second
  one: lock holders waiting for more connections would deadlock a small pool. Writes inside the
  lock are committed even when the locked function throws.
- Java builds run in Docker only. In Git Bash prefix `docker run` with `MSYS_NO_PATHCONV=1` (or
  use PowerShell); `scripts/test-java.js` spawns docker without a shell.
- Java integration test networking: Portvakt and the mock IdP run on the host and must have the
  same URL in the container (issuer pinning, redirects, SAML endpoints), so both sides use
  `http://localhost:3900` and `:4900` (and Postgres `localhost:5433` for the JDBC store tests). In the container `scripts/java-test/PortForward.java`
  forwards those localhost ports to `host.docker.internal` (built into Docker Desktop;
  `--add-host=host.docker.internal:host-gateway` on Linux). The host never uses
  `host.docker.internal`: Docker Desktop writes a LAN address into the Windows hosts file that
  goes stale when the network changes (seen here), and its host networking is opt-in. The Java
  demo runs inside the container on localhost:3300, the redirect URI of `service-c`.
- The Java demo's failsafe runs against `target/classes` (`classesDirectory`): the Spring Boot
  repackaged jar hides the classes ("Failed to find merged annotation for @BootstrapWith").
- Starter: `DefaultOidcUser.getClaims()` calls `getAttributes()`; overriding `getAttributes()`
  to return the claims recurses forever.
- Starter: tokens and pending logins never live in the HTTP session. A Spring Session snapshot
  written back by a concurrent request would bring an old refresh token back (a replay, and
  Portvakt revokes the grant), and a lock alone cannot prevent that. The session holds the grant
  id (`PortvaktSessionState`, kept across `changeSessionId`); `PortvaktTokenStore` holds the
  tokens; `PortvaktAuthorizedClientManager` checks, refreshes and writes inside the store's
  exclusive update (JDBC: one transaction with `SELECT ... FOR UPDATE`). Spring's
  `DefaultOAuth2AuthorizedClientManager` is not used: its repository write happens outside any
  lock. Keep `changeSessionId`; the login callback's grant id travels to the success handler as a
  request attribute.
- Starter: the step-up's `acr_not_met` comes from `PortvaktLoginAuthenticationManager`, which
  wraps the callback filter's AuthenticationManager (an ObjectPostProcessor), so it fails before
  Spring stores the new context or authorized client. An extra AuthenticationProvider cannot do
  it: ProviderManager would try the next provider, which redeems the code again (a replay, and
  Portvakt revokes the grant).
- Starter: Spring's token response clients read the OAuth error body of a 400 only; Portvakt
  answers `invalid_client` with 401 (`PortvaktTokenEndpointErrors` reads both). Requests to the
  token endpoint have one deadline for the whole request (`DeadlineInterceptor`), as the core's
  `Http` (`sendAsync` with a bounded body subscriber).
- Starter: the resource server's defaults (`allow-service`, `allow-representation`) are enforced
  by `PortvaktJwtAuthenticationConverter`: a refused token is unauthenticated with no authorities
  (`restriction()`), so app-defined `authenticated()` rules refuse it; only
  `portvakt.accessToken(r -> ...)` can relax them.
- Starter: the idle timeout is the starter's (`lastSeenAt`, touched by protected requests and
  `getAccessToken`, at most once a minute), not the servlet timeout (set just above it).
- Starter: `OAuth2AuthorizationRequest.Builder.from(...)` copies the built authorization URI, so
  parameters added afterwards are lost; `PortvaktAuthorizationRequestResolver` adds `acr_values`,
  `prompt` and `login_hint` through the delegate's request customizer.
- Starter filters (`PortvaktSessionExpiryFilter`, `PortvaktSessionInfoFilter`) are created by
  the configurer, never as beans: Spring Boot would also register a Filter bean in the servlet
  container, outside the security chain.
- Boot 4 moved the security auto-configurations to `org.springframework.boot.security.*` (the
  filter chain order constant is `SecurityFilterProperties.BASIC_AUTH_ORDER`) and MockMvc's
  annotation to `org.springframework.boot.webmvc.test.autoconfigure`. The starter's ordering uses
  class literals plus `afterName` for the optional `DataSourceAutoConfiguration`;
  `PortvaktAutoConfigurationTest` checks every name resolves (a wrong name is silently ignored).
  A `SpringApplicationBuilder.properties(...)` value loses against `application.yml`; tests that
  start a second demo instance pass command-line arguments.
- Java `safeReturnTo` resolves `%2e` as a dot segment (browsers do), so `/%2e//evil` is refused.
- Windows Python writes CRLF in text mode; edit repo files with `newline=""` (the repo is LF,
  `.gitattributes` has `eol=lf`, and prettier checks it).
- BFF step-up and representation switches refuse cross-site starts (`Sec-Fetch-Site` same-origin
  or none, else a same-origin Referer or the session's `csrf` token); so do logins with `acr` or
  `prompt`, and any login while a session exists (both SDKs). Tests driving them with
  Node's fetch send `sec-fetch-site: same-origin` explicitly.
