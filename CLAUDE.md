# Portvakt project policy

Portvakt is a multi-tenant identity broker: upstream IdPs authenticate people, Portvakt federates
them, applies tenant policy and issues OIDC tokens (one issuer per tenant) to the organisation's
own services.

The plan, fixed decisions and milestones live in [docs/plan.md](docs/plan.md). Fixed decisions
there are not reopened during delivery.

## Layout

| Path                     | Contents                                                        |
| ------------------------ | --------------------------------------------------------------- |
| `apps/server`            | Broker (Express 5); `createApp()` in `src/app.ts`               |
| `apps/login`             | Login/interaction SPA (Vite + React 19)                         |
| `apps/admin`             | Admin portal SPA (Vite + React 19)                              |
| `apps/mock-idp`          | Dev/test upstream IdPs (Express 5)                              |
| `packages/sdk-node`      | TypeScript SDK for Node/Express                                 |
| `packages/design-system` | Delivered design system; source in `src/` kept as delivered     |
| `examples/demo-service`  | Demo downstream service (Service A and B)                       |
| `e2e`                    | Playwright suite                                                |
| `deploy`                 | `docker-compose.dev.yml` (dev/test Postgres), later images/Helm |
| `docs`                   | Plan, architecture, claims contract                             |

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
```

Databases: `portvakt` (dev) and `portvakt_test` (tests), created by `deploy/postgres-init` on first
volume init. Two roles: the app runs as the restricted `portvakt_app` (`DATABASE_URL`,
`TEST_DATABASE_URL`) and migrations as the owner `portvakt` (`MIGRATION_DATABASE_URL`,
`TEST_MIGRATION_DATABASE_URL`). See `.env.example`.

## Server modules (`apps/server/src`)

| Module          | Contents                                                                   |
| --------------- | -------------------------------------------------------------------------- |
| `config/`       | `loadConfig()`: zod-validated env, typed `Config`, production refusals     |
| `crypto/`       | `SecretBox` envelopes, `BlindIndex`, `KeyRing`, client secrets, ES256 keys |
| `db/`           | `pg` pool, `Db` (query + nested transactions), migration runner and CLIs   |
| `domain/`       | Domain types, zod input schemas, personnummer/organisationsnummer parsing  |
| `repositories/` | Parameterised SQL per aggregate; rows mapped to domain types               |
| `testing/`      | Integration test database setup and fixtures (test-only)                   |

Migrations are plain SQL in `apps/server/migrations/NNNN_name.sql`, applied by our own runner
(`src/db/migrate.ts`): it is ~150 lines, takes an advisory lock and keeps checksums, which a
dependency would only wrap.

## Conventions

- TypeScript strict, ESM only (`"type": "module"`). Node packages use NodeNext, so relative imports
  carry a `.js` extension; Vite apps use Bundler resolution and extensionless imports.
- Validate every boundary (HTTP input, config, env, database rows from JSON columns) with zod.
- No personal data in logs: no names, emails, personal identity numbers, tokens or secrets.
- Code, comments, commits and docs in English.
- UI only through `@portvakt/design-system` (`/components`, `/patterns`, `/tokens.css`). Do not
  edit files under `packages/design-system/src`; they are the delivered design system.
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
  so audit history outlives a deleted tenant. In production, start-up must call
  `assertRestrictedRuntimeRole` (wired in M2).
- Downstream client secrets are stored encrypted (oidc-provider needs the plaintext to verify
  `client_secret_basic`/`client_secret_post`); read them with `applications.getClientSecret`.
- Signing key transitions are time-guarded in SQL (`KEY_PUBLISH_AHEAD`, `KEY_RETIRE_AFTER`, passed
  by the caller). Only the audited `force` path (key compromise) skips the wait.
- Rotating `MASTER_KEY` also changes the blind-index key: lookups try every configured key until
  `rewrap-secrets` has re-indexed the rows.
- Server scripts load the root `.env` with `--env-file-if-exists=../../.env`; they print a notice
  when it is missing.
- The init script in `deploy/postgres-init` only runs on a fresh volume. To recreate the databases:
  `docker compose -f deploy/docker-compose.dev.yml down -v` then `npm run db:up`.
