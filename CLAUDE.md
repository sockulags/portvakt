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
```

Databases: `DATABASE_URL` for dev (`portvakt`), `TEST_DATABASE_URL` for tests (`portvakt_test`,
created by `deploy/postgres-init` on first volume init). See `.env.example`.

## Conventions

- TypeScript strict, ESM only (`"type": "module"`). Node packages use NodeNext, so relative imports
  carry a `.js` extension; Vite apps use Bundler resolution and extensionless imports.
- Validate every boundary (HTTP input, config, env, database rows from JSON columns) with zod.
- No personal data in logs: no names, emails, personal identity numbers, tokens or secrets.
- Code, comments, commits and docs in English.
- UI only through `@portvakt/design-system` (`/components`, `/patterns`, `/tokens.css`). Do not
  edit files under `packages/design-system/src`; they are the delivered design system.
- Tests live next to the code as `*.test.ts(x)`; the design-system tests live in its `test/`.

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
- The init script in `deploy/postgres-init` only runs on a fresh volume. To recreate the databases:
  `docker compose -f deploy/docker-compose.dev.yml down -v` then `npm run db:up`.
