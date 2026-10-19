# Contributing

Thank you for helping. This file covers the workflow; [CLAUDE.md](CLAUDE.md) is the detailed
reference for the repository's layout, conventions and gotchas, and [docs/plan.md](docs/plan.md)
holds the fixed decisions, which are not reopened in pull requests.

## Setup

Node 24 and npm 11, Docker (Postgres for tests; the Java SDK builds and tests in a Maven
container, no local JDK needed).

```sh
npm ci --ignore-scripts
npm run db:up        # Postgres 16 on localhost:5433
npm run dev:stack    # the whole local stack (README.md, Quick start)
```

## Before you open a pull request

Run what your change touches, and at least:

```sh
npm run typecheck
npm run lint
npm run format:check   # npm run format writes
npm test               # with npm run db:up
npm run build
```

Plus, when relevant: `npm run test:e2e` (UI or flow changes), `npm run test:java` (the Java SDK
or anything it talks to), `npm run test:e2e:compose` and `npm run helm:check` (packaging),
`npm audit` and `npm run license:check` (dependencies), `npm run images:check` (container
images). CI runs all of them.

## Conventions

- TypeScript strict, ESM, Node packages with NodeNext (relative imports end in `.js`); zod at
  every boundary; tests next to the code as `*.test.ts`.
- No personal data in logs, metrics labels or audit details; secrets and personal identity
  numbers only through the encryption helpers.
- Changing a claim is a change of the claims contract ([docs/claims.md](docs/claims.md));
  configuration variables are documented in [docs/operations.md](docs/operations.md) (a test
  checks it); new audit actions go into the catalogue first.
- Never edit an applied migration; add a new numbered file.
- UI only through the design system; texts in the i18n files (Swedish by default).
- Code, comments, commits and docs in English.
- Keep changes narrow; one topic per pull request, with tests for the behaviour it changes.

## Security issues

Do not open public issues for vulnerabilities: see [SECURITY.md](SECURITY.md).

## License

By contributing you agree that your contribution is licensed under the MIT license of the
project ([LICENSE](LICENSE)).
