# Operations

How to deploy, configure, monitor and recover Portvakt 1.0. The architecture is in
[architecture.md](architecture.md), the threats and residual risks in
[threat-model.md](threat-model.md), the admin API in [admin-api.md](admin-api.md).

## Components

| Deployable          | Image               | Runs                                                                      |
| ------------------- | ------------------- | ------------------------------------------------------------------------- |
| Broker              | `portvakt-server`   | `node dist/main.js` on port 3000 (`PORT`), metrics optionally on 9464     |
| Migration job       | `portvakt-server`   | `node dist/db/migrate-cli.js` (owner role), before every deployment       |
| Audit retention job | `portvakt-server`   | `node dist/audit/prune-cli.js` (owner role), daily                        |
| Admin portal        | `portvakt-admin`    | `node dist/main.js` on port 3400 (`ADMIN_PORT`)                           |
| Admin session table | `portvakt-admin`    | `node dist/migrate-sessions.js`, before every admin deployment            |
| Database            | PostgreSQL 18       | Everything durable: tenants, keys, sessions, audit                        |
| Mock IdP, demo      | `portvakt-mock-idp` | Evaluation and tests only (labelled `se.portvakt.image.production=false`) |
|                     | `portvakt-demo`     |                                                                           |

The images are built from [`deploy/Dockerfile`](../deploy/Dockerfile) (`docker build -f
deploy/Dockerfile --target server .`). They contain compiled JavaScript and production
dependencies only, no npm, set `NODE_ENV=production`, run as UID/GID 10001, write nothing to
their filesystem (run them with a read-only root filesystem), carry OCI labels (version,
revision, source, licenses) and a `HEALTHCHECK` on `/healthz`. No secret is baked in. The same
server image also runs `node dist/db/rewrap-cli.js` (master key rotation) and `node
dist/config/check-cli.js` (configuration check).

Portvakt is stateless apart from Postgres: replicas share nothing in memory that matters for
correctness (rate limit buckets are per replica, see [threat-model.md](threat-model.md)).

## Deploying with Helm

The chart is [`deploy/helm/portvakt`](../deploy/helm/portvakt). Its values are validated by
`values.schema.json`; secrets are never values. [`ci/production-values.yaml`](../deploy/helm/portvakt/ci/production-values.yaml)
is a production-like example. `npm run helm:check` lints and renders the chart (default,
production-like and every-option values) and validates the output with kubeconform, in
containers (CI job `helm`).

1. Create the database and its roles (see [Database roles](#database-roles)).
2. Create the three Secrets (names default to `{fullname}-server`, `{fullname}-admin` and
   `{fullname}-db-owner`, so `portvakt-server`, `portvakt-admin` and `portvakt-db-owner` for the
   release `portvakt`; `server.existingSecret`, `admin.existingSecret` and
   `database.ownerSecret` name others, as below), with the values from [Secrets](#secrets). The
   server and admin pods get runtime database credentials only; the owner URLs are in the owner
   Secret, which only the migration Jobs and the audit retention CronJob mount:

   ```sh
   kubectl create secret generic portvakt-server-secrets \
     --from-literal=DATABASE_URL='postgres://portvakt_app:...@db:5432/portvakt?sslmode=verify-full' \
     --from-literal=MASTER_KEY="$(openssl rand -base64 32)" \
     --from-literal=COOKIE_KEYS="$(openssl rand -hex 32)" \
     --from-literal=METRICS_TOKEN="$(openssl rand -hex 32)" \
     --from-literal=ADMIN_CLIENT_SECRET="$ADMIN_CLIENT_SECRET" \
     --from-literal=BOOTSTRAP_IDP_CLIENT_SECRET='...'
   kubectl create secret generic portvakt-admin-secrets \
     --from-literal=ADMIN_CLIENT_SECRET="$ADMIN_CLIENT_SECRET" \
     --from-literal=ADMIN_COOKIE_SECRET="$(openssl rand -hex 32)" \
     --from-literal=ADMIN_SESSION_ENCRYPTION_KEY="$(openssl rand -base64 32)" \
     --from-literal=ADMIN_DATABASE_URL='postgres://portvakt_admin:...@db:5432/portvakt_admin?sslmode=verify-full' \
     --from-literal=ADMIN_METRICS_TOKEN="$(openssl rand -hex 32)"
   kubectl create secret generic portvakt-db-owner \
     --from-literal=MIGRATION_DATABASE_URL='postgres://portvakt:...@db:5432/portvakt?sslmode=verify-full' \
     --from-literal=ADMIN_MIGRATION_DATABASE_URL='postgres://portvakt_admin_owner:...@db:5432/portvakt_admin?sslmode=verify-full'
   ```

   Keep MASTER_KEY in your secret manager as well: without it the database cannot be used (see
   [Backups](#backups-and-restore)).

3. Install: `helm upgrade --install portvakt deploy/helm/portvakt -f my-values.yaml`, with
   `server.existingSecret: portvakt-server-secrets`, `admin.existingSecret:
portvakt-admin-secrets` and `database.ownerSecret: portvakt-db-owner` for the Secrets above.

What the chart creates:

- **Server Deployment**: `server.replicas` (default 2) or an HPA (`server.autoscaling`), rolling
  updates with `maxUnavailable: 0`, a startup and liveness probe on `/healthz` and a readiness
  probe on `/readyz`, topology spread over zones and nodes, a PodDisruptionBudget
  (`minAvailable: 1`), `runAsNonRoot`, `readOnlyRootFilesystem`, all capabilities dropped,
  seccomp `RuntimeDefault`, no service account token, `/tmp` as a small memory `emptyDir`.
  Configuration from a ConfigMap (`server.*` values and `server.env`), secrets from the server
  Secret (`envFrom`); `MIGRATION_DATABASE_URL` is set empty in the pod, so the owner role never
  reaches it even if the Secret carried it, and `MIGRATE_ON_START` stays `false`
  (`values.schema.json` refuses it in `server.env`).
- **Graceful shutdown**: `preStop` sleeps `server.shutdown.preStopSleepSeconds` (default 5, the
  same as `SHUTDOWN_DRAIN_DELAY`) so endpoint removal reaches every load balancer; on SIGTERM
  Portvakt answers `/readyz` with 503 for `SHUTDOWN_DRAIN_DELAY`, closes the listener and gives
  in-flight requests `SHUTDOWN_TIMEOUT`. `terminationGracePeriodSeconds` is the sum plus 5 s.
- **Admin Deployment** with the same security settings, Service and PDB.
- **Ingress** with TLS for `ingress.host` (Portvakt) and `ingress.adminHost` (the portal).
  `PUBLIC_URL` and `ADMIN_PUBLIC_URL` default to `https://{host}`.
- **Migration Jobs** as `pre-install,pre-upgrade` hooks: `migrate-cli` as the owner role, then
  the admin session table as the session database's owner (both from the owner Secret). A failed migration stops the upgrade before any pod changes. Hooks
  run before the chart's ServiceAccount exists, so they use the namespace's default one, without
  a token.
- **Audit retention CronJob** (`auditPrune.schedule`, default daily 03:17, `concurrencyPolicy:
Forbid`), as the owner role (owner Secret).
- **Metrics**: `METRICS_PORT` (9464) on a Service of its own (`-server-metrics`), never behind
  the Ingress; an optional ServiceMonitor that sends METRICS_TOKEN from the Secret
  (`metrics.serviceMonitor.tokenSecretKey`).
- **NetworkPolicies** (`networkPolicy.enabled`): ingress only from the ingress controller (and
  the metrics scraper on the metrics port); egress only to DNS, the database (CIDRs or
  selectors), upstream IdPs (`networkPolicy.upstream`: CIDRs, private ranges excepted, port 443)
  and, for the admin portal, Portvakt's public origin. The migration and retention jobs reach
  only DNS and the database.
- **Capacity check**: with `database.maxConnections` set, rendering fails when the release could
  hold more connections than that (see [Capacity](#capacity)).

`kubectl exec deploy/portvakt-server -- node dist/config/check-cli.js` prints the problems and
warnings of a running configuration (variable names only).

## Docker Compose

[`deploy/docker-compose.yml`](../deploy/docker-compose.yml) runs the same images on one host:
Postgres (a superuser plus the roles `portvakt`, `portvakt_app`, `portvakt_admin_owner` and
`portvakt_admin`, created by
[`deploy/compose/postgres-init`](../deploy/compose/postgres-init/10-portvakt-roles.sh) from
environment variables), the two migration jobs (the only services with owner credentials), the
broker and the admin portal (runtime roles only), with read-only
root filesystems, no capabilities and `no-new-privileges`. It runs in production mode: copy
[`deploy/compose/production.env.example`](../deploy/compose/production.env.example) to
`deploy/compose/production.env` (ignored by git), fill in every value, put a TLS-terminating
proxy in front of `127.0.0.1:3000` and `127.0.0.1:3400`, and start it:

```sh
docker compose --env-file deploy/compose/production.env -f deploy/docker-compose.yml up -d --build
```

For evaluation on one machine, `npm run compose:local` adds
[`deploy/docker-compose.local.yml`](../deploy/docker-compose.local.yml) and the `demo` profile
(mock IdPs, dev seed, Tjänst A and B): the same images in the explicitly non-production
development mode, with the development values of
[`deploy/compose/local.env`](../deploy/compose/local.env), on the ports of `npm run dev:stack`
(3000, 3100, 3200, 3400, 4500; stop one before starting the other). Every service shares one
network namespace there, so browsers and containers use the same `http://localhost` URLs.
`npm run compose:local:down` removes it with its volume.

`npm run test:e2e:compose` runs the full end-to-end suite against that stack
([`deploy/docker-compose.e2e.yml`](../deploy/docker-compose.e2e.yml)). The suite needs
development mode because production refuses what the test stack is: http on localhost, a mock
IdP on a private address, and a 15-second manual key publish-ahead. The images, the database
roles, the migration jobs and the hardening are the production ones.

## Secrets

Generate every secret separately; production refuses a value used for two purposes.

| Secret                                   | Used by           | Generate                                   |
| ---------------------------------------- | ----------------- | ------------------------------------------ |
| `MASTER_KEY` (and `MASTER_KEY_PREVIOUS`) | server            | `openssl rand -base64 32` (32 bytes)       |
| `COOKIE_KEYS`                            | server            | `openssl rand -hex 32` (at least 32 chars) |
| `METRICS_TOKEN`                          | server            | `openssl rand -hex 32`                     |
| `ADMIN_CLIENT_SECRET`                    | server and portal | `openssl rand -hex 32` (the same value)    |
| `ADMIN_COOKIE_SECRET`                    | portal            | `openssl rand -hex 32`                     |
| `ADMIN_SESSION_ENCRYPTION_KEY`           | portal            | `openssl rand -base64 32`                  |
| `ADMIN_METRICS_TOKEN`                    | portal            | `openssl rand -hex 32`                     |
| Database passwords                       | all               | `openssl rand -hex 24` (URL-safe)          |
| `BOOTSTRAP_IDP_CLIENT_SECRET`            | server            | from the bootstrap IdP's registration      |

Without openssl: `node -e "console.log(require('node:crypto').randomBytes(32).toString('base64'))"`.

## Configuration reference

The server and the admin portal are configured by environment variables only. Durations are
written `90d`, `36h`, `1h30m`, `45s`; rate limits `<count>/<period>` (for example `60/1m`) or
`off`. Every variable is validated at start ([`config/index.ts`](../apps/server/src/config/index.ts),
[`apps/admin/src/config.ts`](../apps/admin/src/config.ts)); errors name the variable, never its
value. A test keeps these tables complete (`config-docs.test.ts` in both apps).

With `NODE_ENV=production` the server also refuses: the development keys and secrets of
`.env.example`, keys with too few distinct bytes, `COOKIE_KEYS` shorter than 32 characters, an
http, localhost or `.test` `PUBLIC_URL` or `ADMIN_PUBLIC_URL`, one database role for both URLs, `MIGRATE_ON_START=true` without `MIGRATION_DATABASE_URL`,
development database passwords, `ALLOW_PRIVATE_UPSTREAM_HOSTS`, a bootstrap without
`ADMIN_CLIENT_SECRET` and `ADMIN_PUBLIC_URL`, metrics on the main port without a 32-character
`METRICS_TOKEN`, `KEY_MANUAL_PUBLISH_AHEAD` below 390 s, and any secret reused for another
purpose. Development and test mode run only with a loopback or `*.localhost` `PUBLIC_URL`. It
warns (at start and in `config:check`) about `TRUST_PROXY=true`, debug logging, a rate limit
switched off, metrics on a separate port without a token, `ADMIN_MIN_ACR` unset,
`MIGRATE_ON_START=true`, and a `MIGRATION_DATABASE_URL` given to the server, which does not use it.

### Server variables

| Variable                               | Default                                 | Meaning                                                                                                                                                                                                                                                                      |
| -------------------------------------- | --------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `NODE_ENV`                             | `development` (image: `production`)     | `production` for every deployment; `development` and `test` only on loopback.                                                                                                                                                                                                |
| `PORT`                                 | `3000`                                  | HTTP port.                                                                                                                                                                                                                                                                   |
| `PUBLIC_URL`                           | `http://localhost:{PORT}` (dev)         | Portvakt's origin without a path; required in production. Issuers are `{PUBLIC_URL}/t/{slug}`; endpoint URLs and cookie security always follow it, never request headers.                                                                                                    |
| `TRUST_PROXY`                          | `false`                                 | Proxy hops trusted for `X-Forwarded-For` (the client IP of rate limits and logs): `false`, a hop count, or `true` (warned).                                                                                                                                                  |
| `MIGRATE_ON_START`                     | `true` outside production, else `false` | Apply migrations at start (needs `MIGRATION_DATABASE_URL` in the replicas; prefer the migration job).                                                                                                                                                                        |
| `LOG_LEVEL`                            | `info`                                  | `fatal`, `error`, `warn`, `info`, `debug`, `trace`, `silent`.                                                                                                                                                                                                                |
| `DATABASE_URL`                         | required                                | Runtime role (DML only). Its user name is the role the migration runner grants.                                                                                                                                                                                              |
| `MIGRATION_DATABASE_URL`               | `DATABASE_URL` (dev); see meaning       | Owner role, for the jobs only: migrations (`migrate-cli`), audit retention (`prune-cli`), the re-wrap (`rewrap-cli`), and `MIGRATE_ON_START`. Required in production there, not needed (and warned about) by the server otherwise. Must be another role than `DATABASE_URL`. |
| `DATABASE_POOL_MAX`                    | `10`                                    | Runtime pool size per replica (2 to 200), plus one LISTEN connection.                                                                                                                                                                                                        |
| `DATABASE_STATEMENT_TIMEOUT`           | `15s`                                   | `statement_timeout` of runtime connections.                                                                                                                                                                                                                                  |
| `DATABASE_IDLE_IN_TRANSACTION_TIMEOUT` | `60s`                                   | `idle_in_transaction_session_timeout` of runtime connections.                                                                                                                                                                                                                |
| `DATABASE_CONNECTION_TIMEOUT`          | `5s`                                    | How long getting a pool connection may take.                                                                                                                                                                                                                                 |
| `MASTER_KEY`                           | required                                | 32 bytes, base64: encrypts signing keys, client secrets, SP keys and personal identity numbers (AES-256-GCM) and derives the blind-index key.                                                                                                                                |
| `MASTER_KEY_PREVIOUS`                  | empty                                   | Older master keys (comma-separated), for decryption and lookups during a rotation.                                                                                                                                                                                           |
| `COOKIE_KEYS`                          | required                                | Comma-separated keys signing oidc-provider's cookies; the first signs, all verify (rotate by prepending).                                                                                                                                                                    |
| `ACCESS_TOKEN_TTL`                     | `5m`                                    | Access token lifetime (also client_credentials). It is how long a token outlives a kill switch.                                                                                                                                                                              |
| `ID_TOKEN_TTL`                         | `5m`                                    | ID token lifetime.                                                                                                                                                                                                                                                           |
| `REFRESH_TOKEN_TTL`                    | `8h`                                    | Ceiling of refresh token lifetimes (the login method's session policy shortens it); at most `SESSION_TTL`.                                                                                                                                                                   |
| `SESSION_TTL`                          | `8h`                                    | Default and ceiling of broker sessions; login methods' `maxAgeSeconds` may not exceed it.                                                                                                                                                                                    |
| `INTERACTION_TTL`                      | `15m`                                   | How long a login interaction (including the upstream login) may take.                                                                                                                                                                                                        |
| `KEY_ROTATION_INTERVAL`                | `90d`                                   | How often a new signing key is introduced.                                                                                                                                                                                                                                   |
| `KEY_PUBLISH_AHEAD`                    | `2d`                                    | How long a scheduled `next` key is published before it signs.                                                                                                                                                                                                                |
| `KEY_RETIRE_AFTER`                     | `2d`                                    | How long a `retiring` key stays published; at least the longest token lifetime and `SESSION_TTL`.                                                                                                                                                                            |
| `KEY_MANUAL_PUBLISH_AHEAD`             | `10m`                                   | Manual rotation without `emergency`: the new key is published at once and signs after this; at least 390 s in production.                                                                                                                                                    |
| `KEY_ROTATION_CHECK_INTERVAL`          | `1h`                                    | How often the rotation job checks for a due transition.                                                                                                                                                                                                                      |
| `PROVIDER_RELOAD_INTERVAL`             | `30s`                                   | Fallback reload of tenant providers and keys when a change notification was missed.                                                                                                                                                                                          |
| `PAYLOAD_CLEANUP_INTERVAL`             | `15m`                                   | How often expired sessions, codes, tokens and replay entries are deleted.                                                                                                                                                                                                    |
| `SHUTDOWN_DRAIN_DELAY`                 | `5s`                                    | After SIGTERM, `/readyz` answers 503 this long before the listener closes (0 disables).                                                                                                                                                                                      |
| `SHUTDOWN_TIMEOUT`                     | `15s`                                   | How long in-flight requests may take after the listener closed.                                                                                                                                                                                                              |
| `ACR_RANKING`                          | `…/loa2,…/loa3,…/loa4`                  | Assurance levels from lowest to highest (Swedish eID Framework URIs by default).                                                                                                                                                                                             |
| `UPSTREAM_TIMEOUT`                     | `10s`                                   | Timeout of each request to an upstream IdP.                                                                                                                                                                                                                                  |
| `UPSTREAM_METADATA_TTL`                | `1h`                                    | How long discovered upstream OIDC metadata is reused.                                                                                                                                                                                                                        |
| `UPSTREAM_FAILURE_CACHE`               | `5s`                                    | A failed discovery is not retried for this long (0 disables).                                                                                                                                                                                                                |
| `SAML_METADATA_CHECK_INTERVAL`         | `5m`                                    | How often SAML metadata URLs are checked for a due refresh (each method refreshes after its own `metadataRefreshSeconds`).                                                                                                                                                   |
| `SAML_METADATA_MAX_AGE`                | `7d`                                    | Cached SAML metadata without `validUntil` is used at most this long after its last successful refresh, then the method fails closed.                                                                                                                                         |
| `SAML_XML_MAX_ELEMENTS`                | `20000`                                 | Largest element count of a SAML Response Portvakt parses (100 to 1,000,000).                                                                                                                                                                                                 |
| `ALLOW_PRIVATE_UPSTREAM_HOSTS`         | empty                                   | Hosts outbound requests may reach although they resolve to private addresses; development and tests only, refused in production.                                                                                                                                             |
| `LOGIN_UI_DIR`                         | `apps/login/dist`                       | The built login UI (the image contains it).                                                                                                                                                                                                                                  |
| `AUDIT_RETENTION`                      | `400d`                                  | Audit events older than this are deleted by `prune-cli` (at least 90 days).                                                                                                                                                                                                  |
| `RATE_LIMIT_AUTHORIZE_IP`              | `120/1m`                                | Authorization requests per client IP (IPv6 per /64).                                                                                                                                                                                                                         |
| `RATE_LIMIT_AUTHORIZE_CLIENT`          | `3000/1m`                               | Authorization requests per tenant and client_id.                                                                                                                                                                                                                             |
| `RATE_LIMIT_INTERACTION_IP`            | `60/1m`                                 | Login UI API calls (method choice, representation) per client IP.                                                                                                                                                                                                            |
| `RATE_LIMIT_FEDERATION_IP`             | `120/1m`                                | Upstream callbacks and SAML endpoints per client IP.                                                                                                                                                                                                                         |
| `RATE_LIMIT_TOKEN_IP`                  | `600/1m`                                | Token, introspection, revocation and PAR requests per client IP.                                                                                                                                                                                                             |
| `RATE_LIMIT_TOKEN_CLIENT`              | `1200/1m`                               | Failed client authentications per tenant and client_id at those endpoints.                                                                                                                                                                                                   |
| `RATE_LIMIT_ADMIN_API`                 | `600/1m`                                | Admin API calls per caller.                                                                                                                                                                                                                                                  |
| `HTTP_REQUEST_TIMEOUT`                 | `30s`                                   | Node's `requestTimeout` (headers and body).                                                                                                                                                                                                                                  |
| `HTTP_HEADERS_TIMEOUT`                 | `20s`                                   | Node's `headersTimeout` (at most the request timeout).                                                                                                                                                                                                                       |
| `HTTP_KEEP_ALIVE_TIMEOUT`              | `65s`                                   | Keep-alive timeout; keep it above the load balancer's idle timeout.                                                                                                                                                                                                          |
| `MAX_URL_LENGTH`                       | `8192`                                  | Longer request URLs get 414.                                                                                                                                                                                                                                                 |
| `HTTP_MAX_HEADER_SIZE`                 | `16384`                                 | Larger header blocks get 431.                                                                                                                                                                                                                                                |
| `METRICS_ENABLED`                      | `true`                                  | Serve Prometheus metrics at `/metrics`.                                                                                                                                                                                                                                      |
| `METRICS_PORT`                         | unset                                   | A separate metrics listener (keep it off the ingress); without it metrics are on `PORT` and need `METRICS_TOKEN` in production.                                                                                                                                              |
| `METRICS_HOST`                         | `0.0.0.0`                               | Address of the separate metrics listener.                                                                                                                                                                                                                                    |
| `METRICS_TOKEN`                        | unset                                   | Bearer token required to scrape (at least 32 characters in production).                                                                                                                                                                                                      |
| `ADMIN_PUBLIC_URL`                     | `http://localhost:3400` (dev)           | The admin portal's origin: the bootstrap registers `{ADMIN_PUBLIC_URL}/t/{tenant}/auth/callback` for `portvakt-admin`.                                                                                                                                                       |
| `ADMIN_CLIENT_SECRET`                  | generated in development                | Client secret of `portvakt-admin` set at the bootstrap (at least 32 characters); the portal uses the same value.                                                                                                                                                             |
| `ADMIN_MIN_ACR`                        | unset (warned)                          | A level of `ACR_RANKING` administrators must sign in with; the admin API refuses lower or unranked acr (`acr_too_low`).                                                                                                                                                      |
| `BOOTSTRAP_IDP_ISSUER`                 | unset                                   | OIDC issuer of the first login method of the `system` tenant (https in production). See [Bootstrap](#bootstrap).                                                                                                                                                             |
| `BOOTSTRAP_IDP_CLIENT_ID`              | required with the issuer                | Client id at that IdP.                                                                                                                                                                                                                                                       |
| `BOOTSTRAP_IDP_CLIENT_SECRET`          | unset                                   | Its client secret (stored encrypted).                                                                                                                                                                                                                                        |
| `BOOTSTRAP_IDP_SCOPES`                 | `openid profile email`                  | Scopes requested upstream (must include `openid`).                                                                                                                                                                                                                           |
| `BOOTSTRAP_IDP_KIND`                   | `employee`                              | `employee` or `citizen`.                                                                                                                                                                                                                                                     |
| `BOOTSTRAP_IDP_DISPLAY_NAME`           | `Administrator sign-in`                 | Name shown in the login UI.                                                                                                                                                                                                                                                  |
| `BOOTSTRAP_IDP_ACR`                    | `urn:portvakt:acr:employee`             | The acr the method asserts (with `BOOTSTRAP_ADMIN_PIN` a level ranked at least loa3).                                                                                                                                                                                        |
| `BOOTSTRAP_IDP_SUBJECT_CLAIM`          | `sub`                                   | Upstream claim of the subject.                                                                                                                                                                                                                                               |
| `BOOTSTRAP_IDP_NAME_CLAIM`             | `name`                                  | Upstream claim of the name.                                                                                                                                                                                                                                                  |
| `BOOTSTRAP_IDP_EMAIL_CLAIM`            | `email`                                 | Upstream claim of the email.                                                                                                                                                                                                                                                 |
| `BOOTSTRAP_IDP_PIN_CLAIM`              | unset                                   | Upstream claim of the personal identity number (required with `BOOTSTRAP_ADMIN_PIN`).                                                                                                                                                                                        |
| `BOOTSTRAP_IDP_ACR_CLAIM`              | unset                                   | Upstream claim of the acr (required with `BOOTSTRAP_ADMIN_PIN`).                                                                                                                                                                                                             |
| `BOOTSTRAP_IDP_TRUST_EMAIL`            | `false`                                 | Map the email without `email_verified` (Entra ID work accounts).                                                                                                                                                                                                             |
| `BOOTSTRAP_ADMIN_SUBJECT`              | unset                                   | Upstream subject of the first platform administrator (or:)                                                                                                                                                                                                                   |
| `BOOTSTRAP_ADMIN_PIN`                  | unset                                   | ... their personal identity number.                                                                                                                                                                                                                                          |

### Admin portal variables

| Variable                         | Default                               | Meaning                                                                                                                   |
| -------------------------------- | ------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| `NODE_ENV`                       | `development` (image: `production`)   | `production` for every deployment.                                                                                        |
| `ADMIN_PORT`                     | `3400`                                | HTTP port.                                                                                                                |
| `ADMIN_PUBLIC_URL`               | `http://localhost:{ADMIN_PORT}` (dev) | The portal's origin (https in production, required).                                                                      |
| `PORTVAKT_PUBLIC_URL`            | `PUBLIC_URL` (dev)                    | Portvakt's `PUBLIC_URL`: tenant issuers are `{PORTVAKT_PUBLIC_URL}/t/{slug}` (required in production).                    |
| `PUBLIC_URL`                     | `http://localhost:3000` (dev)         | Read outside production only, as a fallback for `PORTVAKT_PUBLIC_URL` (a shared `.env`).                                  |
| `ADMIN_API_URL`                  | `PORTVAKT_PUBLIC_URL`                 | Where the BFF calls the admin API; https in production (it sends administrators' access tokens).                          |
| `ADMIN_CLIENT_ID`                | `portvakt-admin`                      | The portal's client id.                                                                                                   |
| `ADMIN_CLIENT_SECRET`            | development secret                    | The same value as the server's `ADMIN_CLIENT_SECRET`.                                                                     |
| `ADMIN_COOKIE_SECRET`            | development secret                    | Comma-separated secrets signing the session cookie (at least 32 characters each).                                         |
| `ADMIN_COOKIE_SECURE`            | `true` except http on localhost       | Secure cookies; `false` is refused in production.                                                                         |
| `ADMIN_SESSION_ENCRYPTION_KEY`   | development key                       | Comma-separated base64 keys sealing sessions (32 bytes each; the first seals).                                            |
| `ADMIN_DATABASE_URL`             | unset (memory store)                  | Postgres for sessions (`portvakt_admin_sessions`); required in production.                                                |
| `ADMIN_MIGRATION_DATABASE_URL`   | `ADMIN_DATABASE_URL`                  | Read by `migrate-sessions` only: the session database's owner, which creates the table. Never given to the portal itself. |
| `ADMIN_DEFAULT_TENANT`           | `system`                              | Where `/` sends the browser.                                                                                              |
| `ADMIN_IDLE_TIMEOUT_SECONDS`     | `1800`                                | Idle timeout of a portal session (at least 60).                                                                           |
| `ADMIN_WEB_DIR`                  | `apps/admin/dist/web`                 | The built SPA (the image contains it).                                                                                    |
| `ADMIN_TRUST_PROXY`              | `false`                               | Proxy hops trusted for `X-Forwarded-For`.                                                                                 |
| `ADMIN_RATE_LIMIT_LOGIN`         | `30/1m`                               | Sign-in routes per client IP.                                                                                             |
| `ADMIN_RATE_LIMIT_TENANT_LOOKUP` | `30/1m`                               | Lookups of unknown tenant slugs per client IP.                                                                            |
| `ADMIN_METRICS_ENABLED`          | `true`                                | `/metrics` (`portvakt_admin_*`) on the main port.                                                                         |
| `ADMIN_METRICS_TOKEN`            | unset                                 | Bearer token for `/metrics`; required in production unless metrics are off.                                               |
| `ADMIN_LOG_LEVEL`                | `info`                                | Log level.                                                                                                                |

## Database roles

Portvakt uses four roles, none of them a superuser. The long-running services (server, admin
portal) get runtime roles only; owner credentials go only to one-off jobs.

- the **owner** (`MIGRATION_DATABASE_URL`) owns Portvakt's database and its schema: migrations,
  the runtime role's grants, audit retention and the re-wrap. Only jobs use it; in production
  the server refuses to start without it only when `MIGRATE_ON_START=true`
  ([`config/index.ts`](../apps/server/src/config/index.ts)).
- the **runtime role** (`DATABASE_URL`) gets DML only, `SELECT, INSERT` on `audit_events`, no
  `TEMPORARY`, no `EXECUTE` on the retention function; the migration runner grants it after
  every run ([`migrations/grants/runtime-role.sql`](../apps/server/migrations/grants/runtime-role.sql)).
  In production Portvakt refuses to start when the `DATABASE_URL` role is a superuser, owns
  `audit_events` or may change or prune it, so the owner can never be used as runtime role
  ([`db/runtime-role.ts`](../apps/server/src/db/runtime-role.ts)); a configured
  `MIGRATION_DATABASE_URL` must name another role.
- the **admin session owner** (`ADMIN_MIGRATION_DATABASE_URL`, `portvakt_admin_owner` in compose)
  owns a database of its own and creates `portvakt_admin_sessions` (`migrate-sessions`).
- the **admin runtime role** (`ADMIN_DATABASE_URL`, `portvakt_admin`) has DML on the tables the
  admin owner creates there (`ALTER DEFAULT PRIVILEGES FOR ROLE portvakt_admin_owner ... GRANT
SELECT, INSERT, UPDATE, DELETE ON TABLES TO portvakt_admin`) and cannot reach Portvakt's
  database.

The compose init script ([`10-portvakt-roles.sh`](../deploy/compose/postgres-init/10-portvakt-roles.sh))
shows the statements. Use TLS to the database (`?sslmode=verify-full` in the URLs).

`config:check` reports the server's configuration; `config:check -- --job` (in the image:
`node dist/config/check-cli.js --job`) reports it as the owner-role jobs see it, which also need
`MIGRATION_DATABASE_URL`.

## Bootstrap

On a database without tenants, the first start creates, under an advisory lock and in one
transaction ([`admin/bootstrap.ts`](../apps/server/src/admin/bootstrap.ts)): the `system` tenant,
the application `portvakt-admin` (roles `platform-admin`, `tenant-admin`; redirect URI
`{ADMIN_PUBLIC_URL}/t/{tenant}/auth/callback`; secret `ADMIN_CLIENT_SECRET`), enabled in
`system`, an OIDC login method from `BOOTSTRAP_IDP_*`, and a pending `platform-admin` assignment
for `BOOTSTRAP_ADMIN_SUBJECT` (or `BOOTSTRAP_ADMIN_PIN`), audited as `admin.bootstrap`. That
person signs in at `{ADMIN_PUBLIC_URL}/t/system/` and becomes platform administrator. Concurrent
replicas bootstrap once. Without tenants and without `BOOTSTRAP_IDP_*` the server only logs a
warning. For Entra ID: register an app with the redirect URI
`{PUBLIC_URL}/t/system/federation/{loginMethodId}/callback` after the first start (the login
method id is in the admin API and the logs), or register the method yourself through the admin
API; see [login-methods.md](login-methods.md).

## Migrations

Plain SQL files in [`apps/server/migrations`](../apps/server/migrations), applied by
`migrate-cli` in order, each in a transaction, under an advisory lock (concurrent runners wait),
with checksums: the runner refuses to start on a changed or missing applied file. A second run is
a no-op (CI checks it). Migrations are additive within 1.x; a release that needs more says so in
the [changelog](../CHANGELOG.md). Run them before the new version's pods start (the Helm hook,
the compose `migrate` job); old replicas keep working against the migrated schema during a
rolling update.

## Signing keys

One ES256 key set signs for every tenant; private keys are encrypted with MASTER_KEY. States:
`next` (published, not signing), `active` (signs), `retiring` (published for verification),
`retired`. Transitions are guarded by time in SQL and run by one replica at a time
([`keys/rotation.ts`](../apps/server/src/keys/rotation.ts)).

- **Scheduled**: every `KEY_ROTATION_INTERVAL` a `next` key appears, becomes `active` after
  `KEY_PUBLISH_AHEAD`, and the old key is `retiring` for `KEY_RETIRE_AFTER`. Nothing to do.
- **Manual** (portal: Nycklar, "Rotera nu" in the system tenant; or `POST /admin/api/v1/signing-keys/rotate` with `{
"reason": "..." }`, platform administrators only): the new key is published at once and signs
  after `KEY_MANUAL_PUBLISH_AHEAD`, longer than the SDKs' JWKS caching, so no verifier sees an
  unknown key. Signed-in sessions continue.
- **Emergency** (`{ "reason": "...", "emergency": true }`): a fresh key signs at once and every
  other key is retired in the same transaction. Every outstanding access and ID token stops
  verifying; applications refresh (the SDKs refetch JWKS for an unknown kid from the token
  endpoint) or sign the person in again. See the runbook below.

`portvakt_signing_key_age_seconds` and `portvakt_signing_keys_loaded` show the state.

## Master key rotation

1. Generate a new key. Set `MASTER_KEY` to it and add the old one to `MASTER_KEY_PREVIOUS`
   (comma-separated), on every replica and job, and roll out. Everything still decrypts; new
   encryptions use the new key, and lookups by personal identity number try every key's blind
   index.
2. Run the re-wrap once: `node dist/db/rewrap-cli.js` in the server image with the server's
   environment plus `MIGRATION_DATABASE_URL` (it connects as the owner, like the other
   maintenance jobs; Kubernetes: a one-off Job mounting the server and owner Secrets; compose:
   `docker compose run --rm -e MIGRATION_DATABASE_URL=... server node dist/db/rewrap-cli.js`).
   It re-encrypts signing keys, client secrets, upstream
   client keys, SAML SP keys and personal identity numbers under the new key and re-indexes
   blind indexes, and prints counts per kind.
3. Keep the old key in `MASTER_KEY_PREVIOUS` for at least `SESSION_TTL` after step 1: sealed SAML
   logout data in live sessions is not re-wrapped. Then remove it and roll out again.

## Backups and restore

Back up:

- **The database** (`pg_dump` or continuous archiving/PITR of the cluster): tenants,
  applications, login methods, persons and identities, assignments, representation grants,
  signing keys, SAML SP keys and metadata cache, sessions and grants (`oidc_payloads`), audit
  events, schema migrations. The admin portal's session database needs no backup (people sign
  in again).
- **MASTER_KEY and every key in MASTER_KEY_PREVIOUS**, separately from the database backups (a
  secret manager with its own backup). A database backup is useless without the key that
  encrypted it, and the two together expose every secret and personal identity number.
- **The other secrets** (`COOKIE_KEYS`, `ADMIN_*` secrets, `METRICS_TOKEN`, database passwords),
  or the ability to regenerate them: they can be replaced; existing browser cookies and portal
  sessions then end.

Restore: restore the database, deploy with the same `MASTER_KEY` (and previous keys), run the
migration job, start. Sessions and refresh tokens in the backup are as old as the backup;
everything issued after it is gone, so people sign in again. Signing keys come back with the
database: tokens signed by a key created after the backup do not verify any more, which ends
those sessions at their next refresh. After restoring an older backup consider an emergency key
rotation if the newer keys might have leaked.

## Monitoring

`/healthz` answers 200 while the process runs; `/readyz` answers 200 when the database is
reachable and signing keys are loaded, 503 otherwise and during shutdown. Metrics are Prometheus
text at `/metrics` (`METRICS_PORT` or the main port with `METRICS_TOKEN`); labels are route
templates, reason codes, grant types, login method ids, tenant slugs and kids, never personal
data ([`metrics/registry.ts`](../apps/server/src/metrics/registry.ts),
[`metrics/collectors.ts`](../apps/server/src/metrics/collectors.ts)).

| Metric                                                             | Meaning                                                        |
| ------------------------------------------------------------------ | -------------------------------------------------------------- |
| `portvakt_http_requests_total`, `..._duration_seconds`             | Requests and latency by method, route template, status         |
| `portvakt_logins_total`                                            | Finished logins by `outcome`, `reason`, `protocol`             |
| `portvakt_tokens_issued_total`                                     | Token endpoint successes by `grant_type`, `tenant`             |
| `portvakt_rate_limited_total`                                      | Requests refused by a rate limit, by `limit`                   |
| `portvakt_upstream_request_duration_seconds`, `_failures_total`    | Upstream requests by `login_method`, `purpose`, outcome        |
| `portvakt_federation_callback_rejected_total`                      | Upstream callbacks with an unknown state                       |
| `portvakt_saml_metadata_refresh_total`, `_refresh_failing`         | SAML metadata refreshes; 1 while a method's refresh fails      |
| `portvakt_saml_metadata_age_seconds`, `_valid_until_seconds`       | Age and validUntil of each method's cached metadata            |
| `portvakt_saml_logout_total`                                       | SAML single logout messages                                    |
| `portvakt_signing_keys_loaded`, `portvakt_signing_key_age_seconds` | Keys of this replica by state; key ages                        |
| `portvakt_db_pool_connections`                                     | Runtime pool connections by `state` (`waiting` > 0: saturated) |
| `process_*`, `nodejs_eventloop_delay_p99_seconds`                  | Process CPU, memory, event loop delay                          |
| `portvakt_admin_*`                                                 | The admin portal's HTTP and session pool metrics               |

Suggested alerts (tune the thresholds to your traffic):

- `/readyz` failing on any replica for 2 minutes, or fewer ready replicas than the PDB allows.
- `sum(rate(portvakt_http_requests_total{status=~"5.."}[5m])) / sum(rate(portvakt_http_requests_total[5m])) > 0.02`.
- `portvakt_signing_keys_loaded{state="active"} == 0` on any replica (it cannot sign).
- `max(portvakt_signing_key_age_seconds{state="active"}) > KEY_ROTATION_INTERVAL + 1d`: the
  rotation job is not running.
- `portvakt_saml_metadata_refresh_failing == 1` for 1 hour, or
  `portvakt_saml_metadata_valid_until_seconds - time() < 2*86400`: a SAML method will fail closed.
- `rate(portvakt_upstream_request_failures_total[10m]) > 0` per `login_method` for 10 minutes:
  an upstream IdP is failing.
- `sum by (reason) (rate(portvakt_logins_total{outcome="failure"}[15m]))` well above its usual
  level.
- `rate(portvakt_rate_limited_total[5m]) > 0` sustained: an attack or a limit that is too low.
- `portvakt_db_pool_connections{state="waiting"} > 0` for 5 minutes: raise
  `DATABASE_POOL_MAX` or the replicas (mind [Capacity](#capacity)).
- `nodejs_eventloop_delay_p99_seconds > 0.2` for 10 minutes.
- Login method secrets and SP certificates expiring within 30 days are flagged in the admin
  portal and in the `warnings` of each login method in the admin API, not as metrics.

## Logging

Both processes log JSON lines (pino) to stdout: `level`, `time`, `msg`, `requestId` and
`traceId` (a valid incoming `traceparent` is continued, `X-Request-Id` kept when well-formed;
both are echoed in responses), plus event fields. Keys that may hold credentials or personal data
are censored at any depth ([`logging/logger.ts`](../apps/server/src/logging/logger.ts)); errors
keep type, message, code and stack. Logs never contain names, emails, personal identity numbers,
tokens or secrets. The audit trail is the `audit_events` table, not the logs
([`audit/catalogue.ts`](../apps/server/src/audit/catalogue.ts) lists every action); forward it by
tailing `audit_events` by `seq`.

## Outage behaviour

- **Portvakt down**: applications validate access tokens locally (cached JWKS, kept for at most
  `jwks.staleMaxAge`, default 1 hour, past their cache age when Portvakt cannot be reached) and
  keep their BFF sessions. When a session's access token needs a refresh, the SDKs keep the
  session for `outageGraceSeconds` / `login.outage-grace` (default 0: the session ends) and new
  sign-ins fail with a clear page (503).
- **Database down or failing over**: `/readyz` answers 503 (pods leave the load balancer),
  requests that need the database fail, the pool reconnects by itself, the change listener reconnects
  with backoff and providers reload, so recovery needs no restart.
- **An upstream IdP down**: only its login method fails (`upstream_unavailable`); discovery
  failures are cached for `UPSTREAM_FAILURE_CACHE`. SAML methods keep using their cached
  metadata until its validUntil or `SAML_METADATA_MAX_AGE`.
- **Overload**: rate limits answer 429 with Retry-After; the SDKs treat 429 and
  `temporarily_unavailable` from the token endpoint as transient (the session keeps its refresh
  token).

## Capacity

Each server replica holds up to `DATABASE_POOL_MAX` (default 10) runtime connections plus one
LISTEN connection; the migration job and the audit retention job hold one owner connection each
while they run; each admin portal replica holds up to 10 session-store connections. Keep

```
(server replicas + surge) × (DATABASE_POOL_MAX + 1) + 2 + admin replicas × 10 (when on the same server)
```

below the database's `max_connections` minus its reserved slots
(`superuser_reserved_connections`, replication, monitoring and any admin tooling). With the HPA,
count its `maxReplicas`; during a rolling update one more pod per Deployment runs (`maxSurge: 1`).
Example: 3 to 8 replicas, pool 10, 2 admin replicas: (8 + 1) × 11 + 2 + 3 × 10 = 131 connections.
The chart's `database.maxConnections` check computes the same. A connection pooler in transaction
mode in front of Postgres is not supported: Portvakt uses LISTEN/NOTIFY, advisory locks and
session settings.

Sizing: v1.0.0 has not been load-tested. The chart's requests (0.1 CPU, 192 MiB per server
replica) are a starting point; logins are dominated by upstream latency, token refreshes by a
few database round trips and an ES256 signature. Measure with your own upstreams and traffic
before sizing for peaks, and scale on CPU (`server.autoscaling`).

## Upgrades

Portvakt follows semantic versioning from 1.0.0. Within 1.x: the claims contract
([claims.md](claims.md)), the admin API v1 ([admin-api.md](admin-api.md)), the SDK APIs and the
configuration variables stay compatible; migrations are additive and run before the new pods, so
rolling updates work without downtime. Read the [changelog](../CHANGELOG.md) before upgrading;
upgrade one minor version at a time when the changelog asks for it. Security fixes are released
for the latest minor version ([SECURITY.md](../SECURITY.md)). Roll back by deploying the previous
images (`helm rollback`, which does not run the migration hook): additive migrations keep the
schema usable by the previous minor release. Do not run the previous version's migration job
against a newer schema: the runner refuses a database with applied migrations it does not know.

**PostgreSQL versions.** CI, the dev database and the Compose stack run PostgreSQL 18. Portvakt
uses no 18-only features, but only 18 is tested. A major PostgreSQL upgrade is a database
operation (`pg_upgrade` or dump and restore), independent of Portvakt's own upgrades. The Compose
files mount the volume at `/var/lib/postgresql`, as the 18 image expects, under new volume names
(`portvakt-pgdata18`, `pgdata18`). A volume created by an earlier Compose file still holds
PostgreSQL 16 data and is no longer used; migrate its data with `pg_upgrade` or a dump and
restore if you need it, then remove it.

## Runbooks

### Compromised signing key

Signs of it: a private key or a database dump together with MASTER_KEY may have leaked.

1. Rotate with emergency: portal (system tenant, Nycklar, "Rotera nu", "Nödrotation (nyckeln är
   röjd)") or
   `POST /admin/api/v1/signing-keys/rotate` with `{ "reason": "key compromise", "emergency": true }`.
   JWKS now publishes only the new key; every replica picks it up through the change notification
   (at the latest after `PROVIDER_RELOAD_INTERVAL`).
2. Every outstanding access and ID token is invalid; BFF sessions refresh with the new key at
   their next token refresh; applications that cache JWKS longer than the SDK defaults must
   refetch.
3. If MASTER_KEY may have leaked too, rotate it ([Master key rotation](#master-key-rotation)),
   then rotate every downstream client secret (`POST /applications/{id}/rotate-secret`), every
   upstream client secret (at the IdP, then `PATCH` the login method), every upstream client key
   of a `private_key_jwt` method (`client-key/prepare`, let the IdP fetch the JWKS,
   `client-key/rotate`) and the SAML SP keys (`sp-keys/prepare`, re-register the SP metadata
   with the IdP, `sp-keys/rotate`).
4. Review `audit_events` (`key.*`, `token.issued`) for the period.

### Compromised upstream IdP

An upstream IdP of a tenant can sign in any person of that tenant at its login method's level.

1. Disable the login method (portal, or `PATCH /tenants/{id}/login-methods/{id}` with `{
"enabled": false }`). This ends every session and grant whose login came through it at once
   (`sessions.revoked`); access tokens already issued expire within `ACCESS_TOKEN_TTL`.
2. If it was the only login method of administrators, use another method of the `system` tenant
   (Portvakt refuses to remove the last one, `self_lockout`).
3. Review `login.success` events of the method and the persons created (`person.created`) since
   the suspected start; unlink identities or delete persons that should not exist.
4. Re-enable it only after the IdP is trustworthy again; nothing revoked comes back.

### Lost master key

Without the key, Portvakt cannot decrypt its signing keys (it cannot sign or become ready), the
stored client secrets, upstream client keys, SAML SP keys or personal identity numbers, and the
blind indexes no longer match.

1. Restore the key from the secret manager's backup. This is the only complete recovery; test
   it.
2. If no copy exists, the encrypted data is lost. Recovery then means a new installation
   pattern: a new MASTER_KEY; new signing keys; new client secrets for every application; the
   upstream secrets and SAML SP keys of every login method re-entered or rotated; identities
   linked by personal identity number re-linked as people sign in again. v1.0.0 has no tested,
   automated procedure for this; do not attempt it on the production database without a
   rehearsal on a copy.

### Database failover

1. During the failover `/readyz` is 503 and requests that need the database fail. Nothing else is
   needed: the pool and the change listener reconnect, and providers and keys reload.
2. If the new primary has a different address, update `DATABASE_URL` (server Secret) and the
   owner URLs (owner Secret) and roll out.
3. After a failover with data loss (asynchronous replication), recently issued refresh tokens
   or rotations may be gone: the affected people sign in again. Check `portvakt_signing_keys_loaded`
   and the latest `key.*` audit events; if a rotation was lost, the next scheduled check repeats
   it.

### Rate-limit tuning

1. `portvakt_rate_limited_total` by `limit` shows which bucket refuses requests; the logs show the
   route template and status 429.
2. Behind a proxy, make sure `TRUST_PROXY` is the number of proxies in front: otherwise every
   client has the proxy's IP and shares one bucket (or, with `true`, clients choose their IP).
3. Raise the specific limit (`RATE_LIMIT_*`; buckets are per replica, so the effective limit is
   replicas × limit). Many users behind one NAT (a municipality's network) mostly hit
   `RATE_LIMIT_AUTHORIZE_IP` and `RATE_LIMIT_INTERACTION_IP`.
4. Put per-IP and per-path limits in the ingress or WAF in front for `/t/*/auth` and
   `/t/*/token` as well ([threat-model.md](threat-model.md), residual risks).
