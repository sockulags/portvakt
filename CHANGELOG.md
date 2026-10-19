# Changelog

All notable changes to Portvakt. The project follows [semantic versioning](https://semver.org):
within 1.x the claims contract, the admin API v1, the SDK APIs and the configuration variables
stay compatible (see [docs/operations.md](docs/operations.md#upgrades)).

## 1.0.0 (2026-10-19)

The first release.

### Broker

- OpenID Connect provider per tenant (`oidc-provider` 9): issuer `{PUBLIC_URL}/t/{tenant}`,
  authorization code with PKCE, refresh token rotation bound to the broker session (a replay
  revokes the grant), client_credentials with per-application `serviceAudiences`, PAR,
  introspection (owning client only) and revocation; userinfo disabled by design.
- Access tokens are ES256 JWTs for one application (`aud`), carrying only `sub`, `tid`, `idp`,
  `idp_kind`, `acr`, `auth_time`, `roles`, `attrs` and `rep`; ID tokens carry profile claims per
  scope, `session_exp`, `pin` and `hsa_id`/`org_affiliation` only with allowed scopes. The
  claims contract v1 is [docs/claims.md](docs/claims.md).
- Upstream OIDC (openid-client): discovery cache, `client_secret_basic`/`post` and
  `private_key_jwt`, asymmetric algorithms only, claim mapping, multi-tenant Entra ID issuers
  with an allowlist, groups overage handling, PAR for personal identity number hints.
- Upstream SAML 2.0 following the Swedish eID Framework: signed AuthnRequests (Redirect and
  POST), encrypted and signed assertions with an algorithm allowlist and signature-wrapping
  defences, bounded XML parsing, replay cache, levels of assurance (`exact`/`minimum`), entity
  categories, PrincipalSelection, signed metadata with scheduled refresh and fail-closed
  staleness, SP key rotation, single logout in both directions.
- Session policy per login method (maximum age, idle timeout, single sign-on), step-up with
  `acr_values` and `max_age` that must sign in the same person, home realm discovery.
- Persons created just in time, identities linked by personal identity number between methods
  that assert at least loa3, roles from assignments, pending assignments and upstream group
  rules, per-application attributes, sticky protected identity.
- Representation (ombud): the chooser after login, `rep` in tokens, re-validation at every
  refresh, revocation ends the grant; Portvakt's own register as the first
  `RepresentationSource`.
- Signing keys in the database, encrypted with MASTER_KEY: scheduled rotation with publish-ahead
  and retire-after, manual rotation with a published lead time, emergency rotation that retires
  every other key at once.
- Secrets, private keys and personal identity numbers encrypted at rest (AES-256-GCM, bound to
  their row) with blind indexes for lookups; master key rotation with `rewrap-secrets`.
- Append-only audit trail with a catalogue of typed events and retention through an owner-only
  database function (`audit:prune`).
- Hardening: per-IP and per-client rate limits, strict CSP and security headers, CSRF
  protection, outbound guard against SSRF for every configured URL, request size and time
  limits, statement timeouts, refusal of development settings in production, `config:check`.
- Observability: JSON logs without personal data with request and trace ids (W3C traceparent),
  Prometheus metrics, `/healthz` and `/readyz`, graceful shutdown with a drain delay.

### Administration

- Admin API v1 with an OpenAPI document: tenants, applications, attachments, login methods,
  roles, rules, assignments, persons, parties, representation grants, signing keys, audit
  events; platform and tenant administrators with live role checks, lockout guards, ETags and an
  audit event for every change.
- Kill switches that end sessions and grants in the same transaction: tenant suspension,
  application disable (per tenant or globally) and detach, login method disable or delete,
  identity unlink, person delete, end-sessions.
- Bootstrap of the `system` tenant and the first platform administrator from `BOOTSTRAP_IDP_*`.
- Admin portal (BFF on the TypeScript SDK and a React SPA in Swedish and English, WCAG 2.1 AA
  checked).

### SDKs

- `@portvakt/sdk-node` 1.0.0 for Node 20+ and Express 4/5: BFF with sealed server-side sessions
  (memory or Postgres store with a per-session lock), access token validation middleware with
  role, acr, service and representation checks, cached service tokens, step-up, representation
  switch, outage grace, CSRF and cross-site guards.
- Java SDK 1.0.0 (`se.portvakt:portvakt-sdk-core`, `portvakt-spring-boot-starter`) for Java 21
  and Spring Boot 4.1 with the same behaviour, a JDBC token store and resource server support.

### Packaging

- Container images `portvakt-server` and `portvakt-admin` (compiled JavaScript, production
  dependencies only, no npm, non-root, read-only root filesystem, OCI labels, health checks), and
  `portvakt-mock-idp` and `portvakt-demo` for evaluation and tests only.
- Docker Compose stack (production mode, a local evaluation mode and the end-to-end suite
  against the production images) and a Helm chart with a migration hook, audit retention
  CronJob, NetworkPolicies, PodDisruptionBudgets, an optional HPA and ServiceMonitor and a
  database capacity check.
- Release workflow building the images with SBOMs on version tags.
- Tested on PostgreSQL 18 (CI, dev database and Compose stack).
