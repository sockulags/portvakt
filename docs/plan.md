# Portvakt — build plan

Portvakt is a multi-tenant identity broker. Upstream identity providers (Entra ID, BankID/Freja
brokers, SITHS brokers) authenticate people; Portvakt federates them, applies tenant policy, and
issues OIDC tokens to the organisation's own services. It is the first service of a starter kit
of shared platform services.

**Target: a production-ready v1.** Every milestone must pass its tests, and the release must pass
the full end-to-end suite against the containerised stack. Robustness requirements (security
hardening, observability, graceful failure) are part of the scope, not polish. Upstream login is
generic OIDC or SAML, so real providers (Entra ID, Criipto, Signicat, Freja via a broker) are configured,
not coded; the mock IdP exists only for development and tests.

## Fixed decisions

These were decided with the owner and are not reopened during delivery.

- **Core:** a TypeScript service embedding `oidc-provider` (panva, OpenID Certified) for the
  protocol. Everything tenant-, policy- and representation-specific is our code. Upstream federation
  uses `openid-client`. No hand-written protocol code beyond what the libraries require.
- **Tenancy:** always multi-tenant. A single-tenant install is an install with one tenant. Each
  tenant has its own issuer: `{PUBLIC_URL}/t/{tenantSlug}`.
- **Upstream:** Portvakt is only a relying party upstream. Tenants configure their own upstream
  IdPs ("login methods") and Portvakt stores their secrets encrypted. v1 supports two upstream
  protocols: **OIDC** (Entra ID, Criipto, Signicat and similar) and **SAML 2.0 following the
  Swedish eID Framework** (Sweden Connect / DIGG technical framework), which is how BankID, Freja
  eID and SITHS are typically reached through IdPs such as Inera's IdP or Swedish eID brokers.
- **Downstream:** apps talk OIDC to Portvakt only. Web apps use the backend-for-frontend pattern
  through the Portvakt SDK. Access tokens are short-lived JWTs with a per-app `aud`.
- **Users:** no pre-provisioning. A person record is created just in time at first login.
- **Authorization boundary:** Portvakt owns identity, assurance level, representation, and
  role/attribute _assignment_. Each app declares its roles and decides what they mean.
- **Runtime:** containers, Kubernetes-friendly (stateless app, Postgres for state, health probes).
- **Stack:** Node 24, TypeScript (ESM), npm workspaces, Express 5, PostgreSQL 16, `pg` with SQL
  migrations, zod, React 19 + Vite for UIs, Vitest for unit/integration, Playwright for e2e.
- **SDKs:** TypeScript (Node, Express) and Java (Java 21, Maven; core library plus Spring Boot 3
  starter). Both SDKs implement the same behaviour and are tested against the same scenarios.
  Java builds and tests run in a Maven container, so no local JDK is required.
- **Design:** all UI uses `packages/design-system` (from `design-system/` as delivered).

## Repository layout

```
apps/server        Broker: OIDC provider per tenant, federation, interactions, admin API, key rotation
apps/login         Login/interaction UI (React SPA, served by server)
apps/admin         Admin portal (React SPA + BFF via the SDK)
apps/mock-idp      Dev/test upstream IdPs: "mock-entra" (employees, groups) and "mock-bankid" (citizens)
packages/sdk-node  TypeScript SDK (Express): BFF login/callback/logout/refresh/step-up, API token validation
sdk-java/          Java SDK: core token validation and claims model (Nimbus JOSE+JWT), plus a
                   Spring Boot starter for BFF login and resource-server validation
packages/design-system  The delivered design system, as a workspace package
examples/demo-service   One demo app, run twice as "Service A" and "Service B"
e2e/               Playwright suite
deploy/            Dockerfiles, docker-compose, Helm chart
docs/              Architecture, claims contract, operations
```

## Domain model

- **Tenant:** slug, name, status. The `system` tenant hosts platform administration.
- **Application:** a downstream service, registered once per install. Has client_id, client auth
  (secret or `private_key_jwt`), redirect URIs, post-logout URIs, declared roles, declared attribute
  keys, and allowed extra scopes (for example `pin` for personal identity number).
- **TenantApplication:** application enabled for a tenant. Only enabled apps can authenticate in
  that tenant. Enabling app B for a tenant that already uses app A gives SSO between them without
  further configuration.
- **LoginMethod:** per tenant, with `protocol` `oidc` or `saml`. OIDC config: issuer, client_id,
  encrypted secret, scopes. SAML config: IdP metadata (URL or inline, refreshed on a schedule and
  signature-checked when a metadata signing certificate is configured), IdP entityID, requested
  LoA / AuthnContextClassRef values, requested attribute set or entity category, SP signing and
  encryption key pair (encrypted at rest, rotatable with overlap), and the attribute mapping.
  Common to both:
  claim mapping (subject, name, email, personal identity number, groups, upstream acr), the acr value
  Portvakt asserts, home-realm email domains, display name/kind (`employee` or `citizen`), secret
  expiry date, and a **session policy**: `maxAgeSeconds`, `idleSeconds`, `allowSso`.
- **Person:** per tenant, internal UUID. **Identity:** link from person to (login method, upstream
  subject). Stores the latest mapped attributes (name, email, pin, groups, protected identity flag).
- **RoleAssignment:** person gets role R in application X. **RoleRule:** in tenant T, login method
  M (optional) and upstream group G gives role R in application X. Rules are evaluated at every login.
- **AttributeAssignment:** person has key/value attribute in application X.
- **Party and RepresentationGrant (ombud):** a party is a person or an organisation (type,
  identifier, display name). A grant lets agent person P act for party Q, optionally limited to
  certain applications, within a validity window, revocable. v1 source is Portvakt's own register
  behind a `RepresentationSource` interface so Bolagsverket or Mina ombud can be added later.
- **SigningKey:** kid, alg (ES256), encrypted private JWK, state `next` / `active` / `retiring` /
  `retired`, timestamps.
- **AuditEvent:** append-only: login success/failure, representation chosen, token issued for app,
  admin changes, key rotation. Fields: tenant, actor, subject, action, details, timestamp.

## SAML upstream (Swedish eID Framework)

- One SP per login method, entityID `{PUBLIC_URL}/t/{tenant}/saml/{loginMethodId}`, with its own
  published SP metadata (signing and encryption certificates, AssertionConsumerService, entity
  categories) so the tenant can register it with the federation or IdP.
- Signed AuthnRequests (HTTP-Redirect or POST binding), RequestedAuthnContext with the configured
  LoA URIs (for example `http://id.elegnamnden.se/loa/1.0/loa3`), optional `PrincipalSelection`
  with personal identity number for step-up and signing scenarios.
- Responses: POST binding to the ACS. Require signed assertions, support encrypted assertions
  (required by the framework), validate audience, recipient, destination, InResponseTo against a
  stored request, NotBefore/NotOnOrAfter with small clock skew, one-time use of assertion IDs
  (replay cache in Postgres), and the issued LoA against what was requested. Reject unsigned or
  wrapped responses (XML signature wrapping defences come from the library plus our own checks).
- Attribute mapping defaults for the framework: `urn:oid:1.2.752.29.4.13` personalIdentityNumber,
  `urn:oid:2.5.4.42` givenName, `urn:oid:2.5.4.4` sn, `urn:oid:2.16.840.1.113730.3.1.241`
  displayName, `urn:oid:1.2.752.201.3.4` prid, `urn:oid:1.2.752.201.3.5` pridPersistence,
  `urn:oid:1.2.752.201.3.6` personalIdentityNumberBinding, `urn:oid:1.2.752.201.3.1`
  orgAffiliation, and for SITHS `urn:oid:1.2.752.29.6.2.1` employeeHsaId. Verify every OID
  against the current "Attribute Specification for the Swedish eID Framework" before shipping;
  the mapping stays configurable per login method. The SAML subject
  used for identity linking is configurable: personal identity number, prid, HSA-id, or NameID.
- Single logout: SP-initiated SLO toward the IdP when the IdP supports it; failures do not block
  local logout.
- The mock IdP gains a SAML IdP mode that signs and encrypts assertions with framework attributes,
  so e2e tests exercise BankID-, Freja- and SITHS-style logins over SAML.

## Session policy semantics

- The broker session lasts at most `maxAgeSeconds` of the login method used.
- Idle: if no authorization or refresh happened within `idleSeconds`, the next request requires
  login. Refresh tokens rotate and live at most `min(idleSeconds, remaining max age)`.
- `allowSso = false`: an authorization request from an app other than the one the session was
  established for requires a fresh upstream login. Same-app re-authorization may reuse the session.
- Apps may tighten policy (`max_age`, `prompt=login`, `acr_values`) but never loosen it.
- The ID token carries `session_exp` (absolute broker session end) so the BFF can expire its own
  session no later than the broker's.

## Claims contract (v1)

ID token and access token for app X in tenant T. Access tokens carry only `sub`, `tid`, `idp`,
`idp_kind`, `acr`, `auth_time`, `roles`, `attrs` and `rep` (besides `iss`, `aud`, `exp`, `iat`, `jti`,
`client_id`), never `name`, `email` or `pin` (data minimisation). ID tokens carry the profile claims
per scope. The userinfo endpoint is disabled: apps read profile claims from the ID token.

| Claim | Meaning |
|---|---|
| `iss` | `{PUBLIC_URL}/t/{T}` |
| `aud` | client_id of X |
| `sub` | The signed-in person's UUID, always, also when representing |
| `tid` | Tenant slug |
| `idp` | Login method id; `idp_kind` is `employee` or `citizen` |
| `acr`, `amr`, `auth_time` | Assurance level asserted by the login method, method (`amr`: ID token only), auth time |
| `roles` | Roles for app X only (direct assignments plus matched rules) |
| `attrs` | Attribute map for app X only |
| `rep` | Present only when representing: `{ "sub": <party UUID>, "type": "person" or "organisation", "name": ... }` |
| `name`, `email` | ID token only, with `profile` / `email` scopes |
| `pin` | ID token only: personal identity number, only with scope `pin` and only if X allows it |
| `protected_identity` | ID token only: `true` when upstream flags protected identity; apps must then minimise display |
| `session_exp` | ID token only: absolute broker session end |

The contract is versioned in `docs/claims.md`. Changing claim names is a breaking change.

## Key management

- ES256 signing keys in the database, private part encrypted with `MASTER_KEY` (AES-256-GCM).
  Upstream client secrets use the same envelope.
- Rotation: a new key is created as `next` and published in JWKS; after `KEY_PUBLISH_AHEAD` it
  becomes `active`; the old one becomes `retiring` and stays in JWKS for at least the longest
  token lifetime, then `retired`. A scheduled job drives this; a Postgres advisory lock ensures one
  instance runs it. Each instance reloads keys periodically so replicas converge.
- Admin can trigger rotation manually. The SDK caches JWKS and refetches on an unknown `kid`
  (rate limited).
- Login methods with a secret expiry date within 30 days are flagged in the admin portal and the
  admin API.

## Outage behaviour

- Apps validate tokens locally and keep their own BFF session, so signed-in users keep working
  while Portvakt is down until their access token needs refreshing. The SDK then keeps the session
  for a configurable grace period (default 0 = sign out) and new sign-ins fail with a clear page.
- Health: `/healthz` (process) and `/readyz` (database reachable, keys loaded).

## Admin

- The admin portal is itself an app on Portvakt (dogfooding): client `portvakt-admin`, roles
  `platform-admin` (meaningful only in the `system` tenant) and `tenant-admin` (manages only its
  own tenant). The admin portal is enabled in every tenant that should self-administer.
- Bootstrap on first start (empty database): create the `system` tenant, the `portvakt-admin`
  application, a login method from `BOOTSTRAP_IDP_*` env vars, and a role rule or assignment that
  makes `BOOTSTRAP_ADMIN_SUBJECT` a platform admin.
- Admin API (`/admin/api`, JSON, bearer access token for `portvakt-admin`): tenants, applications,
  tenant applications, login methods (secret write-only), roles, role rules, assignments, parties,
  representation grants, persons (read, search), keys (list, rotate), audit events (list, filter).
- Admin portal pages cover all of the above with the design system's AppShell, SidebarNav,
  PageHeader, DataTable, FormSection, Field, Overlay and StatCard.

## Milestones

Each milestone ends with: its tests passing, typecheck and lint clean, an independent review, fixes,
and one commit. Milestones run sequentially. At most two subagents run at a time (implementer and
reviewer).

1. **M0 Scaffold.** Workspaces, TypeScript config, ESLint, Vitest, Prettier, docker-compose with
   Postgres for dev/test, design-system as a package that type-checks, `CLAUDE.md` project policy,
   GitHub Actions CI. Accept: `npm run typecheck`, `npm run lint`, `npm test` pass.
2. **M1 Data and crypto.** SQL migrations for the whole domain model, repositories, secret
   envelope encryption, config loading with zod. Accept: integration tests against Postgres for
   repositories, unit tests for crypto.
3. **M2 OIDC core.** Provider per tenant with Postgres adapter, dynamic clients from enabled
   applications, signing keys and rotation job, discovery and JWKS, health probes. Accept:
   integration tests with `openid-client` (discovery per tenant, client of a non-enabled app is
   rejected, rotation keeps old tokens verifiable, tenant issuers differ).
4. **M3 Federation and login.** Mock IdP app, upstream login with `openid-client`, home realm
   discovery, JIT persons and identities, claims and roles/rules/attributes, session policies,
   login UI in the design system. Accept: integration tests for policy semantics and claims.
5. **M3b SAML upstream.** SAML login methods per the section above, SP metadata endpoint, metadata
   refresh, replay cache, SAML mode in the mock IdP, step-up via RequestedAuthnContext. Accept:
   integration tests for signature, encryption, replay, audience, InResponseTo, expiry, LoA
   mismatch, and attribute mapping to the claims contract.
6. **M4 Representation, step-up, audit.** Representation chooser, `rep` claim, grant
   revocation honoured at refresh, `acr_values` step-up, audit events. Accept: integration tests.
7. **M5 SDK and demo service.** BFF middleware, API validation middleware with roles/acr checks,
   JWKS cache, `session_exp`, step-up helper; demo service shown as A and B. Accept: SDK unit tests
   and a local SSO smoke test.
8. **M5b Java SDK.** Core library (JWKS cache with unknown-kid refetch, claims model including
   `rep`, role and acr checks) and Spring Boot starter (oauth2Login wired to a Portvakt
   tenant, `session_exp` enforcement, step-up, resource-server validation). A Java demo service.
   Accept: JUnit tests against a real Portvakt instance in the test stack.
9. **M6 Admin API and portal.** Admin API with platform/tenant scoping, admin portal on the SDK.
   Accept: API integration tests including tenant isolation, portal builds and type-checks.
10. **M7 End-to-end.** Playwright suite over the full local stack (see scenarios below), with the
   Java demo service covering scenarios 2, 3, 6 and 7 as well.
11. **M8 Production hardening.** Rate limiting on login and token endpoints, strict security
   headers and CSP, CSRF protection for admin and interaction forms, input validation everywhere,
   structured JSON logs without personal data, Prometheus metrics, graceful shutdown, migrations
   under an advisory lock, configuration validated at start (refuse to run with dev defaults in
   production), dependency audit clean, and an independent security review with fixes.
12. **M9 Packaging and docs.** Dockerfiles, docker-compose for the full stack, Helm chart,
   README, architecture, claims contract, operations (rotation, outage, backup), threat notes.
   Accept: images build, compose stack passes the e2e suite, `helm template` renders.

## End-to-end scenarios (M7)

1. Platform admin signs in to the admin portal, creates a tenant, enables Service A, adds an
   employee login method and a citizen login method.
2. An employee (mock Entra over OIDC) signs in to Service A without existing beforehand; a group rule gives
   role `handlaggare`, which Service A displays.
3. Service B is not enabled for the tenant: sign-in is refused. After enabling it, the same
   employee reaches Service B without a new upstream login (SSO).
4. A citizen (mock BankID over SAML, Swedish eID Framework attributes) with `allowSso = false` must sign in again when moving from A to B.
5. A short citizen session expires on schedule and Service A requires sign-in again.
6. An agent with a representation grant chooses an organisation; Service A shows that it acts for
   the organisation and who the agent is. After revoking the grant, the next refresh fails.
7. Step-up: Service A requests a higher acr for a sensitive action and the user is sent to a
   login method that provides it.
8. Isolation: a user of tenant X cannot use a login method of tenant Y; a token for Service A is
   rejected by Service B's API; a tenant admin cannot see other tenants in the admin portal.
9. Key rotation from the admin portal: signed-in sessions keep working and new tokens use the new
   key.
10. A SITHS-style employee login over SAML maps the HSA-id and gets roles from a rule.
11. A login method with a secret or SP certificate expiring in less than 30 days is flagged in the portal.

## Out of scope for v1 (recorded as follow-ups)

Direct BankID RP API and Freja REST API integrations (v1 reaches them through SAML or OIDC IdPs), Bolagsverket and Mina ombud as representation sources,
SCIM provisioning, a policy engine for fine-grained authorization, a Python SDK, forwarding audit
events to the starter kit's log service, per-tenant signing keys, and pairwise subjects.
