# Portvakt Java SDK

Portvakt for Java 21 and Spring Boot 4 (servlet), with the same behaviour as the TypeScript SDK
(`packages/sdk-node`):

- **portvakt-sdk-core** (no Spring dependency): configuration with validation, access token and
  ID token validation (Nimbus JOSE+JWT, ES256 only, `iss` pinned), the JWKS cache, the claims
  model (`PortvaktPrincipal`), acr ranking and cached `client_credentials` tokens.
- **portvakt-spring-boot-starter**: browser login (BFF style: server-side session, Spring
  Security `oauth2Login`, PKCE, step-up, representation switch, RP-initiated logout), resource
  server validation with RFC 6750 answers, and a service-to-service token bean. Each part is
  enabled on its own.

The demo service `examples/demo-service-java` ("Tjänst C") uses the starter for all three.

## Maven coordinates

```xml
<dependency>
  <groupId>se.portvakt</groupId>
  <artifactId>portvakt-spring-boot-starter</artifactId>
  <version>1.0.0-SNAPSHOT</version>
</dependency>

<!-- Without Spring: -->
<dependency>
  <groupId>se.portvakt</groupId>
  <artifactId>portvakt-sdk-core</artifactId>
  <version>1.0.0-SNAPSHOT</version>
</dependency>
```

Built against Spring Boot 4.1.1 (Spring Framework 7.0, Spring Security 7.1.1, Jackson 3) and
Nimbus JOSE+JWT 10.9.1, the version Spring Security declares (one Nimbus for the core and
Spring); tested with JUnit 6.0 and AssertJ 3.27 from Boot's BOM. Spring Boot 3.5 is not
supported (its open-source support ended on 2026-06-30). Publishing to a repository belongs to
M9.

## Browser login quick start

```yaml
portvakt:
  issuer: https://login.example.org/t/kommunen # the tenant's issuer, exactly
  client-id: case-service
  client-secret: ${CLIENT_SECRET}
  login:
    enabled: true
    redirect-uri: https://case.example.org/auth/callback # registered in Portvakt
    post-logout-redirect-uri: https://case.example.org/
    public-paths: [/, /css/**, /error]
server:
  servlet:
    session:
      cookie:
        name: case_session # must differ between applications on one host
        secure: true
        same-site: lax
```

With no `SecurityFilterChain` of your own, the starter adds one: the public paths are open,
everything else requires a login. Browser navigations are redirected to the login; XHR/fetch
gets `401 {"error": "login_required", "loginUrl"}`.

```java
@Controller
class CaseController {
  private final PortvaktAccessTokens tokens;

  @GetMapping("/cases")
  String cases(HttpServletRequest request, HttpServletResponse response, Model model) {
    PortvaktPrincipal person = PortvaktSecurity.currentPrincipal().orElseThrow(); // from the ID token
    String token = tokens.getAccessToken(request, response); // refreshed once per session, also across instances
    // call your API with "Authorization: Bearer " + token
    return "cases";
  }

  @RequireAcr(AcrRanking.LOA4) // step-up when the session's acr is lower
  @PostMapping("/cases/{id}/decide")
  String decide(@PathVariable String id) { ... }
}
```

Your own chain applies the same configuration with `http.with(PortvaktSecurity.login(),
Customizer.withDefaults())`, and `portvakt.requireAcr(acr)` (the bean `portvakt`) is an
authorization manager for `authorizeHttpRequests`.

### Routes

| Route                                  | What it does                                                                                                                                                                                                                                                                                                                   |
| -------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `GET /auth/login`                      | Starts a login (authorization code, PKCE, state, nonce). Query: `returnTo` (same-origin path, else `default-return-to`), `acr`, `prompt` (`login`, `select_account`, `none`), `loginHint`, `uiLocales`.                                                                                                                        |
| `GET /auth/callback`                   | Spring's code exchange; the ID token is validated by the core. A login below the requested `acr` answers 403 `acr_not_met` and keeps the existing session.                                                                                                                                                                     |
| `POST /auth/logout`                    | CSRF-protected while a session exists (Spring Security: `_csrf` field or `X-CSRF-TOKEN` header). Ends the session and redirects to Portvakt's end-session endpoint with `id_token_hint` (JSON for fetch); without a local session also, with `client_id` and `post_logout_redirect_uri` (Portvakt asks the person to confirm). |
| `GET /auth/session`                    | JSON for scripts: `authenticated`, `principal` (without `pin`), `expiresAt`, `sessionEndsAt`, `csrfToken`. Never tokens.                                                                                                                                                                                                       |
| `GET /auth/select-representation`      | A new authorization with `prompt=select_account`: the representation chooser, without a new upstream login.                                                                                                                                                                                                                    |
| `GET /auth/step-up?acr=...&returnTo=/` | A new authorization with `acr_values`.                                                                                                                                                                                                                                                                                         |

Step-up and the representation switch replace the session's login, so another site must not be
able to start them; the same holds for `/auth/login` with `acr` or `prompt`, and for any login
while a session exists. When the browser sends `Sec-Fetch-Site`, it must be `same-origin` or
`none`; without it, a same-origin `Referer` is required. A browser navigation from another site
gets a minimal page of your application instead ("Fortsätt till inloggning", no styles or
scripts, strict CSP) whose button starts the same flow from here; XHR and other
non-navigations get 403 `cross_site_request`. Plain links from your own pages work, and a plain
login without a session may be linked from anywhere.

`@RequireAcr` and `portvakt.requireAcr` redirect browser navigations to the step-up (a deep link
from another site gets the same interstitial page) and answer XHR with `401 {"error":
"step_up_required", "acr", "stepUpUrl"}`.

### Session semantics

- The HTTP session holds only a small state: the login time, the session's end, the last
  activity and a random **grant id** (plus Spring Security's CSRF token). The tokens, the
  signed-in person's ID token (name, email, personal identity number) and the pending logins
  with their PKCE verifiers live in the **token store**, keyed by the grant id; Spring Security's
  context is rebuilt from the stored ID token on every request
  (`PortvaktSecurityContextRepository`) and never stored in the HTTP session, so a serialised
  session (Spring Session, a session store) carries no personal data. The client registration
  with its secret is not in the session either. Spring Security changes the session id at every
  login; the grant id stays.
- Token stores (`portvakt.login.token-store`): `memory` (default; one instance only, warned
  about in a `prod`/`production` profile) and `jdbc` (a `DataSource`; several instances and
  Spring Session). The JDBC store keeps one row per grant in `portvakt_grant` (schema in
  `META-INF/portvakt/schema-postgresql.sql`, or `token-store-initialize-schema: true`), sealed with
  AES-256-GCM under `portvakt.login.token-encryption-key` (the grant id as additional data);
  expired rows are deleted in the background. With Spring Session and the in-memory store the
  start-up fails unless `allow-in-memory-token-store-with-spring-session` is set.
- A session ends at the earliest of the ID token's `session_exp` (the broker session),
  `login.max-age` (default 12 h) and `login.idle-timeout` without activity (default 30 min).
  Activity is a protected request or `getAccessToken`; `/auth/session`, the login routes, the
  public paths and static files are not (TypeScript parity). The servlet session timeout is set
  just above the idle timeout.
- `PortvaktAccessTokens.getAccessToken` refreshes through the starter's
  `OAuth2AuthorizedClientManager` when the token has less than the clock skew plus 30 s left,
  but at most half the token's lifetime (short-lived tokens are not refreshed on every request;
  an explicit minimum validity is used as given).
  The check, the refresh and the write of the rotated tokens run inside the token store's
  exclusive update (the JDBC store: one short transaction with `SELECT ... FOR UPDATE` and a lock
  timeout of the HTTP timeout plus 5 s), so a session refreshes once even for concurrent
  requests, stale Spring Session snapshots and several instances: Portvakt rotates refresh
  tokens and treats a replay as theft. A refreshed ID token replaces the principal; the
  session's end only ever moves earlier.
- Portvakt asks to retry later (HTTP 429, or the OAuth error `temporarily_unavailable` with any
  status), at a refresh or at the login callback: transient. `getAccessToken` throws
  `PortvaktRetryLaterException` (a `PortvaktUnavailableException`: 503 with Portvakt's
  `Retry-After`); the session keeps its unchanged refresh token and no outage starts (the grace
  is not involved); the callback answers the unavailable page.
- A refused refresh (`invalid_grant`: grant revoked, representation no longer valid, broker
  session ended) ends the session: `LoginRequiredException` (a login redirect or 401
  `login_required` through the starter's exception resolver). `invalid_client` (Portvakt answers
  it with 401) is the application's configuration: the session stays and the request answers 502.
- Of two callbacks with the same state only one gets the pending login (an atomic take from the
  token store) and redeems the code; the other answers `login_expired`.
- Every request to Portvakt has one deadline for the whole request, including the body.
- Portvakt unreachable during a refresh (network error, timeout or 5xx): with
  `login.outage-grace` 0 (default) the session ends. With a grace, the first failure starts the
  outage (`PortvaktUnavailableException`, 503) and the session continues; it ends only when a
  refresh fails again after the grace has passed since the first failure. A refresh that
  succeeded is kept even when its new ID token cannot be checked yet (the outage path then). A
  token that is still valid needs no Portvakt. New logins answer a clear 503 page while Portvakt is unreachable.
- Discovery is lazy and cached (stale-if-error): the application starts while Portvakt is down.

## Resource server quick start

```yaml
portvakt:
  issuer: https://login.example.org/t/kommunen
  client-id: case-service # the default audience
  resource-server:
    enabled: true
    allow-service: false # client_credentials tokens refused by default
    allowed-services: [archive-service]
    allow-representation: true
```

The default chain covers `/**` (or `/api/**` when the login is enabled too;
`resource-server.paths` overrides it) and applies the requirements above. Per route:

```java
@Bean
SecurityFilterChain api(HttpSecurity http, PortvaktSecurity portvakt) {
  http.securityMatcher("/api/**").with(PortvaktSecurity.resourceServer(), Customizer.withDefaults());
  http.authorizeHttpRequests(a -> a
      .requestMatchers("/api/admin/**").access(portvakt.accessToken(r -> r.roles("admin")))
      .requestMatchers("/api/decisions/**").access(portvakt.accessToken(r -> r.acr(AcrRanking.LOA4)))
      .anyRequest().access(portvakt.accessToken()));
  return http.build();
}
```

The defaults `allow-service`, `allowed-services` and `allow-representation` hold in every chain,
also in your own: a token they refuse is _restricted_ (not authenticated, no authorities), so
`authenticated()`, `hasAuthority(...)` and the `@portvakt` checks answer 403 `insufficient_scope`
with the reason. A route accepts such tokens only explicitly, for example
`portvakt.accessToken(r -> r.allowService(true))` or `r.allowRepresentation(true)`.

Method security (`@EnableMethodSecurity`): `@PreAuthorize("@portvakt.hasRole('handlaggare')")`,
`@portvakt.hasAnyRole(...)`, `@portvakt.acrAtLeast(...)`, `@portvakt.isService()`,
`@portvakt.isRepresenting()`. Roles are also authorities `PORTVAKT_ROLE_<role>` (plus
`PORTVAKT_PERSON` or `PORTVAKT_SERVICE`). The principal is
`PortvaktSecurity.currentPrincipal()`: empty for a restricted token (one the defaults refuse)
unless the route accepted it with `portvakt.accessToken(r -> ...)`, so an open route never
mistakes a service or representation token for a person.

Failures answer with RFC 6750 errors and `WWW-Authenticate: Bearer realm="portvakt", error=...`:
400 `invalid_request` (malformed header), 401 without error (no token), 401 `invalid_token`,
403 `insufficient_scope` (with `reason`: `missing_role`, `service_not_allowed`,
`representation_not_allowed`), 401 `insufficient_user_authentication` with `acr_values`
(RFC 9470), and 503 `temporarily_unavailable` when Portvakt's keys cannot be fetched. Role and
acr requirements apply to person tokens; service principals never have roles.

## Service-to-service

```yaml
portvakt:
  client-credentials:
    enabled: true
```

```java
String token = clientCredentials.forAudience("archive-service").getToken();
```

Tokens (`resource=urn:portvakt:app:{audience}`) are cached until shortly before they expire (10%
of the lifetime, at least 30 s) and fetched once at a time. A network error, timeout or 5xx is
`PortvaktUnavailableException`; a refusal is a `PortvaktException` with Portvakt's OAuth error
code. The target must be enabled in the same tenant and listed in the calling application's
`serviceAudiences` in Portvakt (empty by default: no service tokens for other applications).

## Core without Spring

```java
PortvaktClient portvakt = PortvaktClient.create(PortvaktConfig.builder()
    .issuer("https://login.example.org/t/kommunen")
    .clientId("case-service")
    .clientAuth(ClientAuth.clientSecretBasic(secret)) // only for client_credentials
    .build());
PortvaktPrincipal caller = portvakt.verifier().verifyAccessToken(token, "case-service");
portvakt.verifier().authorize(caller, AccessTokenRequirements.forAudience("case-service").roles("admin").build());
```

`BearerTokens.fromAuthorizationHeader` reads the header; `AccessTokenException` carries the
status, `wwwAuthenticate()` and `body()` of the RFC 6750 answer.

## Principal

`PortvaktPrincipal` (an immutable record): `service`, `sub` (the person, also when representing;
the calling client_id for a service), `tenant`, `clientId`, `idp`, `idpKind`, `acr`,
`authTime`, `roles`, `attrs`, `rep` (`sub`, `type`, `name`), and from the ID token only `name`,
`email`, `pin`, `hsaId`, `orgAffiliation`, `protectedIdentity`. Person and service tokens are
told apart by the claims Portvakt issues (person tokens carry the login claims and a person UUID
as `sub`; client_credentials tokens none of them and `sub` = `client_id`); anything in between is
refused. `toString()` never prints personal data. `AcrRanking.DEFAULT` is loa2 < loa3 < loa4;
values outside the ranking only match themselves.

## Configuration reference

| Property                                                         | Default                   | Meaning                                                                                                                                                                                            |
| ---------------------------------------------------------------- | ------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `portvakt.issuer`                                                | required                  | The tenant issuer `{PUBLIC_URL}/t/{tenant}`, exactly (no trailing slash).                                                                                                                          |
| `portvakt.client-id`                                             | required                  | The application's client_id (default audience).                                                                                                                                                    |
| `portvakt.client-secret`                                         | none                      | At least 16 characters; required for the login and client credentials.                                                                                                                             |
| `portvakt.client-auth-method`                                    | `client-secret-basic`     | `client-secret-basic`, `client-secret-post` or `private-key-jwt`.                                                                                                                                  |
| `portvakt.private-jwk`                                           | none                      | For private_key_jwt: the private JWK (JSON, EC P-256 or RSA, with `kid`).                                                                                                                          |
| `portvakt.scopes`                                                | `openid, profile, email`  | Must include `openid`; `pin`/`hsa` only if the application is allowed them.                                                                                                                        |
| `portvakt.clock-skew`                                            | `30s`                     | Tolerance for `exp`, `nbf`, `iat` (at most 5 min).                                                                                                                                                 |
| `portvakt.http-timeout`                                          | `10s`                     | Every request to Portvakt.                                                                                                                                                                         |
| `portvakt.discovery-cache`                                       | `1h`                      | Discovery is refetched after this (stale metadata is kept on failure).                                                                                                                             |
| `portvakt.failure-cache`                                         | `5s`                      | With nothing cached, a failed discovery or JWKS fetch is retried after this.                                                                                                                       |
| `portvakt.jwks.cache-max-age`                                    | `5m`                      | Keys are refetched after this. Keep it below Portvakt's KEY_MANUAL_PUBLISH_AHEAD minus 90 s.                                                                                                       |
| `portvakt.jwks.cooldown`                                         | `30s`                     | At most one JWKS fetch per this for access tokens; an unknown `kid` within it is refused. ID tokens from the token endpoint always refetch an unknown `kid` (a key rotation never ends a session). |
| `portvakt.jwks.stale-max-age`                                    | `1h`                      | While refetches fail, keys stay in use until cache-max-age plus this; then 503. Longer survives longer outages, but trusts a key an emergency rotation retired that much longer.                   |
| `portvakt.acr-ranking`                                           | loa2, loa3, loa4          | Must match Portvakt's `ACR_RANKING`.                                                                                                                                                               |
| `portvakt.allow-insecure-requests`                               | `false`                   | Allows an `http:` issuer (local development only).                                                                                                                                                 |
| `portvakt.login.enabled`                                         | `false`                   | Browser login.                                                                                                                                                                                     |
| `portvakt.login.base-path`                                       | `/auth`                   | Where the login routes live.                                                                                                                                                                       |
| `portvakt.login.redirect-uri`                                    | `{baseUrl}/auth/callback` | The registered redirect URI; set it explicitly behind a proxy.                                                                                                                                     |
| `portvakt.login.post-logout-redirect-uri`                        | `{baseUrl}/`              | The registered post-logout URI.                                                                                                                                                                    |
| `portvakt.login.default-return-to`                               | `/`                       | After a login without `returnTo`.                                                                                                                                                                  |
| `portvakt.login.idle-timeout`                                    | `30m`                     | Without activity (protected requests, `getAccessToken`) the session ends.                                                                                                                          |
| `portvakt.login.token-store`                                     | `memory`                  | `memory` (one instance) or `jdbc` (a DataSource; several instances).                                                                                                                               |
| `portvakt.login.token-encryption-key`                            | none                      | JDBC store: AES-256-GCM keys, 32 bytes base64 each; the first seals.                                                                                                                               |
| `portvakt.login.token-store-table`                               | `portvakt_grant`          | JDBC store: the table.                                                                                                                                                                             |
| `portvakt.login.token-store-initialize-schema`                   | `false`                   | JDBC store: create the table when missing.                                                                                                                                                         |
| `portvakt.login.token-store-cleanup-interval`                    | `5m`                      | Expired tokens and pending logins are deleted this often.                                                                                                                                          |
| `portvakt.login.allow-in-memory-token-store-with-spring-session` | `false`                   | Allows the in-memory store with Spring Session (one instance only).                                                                                                                                |
| `portvakt.login.max-age`                                         | `12h`                     | The application's own cap (`session_exp` caps it further).                                                                                                                                         |
| `portvakt.login.outage-grace`                                    | `0s`                      | See "Session semantics".                                                                                                                                                                           |
| `portvakt.login.public-paths`                                    | `/error`                  | Open paths of the default chain.                                                                                                                                                                   |
| `portvakt.resource-server.enabled`                               | `false`                   | Bearer token validation.                                                                                                                                                                           |
| `portvakt.resource-server.audience`                              | `portvakt.client-id`      | The token's `aud`.                                                                                                                                                                                 |
| `portvakt.resource-server.paths`                                 | `/**` or `/api/**`        | Paths of the default resource server chain (`/api/**` when the login is enabled).                                                                                                                  |
| `portvakt.resource-server.allow-service`                         | `false`                   | Accept client_credentials tokens from every application of the tenant.                                                                                                                             |
| `portvakt.resource-server.allowed-services`                      | none                      | Accept client_credentials tokens from these client_ids.                                                                                                                                            |
| `portvakt.resource-server.allow-representation`                  | `true`                    | Accept person tokens that act for another party.                                                                                                                                                   |
| `portvakt.client-credentials.enabled`                            | `false`                   | A `ClientCredentialsTokenProvider` bean.                                                                                                                                                           |

Invalid properties stop the start-up with a list of every problem (never a secret value). IDE
completion comes from the generated `spring-configuration-metadata.json`. The bean
`portvaktClock` (a `java.time.Clock`) can be replaced in tests.

## Security notes

- **Issuer pinning is mandatory.** Portvakt signs the tokens of every tenant with the same keys,
  so a token of another tenant has a valid signature. The SDK accepts only `iss` exactly equal to
  the configured issuer, `typ: at+jwt` for access tokens, ES256, and `aud` equal to the API's
  audience. ID tokens are validated by the same core (not by Spring's decoder).
- **Protected identity.** When `protectedIdentity` is true, Portvakt issues no name or email and
  the SDK never keeps them. Applications must minimise what they display and store about the
  person (show "Skyddad identitet", never look the person up elsewhere to fill in details).
- **Representation (`rep`).** `sub` is always the signed-in person; `rep.sub` is the party they
  act for, and `roles` are the person's own. Portvakt only attests that the person holds a
  representation right for the party in this application. **Authorise every action on behalf of
  `rep.sub` with your own rules.** APIs that must not be used on someone's behalf set
  `allow-representation: false` (or `r.allowRepresentation(false)` per route).
- No tokens, cookies, session ids or personal data are logged; log lines carry error codes only.
- Use `same-site: lax` and `secure: true` for the session cookie (`strict` drops it on the first
  navigation after the login redirect). In a `prod`/`production` profile the starter warns at
  start when the cookie is not Secure or has no SameSite.
- Keep Spring Security's default session fixation protection (`changeSessionId`):
  `newSession()` drops the session's tokens right after the login.
- Several instances or Spring Session: use `token-store: jdbc`. The tokens never sit in the HTTP
  session, so a session snapshot written back by another request cannot bring an old refresh
  token back. The JDBC table holds sealed values only; the runtime role needs SELECT, INSERT,
  UPDATE and DELETE on it. Rotate `token-encryption-key` by putting the new key first.

## Building and testing

There is no local JDK requirement: Maven runs in Docker.

```sh
npm run test:java                 # whole build plus integration tests against a real Portvakt
npm run test:java -- -pl portvakt-sdk-core   # other arguments go to Maven
docker run --rm -v "$PWD:/workspace" -v portvakt-m2:/root/.m2 -w /workspace/sdk-java \
  maven:3.9-eclipse-temurin-21 mvn -B -ntp -C verify   # unit tests only (integration tests skip)
```

On Windows with Git Bash prefix the `docker run` with `MSYS_NO_PATHCONV=1`, or use PowerShell.
The scripts run the image pinned by digest in `deploy/images.Dockerfile`, and Maven with strict
checksums (`-C`: a mismatching download fails the build).
